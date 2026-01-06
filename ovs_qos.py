#!/usr/bin/env python3
"""
OVS per-VM upstream rate limiter

- 通过 OVS interface 的 ingress_policing_rate/burst 限制每台 KVM 小鸡上行。
- 周期性读取所有 Interface 的 statistics.rx_bytes 估算上行 Mbps。
- 根据 config.json 中配置的阈值和惩罚策略，动态调整每个接口的 policing。
- 状态持久化在 /run/ovs-qos/state.json，方便 CLI 查询当前限速状态。
"""

import argparse
import fcntl
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional

# 路径约定：所有机器统一
CONFIG_PATH = "/opt/ovs-qos/config.json"
STATE_PATH = "/run/ovs-qos/state.json"
LOG_PATH = "/var/log/ovs-qos.log"
LOCK_PATH = "/run/ovs-qos/daemon.lock"

# 允许通过环境变量覆盖 ovs-vsctl 路径
OVS_VSCTL = os.environ.get("OVS_VSCTL", "ovs-vsctl")

# 命令超时（秒）
OVS_TIMEOUT = 10

# 默认配置，可以被 /opt/ovs-qos/config.json 配置文件覆盖
DEFAULT_CONFIG: Dict[str, Any] = {
    "base_rate_mbit": 1000,
    "iface_name_regexes": [r"^kvm[0-9]+\..*$"],  # 修复：单反斜杠转义点号
    "sample_interval_sec": 60,  # 默认 1 分钟，可通过 config.json 覆盖
    # Stage 1 默认参数（可通过 config.json 调整）
    "stage1_usage_fraction": 0.90,
    "stage1_trigger_seconds": 900,
    "stage1_rate_fraction": 0.90,
    "stage1_penalty_seconds": 1800,
    # Stage 2 默认参数
    "stage2_usage_fraction": 0.80,
    "stage2_trigger_seconds": 1800,
    "stage2_rate_fraction": 0.80,
    "stage2_penalty_seconds": 3600,
}

# 全局缓存：编译后的正则表达式
_compiled_regexes: List = []


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def validate_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """校验配置范围与类型，非法值回退默认值。"""
    validated = DEFAULT_CONFIG.copy()

    def update_number(key: str, min_value: float, max_value: Optional[float] = None) -> None:
        if key not in cfg:
            return
        value = _as_number(cfg.get(key))
        if value is None or value <= min_value or (max_value is not None and value > max_value):
            logging.warning("Invalid config %s=%r, using default %r", key, cfg.get(key), validated[key])
            return
        validated[key] = value

    update_number("base_rate_mbit", 0.0)
    update_number("sample_interval_sec", 0.0)
    update_number("stage1_usage_fraction", 0.0, 1.0)
    update_number("stage1_rate_fraction", 0.0, 1.0)
    update_number("stage2_usage_fraction", 0.0, 1.0)
    update_number("stage2_rate_fraction", 0.0, 1.0)
    update_number("stage1_trigger_seconds", 0.0)
    update_number("stage1_penalty_seconds", 0.0)
    update_number("stage2_trigger_seconds", 0.0)
    update_number("stage2_penalty_seconds", 0.0)

    if "iface_name_regexes" in cfg:
        patterns = cfg.get("iface_name_regexes")
        if isinstance(patterns, list):
            filtered = [p for p in patterns if isinstance(p, str)]
            if filtered:
                validated["iface_name_regexes"] = filtered
            else:
                logging.warning("Invalid config iface_name_regexes=%r, using default %r", patterns, validated["iface_name_regexes"])
        else:
            logging.warning("Invalid config iface_name_regexes=%r, using default %r", patterns, validated["iface_name_regexes"])

    return validated

def ensure_dirs() -> None:
    Path(STATE_PATH).parent.mkdir(parents=True, exist_ok=True)
    Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)


def setup_logging() -> None:
    ensure_dirs()

    # 避免重复添加 handler（例如异常重启或未来扩展命令调用时）
    for h in logging.root.handlers:
        if isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == LOG_PATH:
            logging.root.setLevel(logging.INFO)
            return

    handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=3,  # 保留 .1 .2 .3
        encoding="utf-8",
        delay=True,
    )
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.INFO)


def acquire_lock() -> Any:
    """获取文件锁，防止多实例运行。"""
    ensure_dirs()
    lock_file = open(LOCK_PATH, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        print("Error: Another ovs-qos daemon is already running.", file=sys.stderr)
        sys.exit(1)
    lock_file.write(str(os.getpid()))
    lock_file.flush()
    return lock_file  # 保持引用，防止 GC 释放锁


def load_config() -> Dict[str, Any]:
    """加载配置文件，没有则用默认配置。"""
    cfg = DEFAULT_CONFIG.copy()
    p = Path(CONFIG_PATH)
    if p.exists():
        try:
            with p.open() as f:
                data = json.load(f)
            if isinstance(data, dict):
                # 文件中的键覆盖默认值
                cfg.update(data)
            else:
                logging.error("Config file %s must be a JSON object, using defaults", CONFIG_PATH)
        except Exception:
            logging.exception("Failed to load %s, using defaults", CONFIG_PATH)
    return validate_config(cfg)


def compile_regexes(patterns: List[str]) -> List:
    """编译正则表达式列表，跳过非法正则。"""
    regexes = []
    for p in patterns:
        try:
            regexes.append(re.compile(p))
        except re.error as e:
            logging.error("Invalid regex pattern %r: %s, skipping", p, e)
    return regexes


def run_ovs_vsctl(args: List[str]) -> Optional[Dict[str, Any]]:
    """
    调用 ovs-vsctl 并解析 JSON 输出。
    注意：使用 universal_newlines=True 兼容 Python 3.6。
    """
    cmd = [OVS_VSCTL, "--format=json"] + args
    try:
        out = subprocess.check_output(
            cmd,
            universal_newlines=True,
            stderr=subprocess.STDOUT,
            timeout=OVS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logging.error("ovs-vsctl timed out after %ds: %s", OVS_TIMEOUT, " ".join(cmd))
        return None
    except subprocess.CalledProcessError as e:
        logging.error("ovs-vsctl failed (cmd=%s): %s", " ".join(cmd), e.output.strip())
        return None

    try:
        return json.loads(out)
    except json.JSONDecodeError:
        logging.error("Failed to parse ovs-vsctl JSON output (cmd=%s)", " ".join(cmd))
        return None


def get_interfaces() -> Optional[List[Dict[str, Any]]]:
    """
    获取所有 OVS Interface 的必要字段：
    - name
    - ingress_policing_rate / burst
    - statistics（其中包含 rx_bytes）
    """
    data = run_ovs_vsctl([
        "--columns=name,ingress_policing_rate,ingress_policing_burst,statistics",
        "list", "Interface",
    ])
    if data is None:
        return None
    if not data:
        return []

    headings = data.get("headings", [])
    interfaces: List[Dict[str, Any]] = []
    for row in data.get("data", []):
        item: Dict[str, Any] = {}
        for idx, heading in enumerate(headings):
            item[heading] = row[idx]
        interfaces.append(item)
    return interfaces


def parse_ovs_map(value: Any) -> Dict[str, Any]:
    """
    解析 OVS JSON 中的 map 字段：
    - ["map", [[k1,v1],[k2,v2],...]] -> {k1:v1, k2:v2, ...}
    """
    try:
        if isinstance(value, list) and value and value[0] == "map":
            return {k: v for k, v in value[1]}
    except (TypeError, ValueError):
        pass
    return {}


def parse_ovs_int(value: Any) -> int:
    """
    解析 OVS JSON 中可能的 int 表示方式：
    - 直接 int
    - ["set", [int, ...]] 取第一个 int
    其它情况返回 0。
    """
    if isinstance(value, int):
        return value
    if isinstance(value, list) and value and value[0] == "set":
        for v in value[1]:
            if isinstance(v, int):
                return v
    return 0


def filter_vm_interfaces(
    all_ifaces: List[Dict[str, Any]],
    regexes: List,
) -> Dict[str, Dict[str, Any]]:
    """
    过滤出符合命名规则的 VM 接口（默认 kvmXXXX.0）。
    返回字典：name -> {name, rx_bytes, ingress_policing_rate, ingress_policing_burst}
    """
    result: Dict[str, Dict[str, Any]] = {}

    for iface in all_ifaces:
        name = iface.get("name")
        if not isinstance(name, str):
            continue
        if not any(r.match(name) for r in regexes):
            continue

        stats = parse_ovs_map(iface.get("statistics"))
        rx_bytes = parse_ovs_int(stats.get("rx_bytes"))

        result[name] = {
            "name": name,
            "rx_bytes": rx_bytes,
            "ingress_policing_rate": parse_ovs_int(iface.get("ingress_policing_rate")),
            "ingress_policing_burst": parse_ovs_int(iface.get("ingress_policing_burst")),
        }

    return result


def kbps_from_mbit(mbit: float) -> int:
    return int(mbit * 1000)


def expected_rate_kbps(stage: int, base_rate_kbps: int, stage1_rate_frac: float, stage2_rate_frac: float) -> int:
    if stage == 1:
        return int(base_rate_kbps * stage1_rate_frac)
    if stage == 2:
        return int(base_rate_kbps * stage2_rate_frac)
    return base_rate_kbps


def compute_burst_kb(rate_kbps: int) -> int:
    """
    计算 burst：始终为速率的 10%。
    """
    if rate_kbps <= 0:
        return 0
    return int(rate_kbps * 0.1)


def set_interface_rate(name: str, rate_kbps: int) -> None:
    """设置单个接口的 ingress_policing_rate/burst。"""
    burst_kb = compute_burst_kb(rate_kbps)
    cmd = [
        OVS_VSCTL,
        "set", "interface", name,
        "ingress_policing_rate=%d" % rate_kbps,
        "ingress_policing_burst=%d" % burst_kb,
    ]
    try:
        subprocess.check_call(cmd, stderr=subprocess.STDOUT, timeout=OVS_TIMEOUT)
        logging.info(
            "Set %s rate=%dkbps burst=%dkb",
            name, rate_kbps, burst_kb,
        )
    except subprocess.TimeoutExpired:
        logging.error("Timeout setting rate on %s", name)
    except subprocess.CalledProcessError as e:
        logging.error("Failed to set rate on %s: %s", name, e)


def load_state() -> Dict[str, Any]:
    """加载状态文件（每个接口的 stage / 限速 / 最近速率等）。"""
    p = Path(STATE_PATH)
    if not p.exists():
        return {}
    try:
        with p.open() as f:
            return json.load(f)
    except Exception:
        logging.exception("Failed to load state file")
        return {}


def save_state(state: Dict[str, Any]) -> None:
    """原子方式写入状态文件，防止中途写坏。"""
    try:
        ensure_dirs()
        tmp = Path(STATE_PATH + ".tmp")
        with tmp.open("w") as f:
            json.dump(state, f)
        tmp.replace(STATE_PATH)
    except Exception:
        logging.exception("Failed to save state file")


def now_ts() -> float:
    return time.time()


def init_iface_state(
    state: Dict[str, Any],
    name: str,
    rx_bytes: int,
    base_rate_kbps: int,
    ts: float,
) -> bool:
    """首次发现某接口时，初始化其状态。返回是否新增。"""
    if name not in state:
        state[name] = {
            "stage": 0,
            "stage_until": 0.0,
            "cond1_start": None,
            "cond2_start": None,
            "last_rx_bytes": rx_bytes,
            "last_ts": ts,
            "last_mbps": 0.0,
            "current_rate_kbps": base_rate_kbps,
        }
        return True
    return False


def reset_iface_counters_if_stale(
    st: Dict[str, Any],
    rx_bytes: int,
    ts: float,
    interval: float,
) -> bool:
    """
    守护进程重启或长时间停顿后，旧的 last_ts/condX_start 会导致误判“持续超用”。
    如果距离上次采样时间超过 2 个采样周期，则清空计时器并重置速率统计。
    返回是否有修改。
    """
    last_ts = st.get("last_ts", 0.0)
    if not last_ts or ts < last_ts or ts - last_ts > interval * 2:
        st["last_rx_bytes"] = rx_bytes
        st["last_ts"] = ts
        st["last_mbps"] = 0.0
        st["cond1_start"] = None
        st["cond2_start"] = None
        return True
    return False


def sync_state_rates_on_start(
    state: Dict[str, Any],
    base_rate_kbps: int,
    stage1_rate_frac: float,
    stage2_rate_frac: float,
) -> bool:
    """服务重启时按当前配置重算期望速率并同步到 state。"""
    dirty = False
    for st in state.values():
        stage = st.get("stage", 0)
        expected = expected_rate_kbps(stage, base_rate_kbps, stage1_rate_frac, stage2_rate_frac)
        if st.get("current_rate_kbps") != expected:
            st["current_rate_kbps"] = expected
            dirty = True
    return dirty


def daemon_loop() -> None:
    """主循环：采样流量、更新阶段、下发限速。"""
    global _compiled_regexes

    setup_logging()
    lock_file = acquire_lock()  # noqa: F841 保持引用
    logging.info("ovs-qos daemon starting (pid=%d)", os.getpid())

    cfg = load_config()

    base_rate_kbps = kbps_from_mbit(cfg["base_rate_mbit"])
    patterns = cfg["iface_name_regexes"]
    interval = cfg["sample_interval_sec"]

    # 编译正则并缓存
    _compiled_regexes = compile_regexes(patterns)
    if not _compiled_regexes:
        logging.error("No valid regex patterns, exiting")
        sys.exit(1)

    stage1_frac = cfg["stage1_usage_fraction"]
    stage1_trigger = cfg["stage1_trigger_seconds"]
    stage1_rate_frac = cfg["stage1_rate_fraction"]
    stage1_penalty = cfg["stage1_penalty_seconds"]

    stage2_frac = cfg["stage2_usage_fraction"]
    stage2_trigger = cfg["stage2_trigger_seconds"]
    stage2_rate_frac = cfg["stage2_rate_fraction"]
    stage2_penalty = cfg["stage2_penalty_seconds"]

    state = load_state()
    if sync_state_rates_on_start(state, base_rate_kbps, stage1_rate_frac, stage2_rate_frac):
        save_state(state)

    while True:
        state_dirty = False
        ts = now_ts()
        all_ifaces = get_interfaces()
        if all_ifaces is None:
            logging.error("get_interfaces() failed; skip this cycle and keep state")
            time.sleep(interval)
            continue
        vm_ifaces = filter_vm_interfaces(all_ifaces, _compiled_regexes)

        # 清理已经删除的接口
        for name in list(state.keys()):
            if name not in vm_ifaces:
                logging.info("Interface %s disappeared, removing from state", name)
                state.pop(name, None)
                state_dirty = True

        for name, info in vm_ifaces.items():
            rx_bytes = info["rx_bytes"]
            if init_iface_state(state, name, rx_bytes, base_rate_kbps, ts):
                state_dirty = True
            st = state[name]

            # 如果 policing 与 state 中记录不一致，校正一次
            if info["ingress_policing_rate"] != st["current_rate_kbps"]:
                set_interface_rate(name, st["current_rate_kbps"])

            if reset_iface_counters_if_stale(st, rx_bytes, ts, interval):
                state_dirty = True

            last_ts = st["last_ts"]
            last_rx = st["last_rx_bytes"]

            # 计算最近一个采样周期内平均 Mbps
            if ts <= last_ts:
                mbps = st.get("last_mbps", 0.0)
            else:
                diff_bytes = rx_bytes - last_rx
                if diff_bytes < 0:
                    diff_bytes = 0
                bps = diff_bytes * 8.0 / (ts - last_ts)
                mbps = bps / 1e6

            st["last_mbps"] = mbps
            st["last_rx_bytes"] = rx_bytes
            st["last_ts"] = ts

            usage_frac = 0.0
            if base_rate_kbps > 0:
                # 当前速率相对于"基准带宽"的比例
                usage_frac = (mbps * 1000.0) / base_rate_kbps

            stage = st["stage"]
            cond1_start = st["cond1_start"]
            cond2_start = st["cond2_start"]

            if stage == 0:
                # Stage0 -> Stage1 条件：usage >= stage1_frac 持续 stage1_trigger 秒
                if usage_frac >= stage1_frac:
                    if cond1_start is None:
                        cond1_start = ts
                    elif ts - cond1_start >= stage1_trigger:
                        st["stage"] = 1
                        st["stage_until"] = ts + stage1_penalty
                        cond1_start = None
                        cond2_start = None
                        new_rate = int(base_rate_kbps * stage1_rate_frac)
                        st["current_rate_kbps"] = new_rate
                        set_interface_rate(name, new_rate)
                        state_dirty = True
                        logging.info(
                            "Interface %s -> stage1 (mbps=%.2f, usage=%.2f)",
                            name, mbps, usage_frac,
                        )
                else:
                    cond1_start = None

            elif stage == 1:
                # Stage1 -> Stage2 条件：usage >= stage2_frac 持续 stage2_trigger 秒
                if usage_frac >= stage2_frac:
                    if cond2_start is None:
                        cond2_start = ts
                    elif ts - cond2_start >= stage2_trigger:
                        st["stage"] = 2
                        st["stage_until"] = ts + stage2_penalty
                        cond1_start = None
                        cond2_start = None
                        new_rate = int(base_rate_kbps * stage2_rate_frac)
                        st["current_rate_kbps"] = new_rate
                        set_interface_rate(name, new_rate)
                        state_dirty = True
                        logging.info(
                            "Interface %s -> stage2 (mbps=%.2f, usage=%.2f)",
                            name, mbps, usage_frac,
                        )
                else:
                    cond2_start = None

                # Stage1 惩罚期结束后恢复（仅当没有升级到 stage2 时）
                if st["stage"] == 1 and ts >= st["stage_until"]:
                    st["stage"] = 0
                    st["stage_until"] = 0.0
                    cond1_start = None
                    cond2_start = None
                    st["current_rate_kbps"] = base_rate_kbps
                    set_interface_rate(name, base_rate_kbps)
                    state_dirty = True
                    logging.info(
                        "Interface %s stage1 expired, reset to normal",
                        name,
                    )

            elif stage == 2:
                # Stage2 惩罚期结束后恢复
                if ts >= st["stage_until"]:
                    st["stage"] = 0
                    st["stage_until"] = 0.0
                    cond1_start = None
                    cond2_start = None
                    st["current_rate_kbps"] = base_rate_kbps
                    set_interface_rate(name, base_rate_kbps)
                    state_dirty = True
                    logging.info(
                        "Interface %s stage2 expired, reset to normal",
                        name,
                    )

            st["cond1_start"] = cond1_start
            st["cond2_start"] = cond2_start

        if state_dirty:
            save_state(state)
        time.sleep(interval)


def format_local_time(ts: Optional[float]) -> str:
    """格式化为本地时间。"""
    if not ts:
        return "-"
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_remaining(ts: Optional[float]) -> str:
    """计算距离 ts 还剩多少秒。"""
    if not ts or ts <= 0:
        return "-"
    remaining = ts - time.time()
    if remaining <= 0:
        return "0"
    return str(int(remaining))


def compute_live_mbps(st: Dict[str, Any], rx_bytes: int, now_ts: float) -> float:
    last_ts = st.get("last_ts")
    last_rx = st.get("last_rx_bytes")
    if isinstance(last_ts, (int, float)) and isinstance(last_rx, int) and now_ts > last_ts:
        diff_bytes = rx_bytes - last_rx
        if diff_bytes < 0:
            diff_bytes = 0
        bps = diff_bytes * 8.0 / (now_ts - last_ts)
        return bps / 1e6
    return float(st.get("last_mbps", 0.0) or 0.0)


def cmd_list() -> None:
    """CLI：列出当前所有接口的限速状态。"""
    try:
        setup_logging()
    except Exception:
        logging.basicConfig(level=logging.INFO)
        logging.warning("Failed to initialize file logging; using stderr")

    cfg = load_config()
    interval = cfg["sample_interval_sec"]
    regexes = compile_regexes(cfg["iface_name_regexes"])
    if not regexes:
        logging.error("No valid interface name patterns for list")
        print("No valid interface name patterns.")
        return

    all_ifaces = get_interfaces()
    if all_ifaces is None:
        logging.error("Failed to query OVS interfaces for list")
        print("Failed to query OVS interfaces.")
        return
    vm_ifaces = filter_vm_interfaces(all_ifaces, regexes)
    if not vm_ifaces:
        logging.info("No matching interfaces for list")
        print("No matching interfaces.")
        return

    state = load_state()
    if not state:
        logging.warning("State file missing or empty; stage/penalty info may be incomplete")

    header = "{:<18} {:<6} {:<10} {:<22} {:<12} {:<10}".format(
        "Interface", "Stage", "Limit(M)", "Penalty_Until", "Remaining(s)", "Last_Mbps"
    )
    print(header)
    print("-" * len(header))

    now = time.time()
    for name in sorted(vm_ifaces.keys()):
        st = state.get(name, {})
        info = vm_ifaces[name]
        stage_until = st.get("stage_until", 0.0)
        limit_m = info.get("ingress_policing_rate", 0) / 1000.0
        live_mbps = compute_live_mbps(st, info.get("rx_bytes", 0), now)
        last_ts = st.get("last_ts")
        if isinstance(last_ts, (int, float)):
            if now - last_ts > interval * 2:
                logging.warning(
                    "State sample for %s is stale (last_ts=%s); Last_Mbps may be inaccurate",
                    name,
                    format_local_time(last_ts),
                )
        else:
            logging.warning("State sample for %s missing; Last_Mbps may be inaccurate", name)
        print("{:<18} {:<6} {:<10} {:<22} {:<12} {:<10.2f}".format(
            name,
            st.get("stage", 0),
            limit_m,
            format_local_time(stage_until) if stage_until else "-",
            format_remaining(stage_until),
            live_mbps,
        ))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OVS per-VM upstream rate limiter",
    )
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("daemon", help="Run monitoring daemon")
    sub.add_parser("list", help="Show current limits per interface")
    args = parser.parse_args()

    if args.cmd == "daemon":
        try:
            daemon_loop()
        except Exception:
            logging.exception("Daemon crashed")
            sys.exit(1)
    elif args.cmd == "list":
        try:
            cmd_list()
        except BrokenPipeError:
            # e.g. "list | head" where head closes pipe early
            sys.exit(0)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
