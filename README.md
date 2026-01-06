# OVS-QoS 宿主机上行限速守护进程

## 项目目的与背景
- 解决场景：魔方云默认通过 `tc` 做实例下行限速，无法有效限制宿主机上行，且缺少交换机侧限速条件。
- 方案思路：在宿主机使用 Open vSwitch (OVS) 的 `ingress_policing_rate/burst` 对每个 KVM 实例虚拟网卡做软件限速，模仿“智能带宽”分级惩罚策略。
- 适用环境：Rocky Linux 8.10（或 RHEL/CentOS 8 系列）、Python 3.6+、OVS 已安装可用。
- 生产提示：感谢AI时代🙏连这个readme都是AI写的，但是这句话不是：本代码撰写时参考了 Claude、Gemini 和 Codex，生产环境请自行评估后使用。

## 组件与文件
- `ovs_qos.py`：主程序，包含守护进程、限速逻辑、状态持久化、CLI。
- `/opt/ovs-qos/config.json`：配置文件（可选，覆盖默认参数）。
- `/run/ovs-qos/state.json`：运行时状态（自动生成）。
- `/var/log/ovs-qos.log`：日志（旋转保存）。
- `/run/ovs-qos/daemon.lock`：进程锁文件。

## 工作原理（简要）
1. 定期采样（默认 1 分钟，可配置）：读取 OVS Interface 的 `rx_bytes` 与当前 policing 配置。
2. 按正则匹配符合魔方云命名规范的 KVM 虚拟网卡（默认 `^kvm[0-9]+\\..*$`）并计算最近一个采样周期的平均上行 Mbps。
3. 使用“基准带宽”计算占用率：
   - Stage0→1：占用率 ≥ `stage1_usage_fraction` 持续 `stage1_trigger_seconds`，限速为基准 × `stage1_rate_fraction`。
   - Stage1→2：占用率 ≥ `stage2_usage_fraction` 持续 `stage2_trigger_seconds`，限速为基准 × `stage2_rate_fraction`。
   - 惩罚期到期自动恢复至基准带宽。
   - 判断始终基于“基准带宽”，与当前限速无关（避免阶梯叠加误判）。
4. 下发限速：调用 `ovs-vsctl set interface ... ingress_policing_rate/burst`。`burst` 规则：`max(10%速率, 2000kb)` 且不超过 1 秒带宽，防止过度突发或过小 MTU 影响。
5. 状态持久化：接口新增/删除、阶段切换、计时器重置等变化时写 `/run/ovs-qos/state.json`，并在守护进程重启或采样中断后自动清零过期计时防止误罚。
6. CLI 查询：`python3 ovs_qos.py list` 查看各接口当前阶段、限速、剩余惩罚时间和上一采样 Mbps。

## 环境要求
- Rocky Linux 8.10（或兼容发行版）。
- Python ≥ 3.6，系统自带即可。
- Open vSwitch 安装并运行，`ovs-vsctl` 可用；运行用户具备修改 OVS 接口与写 `/run` `/var/log` 的权限（通常为 root）。
- KVM 网卡命名满足配置的正则规则。

## 配置说明（`/opt/ovs-qos/config.json` 可选）
字段 | 默认值 | 说明
---|---|---
`base_rate_mbit` | 1000 | 每台实例基准上行带宽（Mbps），判罚与恢复都以此为基准。
`iface_name_regexes` | `["^kvm[0-9]+\\..*$"]` | 匹配虚拟网卡名称的正则数组。
`sample_interval_sec` | 60 | 采样间隔（秒）。
`stage1_usage_fraction` | 0.9 | Stage1 触发占用率阈值（基准带宽比例）。
`stage1_trigger_seconds` | 900 | Stage1 连续超用触发时长。
`stage1_rate_fraction` | 0.9 | Stage1 限速占基准带宽的比例。
`stage1_penalty_seconds` | 1800 | Stage1 惩罚持续时间。
`stage2_usage_fraction` | 0.8 | Stage2 触发占用率阈值（同样基于基准带宽）。
`stage2_trigger_seconds` | 1800 | Stage2 连续超用触发时长。
`stage2_rate_fraction` | 0.8 | Stage2 限速占基准带宽的比例。
`stage2_penalty_seconds` | 3600 | Stage2 惩罚持续时间。

说明：配置项类型或范围不合法时会回退默认值，例如 `sample_interval_sec` 无效时回退为 60 秒。

示例配置：
```json
{
   "base_rate_mbit": 1000,
   "iface_name_regexes": ["^kvm[0-9]+\\..*$"],
   "sample_interval_sec": 60,
   "stage1_usage_fraction": 0.9,
   "stage1_trigger_seconds": 900,
   "stage1_rate_fraction": 0.9,
   "stage1_penalty_seconds": 1800,
   "stage2_usage_fraction": 0.8,
   "stage2_trigger_seconds": 1800,
   "stage2_rate_fraction": 0.8,
   "stage2_penalty_seconds": 3600
}
```

## 部署流程（全新服务器）
1. 安装依赖  
   ```bash
   dnf install -y openvswitch python3
   systemctl enable --now openvswitch
   ```
2. 放置程序与配置目录  
   ```bash
   mkdir -p /opt/ovs-qos
   cp ovs_qos.py /opt/ovs-qos/
   chmod 750 /opt/ovs-qos/ovs_qos.py
   # 如需自定义配置
   cp config.json /opt/ovs-qos/config.json
   ```
3. （推荐）创建 systemd 服务 `/etc/systemd/system/ovs-qos.service`  
   ```ini
   [Unit]
   Description=OVS per-VM upstream rate limiter
   After=openvswitch.service

   [Service]
   ExecStart=/usr/bin/python3 /opt/ovs-qos/ovs_qos.py daemon
   Restart=on-failure
   User=root
   Group=root

   [Install]
   WantedBy=multi-user.target
   ```
   ```bash
   systemctl daemon-reload
   systemctl enable --now ovs-qos.service
   ```
4. 手动前台验证（可选）  
   ```bash
   python3 /opt/ovs-qos/ovs_qos.py daemon
   ```
   确认日志无报错后 Ctrl+C。

5. 检查运行状态  
   ```bash
   python3 /opt/ovs-qos/ovs_qos.py list
   tail -f /var/log/ovs-qos.log
   ```
   确认 `/run/ovs-qos/state.json` 正常生成并更新。

## 使用方法
- 启动守护进程：`systemctl start ovs-qos`（或直接运行 daemon 子命令）。
- 查看限速状态：`python3 /opt/ovs-qos/ovs_qos.py list`
- 调整策略：更新 `/opt/ovs-qos/config.json` 后重启服务生效。

## 运行逻辑详解
- 采样：每个周期读取匹配网卡的 `rx_bytes`，按时间差计算平均 Mbps。
- 阈值判罚：占用率以“基准带宽”为分母，Stage 触发需要达到设定阈值且连续超过触发时长；惩罚期后自动恢复。
- 突发控制：`burst = 10% 速率`。
- 状态与容错：重启或采样中断（>2 个采样周期）会清空计时器，避免用旧时间戳误判持续超用；接口消失自动清理状态。
- 日志与锁：旋转日志 `/var/log/ovs-qos.log`，文件锁防止多实例并行。

## 生产注意事项
- 配置检查：确保所有 fraction、时间、带宽值为正数；基准带宽应与售卖/计费口径一致。
- 权限：运行用户必须能写 `/run/ovs-qos` 和 `/var/log/ovs-qos.log`，并有 OVS 配置权限。
- 变更验证：在灰度环境验证正则匹配、阈值与惩罚时长；观察 burst 对流量的实际影响。
- 依赖可用性：`ovs-vsctl` 命令不可用时脚本会持续报错并跳过周期，需监控日志。
- LLM 参与声明：本项目说明与脚本优化参考了 Claude、Gemini 和 Codex，生产环境请根据自身合规和风险要求审慎使用。

## 反馈与扩展
- 可根据需要增加配置合法性校验、Prometheus 导出、或更精细的分级策略。
- 如有问题建议先附带 `/var/log/ovs-qos.log` 与 `state.json` 片段以便排查。
