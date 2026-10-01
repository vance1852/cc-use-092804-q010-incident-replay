# 建立现场异常的确定性回放与安全回退基础平台

本项目是一套可离线运行的 Python 服务端平台，服务于具身智能机器人控制域、AI 计算域和国产电子部件质量域。平台管理控制计算节点、实时控制总线、资源时隙、机器人构建、验证测量、分析租约、部件批次与质量决定，业务状态、幂等结果和审计事件保存在 SQLite 中。

## 目录

- `src/robot_control/`：控制节点、实时总线、资源批次、时隙申请、容量分配和架构情景；
- `src/embodied_ai/`：机器人构建、验证协议、测量导入、排除复核、分析任务和准入决定；
- `src/component_qualification/`：国产电子部件批次、信号测量、统计分析、账号权限和质量审批；
- `src/incident_replay/`：现场异常事件回放、时钟校准版本、确定性时间线、冲突/缺口/漂移标注、封存结论、复开申请、影响面推导与双人确认回退；
- `fixtures/`：离线验收使用的验证协议与结构化测量；
- `tests/`：领域规则、事务、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m robot_control.acceptance --workspace .
PYTHONPATH=src python3 -m embodied_ai.acceptance --workspace .
PYTHONPATH=src python3 -m component_qualification.acceptance
PYTHONPATH=src python3 -m incident_replay.acceptance --workspace .
```

四条命令会在临时 SQLite 数据库中完成控制资源分配、AI 验证分析、国产电子部件质量流程，以及现场急停争议的确定性回放、封存推导、双人确认回退与迟到证据复开，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m robot_control.api --database robot-control.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m embodied_ai.api --database embodied-ai.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m component_qualification.api --database component.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m incident_replay.api --database incident-replay.sqlite3 --host 127.0.0.1 --port 8083
```

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 现场异常回放服务（8083）

事件只追加，后到记录永不覆盖先到记录（`(案卷,来源,序列号)` 唯一）；事件带 `source_clock`、`sequence` 和与 `content` 一致的 SHA-256 摘要。到达顺序由单调的 `arrival_rank` 保留，校准时间线按 `(参考时钟,来源,序列号,到达序号)` 确定性排序，两种顺序都可查。

- **冲突**：不同来源事件落入 5ms 校准时间窗口（窗口内若到达顺序与校准顺序相反则为 critical）；**缺口**：某来源序列号不连续（critical）；**漂移**：校准参数 `drift_ppm` 达到 100ppm 阈值（warning）；**未校准来源**：该来源没有对应校准版本，其事件按来源时钟挂在时间线末尾。
- **版本与封存**：校准版本、回放版本、封存结论均不可变；封存时必须指定触发记录与决定依据（`arrival_order`/`calibrated_order`），存在冲突或严重缺口时须显式确认。
- **迟到证据**：封存后事件写入被拒绝，只能走 `/incidents/{id}/late-evidence` 暂存并生成复开申请，经另一名授权者审批；批准则激活为新证据、构建新版本并再次封存（旧结论原样保留），驳回则标记 `rejected_late`，不改写旧时间线。
- **回退推导与执行**：冻结时按当时的软件组合、跨域票据、安全规则推导受影响设备与候选动作（每台设备附原因链）；方案状态 proposed → confirmed → executing → completed，须由冻结人之外的另一名授权者确认，只能执行推导产生的候选动作。
- **通知与复算**：通知范围由命中的安全规则 `notify_roles` 推导，逐角色确认发送；`POST .../revisions/{n}/replay` 用不可变记录与校准重新推导并核对封存快照摘要，可随时复算事件顺序、决定依据、通知范围和每台设备的回退进度。
