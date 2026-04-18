# IP/CIDR Support Design

Date: 2026-04-19
Status: Approved for spec review

## Goal

按官方 IP/CIDR 支持方向，为本地仓库增加对单个 IP 与 CIDR 目标的可用支持，并保证当前本地主流程在 Claude Code CLI 下依然合理、可控、可验证。

## Core constraint

本次设计遵循以下硬约束：

- 优先对齐官方实现边界，而不是自行扩张范围
- 以 `tools/hunt.py` 与 `tools/recon_engine.sh` 为主实现落点
- 只有在本地现有链路确实会卡住 IP/CIDR 时，才补最小必要兼容
- 不为了“像官方”而破坏当前本地稳定版使用体验

## Upstream alignment target

参考上游提交：

- `955d893` — `Add: IP and CIDR target support (hunt.py + recon_engine.sh)`

这说明官方当前主实现边界集中在：

- `tools/hunt.py`
- `tools/recon_engine.sh`

因此本地这次也应优先沿着同样边界实现，而不是从一开始扩展到全仓所有链路。

## Why

当前本地仓库仍存在明确限制：

- `tools/scope_checker.py` 文档与行为都声明 IP/CIDR 不支持
- `README.md` 也仍然说明 IP 会被拒绝

这导致实际使用中存在明显缺口：

- 单个 IP 资产无法自然进入主流程
- CIDR 无法作为合理输入进行资产发现/筛活
- 即使后续同步官方能力，本地现有 guard / helper / scope 链路也可能继续把 IP/CIDR 当异常输入处理

因此需要做一次“官方主实现 + 本地最小闭环兼容”的收口增强。

## Design principles

- 官方边界优先
- 本地可用性优先于机械照抄
- 先闭环、后扩展
- 不引入新的大规模扫描编排
- 不把 CIDR 粗暴当作普通单目标域名处理

## In scope

### 1. 单个 IP 作为合法 target

允许单个 IPv4/IPv6 目标进入主流程。

目标效果：

- `tools/hunt.py --target 1.2.3.4` 可正常进入后续处理
- `tools/recon_engine.sh` 可接受单 IP 作为输入并走合理路径
- 如本地校验链路会直接拦截 IP，则补最小兼容修复

### 2. CIDR 作为资产范围输入

允许 CIDR 作为一段资产范围输入，但其语义不是“单一站点目标”，而是“待筛活的网络范围”。

目标效果：

- `tools/hunt.py --target 10.10.10.0/24` 可以进入流程
- 优先对 CIDR 做范围内主机发现/筛活
- 只把筛出的有效主机继续喂给后续阶段
- 不将整个 CIDR 直接视为一个普通域名/单目标站点

### 3. 本地最小闭环兼容

如果在按官方边界实现后，本地已有链路会阻断 IP/CIDR，可补最小必要兼容，优先考虑：

- `tools/scope_checker.py`
- 相关测试
- 与 `hunt.py` / `recon_engine.sh` 直接耦合的最小调用路径

兼容修复原则：

- 只修阻塞闭环的问题
- 不顺手把 IP/CIDR 扩到全仓所有功能面

## Out of scope

本次不做以下内容：

- 不做全仓术语/文档的大规模扩散更新
- 不把 IP/CIDR 接进所有 agent/bootstrap/summary 的智能策略层
- 不引入新的大规模批量 hunting 编排
- 不改 autopilot 决策逻辑
- 不顺手合入 CVSS 4.0 等其它上游更新
- 不把 CIDR 当成普通单目标完整狩猎对象

## Behavior definition

### Single IP behavior

单个 IP 视为合法 target。

预期行为：

- 允许通过 target 类型识别
- 进入 `hunt.py` 的后续路径
- `recon_engine.sh` 对单个 IP 采取合理探测行为
- 若涉及 scope 校验，不再一律警告并拒绝

### CIDR behavior

CIDR 视为资产范围输入。

预期行为：

- 允许通过 target 类型识别
- 先执行范围发现/筛活
- 后续处理基于筛出的活跃主机展开
- 不要求在本次设计中实现复杂的批量主机调度策略

### Local compatibility rule

如果官方实现边界与本地现有稳定链路冲突，采用以下优先级：

1. 保持官方实现方向
2. 用最小兼容修复消除阻塞
3. 避免扩大行为变化范围

## Likely files in scope

优先实现文件：

- `tools/hunt.py`
- `tools/recon_engine.sh`

按需补充的最小兼容文件：

- `tools/scope_checker.py`
- `tests/test_hunt_target_types.py`（若新增）
- `tests/test_scope_checker.py`（若已有对应测试文件则优先沿用）
- 与 hunt/recon 直接相关的现有测试文件

## Error handling

### Invalid input

- 非法 IP/CIDR 输入应被明确识别并报错
- 错误信息应指出输入格式问题，而不是模糊地按“域名不在 scope”处理

### Empty CIDR result

- 若 CIDR 范围内未发现有效主机，应给出清晰结果
- 不应继续把空结果当成普通 target 进入后续 hunting

### Scope compatibility

- 若 `scope_checker.py` 参与链路判断，IP/CIDR 不应再默认触发“not supported”警告后直接失败
- 如果当前调用场景仍无法安全判断，至少应返回可解释行为，而非静默错配

## Testing

至少需要覆盖：

1. 单个 IP target 可被识别并进入主流程
2. CIDR target 可被识别并进入范围处理路径
3. 非法 IP/CIDR 输入被明确拒绝
4. 如补了 `scope_checker.py`，则需要覆盖 IP/CIDR 不再被默认拒绝
5. 不影响当前域名 target 的既有行为

如果测试拆分，优先策略：

- `hunt.py` 输入类型识别测试
- `recon_engine.sh` 参数/行为测试
- 最小兼容链路测试

## Risks

### Risk 1: 表面支持、实际卡死

如果只改 `hunt.py` / `recon_engine.sh`，但 `scope_checker.py` 仍拒绝 IP/CIDR，会出现“看起来支持、实际跑不通”。

Mitigation:

- 只要出现真实阻断，就补最小兼容修复
- 用测试覆盖闭环路径

### Risk 2: CIDR 行为失控

如果把 CIDR 当成普通单目标，容易引发不合理的大范围后续动作。

Mitigation:

- 明确 CIDR 只作为范围输入
- 先筛活，再继续后续处理
- 本次不实现激进批量编排

### Risk 3: 本地增强链路假设 target 一定是域名

现有稳定版的部分 helper/summary/guard 链路可能默认以域名为中心。

Mitigation:

- 只修真实阻塞点
- 不在本次把 IP/CIDR 扩散到所有上层文案与智能逻辑

## Completion criteria

本次增强完成的标准：

1. 单个 IP 可作为 target 合理进入主流程
2. CIDR 可作为范围输入被处理
3. 本地不会再因为现有阻塞点把 IP/CIDR 直接判死
4. 既有域名 target 行为不回归
5. 测试覆盖 target 类型识别与最小闭环
6. 实现边界仍主要集中在 `tools/hunt.py` + `tools/recon_engine.sh`
