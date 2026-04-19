# CVSS 4.0 Upgrade Design

Date: 2026-04-19
Status: Approved for spec review

## Goal

按官方方向将本地主评分主路径直接切到 CVSS 4.0，并同步统一代码、终端输出与公开文档表述，避免继续维持 CVSS 3.1 作为主入口。

## Core constraint

本次设计遵循以下硬约束：

- 对外主路径优先与官方保持一致
- 代码、输出、文档三层必须一起主切到 CVSS 4.0
- 不保留 CVSS 3.1 作为长期主路径
- 不借这次切换顺手重写整个 validate 交互框架
- 不夹带与 CVSS 升级无关的上游更新

## Upstream alignment target

上游近期已将 `tools/validate.py` 主评分逻辑升级到 CVSS 4.0，并在文档层同步使用 CVSS 4.0 叙事。

因此本地这次也应按同样方向处理：

- `tools/validate.py` 主评分逻辑切到 CVSS 4.0
- `/validate` 相关输出切到 CVSS 4.0
- 文档中的主描述同步切到 CVSS 4.0

## Why

当前本地仓库仍以 CVSS 3.1 为主，具体表现为：

- `tools/validate.py` 仍使用 CVSS 3.1 公式与向量
- `README.md`、`CLAUDE.md`、`commands/report.md`、`agents/report-writer.md` 等公开说明仍写 CVSS 3.1

这会带来几个问题：

- 与官方当前实现方向不一致
- 后续继续同步上游时冲突更大
- 用户看到的说明与行业当前主流评分版本脱节
- 代码、输出、文档容易继续出现 3.1 / 4.0 混用

因此这次应做一次完整主切，而不是继续维持双栈叙事。

## Design principles

- 官方主路径优先
- 主切而不是双栈长期并存
- 代码、输出、文档同步变更
- 先保证一致性，再考虑补充迁移提示
- 范围严格收口在 validate/report 直接相关层

## In scope

### 1. `tools/validate.py` 主评分逻辑切到 CVSS 4.0

本次会把当前 CVSS 3.1 的主评分实现替换为 CVSS 4.0 主路径。

目标效果：

- 评分指标、向量、分数输出以 CVSS 4.0 为准
- 终端标题与提示语直接写 CVSS 4.0
- 不再把 CVSS 3.1 作为默认评分流程展示

### 2. `/validate` 相关用户可见输出切到 CVSS 4.0

包括但不限于：

- 评分段落标题
- 最终分数输出标题
- 帮助/交互提示中的版本说明

目标效果：

- 用户在终端看到的主评分版本统一是 4.0
- 不再出现“代码是 4.0、提示还是 3.1”的混合状态

### 3. 公开文档同步切到 CVSS 4.0

至少覆盖当前直接暴露 CVSS 3.1 主叙事的文件：

- `README.md`
- `CLAUDE.md`
- `commands/report.md`
- `agents/report-writer.md`
- 其它直接写明 CVSS 3.1 为主路径的文档

目标效果：

- 公开说明与实际运行结果一致
- 后续继续同步官方时冲突更少

## Out of scope

本次不做以下内容：

- 不保留 CVSS 3.1 作为长期双栈主路径
- 不新增“3.1 / 4.0 可切换模式”
- 不重写 validate 的整体 4-gate / 7-question 交互框架
- 不顺手合入其它无关上游更新
- 不大规模改动 report 生成模板结构，除非 CVSS 版本字段直接受影响

## Behavior definition

### Main scoring behavior

`/validate` 默认评分器直接使用 CVSS 4.0。

预期行为：

- 用户进入评分时，看到的是 CVSS 4.0 指标
- 输出结果是 CVSS 4.0 分数与向量
- 严重性分级与 CVSS 4.0 输出一致

### User-facing wording

所有主提示语统一改成 CVSS 4.0。

预期行为：

- 标题写 `CVSS 4.0`
- 最终输出写 `CVSS 4.0 Score`
- 文档不再把 3.1 当主版本写法

### Compatibility note

本次不做双栈，但允许保留很薄的一层迁移说明。

例如：

- 在少量文档中短句说明“现在默认使用 CVSS 4.0”

但不会继续保留完整 CVSS 3.1 主流程说明。

## Likely files in scope

核心实现文件：

- `tools/validate.py`

直接相关文档文件：

- `README.md`
- `CLAUDE.md`
- `commands/report.md`
- `agents/report-writer.md`

测试文件（按实际需要补充/更新）：

- 与 `tools/validate.py` 对应的现有测试文件
- 如当前缺少直接测试，可新增 focused test 文件

## Error handling

### Version consistency

- 代码切到 4.0 后，文档和输出不能残留主路径 3.1 描述
- 如有保留 3.1 字样，必须明确是历史/迁移说明，而不是主路径

### Score output

- 分数、向量、严重性输出必须保持自洽
- 不允许出现 4.0 标题下仍输出 3.1 风格向量或字段

### Validation stability

- 升级 CVSS 版本不应破坏 4-gate / 7-question 主流程
- validate/report 主链路仍应可正常运行

## Testing

至少需要覆盖：

1. `tools/validate.py` 的主评分路径已切到 CVSS 4.0
2. 终端标题/分数输出已使用 CVSS 4.0 文案
3. 文档中公开主描述不再写 CVSS 3.1 为主路径
4. 不影响 validate 的既有主交互流程

如果测试拆分，优先策略：

- 评分输出与标题断言
- 关键文档引用更新断言
- 现有 validate 相关回归测试

## Risks

### Risk 1: 代码切了 4.0，文档还留在 3.1

Mitigation:

- 代码、输出、文档三层一起切
- 把公开文档更新纳入完成标准

### Risk 2: 输出写成 4.0，但底层仍是 3.1 公式

Mitigation:

- 先改测试，再改实现
- 明确检查分数输出与向量格式是否匹配 4.0

### Risk 3: validate 主流程被不必要改动带坏

Mitigation:

- 范围只围绕 CVSS 主路径升级
- 不重写其它 gate 逻辑
- 保持最小实现边界

## Completion criteria

本次增强完成的标准：

1. `tools/validate.py` 主评分逻辑已切到 CVSS 4.0
2. `/validate` 主输出已统一显示 CVSS 4.0
3. 公开文档主叙事已切到 CVSS 4.0
4. 不再把 CVSS 3.1 作为主路径保留
5. validate 主流程无明显回归
6. 后续继续同步官方时，不需要再先清理 3.1 主叙事
