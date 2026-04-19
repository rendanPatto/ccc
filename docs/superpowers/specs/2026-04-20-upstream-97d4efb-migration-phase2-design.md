# Upstream `97d4efb` Migration Alignment — Phase 2 Design

日期：2026-04-20  
状态：draft

## 目标

在 **不破坏当前本地实战工作流** 的前提下，继续推进 `97d4efb` 的迁移式对齐，但这次只做：

- **弱化 legacy 入口**
- **扶正 slash-command 主叙事**
- **不让 legacy 能力失效**

也就是：

- `run_cve_hunt()` 继续可用
- `generate_reports()` 继续可用
- 但它们在运行时和文档层都被明确标记为 **compatibility path**
- 主推荐路径改为：
  - `/intel`
  - `/report`

---

## 背景

上一阶段（Phase 1）已经完成了最关键的“去耦地基”：

- 新增 `tools/legacy_bridge.py`
- `hunt.py` 改走 bridge
- `agent.py` / `remember.py` / `resume.py` 收口到 bridge-backed entrypoints
- 保留 legacy 文件作为兼容后端

这意味着：

- 现在已经具备继续弱化 legacy 入口的条件
- 但还不适合直接删：
  - `tools/cve_hunter.py`
  - `tools/report_generator.py`
  - `memory/hunt_journal.py`

因为当前本地工作流仍然真实依赖这些能力。

所以 Phase 2 的重点不是“删”，而是：

> **让 legacy 入口继续工作，但不再作为主推荐入口。**

---

## 本轮范围

### In Scope

本轮只做这些事：

1. 在 `hunt.py` 中弱化 legacy 入口的用户可见定位
2. 在 `agent.py` 中弱化 legacy tool 的主叙事地位
3. 在文档/命令说明中进一步扶正 `/intel` 与 `/report`
4. 保持当前返回值、主流程、测试链路稳定

### Out of Scope

本轮明确不做：

- 不删除 `tools/cve_hunter.py`
- 不删除 `tools/report_generator.py`
- 不删除 `memory/hunt_journal.py`
- 不把 `run_cve_hunt()` / `generate_reports()` 改成 stub
- 不移除 `agent.py` 中的对应 tool surface
- 不重构 memory 层
- 不把 `/remember` 改成新的存储后端

---

## 方案比较

### 方案 A：仅弱化入口，保留功能（推荐）

做法：

- `run_cve_hunt()` 继续执行
- `generate_reports()` 继续执行
- 但在运行输出中提示：
  - 这是 legacy compatibility path
  - 主路径分别是 `/intel` / `/report`
- 文档进一步把 `/intel` / `/report` 立为主叙事

优点：

- 风险最低
- 不破坏当前实战工作流
- 最符合“稳定版优先”

缺点：

- 短期内仍保留双轨入口

结论：**推荐**

---

### 方案 B：只改文档，不动运行时提示

做法：

- 只在 README / CLAUDE / command docs 里改主叙事
- 代码运行时不提示

优点：

- 更保守

缺点：

- 用户真实使用时感知不到主路径变化
- 后续继续对齐官方的价值偏弱

结论：**不选**

---

### 方案 C：直接把 legacy 入口改成 warning-only stub

做法：

- `run_cve_hunt()` / `generate_reports()` 不再真正执行
- 只提示用户转向 `/intel` / `/report`

优点：

- 最接近官方最终状态

缺点：

- 会显著破坏当前本地 workflow
- 与“实战稳定版”目标冲突

结论：**不选**

---

## 推荐设计

### 1. `hunt.py` 中将 legacy 入口降级为兼容入口

这轮不改函数名、不改参数、不改返回值。

只对用户可见输出做轻量增强：

- `run_cve_hunt()` 执行前或执行时输出一条兼容提示
- `generate_reports()` 执行前或执行时输出一条兼容提示

提示语义应满足：

- 明确这是 compatibility path
- 明确主推荐路径是什么
- 不制造错误感，不打断流程

建议语义：

- `run_cve_hunt()`：
  - legacy compatibility path
  - prefer `/intel` for the primary intel workflow
- `generate_reports()`：
  - legacy compatibility path
  - prefer `/report` for submission-ready reporting

注意：

- 这是提示，不是警告级中断
- 不影响退出码
- 不影响返回值

---

### 2. `agent.py` 中保留 tool surface，但弱化主叙事

`agent.py` 当前仍公开：

- `run_cve_hunt`
- `generate_reports`

这轮不删除它们，因为删了会破坏当前自动化流。

但应在 tool 说明、prompt guidance、或相关辅助文案里做轻量调整：

- 保留这两个 tool
- 但明确：
  - 它们是 compatibility-oriented execution path
  - `/intel` / `/report` 是主推荐工作流

重点是：

- **tool surface 保持稳定**
- **主叙事发生转移**

---

### 3. 文档层继续扶正 `/intel` 和 `/report`

重点调整这些对外入口：

- `README.md`
- `CLAUDE.md`
- `commands/hunt.md`
- 必要时补充：
  - `commands/intel.md`
  - `commands/report.md`

设计目标：

- 用户看到“intel 相关能力”时，主想到的是 `/intel`
- 用户看到“报告生成”时，主想到的是 `/report`
- 老路径只作为兼容层被提及

这里不需要做大改写，只要把主推荐顺序和语气调整正确即可。

---

### 4. `memory/hunt_journal.py` 本轮不动

这轮不建议碰它。

原因：

- 它和当前测试、memory、remember/resume、autopilot 链路绑定太深
- 比起 CVE/report 入口，它的迁移风险更高
- 当前对齐官方的高价值动作，优先是先把 intel/report 的旧入口降级

所以本轮明确：

- `memory/hunt_journal.py` 保持现状
- 只继续保持“兼容后端”定位

---

## 预期结果

本轮做完后，应达到：

1. legacy 入口依然能用
2. 但它们不再是仓库中的主推荐路径
3. `/intel` 与 `/report` 成为更明确的主叙事
4. 现有 CLI / agent / tests 不被打坏
5. 为 Phase 3 的进一步半退役或 stub 化创造条件

---

## 文件范围（预期）

### 主要代码

- `tools/hunt.py`
- `agent.py`

### 文档

- `README.md`
- `CLAUDE.md`
- `commands/hunt.md`
- 可能少量触及：
  - `commands/intel.md`
  - `commands/report.md`

### 测试

- `tests/test_hunt_wrappers.py`
- `tests/test_agent_dispatcher_misc.py`
- 如需要，再补极小量文案/提示断言

---

## 验收标准

本轮完成后，应满足：

1. `run_cve_hunt()` 仍可执行，但输出带 compatibility 提示
2. `generate_reports()` 仍可执行，但输出带 compatibility 提示
3. `agent.py` 中对应能力仍可调度，但主叙事被弱化
4. `/intel` 与 `/report` 在公开文档中成为更明显的主路径
5. focused tests 通过
6. 全量 `pytest -q` 通过

---

## 风险与控制

### 风险 1：提示文案过吵

控制：

- 每个入口只打一条轻量提示
- 不重复刷屏
- 不把 compatibility 提示做成错误/警告级噪音

### 风险 2：改了提示导致测试脆弱

控制：

- 测试只断言关键语义，不绑死整段长文案

### 风险 3：agent 层过度改动导致行为漂移

控制：

- 不改 tool names
- 不改调用顺序
- 只改描述和轻量提示

---

## 实施顺序建议

1. 先补 `hunt.py` 的兼容提示测试
2. 再实现 `hunt.py` 轻量提示
3. 再补 `agent.py` 相关轻量断言
4. 再调整文档主叙事
5. 跑 focused tests
6. 跑全量测试

---

## 结论

Phase 2 应采用：

**“功能保留、入口降级、主叙事切换、保持稳定”的保守推进方案。**

这样可以继续向官方 `97d4efb` 靠拢，但不会为了追求形式对齐而打坏当前本地实战可用性。
