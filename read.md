## 本次会话总结

### 已完成

- Claude Code CLI 安装链补全
  - `install.sh` 现在不只安装 `skills/commands`，还会安装仓库自带 `agents/` 到 `~/.claude/agents/claude-bug-bounty`
  - 让 `recon-ranker` / `validator` / `report-writer` / `autopilot` 这类 agent 真正随安装可用

- `request_guard` 真正接入 `hunt.py` 主链路
  - 已接入主动测试/探测请求，而不是只停留在独立工具或文档层
  - 当前已覆盖：
    - `run_post_param_discovery`
    - `run_api_fuzz`
    - `run_cors_check`
    - `run_cms_exploit`
  - CTF 模式继续保持 `audit-only`
  - guard 异常时自动回退，不硬破坏原有流程

- `autopilot / agent` guard 感知增强
  - `autopilot_state` 新增更明确的 `guard_hint`
  - `Next step` 会优先提示避开 `cooling/tripped host`
  - agent 首步 bootstrap 会显示：
    - `Guard hint`
    - `Avoid now`
    - `Top ready target`
  - agent system prompt 也补了“优先 non-tripped target”的规则

- guard block 持久化到 `hunt-memory`，并接进 `/resume`
  - 命中 guard block 时，会自动写入 `journal.jsonl`
  - 记录内容包括：
    - host
    - URL
    - block action
    - reason
  - `/resume` 现在会展示 `Recent Guard Blocks`
  - 同一进程内做了去重，避免 tight loop 日志爆炸

- `Recent Guard Blocks` 已轻量喂给 `autopilot_state / agent bootstrap`
  - `build_autopilot_state()` 现在会返回 `recent_guard_blocks`
  - `format_autopilot_state()` 会显示 `Recent guard blocks`
  - agent bootstrap 会显示最近的 guard block 记录
  - 这是**可见性增强**，没有改排序、没有改请求逻辑

- `source-hunt` 结果已轻量喂给 `autopilot_state / agent bootstrap`
  - `autopilot_state` 现在会从 `findings/<target>/exposure/` 读取：
    - `repo_source_meta.json`
    - `repo_summary.md`
  - 当前会提炼并显示：
    - `source_kind`
    - `secret_findings`
    - `ci_findings`
    - `confirmation required before clone`
  - 会以 `repo_source_summary` 的形式出现在：
    - `build_autopilot_state()`
    - `format_autopilot_state()`
    - agent bootstrap
  - 这是**repo-source 可见性增强**，没有改 `next_action`、没有改排序、没有改 source-hunt 行为

### 关键决策

- 只增强，不盲目扩大影响面
  - 没把所有 `_fetch_url` 一刀切全接 guard
  - 先接“主动测试路径”，避免误伤被动抓取/老逻辑

- 真实增强优先于表面接线
  - 不只是“能调工具”
  - 而是把 guard / repo-source 状态真正喂给：
    - `autopilot_state`
    - `format_autopilot_state()`
    - agent bootstrap

- 所有新增强都维持“只加上下文，不改硬逻辑”
  - 不改 `next_action`
  - 不改 target 排序
  - 不改 request_guard 行为
  - 不改 source-hunt 执行逻辑

- 日志可恢复，但不能刷屏
  - guard block 落 journal
  - 但按进程内签名去重

### 涉及文件 / 模块

本次会话里重点动过这些文件：

- `install.sh`
- `tools/hunt.py`
- `tools/autopilot_state.py`
- `tools/resume.py`
- `agent.py`

测试补充/更新：

- `tests/test_hunt_wrappers.py`
- `tests/test_autopilot_state_tool.py`
- `tests/test_autopilot_mode.py`
- `tests/test_resume_tool.py`

新增设计 / 计划文档：

- `docs/superpowers/specs/2026-04-17-autopilot-guard-visibility-design.md`
- `docs/superpowers/specs/2026-04-17-repo-source-visibility-design.md`
- `docs/superpowers/specs/2026-04-17-pivot-hint-design.md`
- `docs/superpowers/plans/2026-04-17-autopilot-guard-visibility.md`
- `docs/superpowers/plans/2026-04-17-repo-source-visibility.md`
- `docs/superpowers/plans/2026-04-18-pivot-hint.md`

### 验证情况

已验证：

```bash
bash -n install.sh
```

```bash
HOME=/tmp/cbb-install-test bash ./install.sh
```

```bash
pytest -q
```

```bash
pytest -q tests/test_hunt_wrappers.py tests/test_request_guard_tool.py tests/test_claude_code_helper_flow.py tests/test_autopilot_mode.py
```

```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_agent_helper_tools.py tests/test_request_guard_tool.py tests/test_claude_code_helper_flow.py
```

```bash
pytest -q tests/test_hunt_wrappers.py tests/test_resume_tool.py tests/test_request_guard_tool.py tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_claude_code_helper_flow.py
```

```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_resume_tool.py
```

```bash
pytest -q tests/test_hunt_wrappers.py tests/test_request_guard_tool.py tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_resume_tool.py
```

```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_agent_summaries.py tests/test_source_hunt_cli.py
```

```bash
pytest -q tests/test_autopilot_state_tool.py tests/test_autopilot_mode.py tests/test_agent_summaries.py tests/test_agent_helper_tools.py tests/test_source_hunt_cli.py tests/test_hunt_wrappers.py
```

结果：

- 全量：`364 passed, 2 warnings`
- 相关聚焦回归：
  - `28 passed`
  - `31 passed`
  - `44 passed`
  - `46 passed, 2 warnings`
  - `48 passed, 2 warnings`
- 仍有 2 个已有 `datetime.utcnow()` deprecation warning
- 这两个 warning 和本次增强无直接功能冲突

### 经验与风险

- 当前增强已经形成一条更完整的实战链：
  - `request_guard`
  - `autopilot_state`
  - agent bootstrap
  - `resume`
  - repo-source artifacts

- 目前主动测试路径 guard 化已足够实战，且风险可控

- `Recent Guard Blocks` 和 `repo_source_summary` 现在都能被 autopilot / agent 看见
  - 这会提升 Claude Code CLI 的“下一步判断质量”
  - 但还没有进入硬决策层

- 还没有继续扩大到所有被动抓取/下载逻辑，这是刻意保守

- guard block 去重目前是进程内去重，不是跨进程全局去重

- repo-source 摘要目前只提炼高价值字段，不展开单条 finding
  - 这是刻意控制上下文噪音

### 下一步建议

如果下次继续，优先级建议：

1. 下一步最自然的是实现 `pivot_hint`
   - 设计已写好：
     - `docs/superpowers/specs/2026-04-17-pivot-hint-design.md`
   - 实现计划已写好：
     - `docs/superpowers/plans/2026-04-18-pivot-hint.md`
   - 这一步仍然建议保持保守：
     - 只生成 `pivot_hint`
     - 只做建议展示
     - 不改 `next_action`
     - 不改排序

2. 之后再考虑把 `repo_source_summary` 轻量接进 `/resume`
   - 这也是低风险高价值增强

3. 目前不建议马上做：
   - 让 repo-source 直接改 `next_action`
   - 让 recent guard block 直接参与 target 降权
   - 扩大 request_guard 到更多路径

4. 不建议现在直接整仓 commit
   - 当前工作树里有你之前/本地已有的未跟踪内容：
     - `.codex`
     - `docs/superpowers/`
     - `hunt-memory/`
   - 更适合后面按文件范围做选择性提交

### 当前收口结论

这次会话里，和 Claude Code CLI 实战可用性直接相关的增强，已经补到了一个更实用的阶段：

- 安装链更完整
- guard 真正进主链路
- agent 会主动避开 cooling host
- block 原因能被 `resume` 回看
- recent guard blocks 会进入 autopilot / agent 上下文
- repo-source 摘要会进入 autopilot / agent 上下文

还没进代码、但已经做好设计和计划的下一步是：

- `pivot_hint`

如果下次继续，我可以直接从 `pivot_hint` 这条线接着做，不需要重铺上下文。
