# AION：旁路短图谱与精简工具

本次实现按用户提供的 Heimdall 文章提取两项机制：主 Solver 连续执行，旁路维护可撤销的短图谱；系统提示缩短，技术工具按需发现。没有得到 Heimdall 私有实现的源码，也没有据此声称复现其成绩。

## 实现范围

系统继续使用 Chief / Solver / Worker。`SolverObserver` 是 Supervisor 持有的辅助调用组件，无 Agent 身份、任务队列、技术工具或控制工具。每题只有原 Solver 决定是否采纳图谱、委派、取消或提交。

图谱包含四组简短陈述及来源序号：

| 项 | 含义 | 约束 |
|---|---|---|
| LOCK | 有证据支撑的题目约束或难点假说 | 可修改、撤销，不能当作永久事实 |
| DEAD | 特定条件下已经失败的路径 | 不把一次失败推广到整个技术类别 |
| ANGLES | 尚未充分测试的方向假说 | 不输出下一步指令或命令 |
| TENSION | 相互冲突的两项说法 | 至少引用两个来源事件 |

每组最多 2 项，每项最多 160 字符、1–4 个来源，总图谱最多约 1,500 个估算 token。Pydantic 拒绝多余字段、过长内容和不合规来源格式；StateService 再验证 Run、Solver 身份、题目、会话代际、乐观版本与事件来源。自然语言是否真的有依据仍由模型判断，格式验证不能保证推断正确。

轨迹只来自该 Solver 自己的 SQLite 执行事件，包括本轮内容、有限长度的思考文本、工具调用及结果。Worker 报告在被 Solver 读取后才进入它的轨迹。每次读取最多 80 个事件，投影约 16,000 字符。小于 6 个有效工具结果通常不启动观察；页面或缓冲满且存在有效结果时可提前处理。纯工具目录/观察/等待/进度记录不计作有效结果；满页无有效结果直接推进游标，不调用模型。

两次辅助调用开始时间至少间隔 60 秒，一个 Solver 最多一项在途观察。单次使用原配置模型和 non-thinking 辅助选项，最多 2,048 输出 token、20 秒，并取 Run 剩余时限的较小值。没有定时器催促主线，也没有观察结果通知去唤醒等待中的 Solver。

主模型不等待辅助响应。每次主模型请求只在末尾携带最新图谱的一个副本，不累积所有历史图谱，也不改写固定系统提示。图谱和游标存入 `solver_observation_snapshot`；失败保留旧图谱并消费本批轨迹，避免立即重试。暂停/结束取消在途调用，取消的批次不推进游标；恢复加载最新图谱，未消费轨迹可以再次处理。原始事实、报告与工具输出仍以 SQLite 为准。

## 工具与 Skill

Solver 常驻基础工具包含文件、Shell、任务结果、证据读取和控制操作，并保留 `tool_search`；执行 Worker、Chief 和复核 Worker 继续按各自白名单过滤。

`tool_search(query=...)` 返回分页名称和短说明，`tool_search(name=...)` 返回完整参数 Schema，并在下一轮暴露该真实函数；随后直接按原函数名调用。每个 Agent 最多保留 3 个动态 Schema，目录只包含该角色已授权工具。权限、独占调用、精确值检查、幂等、审计、报告投递和资源清理继续使用原实现。

原 HTTP/TCP/SSH/二进制会话工具保留，CLI 可继续经 Shell 使用。这个阶段没有把所有会话工具改写为 CLI。领域知识和脚本保留；删除自动 Skill 激活、常驻目录及候选注入，按需搜索并显式激活。已激活 Skill 的正文随会话保留，避免压缩或恢复丢失已采用的说明。

## 配置、计量与查看

`AION_COMPACT_TOOLS=true` 与 `AION_SOLVER_OBSERVATION=true` 默认启用。关闭其中一个可单独测量它的影响；这两个开关只改变工具呈现/旁路观察，不恢复旧角色和旧调度路径。每次启动/恢复写入 `solver_context_policy_configured`，主模型、推理参数与原上下文预算不变。

数据库仍为 16，图谱使用现有事件表，不增加迁移。使用新 Run；原运行和以下实施前快照保留：`.aion/refactor-baselines/20260905T101822Z/`，包括工作树压缩包、补丁和逐文件校验清单。

Agent 的分页事件可查看 `solver_observation_started / solver_observation_snapshot / solver_observation_cancelled / solver_observation_discarded`。主响应事件的 `observation_revision` 指向本次带入的快照。观察模型调用使用 `purpose=observation`，按物理调用 ID 纳入 Solver、该题、整场四类 token；取消或错误时缺失 usage 继续显示未知。

## 离线验证证据

新增测试使用本地模型与平台替身，Runner、控制工具、Supervisor、StateService 和资源生命周期走真实实现。

| 验收点 | 证据 |
|---|---|
| 目录按权限发现、底层严格校验、独占调用保留、无通用递归网关 | `tests/test_compact_tools.py::test_compact_catalog_validation_authority_and_solo` |
| 实际 Runner 发现 Schema、通用入口记录进度、零 Worker 执行/提交 | `test_compact_real_runner_discovers_delegation_and_solves_without_worker` |
| 同能力 Schema 缩小，独立关闭观察后不发辅助请求 | `test_same_capabilities_have_smaller_fixed_schema_and_observation_can_be_disabled` |
| 图谱增量消费、调用间隔、允许撤销、辅助成本计入三层汇总 | `tests/test_solver_observation.py::test_observation_is_incremental_bounded_cooldown_and_revisable` |
| 无效 JSON、伪造工具调用、越界来源、超长图谱被丢弃 | `test_observation_invalid_output_never_changes_map_or_runs_tools` |
| 跨角色/题目/Run、过期代际被拒绝，SQLite 重启后图谱保留 | `test_observation_scope_generation_and_restart` |
| 纯状态轮询满页不会遮挡后续执行，也不会单独触发模型 | `test_bookkeeping_page_cannot_hide_later_execution_or_wake_model` |
| 真实主线与观察重叠执行，最新图谱在请求末尾，暂停清理 | `test_real_runner_observation_is_nonblocking_tail_context_and_pause_cancels` |
| 在途辅助调用被取消，消费游标不前移，失败调用计入账本 | `test_pending_observation_is_cancelled_by_challenge_pause` |
| Solver/Worker 的 Skill 按需搜索，显式激活后恢复正文 | `tests/test_direction_skill.py` |

原真实生命周期测试继续在精简入口下覆盖并行 Worker、复核权限、报告等待竞态、提交去重、多答案题以及 TCP/SSH/二进制会话跨等待、压缩、模型恢复。验证日志位于 `.aion/verification/20260905-compact-observation/`。

| 最终检查 | 结果 | 日志 |
|---|---|---|
| 全量 `.venv/bin/python -m pytest -q` | **365 passed，1 skipped，116.65 秒** | `pytest.txt` |
| 现有前端检查 | **7 passed** | `frontend.txt` |
| `node --check scripts/runtime_web/app.js` | 通过 | `javascript.txt` |
| Python 未定义引用检查 F821/F822/F823 | 通过；临时工具环境，无新增项目依赖 | `python-static.txt` |
| `git diff --check` | 通过 | `diff-check.txt` |

唯一跳过项是需要显式 `RUN_LIVE_TEST=1` 和外部凭据的只读平台 smoke test。新增代码、验证日志的 SHA-256 和基线校验值保存在 `verification.json`；`change.patch` 仅包含本次相对于实施前快照的改动。

## 固定上下文测量与边界

相同当前权限、相同真实 Solver 请求下，仅切换工具呈现：

| 固定工具定义 | 全量呈现 | 精简呈现 |
|---|---:|---:|
| 工具数量 | 60 | 12 |
| 序列化 UTF-8 字节 | 43,918 | 5,432 |
| 仓库启发式估算 token | 14,640 | 1,811 |

固定工具定义体积下降约 87.6%。数据与哈希在 `context-metrics.json`，`measure_context.py` 可离线重现。估算值不等于模型服务实际计费 token；工具检索结果、已激活 Skill、图谱输入/输出与解题轨迹会产生额外消耗。

本次没有真实模型质量测评、正式比赛或新的联网攻防运行，没有验证得分提升、全场 token 下降或缓存命中率提升。观察者被限制为无工具且输出格式严格，但假说质量仍须成对评测；工具按需发现也可能增加一次或多次检索。按 [评测方法](paired-evaluation.md) 比较四种消融条件，并完整计入失败题、重试和辅助消耗。
