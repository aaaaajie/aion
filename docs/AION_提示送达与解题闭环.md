# 提示送达与解题闭环

## 已实现

Chief／Solver 在每个主模型轮次边界读取现有持久化收件箱。工具执行不被中断；没有新报告时不添加消息或额外模型调用。仍按原序列、默认 20 条上限和 delivery_id 确认机制处理，主动 observe 与自动投递共用游标。报告进入模型输入，不代表模型采用提示；只有模型响应持久化后才确认交付。模型失败和恢复保留待确认报告；压缩移除待确认的显式观察内容时重新注入。

官方提示及报告 ID／事件序号进入 checkpoint。记忆摘要要求保留提示对假设的影响、未满足前置条件和冲突。提示内容仍是有来源的数据，不具有控制指令权限。

证据引用必须使用工具原样返回的 `evidence:evidence_<32 lowercase hex characters>`。格式错误为 `invalid_evidence_ref`（422）；合法格式的不存在、异题或跨 Run 引用仍为权限错误。没有裸 ID 兼容、迁移或权限放宽。

Shell、HTTP 和网络任务返回 `read_result: {tool, arguments}` 及 `result_state`。`pending` 表示运行中没有当前结果，`partial` 表示运行中已有部分输出，`available` 表示当前有输出，`empty` 表示当前页无结果且任务已终态；Shell 输出清理后为 `cleaned`。任务是否成功仍须看 status、错误和真实输出。`read_result` 用当前页游标和分页参数，允许重读被模型截断的输出；继续分页使用 `next_cursor`。HTTP 请求目录在正文可用时额外提供 `read_response`。不要在读取必要结果前清理任务。

Solver 使用线索、最小验证和前置条件复盘规则；Chief 根据具体停滞、时间、分值和已知代价决定是否请求额外提示。三个现有 Skill 按行为补强，不预载、不按题号分支、不强制 Worker。运行时没有固定字典、题目路径、密钥或历史答案。

## 验证入口

```bash
.venv/bin/python -m pytest -q tests/test_report_delivery.py tests/test_evidence_control.py tests/test_http_tools.py tests/test_network_tools.py tests/test_system_tools.py tests/test_compact_tools.py tests/test_agent_memory.py tests/test_solver_lifecycle.py tests/test_solver_single_agent.py tests/test_solver_resources.py tests/test_subagents.py tests/test_prompts.py tests/test_skills.py tests/test_skill_discovery.py tests/test_directory_isolation.py tests/test_performance_contracts.py
.venv/bin/python -m scripts.replay_solver_decisions
```

真实模型回放显式启用，使用本地配置的模型服务，不提供目标工具：

```bash
.venv/bin/python -m scripts.replay_solver_decisions --live --baseline .aion/verification/solver-efficiency/baseline.tar.gz --output .aion/verification/solver-efficiency/decision-replay-new
```

六个静态案例覆盖稳定错误、过期会话、未读任务、新提示、源码与响应冲突、正常业务链。审阅标准不进入模型输入。固定模型参数，逐案例交替条件顺序；记录提示词哈希、全部物理请求用量、耗时和失败。回放中 Skills 显式提供，只检验内容效果，不检验自动检索或完整解题能力。不得把 MockTransport 契约测试算作模型行为通过。

本次真实回放返回 401，没有有效模型决策输出。原始失败样本保留于 `.aion/verification/solver-efficiency/decision-replay`；脚本已增加认证失败即停止。需要有效模型认证后使用新输出目录重跑，不覆盖失败样本。

## 分层评测与采用门槛

冻结改动前当前工作树为 A；该快照包括此前未提交改动，不能用 Git HEAD 代替。B1 只加报告投递、结果契约和统计；B2 再加通用提示词；B3 再加三个 Skill。各层完整归档与 SHA-256 位于 `.aion/verification/solver-efficiency`。

先完成目标 Linux 的目录隔离验证，再按 `docs/paired-evaluation.md` 使用全新 Run、空记忆、独立工作区、干净靶机运行。不要恢复历史有污染的 Run，不将开发案例或失败题资料挂载给 Solver。模型版本、资源、时间窗和提示策略一致；固定样本集合和顺序，保留失败及基础设施中断。

小样本先比较 A／B1，确认无投递、结果读取和已解题回退；再比较 B1／B2、B2／B3。候选版本按既有规范至少做六组成对重复，交替先后顺序。除诊断题外，加入未用于编写规则的同类题及原本可解题。净得分优先；净得分相同时再比较完成题数、耗时、全部 token，不因开发样本得分上升而跳过泛化检查。发生契约错误或隔离失效则不部署该候选；收益不明确时保留基线，继续收集配对证据。

`analyze_run_performance` 增加 `hint_delivery`：报告序号、准备投递序号、首个携带 delivery_id 的响应序号、墙钟延迟和投递前模型响应数。墙钟包含暂停。`first_related_validation_sequence` 默认为 null，需人工结合真实输出注明证据；不能将下一次工具调用直接视为采用提示。无信息重复尝试同样按“同假设、有效实验、没有增量证据”的标准人工标注，超时、过期会话、未读输出单列为无效实验。引用错误计入已有工具错误统计。

目前只完成本地契约验证、归档和回放入口；模型认证阻止了有效行为回放，未执行完整比赛成对评测或云端部署，尚无净得分和 token 收益结论。
