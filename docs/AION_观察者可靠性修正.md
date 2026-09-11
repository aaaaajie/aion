# 旁路观察者可靠性修正

本轮先修输出契约与诊断。模型、非思考模式、2048 输出预算、20 秒调用窗口、6 次有效工具结果／60 秒触发条件、主 Solver 提示词和图谱临时注入方式均保持现状。不部署、不启动比赛、不增加模型重试或数据库迁移。

## 改动

- 明确只输出 JSON，禁止代码围栏与额外字段；补齐 claim 长度、1–4 个正整数来源、TENSION 至少两个不同来源、整图预算及合法空图谱示例。原有严格校验和同题来源检查继续执行。
- 模型调用开始事件保存实际传入的旧图谱和有界 trace。终态快照记录对应开始事件、耗时、HTTP 状态、结束原因、输出字符数／SHA-256、最多 16000 字符的输出；校验错误最多记录 16 项，包含字段路径、类型与原因，不重复保存错误 input/context。
- 失败区分 request、response、json、schema、sources；持久化失败使用 discarded 事件保留诊断。成功区分 empty、unchanged、updated。空图谱不算失败。
- 每个快照记录本批覆盖区间和 processed／failed。失败仍推进扫描游标并保留旧图谱，避免反复花费 token；失败区间不再被当成成功处理，原始记录仍在 SQLite，可离线分析。第一版不自动重试或回补失败批次。
- 新增只读离线重放，复用在线校验函数，不联网、不写数据库。输出被截断或历史记录缺少输入／输出时明确标为 unavailable。

## 离线重放

在项目根目录运行：

```bash
.venv/bin/python -m scripts.replay_solver_observation /absolute/path/state.sqlite3 --run-id RUN_ID
```

逐条输出 JSON，包含 snapshot sequence、agent_id、接受／拒绝／无法重放、失败阶段和字段错误。它验证已记录输出的格式与来源，不重新生成输出，也不评判假说的技术正确性。新日志遵循项目现有本地明文审计约定；诊断不包含 HTTP 认证请求头。

## 验收与边界

针对性回归覆盖 JSON 围栏、非法 JSON、字符串来源、过多来源、重复来源导致无效 TENSION、额外字段、跨来源引用、超长陈述、禁止工具调用，以及失败后继续处理新证据。沿用真实 StateService、Runner 和观察者生命周期测试；模型使用本地替身。

本轮证据目录：`.aion/verification/20260906-observer-reliability/`。修改前完整快照：`.aion/refactor-baselines/20260905T160814Z-observer-reliability/`。

旧云端 51 次 ValidationError 未保留原始输出，不能补算具体根因。本轮离线通过率不能替代真实模型可用率；尚未验证 87.9% 是否下降，也不宣称得分或 token 改善。后续应先统计新日志中的失败类别、非空且变化的更新数，再以相同题目、模型、窗口和资源进行观察者开／关成对评测，计入辅助调用和图谱携带的总 token。

验证结果：

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 观察者针对性回归 | 17 passed | targeted.log |
| 全量 pytest | 389 passed，2 skipped，84.15 秒 | pytest-full.log |
| 前端检查 | 7 passed | frontend.log |
| JS 语法、git diff --check | 通过 | javascript.log、diff-check.log |
| 新记录只读 CLI 重放 | accepted / updated，数据库哈希不变 | replay-cli.json |
| 旧云端记录重放 | 58 条明确 unavailable，数据库哈希不变 | replay-legacy.json |

两项跳过分别为需要真实平台凭据的 smoke 测试，以及仅 Linux 支持的 setsid subreaper 测试。本轮只在本地 macOS 验证观察者修改，没有重新执行 Linux 环境验证。
