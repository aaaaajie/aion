# 目标优先级与观察者闭环：本地实现及离线验收

日期：2026-09-06。仅修改本地代码并离线验证；未部署、未启动比赛、未调用真实模型或题目接口。没有恢复进程数限制。

## 实现

- Solver 与会话记忆提示恢复目标优先级：出现新能力后先执行证据支持的最短目标检查；同一假设两次有效测试无新增信息先复盘。继续实验须有新证据或判别条件。有依据的少量常见凭据、路径检查仍允许；未执行、失败、未读完和对照失效不构成有效负结果。压缩保存目标、已验证能力、关键前提和下一项判别实验。
- 沿用 `SolverObserver`，配置默认开启，显式 `solver_observation=False` / `AION_SOLVER_OBSERVATION=false` 可关闭。Supervisor 创建独立驱动任务；Runner 只读取快照和通知驱动，不等待观察模型。运行及等待状态均可观察，终态取消请求，写入时再次核对状态、代次和版本。
- 每 Solver 一条在途观察请求；最短 60 秒、通常六条非纯管理工具结果才请求。新撤销或 corrected 复盘可跳过六条门槛，不能跳过时间门槛。无新事实不会只因时间经过请求模型。
- 查询最新 80 条相关事件，模型 trace 最多 16,000 字符；附加证据最多 6,000 字符，优先待处理问题原始依据和最近三条复盘。保留调用参数背景，分开调用、结果、Solver 声明。记录跳过范围，截断不代表覆盖完整历史。图谱覆盖超过 180 秒、失败或代次变化时不继续注入旧判断，只显示滞后状态。输出仍限 2,048 tokens，先完整校验字段与来源，再每组裁剪到两项，空图有效。
- 四组图谱外可附一项 correction。稳定 ID 由运行时生成；改写措辞、类别不能重置待处理问题。状态保存到现有事件日志，不加数据库迁移。
- 反馈复用 `solver_review` 的观察版本、assessment 字段。Runner 固定记录本次实际请求所携带的观察版本及 correction ID，避免并发更新造成送达错记。
- 自述已改、启动回执、未完成/失败执行、重复读取同一任务结果均不能关闭纠正项。后续观察必须引用新的已完成执行证据；撤销依据或资源代次改变使旧项失效。语义上是否支持纠正仍由观察模型判断，运行时校验来源、完成状态、有效性和新鲜度。
- 首次成功响应证明送达后满五分钟，至少两次后续观察引用不同的新执行证据确认持续，才通过现有 ReportRecord/通知机制向 Chief 报告一次。纠正 ID 去重及升级标记同事务保存，重启不重复报告，不暂停任务。
- 分别统计 created、delivered、feedback、resolved、revoked、escalated。送达按持久化响应中的唯一纠正 ID 计数；反馈不等于纠正，送达率不称为纠正成功率。

## 定向验证

使用 `.venv/bin/python -m pytest`、MockTransport、临时 SQLite 和本地合成工具数据。主定向集加后台任务和记忆合并执行，最终 **138 passed in 24.77s**。原始结果保存在 `.aion/verification/observer-goal-priority/targeted-tests.txt`。

主定向集：`test_observer_corrections.py`、`test_solver_observation.py`、`test_prompts.py`、`test_solver_review.py`、`test_completion_delivery.py`、`test_report_delivery.py`、`test_solver_lifecycle.py`、`test_review_metrics.py`、`test_model_usage.py`、`test_online_runtime_config.py`、`test_performance_contracts.py`。

覆盖：默认开关、目标策略提示、来源/条目裁剪、最新窗口及跳过范围、空图与失败、撤销和代次隔离、等待及长前台工具期间观察、单请求并发、终态迟到结果拒绝、反馈不自动关闭、执行证据关闭、重复读去重、五分钟与两次有效观察、升级重启去重和统计。长工具用例在本地 `sleep 1` 仍运行时取得并保存观察结果。

补充资源回归有 **5 项未通过**，均在 `tests/test_solver_resources.py` 等待初始 waiting 状态时超时：一项资源跨等待测试、四项 terminal boundaries 参数测试。日志显示现有等待规则返回 `no_wait_source`，这些旧用例没有提供可唤醒来源。该次扩展执行已中止，`test_solver_tool_shutdown.py` 未获得结论；不计入通过数量。没有为使它们通过而放宽生产等待规则。主定向集中同类旧用例补了明确的合成运行任务来源。

## 历史失败回放

只读数据库：`.aion/remote-logs/online-8a90146e78eb/analysis-20260906T030346Z/state.sqlite3`。

SHA-256：`80b97472f6e2c0e9fcc8b7966c69c71b484d39e14b4bb1b83383e9cfe9ac760e`。

运行：

```sh
.venv/bin/python -m scripts.replay_solver_observation \
  .aion/remote-logs/online-8a90146e78eb/analysis-20260906T030346Z/state.sqlite3 \
  --run-id online-8a90146e78eb
```

结果文件：`.aion/verification/observer-goal-priority/morning-replay.jsonl`。共 62 次已记录输出，59 次通过、3 次拒绝。原先失败的 18 次中，15 次经完整校验再裁剪后通过，3 次仍拒绝：

| 快照事件序号 | 拒绝依据 |
| --- | --- |
| 1460 | TENSION 不足两条来源 |
| 2280 | TENSION 不足两条来源 |
| 2536 | 顶层多出非法 map 包装 |

这证明历史格式/容量失败可以被区分处理，未放宽非法来源或矛盾依据要求；不表示 59 次观察的语义全部正确。旧日志没有新 correction 生命周期，闭环依靠合成响应测试，不能声称在历史线上运行中已成功纠正。

## 验收边界

本轮证明调度、预算、来源隔离、持久化与纠正证据门槛按测试契约工作。认证、参数、客户端不同不得视为同条件对照，已写入观察提示并保留调用背景；离线固定响应不能证明真实模型永不混淆条件。目标优先策略同样是提示策略，不是新增工具封禁。实际解题效率、误报率和模型语义判断仍需后续固定条件线上对照，本次没有对此作性能提升结论。
