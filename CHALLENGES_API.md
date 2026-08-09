# Challenges API：多 Flag 题目与完成判定

## 题目状态

`GET /openapi/v1/challenges` 返回题目列表。与 Flag 生命周期相关的字段是：

- `flag_count`：题目包含的 Flag 总数，一道题可以大于 1。
- `correct_flag_count`：当前已经提交并被平台接受的 Flag 数量，是累计值。
- `is_completed`：平台权威完成状态。只有平台返回 `true` 时，题目才算全部完成。
- `container_status`：靶场容器状态，不代表 Flag 是否全部完成。

`correct_flag_count == flag_count` 可以作为“应该重新同步题目状态”的阈值，但不能替代
`is_completed`。Runtime 在达到这个阈值后重新调用题目列表接口，并以远端
`is_completed` 作为最终完成判定。

## Flag 提交

`POST /openapi/v1/challenges/submit` 的请求体为：

```json
{
  "unique_code": "challenge-code",
  "flag": "candidate-flag"
}
```

同一道题可能需要多次提交。每次提交都必须作为独立 Operation 记录，成功后更新
`correct_flag_count`、积分和匹配索引（如果平台返回）。一次提交成功只表示一个
Flag 被接受，不得直接结束 Challenge Agent 或把题目标记为 completed。

只有重新同步后远端返回 `is_completed: true`，Runtime 才能将本地题目状态设置为
`is_completed=true` / `work_status=completed`。如果远端仍为 `false`，Challenge Agent
必须继续分析、创建后续 Execution Agent 或等待停滞策略，不得因为一个 Cycle 的
`outcome: completed` 而结束整道题。

## Runtime 处理顺序

1. 写入 `operations.started`，再调用提交接口。
2. 将请求结果、异常和耗时写入 SQLite。
3. 成功提交后累加本地 `correct_flag_count`。
4. 达到已知 Flag 数量阈值时重新请求题目列表。
5. 仅当同步结果的 `is_completed` 为 `true` 时标记 Challenge 完成。
6. 未完成时继续 Challenge → Execution 循环；Cycle 完成只表示本轮状态已提交。

Flag 原文不会写入 SQLite、事件、错误、投影或监控接口，只保存安全摘要、哈希和
长度。测试 Runtime 可以禁用提交接口，但生产 Runtime 遵循上述多 Flag 流程。
