# Challenges API：多 Flag 题目与完成判定

## 题目状态

`GET /openapi/v1/challenges` 返回题目列表。与 Flag 生命周期相关的字段是：

- `flag_count`：题目包含的 Flag 总数，一道题可以大于 1。
- `correct_flag_count`：当前已经提交并被平台接受的 Flag 数量，是累计值。
- `is_completed`：平台权威完成状态。只有平台返回 `true` 时，题目才算全部完成。
- `container_status`：靶场容器状态，不代表 Flag 是否全部完成。

`correct_flag_count == flag_count` 可以作为“应该重新同步题目状态”的阈值，但不能替代
`is_completed`。Runtime 在成功提交后重新调用题目列表接口，并以远端
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
Flag 被接受，不得直接结束 Solver 或把题目标记为 completed。

只有重新同步后远端返回 `is_completed: true`，Runtime 才能将本地题目状态设置为
`is_completed=true` / `work_status=completed`。如果远端仍为 `false`，Solver 继续执行、按需委派独立 Worker 或等待外部状态。Worker 终态只结束该任务，不结束整题。

## Runtime 处理顺序

1. 写入 `operations.started`，再调用提交接口。
2. 将请求结果、异常和耗时写入 SQLite。
3. 成功提交后累加本地 `correct_flag_count`。
4. 成功提交后重新请求题目列表；答案计数只是进度，不是完成判定。
5. 仅当同步结果的 `is_completed` 为 `true` 时标记 Challenge 完成。
6. 未完成时保留原 Solver 继续执行；只有整题完成才停止该题关联工作并清理资源。

本地运行沿用现有明文审计设置；精确值保护用于校验提交来源与内容，提交去重使用参数指纹。
测试 Runtime 可以禁用提交接口，正常 Runtime 遵循上述多 Flag 流程。

提交权限仅属于 Solver。相同精确值按哈希去重；请求结果不确定时先读取平台状态进行核对，不能盲目重试。暂停与进程恢复保留待核对 Operation。
