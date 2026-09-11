# 工具复用、证据记忆与 Worker

Solver 直接看到 solver_delegate，现有角色权限、任务去重、排队与报告机制保持不变。提示区分会话内依赖步骤、后台扫描和可独立验收的 Worker 工作；只读复核不能执行实验，不强制创建 Worker。

协议验证先搜索现有工具和依赖。连接重置、空响应或解析错误不等于排除目标，先确认客户端编码与接收逻辑有效。批量脚本以已知小样本检查实际尝试、成功及分类异常计数。

Session Memory 沿用八个章节、原触发与预算，优先保留证据引用、已读路径和范围、已测范围、无效实验及撤销原因、下一项关键不确定性。完整读取必须来自实际回执；不通过解析 Shell 命令猜测。未新增数据库表、旁路模型或周期性调用。

## 验证

定向测试验证直接工具与权限、FastCGI 搜索和协议交互、Worker 并行报告、只读限制、通知、记忆压缩及上下文预算。

`scripts/evaluate_agent_behavior.py` 提供四个固定本地场景，每场景修改前后各三次，交替顺序；每次 Solver 最多 8 轮／90 秒，Worker 最多 4 轮／60 秒。调用真实模型与本地 Shell/FastCGI，Worker 用真实模型加评估专用的内存投递适配器。生产调度与唤醒由独立链路测试验证，不能把适配器当作生产调度的端到端证明。自动指标是可复核的工具与文本信号，正式比较应人工检查完整事件，尤其是否作出了无依据的排除结论。

修改前基线位于 `.aion/verification/evidence-worker/baseline`。首轮调用本地 `.env` 中的模型配置全部收到 HTTP 401，未产生任何有效行为样本；不能把这些记录算成模型失败率。token usage 未返回，费用未知。评估器现已在鉴权错误后立即停止，保留记录，修复配置后应使用新的输出目录。当前没有有效的前后能力比较结论。

调用方式：

```sh
PYTHONPATH=. .venv/bin/python scripts/evaluate_agent_behavior.py --baseline .aion/verification/evidence-worker/baseline --output .aion/verification/evidence-worker/live-retry
```

此修改未部署云端、未启动挑战。多轮挑战比较仍单独执行。
