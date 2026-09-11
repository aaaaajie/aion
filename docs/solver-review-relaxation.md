# Solver 进展记录与复盘减负

2026-09-06，本地修改，尚未部署。

03 的重定向误判和 05 的重复读取表明，需要让 Solver 更容易记录真实观察，并在没有推进时调整方法。普通观察不再必须先获得实现校准；提供 validation 的结论仍检查证据归属、完整读取、校准依赖及撤销关系。无 validation 的新发现不能作为后续校准来源。

## 当前行为

- new_information、no_new_information、inconclusive 均可不带 validation。它们描述进展和不确定性；“已验证／已排除”的结论应提供 validation。
- 每个假设的 stagnation_count 对有新增来源的 no_new_information 和 inconclusive 记录计数。重复来源或空记录不重复计数，也不会清空停滞。带新增来源的 new_information 清零；撤销仍使依赖结论失效。
- 移除每六个未复盘执行结果触发提醒的规则。停滞和异常执行仍可提醒，但为建议，不要求下一次回复交复盘；后台完成交付、重启后的去重和唤醒继续保留。
- 提示词强调最小可区分实验、观察与推断分开、复用结果，以及在有意义进展、重大纠正或持续阻塞时通过 solver_progress 向 Chief 汇报。没有增加工具禁用或执行额度限制。
- 大结果附带 read_result，包含 tool_result_read 和完整参数。未读完的页面给下一页调用；读完返回 null。上下文压缩保留读取指引和结果引用。
- 当前字段使用 stagnation_count、review_recommended、automatic_review_recommended；统计脚本与用例同步更新，不保留旧字段别名。

## 验证

89 项定向测试通过，覆盖复盘／校准权限、停滞计数、异常提醒与重启、后台完成交付、工具纠错、分页恢复、提示词及上下文预算。git diff --check 通过。

这是本地行为与合同验证；尚未用新线上运行验证 03／05 的实际解题效果。
