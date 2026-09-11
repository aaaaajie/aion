# 后台任务与挑战子项

本地实现；未部署云端，也未启动新的挑战测试。

## Agent 工具

`system_task_start` 直接暴露，接收 `name`、`command`、`cwd`、`timeout`、`max_output_chars`。默认运行预算 1800 秒，上限 86400 秒，实际预算受 Run 剩余时间限制。启动立即返回任务 ID、名称、实际预算和读取参数。前台 `system_shell` 不再接受 `run_in_background`；执行器内部复用原有前后台实现。

名称、后台标志和实际预算保存于启动事件，不引入新任务表。完成通知保留去重与成功响应确认，附名称、终态、可用退出码和读取参数。Solver 等待时由持久化完成事件唤醒；正在执行的 Solver/Worker 在下一轮收到结果通知。Worker 没有新增等待工具，独立工作结束后用已有输出工具做有界等待，读取必要结果后再提交最终报告。

任务不跨运行时重启继续执行；原有超时、进程回收及终态清理保持生效。

Shell 沙箱内的 `/tmp`、`TMPDIR`、`TMP` 和 `TEMP` 都映射到当前 Agent 的 `agent/.tmp/<agent-id>/`。任务日志位于该目录的 `tasks/` 子目录，Shell 回执中的 `temp_dir` 和 `output_path` 可直接作为 `system_read_file` 的 Agent 路径使用；输出被清理或过期时返回明确的不可用状态。

## 监控页

快照中的 `background_tasks` 统一投影 Shell 后台任务、HTTP interactions 和网络任务，以类型与原始 ID 去重，根据所属 Agent 归入挑战。Worker 与后台任务分组显示，保留完成任务，支持搜索。

只读接口：`GET /api/tasks/{shell|http|network}/{id}?offset=0&limit=10000`。返回任务摘要、近期事件和按字符分页的输出，每页最多 10000 字符。HTTP 的执行和分析状态分别展示。分页使用任务记录中的路径；客户端不能传文件路径。没有输出文件或输出已清理时明确显示不可用。

监控器使用显式 `workspace_root` 定位任务输出；独立监控 CLI 新增 `--workspace-root`，服务单元配置为 `/var/lib/aion/workspace`。离线日志包未带输出时仍可查看任务和事件。数据沿用监控页现有 `_redact` 策略（当前项目配置为本地明文展示）。

页面保留当前选中任务、按需分页和滚动位置；刷新后从任务表恢复节点，不依赖前端事件窗口。没有新增停止按钮或控制接口。

## 验证

定向回归 131 项通过，1 项 Linux 专属 setsid 用例在 macOS 跳过。补充验证 Worker 完成通知、运行预算截断、真实 Solver 的启动—独立工作—等待—唤醒链路。

浏览器检查包括三类任务归组、搜索（过滤为 1 项后恢复 3 项）、分页、缺失输出提示及 390px 窄屏；窄屏没有横向溢出。截图位于 `output/playwright/background-detail.png` 和 `output/playwright/background-mobile.png`。

云端部署和新的 03／05 测试仍需单独执行，先核实上轮容器释放状态。
