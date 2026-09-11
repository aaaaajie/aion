# 工具超时与暂停阻塞修复

本轮修复 `online-bfa30fe23fa8` 暴露的 Shell 与暂停阻塞链路。代码和离线验证均在本地完成，没有部署、恢复旧 Run、调用真实模型或启动比赛。

## 原因与实现

原实现把主进程退出和输出管道 EOF 混为一体。主进程退出后，`_terminate_process` 提前返回；后台子进程继续持有管道，Shell monitor 和 Agent 清理无限等待，Chief 暂停也无法返回。

- **Shell 任务拥有独立进程所有者。** 先持久登记所有者 PID、创建时间，再通过控制管道启动沙箱命令。命令输出使用独立管道并有上限地写入日志，不继承 Runtime 的控制管道。所有者保持会话身份直到回收结束；Linux 使用 subreaper 接管另起会话或双重 fork 的后代。
- **一个终止入口覆盖正常退出、超时、停止、取消和恢复。** TERM 最多 2 秒、KILL 最多 2 秒、输出排空最多 1 秒；Runtime 为强制回收和持久记录保留收尾余量。子进程通过创建时间核验，不按陈旧 PID 杀进程。普通 Shell 中的 `& / nohup` 随所属任务结束；需要后台执行时使用现有 `run_in_background=true`。
- **取消和持久化失败有明确收尾。** 创建期间取消不会激活命令；未完成的 spawn 保留引用。终态写入失败保留任务并允许清理时再次落库，SQLite 保证只产生一个终态。异常结果保留已捕获输出和清理诊断。
- **Supervisor 先关闭工具准入，再并行取消和清理。** Agent 本地收尾共用 10 秒窗口，等待不会因为被取消的协程拒绝退出而无限延长。每个失败项独立记录并保留引用，其他资源继续清理；旧执行或资源未停止时拒绝恢复。所有者意外丢失且未回传清理确认时保留失败状态，不以 PID 已消失推断子进程已释放。
- **Chief 暂停返回清理与释放两组结果。** 技术清理失败仍能进入平台释放流程并返回失败详情，批次继续处理其他题目；容量仍只按平台确认释放计算。整场暂停保留已完成 Agent 的终态。

工具名称、参数、模型、提示词和旁路观察配置未改变。Shell 结果增加 `cleanup` 与 `output_incomplete`；清理详情存入现有持久事件，不变更数据库版本，不增加迁移或兼容分支。后台输出、等待和压缩期间的其他技术会话继续由 Supervisor 持有。

## 验收清单

| 验收项 | 结果与证据 |
|---|---|
| 父进程退出，后台子进程继承 stdout/stderr、忽略 TERM、重定向输出 | `tests/test_shell_lifecycle.py`，验证进程消失、输出保留、终态只出现一次 |
| Linux 独立会话后代回收 | 同文件的 `test_linux_independent_session_is_owned_after_parent_exit`，setpriv 与 bwrap 两条真实沙箱路径 |
| 超时后同一 Solver 继续执行并提交 | `tests/test_solver_tool_shutdown.py::test_solver_executes_after_shell_timeout_and_submits`，真实 Runner/工具/StateService，平台仅收到一次正确答案 |
| Chief 暂停后继续启动另一题；保留容器同样清理 Shell | 同文件的 `test_chief_pauses_shell_and_starts_another_solver`，两种参数各一例 |
| 清理拒绝取消，其他资源正常释放，失败可见，恢复被阻止 | 同文件的 `test_cancellation_resistant_cleanup_is_retained_and_resume_blocked`；缩短测试预算，保持真实并发和持久记录路径 |
| 并发停止、创建阶段取消、输出写失败、终态落库失败 | Shell 故障回归；使用真实进程、文件大小限制及定点故障注入 |
| 所有者失去响应也不会无限等待 | 对真实所有者发送 SIGSTOP，显式停止在收尾预算内完成强制回收 |
| 所有者未经清理确认便退出 | 新增 `test_missing_owner_ack_is_retained_as_cleanup_failure`：返回 `shell_owner_lost`、持久保留未知清理状态、拒绝新的 Shell，不把 EOF 当作释放证明 |
| 不误杀其他任务或被复用的 PID | 并行任务隔离测试、`tests/test_process_resources.py::test_recovery_does_not_signal_a_reused_pid_identity` |
| 暂停不覆盖已完成状态 | Solver 完成后再暂停，Agent 仍为 `completed` |
| 等待、压缩、模型恢复后 HTTP/TCP/SSH/二进制会话继续可用 | 现有 `tests/test_solver_resources.py`，包含在最终全量检查中 |

## 最终检查

日志目录：`.aion/verification/20260905-tool-lifecycle/`。

| 检查 | 最终结果 | 日志 |
|---|---|---|
| 全量 pytest | 382 passed，2 skipped，199.23 秒 | `pytest-full.log` |
| 现有前端检查 | 7 passed | `frontend.log` |
| JavaScript 语法 | 通过 | `javascript.log` |
| Python 未定义引用 | 0 项 | `python-undefined.json` |
| `git diff --check` | 通过 | `diff-check.log` |
| Linux x86_64，setpriv | 19 passed，39.45 秒 | `linux-setpriv.log` |
| Linux ARM64，bwrap | 19 passed，37.33 秒 | `linux-bwrap.log` |

两种 Linux 场景均使用 Docker 隔离环境、只读代码挂载，执行时 `--network none`，没有挂载生产凭据、历史 Run 或宿主机 Docker socket。`linux-run.py`、测试依赖副本和验证镜像 Dockerfile 可用于重现。模型和平台均为本地替身，控制工具、Supervisor、Runner、StateService、Shell 和操作系统进程使用真实实现。

## 验证边界与保留资料

- 全量检查跳过真实平台 smoke test；macOS 跳过 Linux 专属 setsid/subreaper 用例，该用例已在两条 Linux 路径补验。
- macOS 验证同一会话/进程组内的后台子进程；跨会话、双重 fork 后代的验证证据来自 Linux。内核不可中断 I/O、整个事件循环或 SQLite 无法响应不属于已注入的故障；失败资源不得据此标记为已释放。
- 本机 x86 模拟环境的 bwrap 曾因未实现系统调用而无法创建沙箱，改用原生 ARM64 Linux 验证。这里不声称已在生产 x86_64 VPS 上完成同环境复测。
- 环境构建期间曾出现时间断言失败。最终全量检查在构建完成后通过；原有模型/工具目录测试的 5 秒守护窗口未放宽。显式停止为强制回收预留了更大的预算余量。
- 本轮不使用离线结果宣称分数提高或 token 降低。

修复前快照：`.aion/refactor-baselines/20260905T142800Z-tool-lifecycle/`，包含工作树归档、补丁及 SHA-256 清单。历史基线和云端运行归档保留。本轮相对快照的独立补丁、文件校验和与检查结果位于日志目录的 `current-change.patch` 和 `manifest.json`。
