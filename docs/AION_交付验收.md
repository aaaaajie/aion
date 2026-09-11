# AION 连续 Solver＋按需 Worker：交付验收

交付日期：2026-09-05。本轮交付当前工作树中的本地实现、离线测试与三组成对评测方法。四个阶段已落地；下列证据走真实 StateService、Supervisor、Runner 与控制工具，模型和题目平台使用本地替身。没有启动正式比赛或以历史中断日志宣称性能提升。

此清单保留连续 Solver 重构交付时的验证记录。后续按用户新要求加入的旁路短图谱、精简工具与按需 Skill，见 [后续实现与最新验证](AION_短图谱与精简工具.md)。原 Observer Agent 及调度机制仍已删除。

## 快照与数据约定

| 项目 | 证据 |
|---|---|
| 原基线保留 | `.aion/refactor-baselines/20260905T070949Z/worktree.tar.gz` |
| 实施前新快照 | `.aion/refactor-baselines/20260905T075909Z/worktree.tar.gz`、`working-tree.patch`、`manifest.json`；manifest 保存逐文件 SHA-256，HEAD 为 `aeae58899031c99716defb0367ba14c936f342ca` |
| 历史运行保留 | 使用独立测试 Run；新 Run 复用已有 run_id 会拒绝覆盖，`tests/test_runtime_cleanup.py` |
| 数据库版本 16 | `test_schema16_rejects_old_database_without_modifying_it` 验证版本 15 元数据及历史表均未修改；没有迁移或旧角色兼容入口 |
| 模型、推理和预算 | `tests/test_performance_contracts.py::test_competition_context_and_schema_contract`、`tests/test_agent_memory.py`；原 Challenge→Solver、Execution→Worker 预算映射 |

上述 `.aion` 路径相对于项目根 `/Users/mr.li/aion`。快照和历史运行没有被新测试数据库替换。

## 阶段一：单 Solver 闭环

| 完成项 | 验收证据 |
|---|---|
| 仅 Chief/Solver/Worker，零 Worker 解题和提交 | `test_real_runner_solves_without_worker_and_releases_resources`；实际读取文件、执行答案工具、确认完成、释放靶机 |
| 每题唯一持久 Solver，启动使用实际 ID | `test_concurrent_launch_pause_resume_retains_solver`、`test_independent_services_share_unique_solver_identity`、`test_second_supervisor_cannot_take_over_live_run`；并发启动、独立 StateService 注册及同机重复接管分别覆盖 |
| 暂停/故障恢复复用身份与记忆 | `tests/test_solver_resources.py` 的新 Supervisor 恢复场景；`tests/test_runtime_network.py` 的 Runtime 暂停/恢复场景 |
| Supervisor 持有资源，会话等待与压缩不销毁连接 | `test_binary_tcp_ssh_survive_wait_compaction_and_recoverable_model_failure`；真实 Runner 会话、二进制进程、localhost TCP、HTTP Cookie 会话和 Paramiko SSH 连接 |
| 幂等清理，各类失败互不跳过并持久记录 | `test_cleanup_failure_is_persisted_other_resources_close_and_retry_succeeds`；HTTP 连接池按 Agent 关闭，失败项保留重试 |
| 未到平台权威完成状态不结束题目 | `test_multi_answer_solver_keeps_running_after_partial_acceptance`、`test_flag_counts_do_not_finish_solver_before_platform_confirmation` |
| 精确提交去重与不确定结果核对 | `test_exact_submission_dedup_and_uncertain_result_never_blindly_retry` 的 partial/malformed/timeout 三种情况；物理提交一次，无法确认时 Operation 保持 indeterminate |

## 阶段二：显式执行 Worker

| 完成项 | 验收证据 |
|---|---|
| 独立任务并行，同一执行者连续推进依赖步骤 | `test_two_workers_parallel_continuous_steps_and_review_use_real_runner`；两 Worker 同时活动，各自读取、更新、继续读取、终态报告 |
| 显式任务键，同键同内容幂等、不同内容冲突 | `test_solver_identity_survives_inactive_status_and_task_key_is_explicit`；重复委派不会重复执行，不允许 Worker 递归委派 |
| 非终态更新与唯一终态分开 | `test_report_dedup_terminal_cancel_and_late_audit`；调用 ID 冲突、内容去重、取消与报告竞态、迟到审计 |
| 报告不派生 Agent、不自动停止主线 | 上述实际 Runner 并行任务场景，以及取消/报告事务测试 |
| Worker 时限从实际开始计算 | `test_worker_budget_starts_after_queue_and_timeout_preserves_solver`；排队超过 Worker 时限后仍获得原执行预算，到期不停止 Solver |
| 所有 Agent 受整场绝对截止限制 | `test_terminal_boundaries_clean_processes_and_confirm_capacity[deadline]`；排队准入再次检查 Run 状态与截止 |
| 同题共享证据，跨题/跨 Run 拒绝，分页读取 | `test_same_challenge_evidence_pages_cross_scope_denied_and_review_cannot_write`、`tests/test_evidence_control.py` |
| 未确认报告重放，确认绑定已落库模型响应 | `test_delivery_replays_until_matching_persisted_response_and_wait_cannot_lose_report`；恢复场景同时验证未确认批次保留 |
| 候选答案在重启后完整重放 | `test_pending_candidate_report_replays_exactly_after_service_restart` 比较整个投递批次内容 |

## 阶段三：复核与 Chief 控制

| 完成项 | 验收证据 |
|---|---|
| review Worker 通过真实工具链提交报告 | 实际 Runner 的复核场景以及 `test_current_api_enforces_review_and_run_scope` |
| review 白名单与 StateService 双重限制 | 执行目标、提交、委派、写 Evidence/Finding 的拒绝测试；允许同题证据和报告读取 |
| Chief 批量暂停，默认释放、可显式保留 | `test_batch_pause_release_failure_retains_capacity_and_close_stays_closed`；retain 资源边界场景验证保留靶机但关闭连接 |
| 永久关闭、逐题返回、容量以平台确认释放为准 | 批量控制含不存在题目的局部失败；释放失败继续占槽，刷新目录不能重新激活永久关闭题目 |
| Worker 崩溃中断一次，不自动续跑 | `test_new_supervisor_recovers_original_solver_and_interrupts_queued_worker_once`、`test_recovery_interrupts_workers_once_preserves_memory_and_unacknowledged_delivery` |
| 旧句柄失效、记录的进程被回收 | 恢复资源场景；`test_recorded_process_cleanup_kills_term_ignoring_descendant` 覆盖忽略 TERM 的子进程 |
| 删除旧自动机制与专用状态 | 删除 BS 黑板/Observer/Bootstrap/旧阶段提示词和路由文件；删除自动催报、续派、兄弟停止、停滞及 Quiescence 决策代码。健康采样不唤醒模型 |

## 阶段四：产品与交付

| 完成项 | 验收证据 |
|---|---|
| 面板 Chief→Solver→Worker，区分 execute/review | `tests/test_runtime_web.py`、`tests/test_runtime_web_ui.py`，以及本地浏览器桌面/窄屏核验 |
| 每 Agent、每题、整场四类 token | `tests/test_model_usage.py`；按物理调用 ID 去重，含重试、摘要、Skill 发现与平台适配请求；缺失指标显示未知 |
| 当前内部 API、启动配置、提示词与 Skill | `tests/test_model_usage.py` 的 API 检查、`tests/test_prompts.py`、`tests/test_skills.py`、`tests/test_quick_runtime_config.py` |
| 技术文档与成对评测 | [技术方案](../AION_技术方案.md)、[多答案 API 契约](../CHALLENGES_API.md)、[三组成对评测方法](paired-evaluation.md) |
| 最终检查 | 全量 pytest、现有前端测试、JS 语法、Python 未定义引用检查和 `git diff --check`；结果见下表 |

## 最终验证记录

验证日志目录：`.aion/verification/20260905-solver-worker/`。

| 检查 | 命令 | 结果/日志 |
|---|---|---|
| 全量 pytest | `.venv/bin/python -m pytest -q` | **354 passed，1 skipped，51.09 秒**；`pytest.txt` |
| 现有前端检查 | `.venv/bin/python -m pytest -q tests/test_runtime_web.py tests/test_runtime_web_ui.py` | 7 passed；`frontend.txt` |
| JavaScript 语法 | `node --check scripts/runtime_web/app.js` | 通过；`javascript.txt` |
| Python 静态引用 | `ruff check --select F821,F822,F823`（临时工具环境，无新增项目依赖） | 通过；`python-static.txt` |
| Diff 空白检查 | `git diff --check` | 通过；`diff-check.txt` |
| 浏览器 | 本地只读版本 16 夹具 | 桌面与窄屏角色导航、复核报告、等待状态、token 缺失值及整场汇总；未观察到 console error/warn；`browser-qa.md` |

`verification.json` 保存最终命令、结果、源文件与日志 SHA-256，以及两个基线快照的校验值。预览页和临时预览服务已关闭。

## 未验证边界

- 本轮未调用真实模型或正式 Benchmark、未启动正式比赛、未执行长时间成对评测。唯一跳过项是需显式 `RUN_LIVE_TEST=1` 与外部凭据的只读平台 smoke test。
- 执行环境是 macOS。二进制测试创建真实本地进程；Linux ELF/bwrap 的系统边界用夹具替代，未在 Linux 发布容器重新验证隔离器。TCP、HTTP 和 SSH 的会话生命周期使用本地真实网络连接。
- 恢复用新 Supervisor 读取原 SQLite；独立进程直接退出后遗留进程被实际回收。未对完整在线 Runtime、VPN 与远端靶机联合执行部署级故障演练。
- SSH 的认证和 exec 生命周期已验；本轮没有对真实多跳网络、真实凭据或 SFTP 服务进行新的在线验收，既有 SSH 工具测试继续保留。
- 并发启动覆盖 Runtime 内并发请求、独立 StateService 注册，以及同机第二监督者被内核文件锁拒绝。一个 Run 由一个 Runtime 监督；未支持多机共享文件系统上的分布式多主运行。
- 保留当前本地明文审计约定。报告中的候选答案持久化以保证重放完整；精确值保护和提交去重不等于日志脱敏。
