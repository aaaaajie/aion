# Run／题目目录隔离修复

## 原因与改动

云端 a-03 曾通过 Shell 读取公共工作区的 `a06_evidence/app.py`。旧沙箱将整个工作区只读挂载，文件工具也默认允许读项目目录，因此只读限制不能防止异题材料混入。

- Linux Shell 不再挂载公共工作区，只挂载本 Agent 的 work／HOME／TMPDIR／任务输出、本 Run 同题 shared，以及明确指定的 Skill、Python 和工具链。使用私有 PID namespace 和丢弃 capabilities，避免通过宿主 `/proc` 访问其他进程的文件视图。系统 `/etc` 改为运行依赖清单，不开放整棵配置目录。
- 删除仅降权、不隔离目录的 setpriv 后端及对应测试。Dockerfile 安装、检查 bubblewrap；缺少可用沙箱时失败，不退回普通 Shell。删除旧 sandbox 用户配置和递归 chown 公共工作区行为。
- macOS 默认拒绝非授权文件内容读取，只开放系统依赖、明确列出的只读工具目录和当前 Agent／同题目录。公共 `/tmp` 不再开放；命令统一使用 `$TMPDIR`。Linux 的 `/tmp` 仍映射到该 Agent 的持久临时目录。
- 文件工具相对路径默认指向 Agent work，`shared/` 指向当前 Run 同题目录；公共根目录、其他题、其他 Run、其他 Agent 和软链接越界均拒绝。Shell cwd 同样受限。技术知识通过 Skill 工具或 `$AION_SKILLS_ROOT` 读取。
- Supervisor 将二进制、Artifact、Pentest／SSH 本地文件根目录绑定到当前 Agent work。HTTP 上传、变量字典、路径探测字典使用同一 Agent 的文件策略，连接实例继续复用。专用工具的本地文件参数以 Agent work 为基准；同题共享文件可通过 Shell／文件工具读取并按需复制到自己的 work，Evidence API 同题共享规则不变。
- 调试器脚本通过受管 Agent Shell 执行，不再直接启动未隔离的 gdb；复用原来的超时、取消和清理入口。

## 验证

`tests/test_directory_isolation.py` 使用真实 ToolExecutor、文件系统和操作系统进程，验证公共遗留文件、旧 Run、异题目录、另一 Agent 私有目录和软链接均不能读取；同题共享目录可读写。HTTP 使用本地平台／传输替身，外部文件上传在发送请求前被拒绝，自身文件可上传。调试器入口以本地脚本替身走真实 Shell 沙箱，越界读取失败且资源被释放。

保留真实 Runner 的零 Worker 解题、同题 Worker 连续执行、等待／压缩／模型恢复后会话复用、超时／暂停／完成清理回归。旧测试中的公共答案夹具改为当前 Run 同题共享夹具；二进制夹具改为 Agent work，未放宽隔离规则来迁就旧路径。

证据目录：`.aion/verification/20260906-directory-isolation/`。
修改前快照：`.aion/refactor-baselines/20260905T165328Z-directory-isolation/`，含完整工作树、差异和哈希。

Linux 重现命令（使用已有本地验证镜像，网络关闭，只挂载代码与测试依赖）：

```bash
.venv/bin/python .aion/verification/20260905-tool-lifecycle/linux-run.py bwrap tests/test_directory_isolation.py tests/test_shell_lifecycle.py tests/test_solver_tool_shutdown.py -q
```

## 交付边界

本轮是本地修复，未部署、停止或重启云端任务，未删除公共工作区中的历史材料，也未启动新比赛。已经读取异题内容的 Solver 记忆不会因代码修改自动变干净，后续效果评测应从新 Run 和干净环境开始。

Linux 验证环境为本地 Docker 原生 ARM64，启用了验证所需 namespace 权限；尚未在生产 VPS 的 AMD64／systemd 环境或重建后的完整生产镜像验证本版。使用受限 Docker 环境时必须提供可用的 bubblewrap namespace 环境，不再支持 setpriv 降级。macOS 用真实 sandbox-exec 验证；这不是对恶意宿主进程、并发文件替换竞态或网络隔离的完整安全审计。

最终结果：

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| 目录隔离及离线工具链 | 13 passed | isolation.log |
| 技术会话与 HTTP 文件边界 | 11 passed | resources.log |
| 全量 pytest | 391 passed，2 skipped，80.60 秒 | pytest-full.log |
| Linux ARM64 bubblewrap | 20 passed，12.77 秒 | linux-bwrap.log |
| 前端检查 | 7 passed | frontend.log |
| JS 语法、git diff --check | 通过 | javascript.log、diff-check.log |

两项跳过为真实平台 smoke（未提供测试凭据）和本地 macOS 不适用的 Linux subreaper 场景；后者已在上述 Linux 验证中执行。调试中一次全量检查出现 SQLite 锁竞争，单项复测和最终全量均通过；最终日志是最后一次完整检查结果。
