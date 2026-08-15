# AION VPS 运维手册

本文档是 AION VPS 部署和运行操作的唯一说明。日常操作统一在本机
`/Users/mr.li/aion` 下执行 `deploy/aion-vps`，不要手工 rsync、覆盖
`/opt/aion/current`，也不要直接修改 systemd unit。

## 固定环境

- 服务器：`root@43.138.171.224`
- SSH 私钥：`/Users/mr.li/Documents/key/root.pem`
- Host Key：`deploy/vps_known_hosts`
- Monitor：`https://43.138.171.224:8443/`
- 代码：`/opt/aion/releases/<release-id>`
- 当前版本：`/opt/aion/current`
- Python 环境：`/opt/aion/venvs/<requirements-sha256>`
- Agent 工作区：`/var/lib/aion/workspace`
- Run 数据：`/var/lib/aion/runs`
- OpenVPN：`/etc/aion/vpn/benchmark.ovpn`
- 持久配置：`/etc/aion/aion.env`，不含 `BENCHMARK_TOKEN`

`/etc/aion/aion.env` 必须同时提供 `LLM_BASE_URL`、`LLM_MODEL`、
`LLM_API_KEY` 和 `AION_SKILL_DISCOVERY_MODEL`。Skill Discovery 模型使用同一
Base URL 与 API Key；该项应配置为支持普通 OpenAI-compatible Chat Completions
的轻量模型。缺失或调用失败时 Runtime 会记录降级事件并使用本地候选，不会阻塞
Execution。

可选配置 `AION_BOOTSTRAP_ENABLED=false` 可关闭每个 Challenge 的自动 Bootstrap；未配置时默认启用。

私钥始终留在本机。Monitor 使用自签名证书，浏览器第一次访问需要接受证书警告。

## 固定版本工具链（离线）

比赛环境不联网，所有执行环境必须随 release 自包含：

- Python 运行时和二进制分析依赖统一放在 Linux x86_64 wheelhouse；完整锁定清单是
  `tools/binaries/offline-requirements.lock`，发布包同时带上
  `tools/binaries/wheelhouse.sha256`。release manager 只执行带
  `--no-index` 的本地安装，运行期不执行 pip、apt 或其他联网安装。
- 系统工具必须放在 `tools/binaries/bin/`，版本、启动参数和 SHA-256 记录在
  `tools/binaries/manifest.json`。联网构建机准备好精确版本后，在 Linux x86_64 上执行
  `python scripts/package_linux_toolchain.py --source /absolute/path/to/bin`，再执行
  `python scripts/package_linux_toolchain.py --check`。
- `aionctl doctor` 和 release prepare 都会校验目标平台、wheelhouse 完整性、每个工具的
  可执行权限、版本输出和 SHA-256；任何必需项缺失都会拒绝启动执行代理。运行时 PATH
  只把 release 自带的 `bin/` 放在最前面，不接受宿主机上同名的其他版本。
- pwntools 的联网更新检查在 Agent 沙箱 HOME 预置 `never` 标记，离线运行不产生外联。

构建完成后的本地校验：`python tools/binaries/offline_tools.py checksums` 更新 wheel
清单，然后执行 `python scripts/package_linux_toolchain.py --check`。

## 远程服务器登录信息（供 AI/运维读取）

```text
用途：AION 比赛 Runtime VPS
公网 IP：43.138.171.224
SSH 端口：22
SSH 用户：root
认证方式：SSH 私钥
本机私钥：/Users/mr.li/Documents/key/root.pem
Pinned known-hosts：/Users/mr.li/aion/deploy/vps_known_hosts
系统：OpenCloudOS 9.6
架构：x86_64
应用目录：/opt/aion
数据目录：/var/lib/aion
配置目录：/etc/aion
```

从本机直接登录的完整命令：

```bash
ssh \
  -i /Users/mr.li/Documents/key/root.pem \
  -o IdentitiesOnly=yes \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/Users/mr.li/aion/deploy/vps_known_hosts \
  root@43.138.171.224
```

给后续 AI 的约束：

- 使用 `root` 用户，不要尝试 `ubuntu`。
- 使用 `root.pem`；旧的 `/Users/mr.li/Documents/key/vps.pem` 不可用。
- 不得关闭 `StrictHostKeyChecking`，也不得绕过 pinned known-hosts。
- 不得读取、输出、复制或上传私钥内容；只允许把上述本机路径交给 SSH 客户端。
- 不使用密码登录，不把私钥上传到服务器。
- SSH 登录只用于诊断或本地 CLI 内部操作；日常运维仍优先使用 `deploy/aion-vps`。
- 不通过包管理器安装临时工具；执行工具必须由 release 的离线 toolchain 提供。

## 最常用操作

先进入项目目录：

```bash
cd /Users/mr.li/aion
```

检查服务器状态：

```bash
deploy/aion-vps status
deploy/aion-vps doctor
```

部署新代码并续跑当前 run：

```bash
deploy/aion-vps deploy --benchmark-token '<TOKEN>'
```

部署代码、上传新 VPN，并续跑当前 run：

```bash
deploy/aion-vps deploy \
  --benchmark-token '<TOKEN>' \
  --vpn '/absolute/path/to/profile.ovpn'
```

`deploy` 会自动运行完整 pytest、执行 rsync dry-run、准备只读 release、复用未变化的
venv、暂停当前任务、切换 release、恢复同一 run 并执行健康检查。服务未运行时只部署，
不会擅自新建任务。

## 任务启停

创建全新 run：

```bash
deploy/aion-vps start --benchmark-token '<TOKEN>'
```

使用新 VPN 创建全新 run：

```bash
deploy/aion-vps start \
  --benchmark-token '<TOKEN>' \
  --vpn '/absolute/path/to/profile.ovpn'
```

恢复最近的未完成 run：

```bash
deploy/aion-vps resume --benchmark-token '<TOKEN>' --run-id latest
```

恢复指定 run：

```bash
deploy/aion-vps resume \
  --benchmark-token '<TOKEN>' \
  --run-id 'online-xxxxxxxxxxxx'
```

暂停并恢复当前 run，常用于只重启 Runtime/VPN：

```bash
deploy/aion-vps restart --benchmark-token '<TOKEN>'
```

最终停止：

```bash
deploy/aion-vps stop
```

`restart` 和代码部署使用部署暂停语义，保留 Chief/Challenge 的可恢复状态；无法安全
重放的 Execution Agent 会标记为 `interrupted` 后重新调度。`stop` 是最终停止语义，
不要把它当成日常重启命令。已完成 run 不允许 resume，也不会自动创建新 run。

## 日志与诊断包

查看最近 200 行 journal：

```bash
deploy/aion-vps logs tail
```

持续跟踪日志，按 `Ctrl-C` 退出：

```bash
deploy/aion-vps logs tail --follow
```

下载最近 run 的诊断包：

```bash
deploy/aion-vps logs pull --run-id latest
```

下载指定 run，并明确包含工作区：

```bash
deploy/aion-vps logs pull \
  --run-id 'online-xxxxxxxxxxxx' \
  --include-workspace
```

下载结果保存在：

```text
.aion/remote-logs/<run-id>/<UTC时间>.tar.gz
```

默认诊断包只包含 SQLite 一致性快照、对应 journal、systemd 状态和 release 信息；
不包含 `.env`、Benchmark Token、VPN 文件或 Agent 工作区。`--include-workspace`
可能包含题目证据、Flag 或其他敏感内容，只在确实需要时使用。文件权限固定为 `0600`，
下载后会自动校验 SQLite 和 SHA-256。

为当前运行开启只读下载入口（不会停止或重启 AION Runtime）：

```bash
printf '%s' '<下载密码>' | deploy/aion-vps runs-share --username aion --password-stdin
```

入口为 `https://43.138.171.224:8443/runs/`。该入口使用独立的 Basic Auth
账号和现有 HTTPS 证书，只允许 `GET`/`HEAD`，后端仅绑定 `127.0.0.1`，数据源为
`/var/lib/aion/runs`。其中的 SQLite 可能在运行中带有 WAL，建议在 Run 停止后再下载
数据库；工作区证据仍不在这里，使用 `logs pull --include-workspace` 导出。

## Release 与回滚

回滚到上一个成功 release，并恢复当前 run：

```bash
deploy/aion-vps rollback --benchmark-token '<TOKEN>'
```

系统保留最近 3 个成功 release。发布在旧服务运行期间先完成上传、依赖检查、Python
导入和编译；只有最终符号链接切换需要短暂停机。启动失败会恢复上一 release 和上一
VPN。第一次从旧平铺目录迁移时只保证恢复旧文件并保持停止，不会用不支持 resume 的
旧入口擅自新建 run。

## Token 与 VPN 规则

- 所有 start/resume/restart 和运行中部署都必须显式传入 `--benchmark-token`。
- 工具不会读取 `.env` 中的 Token，也没有 Token fallback。
- Token 通过 SSH stdin 传入远端，再由 systemd `LoadCredential` 提供给 Runtime。
- Token 不进入远端命令行、unit、journal、release 或持久配置。
- Token 仍可能出现在本机 Shell history；操作后可按本机 Shell 策略清理对应历史记录。
- 不传 `--vpn` 时复用服务器当前 VPN；传入时必须是绝对路径的 `.ovpn` 文件。
- VPN 配置若包含执行宿主机脚本、替换默认路由等危险指令，工具会拒绝上传。
- 新 VPN 启动失败、Monitor 未就绪或默认路由改变时，操作失败并恢复上一 VPN。

## 安全边界

- 日常部署绝不执行 `dnf`，也不安装或升级任何系统包。
- 固定宿主依赖仅为 OpenVPN、bubblewrap、Python 3.11 和 Nginx；执行工具从 release
  自带的 `tools/binaries/bin/` 提供。
- `doctor` 会校验 release 内工具链和版本；部署前后 RPM 包清单摘要必须一致。
- 只上传 `agent/`、`tools/`、`challenges_sdk/`、`third_party/`、`scripts/`、`deploy/`、
  `pyproject.toml` 和 `requirements.lock`。
- 不上传 `.env`、`.venv`、`.aion`、证据目录、recon、work 或本机临时文件。
- `/etc/aion/aion.env` 在日常部署中保持不变。
- 不修改服务器现有 80/443 站点、`bodian.conf`、Docker 服务或其他业务目录。

## 故障处理顺序

1. 先运行 `deploy/aion-vps status`，确认 service、run、VPN 和 Monitor 状态。
2. 使用 `deploy/aion-vps logs tail` 查看启动错误。
3. 使用 `deploy/aion-vps doctor` 检查固定依赖、Nginx、磁盘和 release toolchain 状态。
4. 需要离线分析时执行 `deploy/aion-vps logs pull --run-id latest`。
5. 新版本故障时执行 `deploy/aion-vps rollback --benchmark-token '<TOKEN>'`。
6. 不要手工删除 `/var/lib/aion/runs`、SQLite WAL、release 或 credential 目录。

只有在本地 CLI 本身损坏、无法运行时，才 SSH 到服务器使用远端 `aionctl status`、
`aionctl logs` 和 `aionctl stop` 进行应急诊断。恢复后仍应回到本地 `deploy/aion-vps`
执行日常操作，避免本地与服务器状态脱节。
