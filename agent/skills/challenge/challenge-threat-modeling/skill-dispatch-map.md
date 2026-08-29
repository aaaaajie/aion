# Canonical Skill 调度映射

挑战 Agent 先完成资产、入口、信任边界和验证假设建模，再为一个明确问题选择一个执行 Skill。Skill 名称使用 Catalog 中的 canonical ID；不要仅凭漏洞关键词直接激活，也不要在未验证时拼接多个利用链。

## 方向路由

| 方向/问题 | 首选 Skill | 后续分支 |
|---|---|---|
| 源码、依赖、路由、输入到危险汇点 | `execution/src-audit-workflow` | `execution/src-auth-business-logic` 或对应专项 Web Skill |
| 角色、会话、对象权限、多步骤业务状态 | `execution/src-auth-business-logic` | 仅在差异明确时做 HTTP 验证 |
| Linux ELF、架构、保护、函数和输入路径 | `execution/binary-reverse-triage` | `execution/binary-fuzz-crash` 或 `execution/binary-exploit-and-variant-analysis` |
| 有限输入变异、崩溃复现和崩溃归并 | `execution/binary-fuzz-crash` | `execution/binary-exploit-and-variant-analysis` |
| 栈/堆/格式化字符串/整数/UAF 或补丁差异假设 | `execution/binary-exploit-and-variant-analysis` | 需要时引用 `stack-overflow-and-rop`、`heap-exploitation` 等专项 Skill |
| 内网资产、端口、服务和 Banner | `execution/internal-network-recon` | `execution/internal-ssh-pivot-and-post-access` 或服务专项 Skill |
| 已授权 SSH、单跳 Direct-TCPIP、有限权限检查 | `execution/internal-ssh-pivot-and-post-access` | 关闭 session/channel 并回收证据 |
| AI Agent、RAG、工具、记忆或敏感数据边界 | `execution/ai-agent-security-testing` | `execution/ai-defense-evaluation` |
| 防御前后、基线、误报、阻断、成本和耗时 | `execution/ai-defense-evaluation` | `execution/competition-evidence-and-metrics` |
| 已有运行记录和证据的比赛指标整理 | `execution/competition-evidence-and-metrics` | 不重新发起探测或改变目标状态 |

## Web 专项引用

源码或运行时证据已形成明确假设后，才转入对应专项 Skill：

- SQL 注入：`execution/sqli-sql-injection`
- XSS：`execution/xss-cross-site-scripting`
- CSRF：`execution/csrf-cross-site-request-forgery`
- 路径遍历/LFI：`execution/path-traversal-lfi`
- SSRF：`execution/offensive-ssrf`
- 命令注入：`execution/cmdi-command-injection`
- 反序列化：`execution/deserialization-insecure`
- JWT/API 认证：`execution/api-auth-and-jwt-abuse`
- 文件上传：`execution/php-file-upload-audit`

专项 Skill 仍须返回证据或明确的 `inconclusive`，不能把异常响应、静态模式或单一关键词当作漏洞成立。

## 逆向和利用专项引用

`binary-reverse-triage` 是二进制入口。仅在平台、架构和输入路径匹配后，按假设引用 `ida-reverse`、`ghidra-reverse`、`binary-diff`、`dotnet-reverse`、`go-rust-reverse`、`apk-reverse`、`mobile-reverse` 或 `macos-reverse`。`binary-exploit-and-variant-analysis` 负责利用性验证；缺少 Linux 动态环境、覆盖率引擎、符号执行器或污点分析器时，报告依赖缺口，不得把有限测试描述为完整自动化能力。

## AI 和区块链边界

AI 测试只对存在对应模型输入、检索、工具、记忆或敏感数据边界的目标激活。区块链/Foundry/ABI 资源本轮不纳入 canonical 首批挂载，保留现有资源作为后续独立方向；未提供对应工具和证据时不推断链上利用成立。

## 统一交付

每个执行任务必须包含目标、假设、工具调用、验证状态、证据引用、停止原因和清理状态，并最终只提交一个规范的 `execution_report`。缺少工具、超时、平台不匹配或目标不可达时使用明确状态（如 `ENTRY_UNREACHABLE`、`DEPENDENCY_UNAVAILABLE`、`TIMEOUT`、`INCONCLUSIVE`），不静默降级。
