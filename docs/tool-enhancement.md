# 解题工具增强交付

## 行为与使用

新增能力均通过 `tool_search(name=...)` 按需暴露真实函数给 Solver 和 Worker；不新增独立调度器。普通 HTTP 请求继续使用 `system_http_request`。

| 工具 | 用途 | 关键语义 |
|---|---|---|
| `system_http_replay` | 从已保存请求建立一次新实验 | `interaction_id`、`request_id` 和 `overrides`；字段整体替换，原计划不变，同 Run/Agent 校验，沿用当前 Cookie Jar；必须单独调用 |
| `system_http_compare` | 比较两个已保存响应 | `left`、`right` 各含 interaction/request ID；不发请求，显示状态、跳转、Cookie 属性、正文及 JSON 字段差异 |
| `system_browser_open` | 打开正常业务页面 | 明确 HTTP(S) URL；每 Agent 独立 Context，最多四个页面 |
| `system_browser_action` | 页面操作 | `session_id`、`action`；支持 navigate/click/fill/select/wait/screenshot/upload，按操作提供 selector/value |
| `system_browser_output` | 查看页面与网络证据 | 游标分页、元素摘要、截图、下载和捕获请求 ID |
| `system_browser_export_request` | 导出完整请求 | 返回可直接验证并交给 `system_http_request` 的 arguments，本操作不发送网络请求 |
| `system_browser_close` | 关闭页面 | 保存证据；Agent 结束通过已有 provider.close 关闭进程 |
| `system_source_scan` | 离线源码定位 | 指定工作区目录；返回既有后台 task ID，通过 `system_task_output` 读取结果和原始 JSON 路径 |

HTTP 示例：

```json
{"name":"system_http_replay","arguments":{"interaction_id":"interaction-example","request_id":"request-example","overrides":{"headers":{"Accept":"application/json"}}}}
```

ID 必须来自当前 Agent 的实际回执。`headers`、`query`、`cookies`、`body` 不进行递归合并；query 字段替换后仍遵循既有 HTTP URL 查询合并规则。如需移除 URL 内嵌参数，显式覆盖 URL。原始 multipart 文件引用按执行时文件内容处理，不承诺历史文件快照。会话 Cookie 使用当前状态，认证失败时需要重新建立正常请求。

响应比较默认最多读取每侧 30 KB，可提高至 100 KB；正文差异输出上限 30,000 字符，JSON 变化上限 200 项。正文缺失或不完整时显式标识，不推断业务等价或入口存在。HTTP 回执注明执行来源和已确认的失败阶段；无法细分时保留 unknown。

浏览器每页最多捕获 500 条响应/失败记录，请求体上限 100 KB；未知大小或过大的响应正文不缓存。Cookie/认证头保存在 Agent 自己的证据目录。multipart 上传不声称完整保留，因此不可导出重放；上传操作本身支持工作区内不超过 10 MB 的文件。localStorage 不转换为 Cookie，凭据可能过期。重启后只读历史证据，不恢复页面操作。浏览器进程按唯一启动标记登记所有者，避免把其他 Agent 的进程记到本 Agent。

源码扫描固定使用 Semgrep CE 1.136.0 和本地规则，覆盖 Python、PHP、JavaScript/TypeScript 的审计入口。命中统一标为 review_lead；不提供“已证实漏洞”判断。扫描脚本和规则作为 Shell 沙箱只读资源；沿用 Shell 超时、终止、资源限制和产物生命周期。默认忽略依赖、构建和版本控制目录，单文件扫描上限 1 MB，报告预览最多 100 条，完整结果保留在 JSON 产物。

## 发布边界

Playwright 固定为 1.55.0，对应 Chromium 140.0.7339.16。Linux x86_64 浏览器树位于 `tools/binaries/playwright-browsers`；全部 Python 依赖列入 `offline-requirements.lock`，wheelhouse 校验和同步更新。浏览器与规则资产另有 `enhanced-assets.sha256.json`，系统包版本记录在 `system-packages.lock`。

主 Dockerfile 离线安装 Python wheels；浏览器系统库仅在连接网络的镜像构建阶段安装，运行时不下载依赖。构建末尾以 `RUN --network=none` 执行浏览器和源码样例检查。`deploy/Dockerfile.tool-enhancement` 可从已有 AION Linux amd64 基础镜像制作增量交付镜像；最终导出镜像包含所需系统库，目标机通过 `docker load` 导入，无需包管理器。

`python scripts/package_linux_toolchain.py --check` 验证必需工具、Python 依赖及浏览器/规则校验和。完整端到端检查命令：

```sh
docker run --rm --platform linux/amd64 --network none --entrypoint python aion:tool-enhancement /opt/aion/scripts/check_enhanced_toolchain.py
```

输出目录：`output/tool-enhancement/`。其中包含离线镜像归档、完整工具链报告、单元测试日志、真实后台扫描验证结果及模型对照记录。模型配置和凭据不会进入镜像归档。

## 验证口径

- Linux amd64 断网检查覆盖登录、动态 API、截图、上传、下载、请求转交 HTTP、隔离、关闭、重启只读，以及三种语言命中和正常代码对照。
- 原生 Linux ARM64 单独验证真实 SourceTools → Shell 后台任务链及 cgroup 限额。这是本地验证环境；交付镜像仍为 amd64。本机 amd64 仿真不支持 bubblewrap 所需操作，相关失败尝试保留但不作为能力得分。
- 模型对照使用固定 `deepseek-v4-flash`、16 轮/180 秒预算、同一个无历史答案的本地登录与源码样例；分别开放旧/新工具集合，各三次。它是同运行时的工具集合对照，不是完整历史发行版对照。
- 原始模型文本与执行证据保留；计分接受说明文字中的完整 JSON 答案，同时核验实际认证响应。模型接口连接失败单独标为基础设施失败；如替换该轮，保留原尝试。
- 简单样例中新增工具可能不被选用，因此本对照不能证明复杂题的完成率提升。发布结论应依据功能验收，不将三个样本的耗时差异宣传为稳定提速。

未部署、切换或启动任何云端解题任务。

## 本次验收结果

- 定向测试：122 passed；另对最后的响应截断标识调整完成相关回归。
- amd64 镜像断网浏览器/源码检查通过；完整工具链所有必需项通过。原有可选项 seccomp-tools、hydra、angr、ropper 未作为本次新增依赖。
- 原生 Linux SourceTools 后台扫描完成，返回实际代码片段，cgroup 限制为 512 MiB / 1 CPU。
- 固定模型有效对照：旧集合 3/3、新集合 3/3；中位耗时分别 21.71 秒、22.11 秒；各有 1 次重复请求，工具失败均为 0。六轮均未选择新增工具。一个模型连接失败尝试保留并补测，不计为解题失败。
- 工作区已有的 compact-tools 工具数量断言与等待状态测试仍存在失败。等待状态失败在禁用本轮新增浏览器/源码 provider 后仍能复现，未修改其既有行为；不声称整个仓库测试全绿。

详细结果见 `output/tool-enhancement/comparison-report.json`、`toolchain-validation.json`、`source-task-check.log`、`unit-tests.log`；完整原始尝试另行保留。
