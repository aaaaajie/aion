# Tscan 基础 POC 试点

维护者 CLI 只执行经过静态适配的单文件、单文档 YAML。原始文件不会被改写，也不会执行 YAML 表达式、脚本或外部资源。

```bash
# 只校验，不发请求
python -m tools.poc_runtime inspect --poc /path/to/poc.yml

# 对一个明确的目标 origin 执行一个规则
python -m tools.poc_runtime run \
  --poc /path/to/poc.yml \
  --target https://target.example \
  --output output/poc-run-001

# 只读查看本地 Yakit SQLite 的表和行数
python -m tools.poc_runtime yak-audit \
  --database /path/to/yakit-profile-plugin.db \
  --output output/yak-audit-001

# 维护者一次性构建只读索引包；输出目录必须是新目录且不在输入目录内
python -m tools.poc_runtime index \
  --source tscan=/path/to/TscanPlus/config/Pocs \
  --source yak=/path/to/yakit-profile-plugin.db \
  --output output/poc-index-001
```

当前支持 Tscan 中的 Afrog 和 Xray 映射规则：唯一命名规则、一个静态 HTTP 请求、GET/POST、origin 相对路径、静态字符串 headers/body，以及 `response.status == N`、`response.body.bcontains(...)`、`response.headers["..."] .contains(...)` 和 `response.content_type.contains(...)` 的 `&&`/`||` 组合。请求必须在发送前完整通过校验。

变量、提取器、多规则、多阶段请求、payload 展开、脚本、正则 matcher、未知字段、非 HTTP 协议和未完整消费的表达式都会返回明确的拒绝原因，并发送零请求。fscan 列表规则、Nuclei 和 Yak 脚本本轮只做审计或盘点。

`run` 的输出目录必须不存在。`result.json` 保存 `matched`、`not_matched` 或 `inconclusive`、interaction/request ID、传输失败阶段和逐项 matcher 证据；`http-interaction/` 保存现有 HTTP 引擎产生的请求日志、响应元数据和限量正文；`poc.json` 保存来源文件哈希和适配后的请求摘要。

退出码为：`0` 表示请求完成且判断为 matched 或 not_matched；`2` 表示输入或适配不支持；`3` 表示传输失败、响应正文缺失/截断或其它无法确定的执行结果。命中只表示满足 POC 判断条件，不等同于漏洞已证实。

Yakit 盘点以 SQLite 只读模式打开数据库，只记录表结构和行数，不运行 Yak 插件、不读取外部资源，也不据数据库记录推断脚本语义。

## Agent 工具闭环

Solver 和执行型 Worker 可使用 `system_poc_search`、`system_poc_inspect`、`system_poc_run` 和 `system_poc_output`。先用产品名、CVE 或已观察特征搜索，再 inspect 判断适用条件与阻塞原因；只对 `supported` 记录执行一次，随后用 output 等待或读取同一个 interaction。Yak/Yakit 记录可以检索和查看原文，但标记为 `reference_only`，不会发送请求。请求预览会隐藏认证头和 Cookie，完整请求与响应仍由 Agent 私有 HTTP 证据保存。

`system_poc_run` 重新读取索引内容并校验 SHA-256，使用现有 Run/Agent 的 HTTP 资源准入和会话；它不会猜测路径、自动转换模板或重复提交。`system_poc_output` 只从持久化响应证据读取正文（最多 2 MiB），按三值逻辑返回 `matched`、`not_matched` 或 `inconclusive`。模板条件满足不直接等同于漏洞成立；500、403、重定向和认证状态需结合实际业务证据解释。

调用时必须使用 `system_poc_search` 返回的完整 `poc_ref`，不能用文件名或 POC 名称代替；检索词按空格拆分并要求全部匹配。`system_poc_run.target` 填目标的 `http://` 或 `https://` origin，不带 query/fragment；需要 Cookie 会话时传当前 Agent 自己的 `session_id`。如果 run 返回 queued/pending，只调用 `system_poc_output` 等待，不重新 run。compact 工具模式下先 `tool_search(name="system_poc_run")` 暴露 Schema，下一轮直接调用 `system_poc_run`。
