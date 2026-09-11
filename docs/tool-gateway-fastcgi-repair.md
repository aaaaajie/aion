# 工具网关纠错与 FastCGI 结束判定修复

2026-09-06。依据 online-de1d2d46931c 的运行记录实施；09:04:02 UTC 快照确认 a-18 的平台 is_completed=true、correct_flag_count=1。只下载只读快照，未修改运行中的服务、部署或启动新比赛。

## 网关与参数纠错

- 区分外层非法 JSON、字段 schema 错误和禁止嵌套；返回实际 JSON 行列位置或字段错误，不再全部解释为“网关嵌套”。
- 删除无法恢复参数时虚构 localhost 健康请求的兜底。未知意图指向工具目录；已知工具的非法参数指向该工具准确 schema。
- 查询工具时使用 `tool_search(query=...)`；需要执行时使用 `tool_search(name=...)` 取得真实函数 schema，下一轮直接调用该函数。建议中的工具经过当前角色注册表检查，参数经过实际输入模型校验；纠错阶段不执行工具，不自动修补 JSON 或重发请求。
- 网络等工具多包一层 arguments 时，仅在去掉包装后的输入通过实际 schema 时给出可执行调用；原调用仍明确拒绝，没有增加别名或兼容入口。
- 非法 HTTP JSON 没有可恢复参数时，建议查询准确 schema，不再建议对示例地址执行预检。有完整原参数时，预检建议保留该参数。
- 重复参数提醒从仅 probe 扩展到按工具记录相同错误摘要。保留原字段错误，不封禁工具、不新增重试或恢复预算。
- solver_review 不再把每个错误都解释成 summary_zh；只有真的出现该字段才提示改名。信息结论缺 validation 时明确解释验证要求，未验证的实验可以声明 inconclusive。

## FastCGI

本轮多个响应已经保留正文，app_status=0、protocol_status=0，却因没有独立的空 STDOUT 记录而返回 fastcgi_protocol_error。

[PHP 5.6 的 fcgi_flush](https://raw.githubusercontent.com/php/php-src/PHP-5.6/sapi/cgi/fastcgi.c) 在关闭当前输出记录后直接追加 END_REQUEST；不保证额外发送空 STDOUT。[FastCGI 规范 §5.5](https://fast-cgi.github.io/spec#55-fcgi_end_request) 将 END_REQUEST 定义为请求结束。

现在把完整、匹配请求 ID 的 END_REQUEST 作为请求完成边界；不按服务器版本分支，不自动重试。新增 end_request_received、stdout_terminated、stderr_terminated 诊断字段；complete 表示传输层请求结束，不代表应用成功或实验结论有效。非零应用／协议状态仍作为失败返回；超时、缺失 END_REQUEST、输出超限、错误请求 ID／版本、畸形记录仍失败，保留已读输出。

## 定向验证

57 项通过，3.01 秒；涉及 test_probe_correction、test_tooling、test_compact_tools、test_tool_examples、test_fastcgi、test_performance_contracts。包含：纠错建议实际可调用且不提前执行；外层 JSON 错误位置；tool_search 正确入口；多余 arguments 包装；重复网关错误；PHP 式分片响应、有／无正文、非零退出；既有超时和完整性测试。git diff --check 通过。

未运行全量测试、未调用真实模型、未请求比赛目标。线上不会自动获得此次本地修改；本轮不宣称已改善自然任务中的错误率或耗时。
