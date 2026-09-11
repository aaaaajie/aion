# FastCGI 请求工具

`system_fastcgi_request` 是通用的 FastCGI/1 Responder TCP 客户端。Solver 和执行型 Worker 先用 `tool_search(name="system_fastcgi_request")` 暴露真实 Schema，再直接调用该函数；Chief 和只读复核 Worker 无此权限。

## 用法

先获取参数 schema：

```json
{"name":"system_fastcgi_request"}
```

下一轮直接调用真实函数，例如本地开发环境的健康检查：

```json
{
  "host": "127.0.0.1",
  "port": 9000,
  "params": {
    "REQUEST_METHOD": "GET",
    "SCRIPT_FILENAME": "/srv/app/health.php",
    "SERVER_PROTOCOL": "HTTP/1.1",
    "CONTENT_LENGTH": "0"
  }
}
```

地址和服务端脚本路径由当前环境确定，示例不是自动插入的默认参数。有请求体时通过 `stdin` 和 `stdin_encoding`（`utf-8` 或 `base64`）提供；需要 CONTENT_LENGTH 的应用由调用方提供正确的字节长度。工具不猜测脚本路径，也不插入 PHP 配置。

## 返回与限制

- 分别返回 `stdout`、`stderr`：合法 UTF-8 直接给文本，其他字节只给 Base64，不重复返回两种编码。标准输出保留原始 CGI 头部和正文。
- `bytes_received` 仅统计客户端实际读取的字节；`raw_response` 无损保留这些字节（含记录头、Padding 和半截记录），使用同样的 UTF-8/Base64 编码及 `bytes` 长度字段。不会按记录头声明的长度虚增计数。它与已解析的 `stdout/stderr` 是同一响应的两种视图，不能相加计数；超出输出上限的完整记录内容可能仅保留在原始视图中。
- `transport.status` 区分 `end_request`、`timeout`、`eof`、`reset`、`connection_error` 和 `local_stop`；`phase` 为 `connect/send/receive`，`error_type` 是本地异常类型或 null。`local_stop` 表示客户端因协议/输出限制等主动结束读取，不能解读为远端断开。`end_request` 不保证应用退出码为零。
- `error` 及 `transport` 是本地诊断，不进入任何响应缓冲区。即使零字节超时也有独立传输状态；超时/reset 前的原始字节仍保留。未收齐的记录不进入 `stdout/stderr`，应查看 `raw_response`。标记文本若由服务端真实发送则原样保留，不能按 `<RST-after-data>` 的拼写过滤数据。
- `app_status` 是 FastCGI 应用退出码，`protocol_status` 是 FastCGI 协议状态，都不是 HTTP 状态码。`ok=true` 不代表应用正文中的业务请求成功。
- `complete` 表示已收到完整的终结响应；已发送但响应不完整时 `outcome_unknown=true`，不能推断应用未执行，更不能作为完整负结果。错误会保留已经完整接收的输出记录。
- 失败回执使用统一的 `error.stage/code/message/retry/details` 契约，`retry.allowed=false`；同时保留 `data` 中的输出和完成状态。`fastcgi_timeout`、`fastcgi_incomplete` 等是执行错误，修改参数不能修复工具内部的回执格式错误。
- 默认总请求超时 10 秒，上限 30 秒；参数和输入各最多 1 MiB。输出默认最多 16 KiB，上限 1 MiB，另限制记录封装字节以防无内容记录流。超限主动关闭连接并标记不完整。
- 每次调用一条连接、一个 Responder 请求。请求结束、超时、取消或 Provider 关闭后释放连接；无自动重试、连接复用或多路复用。当前只支持 TCP，不支持 Unix socket。
- 成功结果复用 Runner 的证据保存和大结果读取流程，带 `evidence_refs` 与事件序号；执行结果接入自动复盘和观察器的字段提取。

## 设计与验证

18 历史记录中的 `fcgi.py` 约 2,886 字符，同时包含协议处理和特定应用操作。本工具独立实现通用协议层，不复制题目脚本或历史答案。

项目现有依赖没有 FastCGI 客户端。实现使用 Python 标准库 `asyncio`、`struct`、`base64`，直接支持现有异步取消和 Provider 生命周期，没有引入新运行依赖。评估过 [fcgi-client](https://pypi.org/project/fcgi-client/) 的现成客户端接口与 [simple-fastcgi](https://pypi.org/project/simple-fastcgi/) 的协议/服务端处理接口；本轮保留范围较小、输出边界可直接测试的独立客户端，不引入额外服务器框架。

协议参考 [FastCGI Specification](https://fast-cgi.github.io/original/)。测试以独立本地 TCP 服务端解码真实请求，覆盖长参数、跨记录分片、Padding、碎片化响应、二进制数据、错误终态、超时、取消、关闭、角色权限，以及真实 Runner 的按需发现和证据保存。

测试日志：`.aion/verification/20260906-fastcgi/pytest.log`。没有部署或访问比赛目标。预期节省的是模型重新生成、修补和运行协议脚本的开销；实际 token、墙钟耗时和比赛收益尚未进行配对测量。
