# AION fscan fork

Vendored from https://github.com/shadow1ng/fscan at commit
`bf036fd9b272a56d493796badcf0a269f0a83ec0` (2026-07-10).

## AION SDK 与 bridge

- 删除顶层 `web/`（Web UI）与 `main_web.go`；其余 Go 源码（`common/`、`core/`、
  `plugins/`、`webscan/`）原样保留，以保证服务识别与 Web 标题链路可编译。
- `pkg/fscan` 提供流式 `ScanEachWithController`，结果不在 bridge 内存中累计。
- `cmd/aion-bridge` 是 AION 唯一运行入口。Python 通过 stdin/stdout NDJSON
  控制协议启动、暂停、恢复和停止扫描，不再拼接 fscan CLI 参数。
- bridge 始终禁用弱口令、POC 与 local-effect 插件。`web_mark=true` 精确启用
  `webtitle`；false 时不派发任何插件，但主机发现、TCP 扫描和 Nmap probes
  服务识别继续工作。
- 产物仅用于构建期；AION 运行期零 Go 依赖。

## 构建

使用 `scripts/build_aion_fscan.sh`，产出：

- `deploy/bin/aion-fscan-darwin-arm64`
- `deploy/bin/aion-fscan-linux-amd64`（比赛上传用，`GOOS=linux GOARCH=amd64`）

需要 Go 1.25+（仅构建期）。

## NDJSON 控制协议

stdin 第一行必须是 `start`，之后只接受 `pause/resume/stop`。stdout 只输出
`ready/progress/result/finished/error`：

```json
{"type":"start","protocol_version":"1","task_id":"network-...","targets":"10.0.0.0/24","ports":"80,443","web_mark":true}
{"type":"ready","protocol_version":"1","scanner_version":"2.2.0","task_id":"network-..."}
{"type":"result","result":{"type":"PORT","target":"10.0.0.1:80","status":"open","details":{"port":80}}}
{"type":"finished","status":"completed","stats":{"tasks_total":1,"tasks_completed":1}}
```

stderr 仅用于诊断，不属于协议。
