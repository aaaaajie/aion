# CTF Web 候选字典

这些文件是运行时随 `tools` 一起发布的精选候选，不是无限扫描清单。

- `web-paths-quick.txt`：页面和 Web 路由候选。
- `file-names-quick.txt`：配置、源码、备份、日志和部署文件名。
- `http-params-quick.txt`：参数发现候选。
- `credentials-quick.txt`：有明确认证依据时使用的有限口令候选。
- `linux-lfi.txt`：确认 Linux、文件读取或命令执行后使用的 LFI/运行时路径候选。

`web-paths-quick.txt` 中的历史复盘条目经过通用化筛选，并使用固定种子分散到中部区域。
题目专属最终路径、题号和运行批次不会进入字典。来源、哈希、行数和候选上限见
`manifest.json`。

运行时通过 `system_web_path_probe.packaged_wordlists` 传入文件名选择发布目录中的只读字典，
例如 `{"packaged_wordlists":["web-paths-quick.txt"]}`。不要把
`/opt/aion/current` 或 `tools/wordlists/ctf` 填入 `wordlist_paths`；后者只接受 Agent
workspace 中的自定义文件。

参数探测变量的 `file_path` 支持 `packaged:<name>`，例如
`packaged:linux-lfi.txt`；该形式同样只允许 manifest 中的固定文件名。

自定义 Web 路径或页面派生字典通过 `system_web_path_probe.max_candidates` 控制，默认最多
生成 256 个候选。参数候选最多 128 个，口令候选最多 64 个。字典未命中时需要保留已测试
范围和响应判定，再根据权限、路径基准、会话或执行环境选择下一项检查。
