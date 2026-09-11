# AION POC 静态兼容性审计器

`tools.poc_audit` 是维护者使用的只读 CLI。它枚举本地 POC 文件，识别 Afrog、Xray、fscan 和 Nuclei 结构，盘点请求、变量、提取器、表达式和未支持字段，并按 `http-basic-v1` 标准给出后续实现候选。它不发送请求、不启动子进程、不执行表达式或脚本，也不下载规则。

## 使用

```bash
python -m tools.poc_audit \
  --source tscan=/path/to/TscanPlus/config/Pocs \
  --source fscan=third_party/fscan/webscan/pocs \
  --output output/poc-audit
```

`--source` 可以重复，值必须是 `NAME=PATH`，路径可以指向文件或目录。YAML/YML 文件才会解析；普通文件会保留跳过记录。扫描不跟随符号链接，输入根目录本身也不能是符号链接。输出目录必须尚不存在，并且必须位于全部输入目录之外。

默认限制是单文件 2 MiB、嵌套深度 64、节点数 100,000，可用 `--max-file-bytes`、`--max-depth` 和 `--max-nodes` 调整。损坏、未知或不兼容的 POC 仍然完成审计并以退出码 0 返回；输入、遍历或输出失败使用退出码 2，并在 JSON 错误中标记 `complete: false`。

## 输出

- `summary.json`：审计版本、输入快照、计数、全体 YAML 文档和有效文档两个覆盖率分母、重复内容/重复 ID 冲突、耗时、峰值内存及零执行计数器。
- `records.jsonl`：文件和文档级记录。每条文档记录保留格式、标识元数据、字段位置、请求/变量/表达式盘点及阻塞原因。
- `report.md`：面向维护者的格式分布、主要阻塞原因示例和下一阶段能力优先级。

分类含义如下：

- `candidate_basic_http`：单个 GET/POST 的静态 HTTP 请求和有限字面量判断，达到静态候选标准；不代表当前可执行或漏洞成立。
- `requires_semantic_support`：已识别格式，但包含动态变量、提取器、多请求、脚本、payload、OOB、复杂表达式等后续能力。
- `unknown_format`：YAML 有效，但没有匹配首轮格式签名。
- `invalid_document`：YAML 语法、重复键、非字符串键、别名循环、自定义标签、大小/深度/节点限制等使文档不能安全盘点。

表达式只做词法盘点，报告函数、字段、操作符、规则调用和未知片段；变量依赖会区分未解析引用与疑似循环。目录名仅作为来源标签，不决定格式。文件名也不推测规则身份，模板中的 `verified` 不会被当作实测结论。

## 解释结果

覆盖率不能把格式或功能重叠简单相加。重复文件仍保留逐文件记录，`summary.json` 另给原始 SHA-256 去重组数；同一 ID 对应不同哈希时记录冲突。fscan 中现有 Afrog/Xray/Nuclei 适配代码的转换结果也不等于语义完整兼容，审计报告会把补充状态码、连续 `r0/r1` 遍历和缺失字段等限制单独列入阻塞原因。

本轮工具只提供维护者 CLI，不加入 Agent 工具入口，也不改变现有知识库索引和任务调度流程。审计完成后，再依据阻塞频率决定请求执行器、提取器、变量依赖和各方言表达式的实现顺序。
