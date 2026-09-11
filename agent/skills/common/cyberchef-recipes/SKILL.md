---
name: cyberchef-recipes
description: >-
  CyberChef 解密、编解码与配方操作。Use for Base64/hex/URL decoding,
  XOR, supplied-key AES/RSA decryption, decompression or hashes with
  system_cyberchef; covers exact arguments, byte preservation and error recovery.
---

# CyberChef 配方使用规范

## 查询、执行、取结果

1. `tool_search` 查找 `system_cyberchef`，读取当前 schema 和示例。
2. 不确定操作名或参数时，调用 `{"action":"operations","query":"AES Decrypt"}`。
   查询直接返回名称和参数，不产生后台任务；空 query 列出支持的操作。
   有 `details_truncated=true` 时缩小查询词，不猜未返回的参数。
3. `action=bake` 输入只选 `input` 或 `input_path` 之一。操作名精确匹配。
   优先使用命名 args；使用默认值时省略 args。不要写 `args:[]` 代替默认参数；
   UI 导出的数组必须与当前版本完整的位置参数匹配。
4. 从单步已知转换开始，确认输出符合预期再串联；已有明确配方可直接执行。
5. bake 返回后台任务。使用返回的 task_id 查询 `system_task_output`；不得为了取结果重复 bake。
   外层任务结束后，还要检查输出 JSON 的 `state`：只有 `completed` 表示配方执行完成。
6. 读取返回的 `output_path` 和 `report_path`。以完整字节、长度、SHA-256 为准。
   `preview_truncated=true` 或 `preview_utf8=null` 不代表结果失败。

## 输入编码与密钥

普通 Base64 字符串解码：

```json
{"input":"aGVsbG8=","recipe":[{"op":"From Base64"}]}
```

`input_encoding` 是把工具传入的字符串还原为字节的传输编码，发生在配方之前。
上例保持默认 utf8，不能同时设置 base64 再重复执行 From Base64。
文件 `input_path` 原样读取，不指定 input_encoding。输出包含非文本字节时使用文件或 base64，不能凭 UTF-8 预览重建。

命名参数示例：

```json
{"input":"abc","recipe":[{"op":"SHA2","args":{"size":"256"}}]}
```

AES/RSA 先确认密钥来源、密钥编码、IV、模式、padding、密文格式；缺少必要参数时先寻找证据。
`{"option":"Hex","string":"..."}` 是密钥等 toggleString 参数的形式。
不要把哈希识别或可读输出描述为成功恢复原文。用已知明文、格式、认证标签或题目验证确认。

## 报错后如何处理

| 错误/状态 | 下一步 |
|---|---|
| unsupported_operation | 按 `tool_search(name="system_cyberchef")` 返回的 schema 选择准确操作；Magic、Bzip2、通用脚本、网络操作未开放。 |
| invalid_arguments | 查询该操作，按参数名修正；位置数组改为命名参数或补全，默认值省略 args。 |
| invalid_input / invalid_encoding | 检查传输编码、Base64 padding、hex 是否成对；不要盲目变换原始字节。 |
| input_limit / output_limit | 输入及每步输出限 4 MiB；选择必要数据。加密/压缩流不可随意截断或分块。 |
| recipe_failed | 根据 step_index 和 operation 检查失败步骤及密钥、模式、格式；保留此前证据。 |
| timed_out / recipe_timeout | 减少配方或缩小有意义的输入；有理由且未达上限时才调整预算，最大 120 秒。 |
| worker_failed / 工具缺失 / 任务启动失败 | 属于运行环境问题，保留错误；不在运行时安装包或反复重试相同请求。 |

相同输入、参数和条件的重试不提供新证据。两次修正仍失败时记录具体阻塞点，换方法或补齐前提。
这些说明按需加载，不要求对无关任务使用 CyberChef。
