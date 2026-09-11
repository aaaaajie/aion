---
name: path-traversal-lfi
description: >-
  Path traversal and Local File Inclusion (LFI) analysis and validation for
  authorized Web targets. Use it when file names or paths may reach file APIs;
  focus on input semantics, minimal proof and result diagnosis.
  通用路径穿越与本地文件包含（LFI）分析和验证。适用于下载、预览、文件名、路径、
  include 或其他文件操作参数可能影响文件系统位置的授权 Web 目标；关注输入到文件
  操作的语义、最小验证和结果诊断，不包含题目专属路径或答案。
---

# Path traversal and LFI

只在目标范围已明确且得到授权时使用。此 skill 负责识别和验证文件路径控制，
不把历史题目的 endpoint、目录、凭据、目标文件或成功 payload 当作当前事实。

## When to use

Use when a download or preview parameter controls a file path, when source or
errors suggest path traversal, directory traversal, LFI, arbitrary file read,
path normalization, an absolute path being accepted, or a filter removing
parent-directory segments. 当观察到下载/预览参数控制文件名或路径、路径拼接、绝对
路径被接受、过滤父目录片段、任意文件读取、文件包含或读取错误差异时使用。
仅凭出现 file、path、web 等宽泛词汇不要激活。 Not for UI path animation,
client-side route navigation, or generic URL routing without a file operation.

## 最小决策流程

1. **定位 sink**：从当前请求、响应、局部源码或错误信息确认用户输入是否进入文件
   打开、读取、下载、模板加载、include/require 或归档处理。对象 ID、显示名称和实际
   文件路径要分开记录。
2. **建立正常对照**：先用当前应用提供的已知有效文件名或资源 ID 请求一次，记录方法、
   会话、响应状态、长度、内容类型和正文完整性。
3. **做最小路径测试**：只改变一个路径语义。优先用当前证据中可确认的安全文件作
   对照，测试相对父目录片段和绝对路径是否被接受。不要直接猜目标位置。
4. **校准解析层**：确认 URL 解码、框架解析、应用替换/规范化、前后缀拼接和操作系统
   解析的顺序。编码变体必须由观察到的解码层或错误差异支持，一次只改变一层。
5. **区分能力**：证明“输入被接受”“可读取文件”“可包含并求值”是三个不同结论；
   文件内容被返回不等于代码执行，代码片段被返回也不等于已经执行。
6. **诊断并停止**：把不存在、权限不足、会话失效、固定后缀、编码错误和输出截断分开
   记录。能力成立后返回其边界和证据，目标位置由当前证据决定；不要继续无边界枚举。

## 通用输入形状

以下只是语义模板，`<known-file>` 必须由当前目标或本地 fixture 提供；它们不是固定目标
路径，也不是要求全部执行的字典：

```text
file=<known-file>
file=../<known-file>
file=..%2f<known-file>
file=..%252f<known-file>
file=/<absolute-known-file>
```

先使用能回答一个问题的最小形状。绝对路径只有在应用会把输入直接交给文件 API，或
当前证据显示前缀会被替换时才有意义；固定目录、固定后缀和 basename 校验可能改变结果。

## 解析与结果规则

- 相对路径校准应从实际基准目录和已知文件出发；多余的父目录可能被操作系统解析到根，
  也可能被应用拒绝，不能仅凭层数推断结果。
- “过滤 `../`”不是完整安全结论。要观察过滤发生在解码前还是解码后，以及是否在最终
  文件 API 调用前做规范化和目录边界检查。
- 读取接口和 include/require 的行为不同。只有当前调用点确实使用包含/求值语义，且
  返回的行为证明发生求值时，才记录为 LFI 执行能力；不要因为文件内容看起来像代码就
  认定已执行。
- 在 PHP 目标上，`php://filter` 是文件流转换能力；用它读取当前证据指向的源码时，
  必须记录 PHP 版本、wrapper 是否可用、返回内容是否完整。它本身不等于 RCE，进一步
  的执行链应转交对应技术 skill。

## 结果报告

报告至少包含：

- 输入来源和 sink 类型；
- 正常对照与最小变化；
- 解析层、会话、身份、进程/服务和文件系统边界；
- 状态码、重定向、响应长度、正文完整性和错误类别；
- 已验证能力、未验证部分、下一项区分性测试和停止条件。

原始响应、凭据和候选内容放在证据中，普通摘要只引用证据。只有目标验证器接受或目标
内容被独立确认，才能报告任务完成。

## 按需读取

当需要更细的路径解析、编码、PHP wrapper 或失败诊断时，读取
`references/detailed-workflow.md` 的对应章节；不要为获取更多 payload 而全文机械读取。
