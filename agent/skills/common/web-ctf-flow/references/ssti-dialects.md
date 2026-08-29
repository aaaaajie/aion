# 模板渲染快速对照

仅用于明确授权的 CTF、靶场和 benchmark。下面的表达式只是无害算术 canary，
用于判断模板是否求值，不是文件读取、凭据访问或外部网络 Payload。

| 模板家族 | canary | 确认条件 |
| --- | --- | --- |
| Jinja2 / Twig / Nunjucks | `{{7*7}}` | 响应中出现 `49` 而不是原文 |
| Freemarker | `${7*7}` | 响应中出现 `49` |
| ERB / EEx 类 | `<%= 7*7 %>` | 响应中出现 `49` |
| Velocity 类 | `#set($x=7*7)$x` | 响应中出现 `49` |
| Handlebars / Mustache | `{{7*7}}` | 通常保留原文，不视为确认 |

## 排查顺序

1. 将 canary 放入题目明确会被渲染的字段。
2. 使用同一认证 Session 读取对象，并使用创建接口返回的 ID。
3. 原样返回时先检查转义、渲染时机和实际 view 路由。
4. 求值确认后，只按题目声明的 flag carrier 和 proof path 继续。

## Checkpoint 投影

共享 checkpoint 只保留：路由、状态前置、模板家族、结果类别、对象引用和下一步。
不要写入 Cookie、完整响应、Evidence 正文、凭据或候选值。
