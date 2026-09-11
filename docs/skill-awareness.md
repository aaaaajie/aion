# Skill 及时发现

Solver 和执行型 Worker 的真实工具注册表含 SkillTools 时，AgentRunner 默认提供能力目录与只读候选提示。目录涵盖现有 Web 能力包，并加入认证业务逻辑、协议、源码审计、POC 检索及 CyberChef。Chief 和 Review Worker 不会获得额外权限。

目录来自当前 Skill Catalog，只显示挂载、角色可见的 Skill 元数据；关联工具还必须实际注册且授权。它不包含 Skill 正文。全目录继续通过 `skill_search` 查询，`skill_invoke` 激活，`skill_resource_read` 按需读取长正文，工具参数通过 `tool_search` 获取。

## 信号与边界

初始任务、模型公开的观察/假设、工具结果、Worker 报告和观察器新内容进入本地匹配。只读取文本证据值，不读取隐藏推理；空字段名不会触发。单个信号最多检查 24,000 字符。中英文别名匹配，英文使用单词边界；已有 Catalog 描述检索用于候选排序。关键词取自维护的别名表，因此覆盖范围以该表为准，不保证任意措辞的语义召回。

Schema、Skill 检索/激活/参考资料结果及工具结果查询不作为新线索；明确读取 Skill 路径的文件或 Shell 调用也被排除。注入的能力/Skill 块和裸 Skill ID 不用于再次匹配。外部内容只选择发布包中的固定元数据和别名；原始页面指令不被复制到系统提示。否定句也可能出现关键词，因此候选仅代表可能相关。

每次最多三个具体候选。按 Skill ID 与触发别名去重，不按 Web 方向整体去重；后到的不同线索可以替换候选。候选、检测轮次、来源、信号哈希和已提示依据通过现有 `capability_awareness_state` 事件持久化。`capability_awareness_presented` 记录提交模型请求前的目录与候选。激活通过原有 `skill_activated` 事件记录。

每轮请求前重建系统上下文，保持目录和当前候选可见，并立即注入新激活 Skill 的激活视图。压缩和恢复会重新生成目录与激活视图，不依靠摘要保存正文。已激活 Skill 从候选提示中隐藏；正文长度仍服从既有 Skill 预算。每个 Agent 的状态独立。

## 维护与验证

维护 `agent/skills/awareness.py` 中的 ROUTES：使用真实 Skill ID，填写具体中英文现象与机制别名，关联真实工具名。通用 Web Skill 目录由现有能力包补齐；没有专门关联的 Skill 仍可搜索和激活，不猜造工具入口。

```bash
.venv/bin/python -m pytest -q tests/test_skill_awareness.py
.venv/bin/python -m scripts.evaluate_skill_awareness --output output/skill-awareness-NEW
```

模拟使用当前模型、真实 AgentRunner/SkillTools/紧凑工具网关和自建分阶段证据。三个场景、新旧两组、各三次，共 18 次；每次上限 12 轮、120 秒，独立 Run/Agent。唯一对照变量为目录与自动提示开关 `AgentRunner(capability_awareness=...)`；默认开启，无额外部署配置。sqlmap 使用真实参数模型的禁执行模拟回执，不会发送目标请求。

输出 manifest、每次 report、公开模型请求记录、summary 和汇总 Markdown。模型请求记录不保存隐藏推理。统计判断正确、能力可见、Skill 激活、发现/激活延迟、无关激活、重复调用、工具失败、耗时和 token；基础设施失败单列。模型无需 Skill 也可能解出简单样例，因此小模拟不能证明比赛解题速度提升。
