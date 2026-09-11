# Solver 决策与 Skills 优化实施记录

## 实施内容

本轮修改 Solver、Session Memory、Tool Surface 三处提示词，重写五个现有 Skill，新增网络 Skill 的 FastCGI 参考文档；没有新增独立 Skill、线上 API、状态字段或依赖，没有修改线上工具暴露方式，也没有部署或启动靶场。

通用提示词负责观察／假设／已验证能力／阴性结论的边界、停滞后的前提复查、已有能力后的目标收敛。记忆沿用原有八个标题，保留条件、来源、未满足前提与撤销关系。Skill 负责具体的页面与业务分层、会话隔离、局部源码追踪、认证依赖和客户端复验。SQLi 删除按手工／工具拆假设及必须调用 sqlmap 的要求。

发现描述补充中文现象词，以适配现有中文 Solver。Tool Surface 明确区分工具检索与 Skill 检索：工具搜索没有结果不代表没有合适的 Skill。

## 回放器

`scripts/replay_solver_decisions.py` 复用真实 `SkillCatalog`、`SkillSessionContext`、`StateService`、`ToolRegistry(compact=True)` 和 `ToolExecutor`。每个试验在独立 SQLite 中持久化激活状态；带记忆场景调用相应版本的摘要提示词，采用现有摘要输入构造和归一化，然后从数据库恢复记忆及 Skill 上下文。恢复后的决策不再接收原始轨迹。

固定证据通过 `replay_read_evidence` 返回。未注册 HTTP、Shell、提交或扫描执行工具；不存在的证据引用返回标准错误，不能被解释成目标阴性。评测复用 Skill 的真实工具协议，但不是完整线上 Solver／目标工具环境。

三组分别为：

| 条件 | 提示词及记忆提示词 | Skill 目录 |
|---|---|---|
| baseline | 修改前 | 修改前 |
| prompt | 本轮修订 | 修改前 |
| skills | 本轮修订 | 本轮修订 |

保留原十个场景（撤销场景将虚构的已激活 Skill 标识替换为实际 ID），新增六类场景及六个留出变体，另加一个空目录场景验证无匹配时的行为，共 23 场景 × 3 条件 × 3 次 = 207 次。每次最多十二轮模型调用，记忆请求也计入；不自动重试、续预算或将截断输出视为完成。

所有组暴露相同工具定义。`--candidate` 的内容在模型调用前复制至输出目录，防止并行工作区编辑改变参考资源。结果保存提示词、目录、用例及工具定义指纹、模型用量、调用轨迹、激活事件、恢复记忆、最终决策和错误。评审标准不进入 Solver 或摘要模型输入。

`summary.json` 区分调用事实和语义判断。调用数量不是决策质量；未评审的“事实升级次数”为 null。显式语义评审经 `--assessments` 导入后生成逐场景验收与差异报告，不使用关键词命中冒充行为评分。

## 版本隔离与检查

工作目录在本轮开始前已有大量修改，实施期间又出现其他任务添加的 Web／源码工具指引。本轮保留这些改动。为了隔离归因，正式候选目录从修改前归档生成，只叠加本轮三处提示词、五个 Skill 和新增参考文档；其他任务后加的段落不进入本轮内容对照。

验证目录：`.aion/verification/solver-optimization-20260906T182328Z/`。

- `baseline.tar.gz`：本轮开始时的提示词、目录及旧回放脚本／用例。
- `candidate-isolated.tar.gz`：第一版受控候选内容。
- `candidate-v2.tar.gz`：根据首轮回放修正的第二版候选内容。
- `candidate-final.tar.gz`：第二版仅叠加事件序号与业务对象 ID 区分规则的最终内容。
- `content-final.patch` / `final-content-check.json`：最终九个内容文件相对基线的独立差异及工作区一致性检查。
- `content.patch` / `content-v2.patch`：两版候选相对修改前内容的独立差异。
- `comparison/`：第一版三组评测及固定候选目录。
- `comparison-v2/`：第二版三组评测及固定候选目录。
- `live/`：旧凭据返回 401 的记录；后续试验自动停止。
- `live-authorized/`：凭据更新后的探索记录；发现入口混淆和并行修改后终止，不纳入正式验收。

定向测试：99 passed，1 deselected（最后完整运行 7.34 秒）。覆盖 Skill 编译、发现、激活与资源读取、网关权限／schema、固定证据错误、持久化记忆恢复、十二轮预算、三组隔离与报告对未评审结果的处理。编译和 `git diff --check` 通过。

排除的是已有 `test_compact_real_runner_discovers_delegation_and_solves_without_worker`：其断言要求 13 个直接工具且不含 solver_delegate，而当前工作区已是 14 个且含该工具。本轮未改变该工具表面，原失败保留在 `pytest.log`。

五个 Skill 经 AION Catalog 编译均完整进入激活视图，长度低于 6,000 字符，引用资源存在。通用 skill-creator 校验器通过四个 Skill；SQLi 保留 AION 已支持的 when_to_use 扩展字段，通用校验器不认识它，以 AION Catalog 和相应测试为准。

## 重现

默认命令只验证用例，不访问模型：

```sh
.venv/bin/python -m scripts.replay_solver_decisions
```

配置有效的本地模型凭据后，使用新的输出目录运行完整对照：

```sh
.venv/bin/python -m scripts.replay_solver_decisions --live \
  --baseline .aion/verification/solver-optimization-20260906T182328Z/baseline.tar.gz \
  --candidate .aion/verification/solver-optimization-20260906T182328Z/candidate-v2 \
  --output .aion/verification/solver-decisions-new
```

填写某次输出的 `review-pending.json` 中实际已评审的条目，保存为单独 JSON 数组后：

```sh
.venv/bin/python -m scripts.replay_solver_decisions \
  --review-output .aion/verification/solver-decisions-new \
  --assessments /absolute/path/to/assessments.json
```

模型密钥仅用于本地配置和认证请求，不进入候选归档、请求正文、报告或用例。离线结果不能替代独立云端完成率、耗时及成本统计。

## 根据真实回放进行的第二轮修正

首个固定候选的页面分层留出样例没有达到 2/3 的决策门槛：即使激活 Web Skill，模型仍可能围绕失败页面重试，或将两个输入无差异扩大成输入无关。撤销记忆场景保留了撤销关系，但仍出现把旧“重复搜索”提案写回下一步的现象。

据此做三项窄修正：Solver 明确相同两输入不能证明所有输入独立，且记录中的下一步仍不清楚时应先检索方法；记忆根据纠正后的前提重算下一步，不把缺少执行工具当成方法空白；Web Skill 明确先用已有 Cookie 检查独立身份／只读业务控制，不要求失败页面先恢复。

回放说明也纠正了一个评测干扰：目标操作不执行，并不使 Skill 的判断方法失去适用性；明确告知不存在目标执行工具，避免在有限轮数内反复清点已知不可用的工具。该说明对三组完全相同，不包含期待答案或 Skill ID。第二版候选保存在 `candidate-v2.tar.gz`，与第一版结果分开记录。

语义评审口径：逐条检查留出场景的最终决策，以及压缩场景的恢复记忆。下一步必须能区分该场景的关键未决前提，单纯复述“要有对照”不算通过。“不确定性升级为事实”按不同的、缺乏支持的当前技术断言计数，同一断言在摘要和结论重复只计一次；未来条件分支中过强的判读另在评审理由中注明，不冒充已发生的事实升级。计数只覆盖明确列出的已评审运行，不外推到未评审输出。


## 实际回放结果与验收差异

使用本地配置的 `deepseek-v4-flash`，完成两轮各 207 次三组对照。以下重点报告第二轮 `comparison-v2/`；最终记忆微调只做 `memory-final/` 的 18 次专项复验，不将不同版本混算。每次固定三重复、最多十二次模型交互，无自动追加预算。接口恢复后另留有九次 `memory-recovery/` 撤销样例记录，最终专项已覆盖该问题，不混入主表。

第二轮记录 207/207：baseline 完成 61、错误 8；prompt 完成 60、错误 9；skills 完成 61、错误 8。25 次错误均为接口传输问题（ReadTimeout 12、ConnectError 7、RemoteProtocolError 6），并非目标失败，也不作为策略阴性。它们保留在原运行；撤销记忆样例的九次恰受此影响，后用独立专项验证。

### 调用与留出决策

十二个需要方法帮助的场景，达到“至少两次搜索并激活预设相关 Skill”的场景数：baseline **8/12**、prompt **6/12**、skills **12/12**。这是实际网关调用，并非将 Skill 全文预塞给模型。查询也可能命中其他适用 Skill；此项按运行前固定的相关 ID 列表严格统计。

逐条人工评审六类留出场景，共 54 次，每组 18 次。下表为选择具有区分能力的下一步次数（每格分母 3）：

| 留出场景 | baseline | prompt | skills |
|---|---:|---:|---:|
| 页面失败但业务状态可能已改变 | 0 | 0 | 2 |
| 启动连接失败后恢复 | 0 | 1 | 2 |
| 局部源码出现后收敛 | 3 | 2 | 2 |
| 扫描污染共享会话 | 3 | 2 | 2 |
| 迁移计划与行为冲突 | 1 | 2 | 3 |
| 更换工具仍沿用同一机制 | 1 | 3 | 3 |

skills 组六类均达到 2/3 的“下一步”门槛；这不等于整段建议无误。例如先复验已知正常读取可以是有效下一步，但后续仍可能将单次重定向直接判为全局失效，或未明确隔离 Cookie 容器。逐条理由在 `comparison-v2/assessments.json`，未经评审的输出保持未知。

### 单独记录事实升级和记忆问题

上述 54 次评审中，“不确定性被写成当前事实”的不同断言次数：baseline **10**、prompt **11**、skills **9**，各自分母为 18 次已评审运行，不能作为全部 207 次的错误率。例子包括把页面状态认作后端执行事实、把无信息批次认作有效阴性，以及把事件序号误当对象 ID。没有用综合得分隐藏这些问题。

在这批留出中，每组有九次压缩记忆：严格保留相关边界的次数分别 **4/9、7/9、7/9**。仍有摘要把某项未校准结果写成有效阴性或把拟议凭据等同于提升身份。下一步正确不能抵销这种记忆错误。

针对事件序号混淆，最终提示词明确：事件序号是证据事件 ID，业务对象 ID 必须分别保留；未返回的对象 ID 写未知，不递增事件序号构造对象。最终专项为撤销记忆、扫描会话两个场景 × 三组 × 三次，共 **18/18 完成、零接口错误**：

- 撤销场景：三组各 3/3 保留“80 撤销 50 及依赖排除撤回”，各 3/3 选择有效控制后的重测。prompt 与 skills 各 3/3 不重复搜索／激活已有 Skill；baseline 未通过该调用门槛。
- 会话场景：新记忆提示词的两组共 6/6 未再将 31/35/36 当成预约 ID；三组各 3/3 选择已知读取／新会话校准。skills 搜索并激活 Web Skill 为 2/3。
- 仍未彻底解决：会话摘要/最终陈述把“无新信息”改写成“无新 ID 返回”，或声称已有读取回执、探针已收到响应。专项事实升级次数为 **4、4、3**（各六次评审）；严格记忆保真均为 **4/6**。该专项只验证此次窄修正，不能证明总体记忆已经可靠。

### 尚未通过的验收项

**本轮内容和受控执行实现完成，但行为验收未全部通过。** 主对照 skills 组在空目录样例仍实际检索 5/2/2 次；路径明确的 expired-session、unread-task、working-chain 仍有多余搜索或加载。已激活复用在最终专项有所改善，但不能外推为空目录或全部明确路径场景已解决。严格记忆保真与零事实升级同样未达到。

已根据首轮轨迹修正停滞触发、工具检索与 Skill 检索区分、页面独立业务控制，并根据第二轮补事件 ID 规则。本轮停止于这些可归因的内容修订，不将剩余问题扩展成运行时架构改造，也不反复重抽样直到凑够通过次数。后续内容试验应优先针对空目录停止条件和摘要中“观察内容不可补写”；需要独立数据验证，不能据当前三重复给出稳定收益承诺。

### 结果文件

- 主对照：[report.md](../../.aion/verification/solver-optimization-20260906T182328Z/comparison-v2/report.md)、[summary.json](../../.aion/verification/solver-optimization-20260906T182328Z/comparison-v2/summary.json)、[assessments.json](../../.aion/verification/solver-optimization-20260906T182328Z/comparison-v2/assessments.json)。
- 最终记忆专项：[report.md](../../.aion/verification/solver-optimization-20260906T182328Z/memory-final/report.md)、[assessments.json](../../.aion/verification/solver-optimization-20260906T182328Z/memory-final/assessments.json)。
- [最终内容差异](../../.aion/verification/solver-optimization-20260906T182328Z/content-final.patch)及[一致性检查](../../.aion/verification/solver-optimization-20260906T182328Z/final-content-check.json)。

各运行的 manifest 记录提示词／记忆／目录／用例／工具指纹；逐运行目录有完整请求、响应、工具回执、激活 ID、用量、耗时、错误和 SQLite 状态。逐组用量及试验耗时总和在 summary.json；并发下耗时总和不等于墙钟时间，不据此推断生产成本改善。所有目标操作仅为固定证据回执，没有请求真实靶场、重启云端任务或部署。
