# AgentGuard 技术待办

## 文档用途

本文只保存细粒度、可执行的技术 backlog。开发路径和能力节点以根目录 [`ROADMAP.md`](../ROADMAP.md) 为准；面向使用者的版本变化以 [`CHANGELOG.md`](../CHANGELOG.md) 为准；已验证能力和限制由对应状态页、契约与测试说明。

维护约定：

- 每项应描述可验证的结果，必要时链接 Issue、PR、契约或测试；Issue/PR 不是必填项。
- 本文不声明项目阶段、发布日期、里程碑完成情况、能力优先级或人员分工。
- 完成项在结果进入 `dev` 并通过相应测试与检查后移除；Git 历史保留变更过程。
- 涉及公共契约、安全语义、数据库迁移或发布边界时，必须在对应设计或 ADR 中记录决策，不能只修改本清单。

## 长期结构债务（不进入能力 DAG）

- [ ] 按 Audit、Policy、Identity、Evaluation、Security State、Approval/Lease 拆分 Control Plane store facade，同时保留现有事务边界。
- [ ] 渐进拆分 Core fusion、Adapter context guard、benchmark runner/config/tools 和 Dashboard 巨型组件；文件移动与行为变化分开提交。
- [ ] 将根 `scripts/` 收敛为薄 CLI，核心逻辑回到所属 package；旧命令只在明确兼容期内保留包装。

## CON-01 · 跨语言契约对齐

- [ ] 清点 Pydantic、OpenAPI、JSON Schema 和 TypeScript transport DTO 的权威来源、生成方向及当前差异。
- [ ] 从权威 Pydantic 模型生成或校验 OpenAPI/JSON Schema 与 TypeScript transport DTO，消除手工维护的重复字段定义。
- [ ] 为跨语言序列化、可选字段、枚举、未知字段拒绝和兼容失败增加 golden vectors 与契约测试。
- [ ] 明确区分安全摘要使用的受限 canonical JSON 与审计链使用的 RFC 8785 JCS，并为生产者和消费者增加防混用测试。
- [ ] 为现有调用方制定兼容迁移顺序，确保 Schema、writer、reader 和 Dashboard mapper 在同一契约变更中同步。

## ADP-01 · Adapter 生命周期扩展契约

- [ ] 清点现有 SDK 和 Adapter 的安全执行入口，固定唯一 evaluate、approval/lease、invoke、receipt 模板及其顺序不变量。
- [ ] 定义公开 lifecycle 扩展协议，明确各阶段输入输出、幂等边界、异常传播和 fail-closed 语义。
- [ ] 定义 compatibility 协商、side-effect 报告及 scoring 输入输出契约，避免扩展方依赖 SDK 私有函数。
- [ ] 在契约中划清产品执行职责与 evaluation 扩展职责，并为 PoisonedRAG、memory case、competition profile 和特定 QA 逻辑标出对应扩展面。
- [ ] 为公开扩展点增加契约测试和最小参考实现，覆盖 allow、deny、ask、超时、漂移及 receipt 失败路径。
- [ ] 验证未注册扩展时产品默认行为不变，扩展异常不会绕过执行前控制或改变正式判定来源。

## WS-01 · 产品/评测依赖隔离

- [ ] 建立明确的 uv workspace 成员和依赖组，使产品环境不默认安装完整 evaluation 依赖。
- [ ] 将产品 package 与 evaluation package 声明为边界清晰的 workspace 成员，禁止 evaluation 依赖反向进入产品依赖链。
- [ ] 区分产品、开发、evaluation、浏览器和 live Provider 安装集合，并为每个受支持集合保留锁定安装命令。
- [ ] 决定 Guard API 独立 lock 是否属于正式支持的独立部署模式；为保留的安装模式建立 CI，为不支持的模式移除重复真值。
- [ ] 调整托管 CI，使产品检查使用最小产品依赖，evaluation 检查通过独立、显式的安装路径运行。
- [ ] 检查 workspace 和制品边界，确保 benchmark 数据、测试 fixture、浏览器产物和本地报告不会进入产品包。

## QA-01 · 测试与支持面基线

- [ ] 为现有测试显式补齐 `unit`、`contract`、`integration`、`postgres`、`e2e`、`benchmark`、`live` 分类，逐步移除文件名启发式分类。
- [ ] 确定受支持的 benchmark contract/runtime 最小集合，并为其建立独立、可准确陈述范围的 PR 检查。
- [ ] 记录各测试集合的收集范围、依赖条件和基线数量，禁止用默认 pytest 结果代替全仓 benchmark 覆盖声明。
- [ ] 修复或移除缺失 fixture、仓库外硬编码路径、过期预期和未定义变量对应的 legacy benchmark 测试。
- [ ] 将完整、慢速或依赖浏览器/外部 Provider 的 benchmark 放入 nightly 或显式 opt-in 流程。
- [ ] 测量各 package 的 branch coverage 基线并采用不下降策略；对 auth、approval、lease、enforcement、receipt 和 audit integrity 设置更强覆盖要求。
- [ ] 拆分巨型测试文件，使测试目录按组件和能力镜像源码边界。

## PKG-01 · 统一版本与制品身份

- [ ] 清点 Python packages、Node packages、Dashboard 和 Docker 的版本来源、发布属性与当前映射差异。
- [ ] 建立统一版本来源，并让所有候选制品的 metadata、文件名、镜像标签和运行时自报版本由其确定或接受一致性校验。
- [ ] 扩展版本检查，覆盖 LangGraph Adapter、evaluation package、Dashboard 和其他进入候选集合的制品，而不只覆盖 Core、API、CLI 与 OpenClaw。
- [ ] 为每个候选制品记录完整源码 SHA、内容 digest 和构建身份，禁止不同源码复用同一版本身份。
- [ ] 扩展 artifact manifest 校验，使缺失、额外、重名、摘要变化、源码 revision 不一致或产品包混入 evaluation 内容时明确失败。
- [ ] 记录哪些组件是可发布制品、内部构建物或仅源码工作区，避免版本存在被误解为已经发布。

## 尚未立项的候选设计注记

以下内容不是可认领待办或实现承诺。只有经过独立契约评审并正式立项后，才应转换为带能力 ID 的可执行清单：

- 若考虑在公共模型中增加 `risk_breakdown`，必须先冻结评分解释、字段、聚合不变量、脱敏规则和迁移边界。
- 若考虑把 `context_sources` 升级为结构化公共模型，必须先冻结生产者字段、信任语义、脱敏规则和跨 runtime 映射。
