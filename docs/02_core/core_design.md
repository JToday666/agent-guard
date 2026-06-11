# Agent Security Core 设计

## 1. 文档定位

Core 是 AgentGuard 的唯一安全判断中心。本文定义 Core 的职责、内部模块、检测器、决策流程和验收边界。

关联入口：

- [接口契约与事件模型](interface_contract.md)
- [威胁模型](threat_model.md)
- [实施路线与验收标准](../06_delivery/implementation_plan.md)

## 2. 职责边界

Core 负责：

- schema 校验；
- 风险检测；
- 风险评分；
- 策略决策；
- 审批状态；
- 审计记录；
- 指标统计；
- P1/P2 的 provenance、memory guard、action critic 扩展。

Core 不负责：

- 调用或执行工具；
- 读取运行时私有状态；
- 渲染 Dashboard 页面；
- 管理 Redteam 样本 ground truth。

## 3. 输入与输出

| 输入              | 来源                         | 输出                       |
| ----------------- | ---------------------------- | -------------------------- |
| ToolCallEvent     | LangGraph / OpenClaw Adapter | PolicyDecision、AuditEvent |
| ContextBuildEvent | pre model hook               | PolicyDecision、AuditEvent |
| ModelCallEvent    | model hook                   | AuditEvent 或告警          |
| ToolResultEvent   | tool result hook             | AuditEvent 或告警          |
| MemoryEvent       | memory wrapper               | PolicyDecision、AuditEvent |

## 4. 结构

```text
packages/agentguard-core/
└── agentguard_core/
    ├── events/
    ├── detectors/
    ├── policy/
    ├── isolation/
    ├── action_critic/
    ├── provenance/
    ├── audit/
    ├── metrics/
    └── storage/
```

## 4.1 正式存储

P0 正式 Core 默认使用 PostgreSQL：

```text
postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard
```

该默认值只作为本地 development fallback。用户安装 `agentguard-core` 后不修改源码或 package 内 migration，而是通过环境变量配置自己的数据库：

```bash
export AGENTGUARD_DATABASE_URL=postgresql+psycopg://user:password@host:5432/agent_guard
```

存储层使用 SQLAlchemy 2.x 同步 engine 和 Alembic migration。用户负责准备 PostgreSQL server、database 和账号；Core/Alembic 负责创建 `audit_events` 与 `approvals` 表及基础索引。Core 继续以 JSONB 保存事件和审批 payload，避免 P0 阶段过早拆分规范化表。

初始化命令：

```bash
AGENTGUARD_DATABASE_URL=postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard \
uv run alembic upgrade head
```

`guard-api` 服务启动时会执行配置校验和 Core 初始化。`AGENTGUARD_ENV=production` 时必须显式覆盖 `AGENTGUARD_DATABASE_URL`、`AGENTGUARD_ADAPTER_TOKEN` 和 `AGENTGUARD_CONTROL_TOKEN`，不能依赖默认 development 配置。服务启动后可用 `GET /health?check_db=true` 验证数据库连接。

仓库提供 `.env.example` 作为本地配置模板；Core 不自动加载 `.env`，部署时由 shell、进程管理器或平台注入环境变量。

## 5. 决策流程

```mermaid
flowchart TB
    A["接收事件"]
    B["Schema 校验"]
    C["资源派生"]
    D["风险检测"]
    E["风险评分"]
    F["策略决策"]
    G{"allow / deny / ask"}
    H["审批服务"]
    I["审计记录"]
    J["指标统计"]
    K["返回决策"]

    A --> B --> C --> D --> E --> F --> G
    G --> H
    G --> I
    I --> J
    G --> K
```

## 6. 检测器

| 检测器                       | 阶段  | 作用                                          |
| ---------------------------- | ----- | --------------------------------------------- |
| SensitiveFileDetector        | P0    | 检测 `.env`、token、secret、key、private 路径 |
| ToolHijackDetector           | P0    | 检测工具名、工具类型和用户任务不匹配          |
| TaskMismatchDetector         | P0    | 判断工具动作与 `user_task` 是否偏离           |
| OutboundDLPDetector          | P0-P1 | 检测邮件、消息、API 外发中的敏感数据          |
| PromptInjectionDetector      | P1    | 检测不可信内容中的注入语句                    |
| JailbreakDetector            | P1    | 检测模型越狱输入或输出                        |
| CodeExecDetector             | P1    | 检测危险命令、系统探测、删除和外连            |
| MemoryPoisoningDetector      | P1-P2 | 检测恶意长期记忆写入                          |
| EnvironmentPoisoningDetector | P1-P2 | 检测 README、日志、API 返回污染               |
| NetworkSSRFDetector          | P2    | 检测内网、metadata 和异常外连访问             |

## 7. 策略决策

P0 决策：

| 决策    | 含义   | Adapter 行为         |
| ------- | ------ | -------------------- |
| `allow` | 低风险 | 执行工具             |
| `deny`  | 高风险 | 阻断工具并记录审计   |
| `ask`   | 中风险 | 暂停动作并创建审批项 |

P1/P2 扩展：

| 决策          | 含义               |
| ------------- | ------------------ |
| `modify`      | 改写参数后放行     |
| `audit_only`  | 仅记录，不影响执行 |
| `shadow_deny` | 影子模式模拟阻断   |

## 8. P0/P1/P2 开发边界

| 阶段 | Core 交付                                                                     |
| ---- | ----------------------------------------------------------------------------- |
| P0   | tool-call API、三类决策、敏感文件/工具劫持/任务偏离检测、AuditEvent、基础指标 |
| P1   | 上下文和模型调用审计、消息外发、记忆写入、审批服务、FPR/FNR                   |
| P2   | Memory Guard、Action Critic、Provenance Graph、Tamper-Evident Audit、消融实验 |

## 9. 验收证据

1. 对 `read_file('/private/token.txt')` 返回 `deny`。
2. 对非白名单邮件外发返回 `ask` 或 `deny`。
3. 对正常文档读取返回 `allow`。
4. 每次决策生成 `rule_hits`、`risk_score`、`reason`。
5. 指标接口能汇总 Block Rate、FPR、FNR、Latency。
