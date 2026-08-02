# 证据链与溯源 API 协作契约

> 状态：协作提案，尚未冻结  
> 更新日期：2026-08-03  
> 参与方：Dashboard、Guard API / Control Plane、AgentGuard Core、LangGraph Adapter、OpenClaw Plugin

## 1. 文档定位

本文用于前后端评审和协商攻击证据展示器所需的 API 增量，定义建议的请求、响应、字段语义、示例、兼容策略、写入归属和验收方式。

当前稳定契约仍是 [接口契约与事件模型](../02_core/interface_contract.md)。本文中的目标字段在评审通过前均不代表已经实现；冻结后必须先同步稳定接口契约，再同步 `schemas/`、类型、实现和 contract tests。

本文只覆盖证据链与溯源展示，不扩展登录、长期 token、策略回放或新的 Dashboard 管理能力。

## 2. 已确认的架构结论

1. 不新增 Dashboard 专用证据聚合端点。
2. 不新增独立 execution receipt 端点。
3. `AuditEvent` 是策略评估、运行时结果和观察事件的持久化证据载体。
4. `GET /v1/traces/{trace_id}` 是同一 trace 的证据查询视图。
5. `GET /v1/traces/{trace_id}/provenance` 保持现有顶层结构，不返回前端坐标。
6. 策略评估审计由 Guard API 唯一写入；Adapter 只回写运行时结果或纯观察事件。
7. API 和 Mock 使用同一证据字段和状态语义。
8. 字段缺失保持未知，不得推断为允许、未执行、零副作用或低风险。
9. 工具结果隔离不表示撤销工具已经产生的外部副作用。
10. 审计完整性只使用现有顶层 `AuditEvent.integrity`，不得在 `evidence`、`metadata` 或根节点再定义 `chain_index`、`entry_hash`、`previous_hash` 等平行字段。

## 3. 当前实现与目标差异

| 能力          | 当前实现                                                                  | 目标                                                       |
| ------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------- |
| GuardEvent    | `schema_version="0.3"`                                                    | 保持不变                                                   |
| GuardDecision | 最终风险分、规则命中和原因                                                | 可选增加结构化 `risk_breakdown`                            |
| AuditEvent    | `schema_version="0.3"`，顶层兼容字段为主                                  | 增加明确的 `record_type`、结构化 `evidence` 和稳定 `links` |
| 策略审计      | Guard API 已写入；LangGraph Guard API 模式仍可能重复提交                  | Guard API 唯一写入一条逻辑策略审计                         |
| 运行时回执    | LangGraph 有本地结果对象，OpenClaw 有 Hook 观察，但未形成统一审计结构     | Adapter 通过现有审计写入接口回写                           |
| 幂等          | PostgreSQL 同 ID 直接忽略，未比较内容；内存存储行为不同                   | 两种存储具有相同的同内容重试和异内容冲突语义               |
| 完整性元数据  | 已由服务端写入 `integrity.sequence/prev_hash/event_hash/canonicalization` | 直接复用，不新增第二套字段                                 |
| Trace 窗口    | 最多返回 1000 条，无明确截断事实                                          | 增加向后兼容的窗口元数据                                   |
| 指标          | 所有审计记录可能进入 allow/ask/deny 聚合                                  | 只统计逻辑唯一的策略评估                                   |
| Provenance    | event、decision、audit、review 等基础节点                                 | 扩展完整生命周期节点与关系                                 |

## 4. 待共同确认的决策

| 编号 | 决策                       | 推荐方案                                                      | 备选方案                                    | 状态   |
| ---- | -------------------------- | ------------------------------------------------------------- | ------------------------------------------- | ------ |
| D-01 | AuditEvent 版本            | GuardEvent 保持 `0.3`，目标 AuditEvent 升级为 `0.4`           | AuditEvent 保持 `0.3`，仅增加 optional 字段 | 待确认 |
| D-02 | 非策略记录的旧顶层策略字段 | `0.4` 中允许 `decision/risk_score/severity/blocked` 为 `null` | 保留中性兼容投影，并要求新消费者忽略        | 待确认 |
| D-03 | Trace 窗口字段             | 新增 `audit_window`                                           | 新增平铺的 `returned_count/has_more`        | 待确认 |
| D-04 | Evaluate 请求级幂等        | 以 `GuardEvent.event_id` 和规范化请求摘要实现                 | 只保证 AuditEvent 写入幂等                  | 待确认 |
| D-05 | Evidence 大小边界          | 单事件 evidence 最大 64 KiB，字符串和数组分别限长             | 使用部署级配置覆盖默认值                    | 待确认 |

本文后续示例采用推荐方案：GuardEvent `0.3`、AuditEvent `0.4`，纯观察事件的策略字段为 `null`。若评审选择备选方案，必须同步修改本文示例和字段矩阵后再冻结。

## 5. 复用接口矩阵

| 接口                                       | 调用方           | 鉴权                                  | 当前响应是否保持兼容 | 目标修改                                               |
| ------------------------------------------ | ---------------- | ------------------------------------- | -------------------- | ------------------------------------------------------ |
| `POST /v1/guard/evaluate`                  | Adapter / Plugin | adapter token，`event:evaluate`       | 是                   | GuardDecision 增加可选风险分解；内部写入增强的策略审计 |
| `POST /v1/audit/events`                    | Adapter / Plugin | adapter token，`event:audit:write`    | 是                   | 接收运行时结果和观察事件；实现统一幂等与冲突           |
| `GET /v1/audit/events`                     | Dashboard / CLI  | browser session 或 `audit:read`       | 是，继续返回数组     | 返回存储的新增 AuditEvent 字段                         |
| `GET /v1/traces/{trace_id}`                | Dashboard / CLI  | browser session 或 `trace:read`       | 是，新增字段可忽略   | 返回增强 AuditEvent 和 `audit_window`                  |
| `GET /v1/traces/{trace_id}/provenance`     | Dashboard / CLI  | browser session 或 `trace:read`       | 是，顶层结构不变     | 扩展节点、关系和 metadata                              |
| `GET /v1/audit/integrity`                  | Dashboard / CLI  | browser session 或 `audit:read`       | 是                   | 无必需改动                                             |
| `GET /v1/metrics/eval`                     | Dashboard / CLI  | browser session 或 `metrics:read`     | 是                   | 只聚合逻辑唯一的策略评估                               |
| `GET /v1/metrics/runtime`                  | Dashboard / CLI  | browser session 或 `metrics:read`     | 是                   | 决策统计排除运行时结果和观察记录                       |
| `GET /v1/approvals/pending`                | Dashboard / CLI  | browser session 或审批读取 scope      | 是                   | 无字段要求变更                                         |
| `GET /v1/approvals/{approval_id}/wait`     | Adapter / Plugin | adapter token，`approval:wait`        | 是                   | 无字段要求变更                                         |
| `POST /v1/approvals/{approval_id}/resolve` | Dashboard        | browser session、CSRF、approval nonce | 是                   | 无字段要求变更                                         |

## 6. 通用 HTTP 规范

### 6.1 编码和时间

- 请求和响应使用 UTF-8 JSON。
- 时间使用带时区的 RFC 3339 字符串，服务端持久化时统一到 UTC。
- 所有 ID 都是不可解释的字符串；消费者不得通过拆分 ID 推断业务含义。
- 枚举使用小写 snake_case。
- `null` 表示已定义字段当前没有事实；字段缺失表示旧版本或生产者没有提供。

### 6.2 错误响应

沿用现有错误 envelope：

```json
{
  "error": {
    "code": "EVIDENCE_VALIDATION_ERROR",
    "message": "Audit evidence validation failed.",
    "details": [
      {
        "loc": ["body", "evidence", "execution", "status"],
        "msg": "Input should be one of: not_invoked, executed, failed, unknown",
        "type": "enum"
      }
    ]
  }
}
```

建议新增或固定以下错误码：

| HTTP | `error.code`                | 含义                                     |
| ---- | --------------------------- | ---------------------------------------- |
| 400  | `UNSUPPORTED_AUDIT_SCHEMA`  | 不支持请求中的 AuditEvent 版本           |
| 409  | `AUDIT_ID_CONFLICT`         | 相同 `audit_id` 已对应不同规范化内容     |
| 413  | `EVIDENCE_TOO_LARGE`        | 脱敏后 evidence 仍超过服务端限制         |
| 422  | `EVIDENCE_VALIDATION_ERROR` | record type 与 evidence 字段不匹配       |
| 422  | `OUTPUT_ONLY_FIELD`         | Adapter 尝试写入服务端生成的 `integrity` |

鉴权失败继续沿用现有 `401/403` 语义，不在错误详情中回显 token、Cookie 或完整请求体。

### 6.3 未知值原则

- 不提供 execution receipt 时使用 `execution.status="unknown"` 和 `receipt_recorded=false`。
- 未测量副作用时使用 `measurement_status="not_measured"`、`count=null`。
- 不适用副作用时使用 `measurement_status="not_applicable"`、`count=null`。
- 未知策略决定使用 `null`，不得使用 `allow` 占位。
- 未知风险分使用 `null`，不得使用 `0` 占位。
- 未知布尔事实使用 `null`，不得使用 `false` 占位。

## 7. 版本与发布顺序

### 7.1 推荐版本策略

- `GuardEvent.schema_version` 继续固定为 `"0.3"`。
- `GuardDecision` 以 optional 字段方式增加 `risk_breakdown`，不删除现有字段。
- 新写入的目标 `AuditEvent.schema_version` 使用 `"0.4"`。
- Guard API 在过渡期读取 `"0.3"` 和 `"0.4"`；查询接口按存储版本原样返回。
- `schemas/audit_event.schema.json` 在契约冻结后扩展为 `0.3 | 0.4` 的版本分支。
- `0.3` 历史事件不得在读取时伪造 `0.4` evidence。

### 7.2 推荐发布顺序

1. Dashboard、CLI 和内部 reader 先支持 `0.3 | 0.4`。
2. Guard API 模型和存储支持读取、校验和返回 `0.4`。
3. Guard API 开始写入 `policy_evaluation` 0.4。
4. LangGraph Adapter 和 OpenClaw Plugin 开始写入 runtime 0.4。
5. 指标切换为 record type 感知和逻辑去重。
6. provenance writer 扩展节点和关系。
7. 完成真实 API 端到端测试后冻结迁移窗口。

### 7.3 存储迁移

当前 AuditEvent 和 provenance payload 使用 JSONB，目标字段不要求新增表或列。P0 不新增数据库迁移。

如果生产数据量使 `record_type` 查询成为瓶颈，可在测量后增加表达式索引；不得仅为本轮展示提前增加没有数据依据的索引。

## 8. AuditEvent 0.4 目标结构

### 8.1 顶层字段

| 字段               | 类型                           | 生产者               | 说明                                       |
| ------------------ | ------------------------------ | -------------------- | ------------------------------------------ |
| `audit_id`         | string                         | Guard API 或 Adapter | 稳定写入 ID                                |
| `schema_version`   | `"0.4"`                        | 生产者               | 目标 AuditEvent 版本                       |
| `record_type`      | enum                           | 生产者               | 策略评估、运行时结果、运行时观察或配置审计 |
| `trace_id`         | string                         | 生产者               | 证据链 ID                                  |
| `case_id`          | string \| null                 | 生产者               | AttackBench case，可空                     |
| `runtime`          | string                         | 生产者               | `langgraph`、`openclaw` 或已注册 runtime   |
| `timestamp`        | RFC 3339 string                | 生产者               | 该记录事实发生时间                         |
| `stage`            | string                         | 生产者               | 生命周期阶段                               |
| `event_type`       | string                         | 生产者               | GuardEvent 或运行时事件类型                |
| `attack_type`      | string \| null                 | 生产者               | 样本标签，不由 Dashboard 推断              |
| `is_malicious`     | boolean \| null                | 生产者               | 样本真值，可空                             |
| `summary`          | string                         | 生产者               | 有界、脱敏摘要                             |
| `decision`         | `allow \| ask \| deny \| null` | 生产者               | 顶层兼容摘要；非策略记录可空               |
| `risk_score`       | integer 0–100 \| null          | 生产者               | 顶层兼容摘要；非策略记录可空               |
| `severity`         | string \| null                 | 生产者               | 顶层兼容摘要；非策略记录可空               |
| `blocked`          | boolean \| null                | 生产者               | 旧策略介入字段，不是执行回执               |
| `resource_targets` | string[]                       | 生产者               | 脱敏后的兼容目标摘要                       |
| `rule_hits`        | string[]                       | 生产者               | 兼容的规则 ID 列表                         |
| `reason`           | string                         | 生产者               | 策略或运行时记录原因                       |
| `links`            | object                         | 生产者               | 稳定关联 ID                                |
| `latency_ms`       | integer \| null                | 生产者               | 当前记录对应阶段的延迟                     |
| `metadata`         | object                         | 生产者               | 非核心扩展，禁止存放秘密                   |
| `evidence`         | object                         | 生产者               | 结构化、脱敏、有界证据                     |
| `integrity`        | object                         | Guard API            | 输出专用的哈希链位置                       |

`blocked` 继续存在只为旧客户端兼容。它当前可能对应 `deny` 或 `ask`，不得解释为工具实际未执行。实际执行事实只读取 `evidence.execution`。

### 8.2 Record type

```text
policy_evaluation
runtime_outcome
runtime_observation
config_audit
```

| `record_type`         | 写入方           | 含义                                 |
| --------------------- | ---------------- | ------------------------------------ |
| `policy_evaluation`   | Guard API        | Core 对 GuardEvent 的一次策略判断    |
| `runtime_outcome`     | Adapter / Plugin | 策略处理后观察到的实际执行和结果处置 |
| `runtime_observation` | Adapter / Plugin | 不改变执行路径的生命周期观察         |
| `config_audit`        | Guard API        | 配置审计评估和 findings 摘要         |

### 8.3 字段要求矩阵

| 字段                                   | policy evaluation | runtime outcome            | runtime observation | config audit                 |
| -------------------------------------- | ----------------- | -------------------------- | ------------------- | ---------------------------- |
| `record_type`                          | 必填              | 必填                       | 必填                | 必填                         |
| `decision/risk_score/severity/blocked` | 必填              | 有关联策略时复制，否则为空 | 空                  | 必填                         |
| `links.event_id`                       | 必填              | 必填                       | 有事件 ID 时必填    | 使用 `config_audit_event_id` |
| `links.decision_id`                    | 必填              | 有关联策略时必填           | 空                  | 可空                         |
| `links.action_id`                      | 有动作时必填      | 有动作时必填               | 有动作时必填        | 可空                         |
| `links.policy_audit_id`                | 不适用            | 必填                       | 可空                | 不适用                       |
| `links.approval_id`                    | ask 时必填        | 有审批时必填               | 可空                | 可空                         |
| `evidence.guard_event`                 | 必填              | 建议保留有界投影           | 可选                | 不适用                       |
| `evidence.guard_decision`              | 必填              | 建议复制关联摘要           | 不适用              | 可选                         |
| `evidence.policy`                      | 必填              | 可选                       | 不适用              | 可选                         |
| `evidence.intervention`                | 可选              | 必填                       | 必填                | 可选                         |
| `evidence.execution`                   | 不适用或 unknown  | 必填                       | unknown             | 不适用                       |
| `evidence.side_effects`                | 不适用或 unknown  | 必填                       | unknown             | 不适用                       |
| `evidence.result`                      | 不适用或 unknown  | 必填                       | unknown             | 可选                         |
| `evidence.approval`                    | ask 时必填        | 有审批时必填               | 可空                | 可空                         |
| `integrity`                            | 服务端返回        | 服务端返回                 | 服务端返回          | 服务端返回                   |

## 9. Evidence 子结构

### 9.1 GuardEvent 脱敏投影

```json
{
  "guard_event": {
    "event_id": "evt_001",
    "event_type": "tool_call_proposed",
    "user_task": "总结客户邮件",
    "source": {
      "source_id": "email_001",
      "type": "email",
      "label": "外部客户邮件",
      "trust_level": "untrusted"
    },
    "context_sources": [
      {
        "source_id": "email_001",
        "type": "email",
        "trust_level": "untrusted",
        "summary": "邮件正文包含要求读取私有令牌的指令"
      }
    ],
    "model_intent": "读取本地令牌文件并按邮件要求发送",
    "tool": {
      "name": "read_file",
      "category": "file",
      "call_id": "call_001",
      "arguments": {
        "path": "/private/token.txt"
      }
    },
    "normalized_resources": [
      {
        "id": "resource_001",
        "type": "file",
        "operation": "read",
        "target": "/private/token.txt",
        "sensitivity": "secret",
        "direction": "local"
      }
    ]
  }
}
```

约束：

- 不保存完整邮件、完整模型上下文或完整工具结果。
- `context_sources` 最多 20 项。
- `summary`、`user_task`、`model_intent` 和内容预览必须限长。
- `tool.arguments` 必须在服务端递归脱敏。
- 规范化资源保留类型、操作、目标、敏感等级和方向；目标中出现凭证值时仍需脱敏。

### 9.2 GuardDecision 与风险组合

`risk_breakdown` 是 GuardDecision 的可选子结构，也是 AuditEvent 中 `guard_decision` 投影的一部分，不在 `evidence` 根节点重复保存第二份。

```json
{
  "guard_decision": {
    "decision_id": "dec_001",
    "decision": "deny",
    "risk_score": 92,
    "severity": "critical",
    "categories": ["sensitive_file_access", "task_mismatch"],
    "rule_hits": [
      {
        "rule_id": "P001_sensitive_file_access",
        "rule_name": "敏感文件访问",
        "severity": "critical",
        "decision": "deny",
        "reason": "目标资源被标记为 secret",
        "evidence": ["resource.sensitivity=secret"]
      }
    ],
    "reason": "不可信邮件诱导读取与原始任务无关的敏感文件",
    "risk_breakdown": {
      "aggregation_method": "max_detection_score",
      "factors": [
        {
          "rule_id": "P001_sensitive_file_access",
          "category": "sensitive_file_access",
          "label": "敏感文件访问",
          "score": 92,
          "severity": "critical",
          "decision": "deny",
          "reason": "目标资源被标记为 secret"
        },
        {
          "rule_id": "P004_task_mismatch",
          "category": "task_mismatch",
          "label": "任务偏离",
          "score": 82,
          "severity": "high",
          "decision": "deny",
          "reason": "读取私有令牌不属于邮件总结任务"
        }
      ],
      "final_score": 92,
      "final_decision": "deny"
    }
  }
}
```

约束：

- `aggregation_method` 首个稳定值为 `max_detection_score`。
- `final_score` 必须等于 GuardDecision `risk_score`。
- `final_decision` 必须等于 GuardDecision `decision`。
- 因子来自本次实际 detector 结果，不对历史事件补造。
- `rule_hits.evidence` 只能包含可安全展示的布尔、类别、规范化目标或脱敏摘要。

### 9.3 事件时策略

```json
{
  "policy": {
    "bundle_id": "default",
    "version": "p1",
    "revision": 7,
    "canonical_digest": "sha256:8d715...",
    "canonicalization": "json:sorted-keys:v1"
  }
}
```

推荐 digest 计算方式：

1. 读取本次评估实际使用的 `PolicySnapshotRecord`。
2. 对该 record 中的 `PolicyBundle` 做 JSON 序列化。
3. UTF-8、键名排序、无多余空格、保留 Unicode。
4. 计算 SHA-256。
5. 输出 `sha256:<lowercase hex>`。

Guard API 必须用同一次快照读取结果完成 Core 判定和 AuditEvent 写入。不得判定后再次读取“当前策略”补 revision。

若使用启动时默认策略而不是已保存快照：

- `bundle_id` 和 `version` 仍来自实际 PolicyBundle；
- `revision=null`；
- digest 仍计算；
- 可在 metadata 中记录 `policy_source="default"`，不得伪造 revision。

### 9.4 干预类型

```text
pre_execution_deny
tool_result_quarantine
model_output_revision
audit_observation
approval_release
none
unknown
```

```json
{
  "intervention": {
    "type": "pre_execution_deny",
    "reason": "策略拒绝后 Adapter 在工具调用前终止"
  }
}
```

### 9.5 执行回执

```text
not_invoked
executed
failed
unknown
```

```json
{
  "execution": {
    "status": "not_invoked",
    "receipt_recorded": true,
    "invoked_at": null,
    "completed_at": "2026-08-03T02:00:00Z",
    "error": null,
    "tool_result_entered_context": false,
    "persisted": false
  }
}
```

约束：

- `receipt_recorded=true` 表示 Adapter 确实观察并提交了运行时结果。
- `decision=deny` 不能自动产生 `status=not_invoked`。
- `blocked=true` 不能自动产生 `status=not_invoked`。
- `failed` 表示工具曾被调用但执行失败，不能归为“未调用”。
- `tool_result_entered_context` 和 `persisted` 未观察时必须为 `null`。

### 9.6 副作用证据

```text
measured
not_measured
not_applicable
unknown
```

```json
{
  "side_effects": {
    "measurement_status": "measured",
    "count": 0,
    "summary": "运行时快照差异为空"
  }
}
```

约束：

- 只有 `measurement_status=measured` 且 `count=0` 才能显示“副作用为 0”。
- `not_measured`、`not_applicable`、`unknown` 的 `count` 必须为 `null`。
- 隔离工具结果不能把已经发生的外部副作用改写为 0。

### 9.7 结果处置

```text
passed_through
quarantined
modified
discarded
not_applicable
unknown
```

```json
{
  "result": {
    "disposition": "quarantined",
    "summary": "工具结果未进入模型上下文或记忆",
    "sanitized": false
  }
}
```

`sanitized=true` 时 `disposition` 使用 `modified`，不另设一套 `sanitized` disposition。

### 9.8 审批证据

```json
{
  "approval": {
    "approval_id": "app_001",
    "status": "allowed",
    "decision": "allow_once",
    "resolved_at": "2026-08-03T02:00:02Z"
  }
}
```

Evidence 中的稳定状态：

```text
pending
allowed
denied
expired
not_required
unknown
```

审批表本身可以继续使用 `status=resolved` 和 `decision=allow_once|deny`；Guard API 在 evidence 投影中把二者规范化为 `allowed` 或 `denied`。

### 9.9 Links

```json
{
  "links": {
    "event_id": "evt_001",
    "decision_id": "dec_001",
    "action_id": "call_001",
    "approval_id": "app_001",
    "policy_audit_id": "audit_policy_001",
    "parent_audit_id": "audit_parent_001"
  }
}
```

| 字段               | 含义                                          |
| ------------------ | --------------------------------------------- |
| `event_id`         | GuardEvent 或运行时事件 ID                    |
| `decision_id`      | 关联 GuardDecision                            |
| `action_id`        | 工具调用、消息发送、记忆写入或模型输出动作 ID |
| `approval_id`      | 关联审批                                      |
| `policy_audit_id`  | runtime outcome 指向策略评估审计              |
| `parent_audit_id`  | 观察或派生事件的直接父审计                    |
| `critic_review_id` | Action Critic review                          |
| `memory_change_id` | Memory Guard change                           |

`links` 的值保持 string；不得在同一 key 中混用 string 和 array。

### 9.10 审计完整性

完整性元数据由 Guard API 存储层生成，Adapter 不得提交：

```json
{
  "integrity": {
    "sequence": 1842,
    "prev_hash": "46cd...",
    "event_hash": "8f31...",
    "canonicalization": "json:v1"
  }
}
```

唯一字段语义：

| 字段               | 含义                                |
| ------------------ | ----------------------------------- |
| `sequence`         | 全局审计链序号，不是 trace 内序号   |
| `prev_hash`        | 前一条全局审计的哈希；链首为 `null` |
| `event_hash`       | 当前事件哈希                        |
| `canonicalization` | 哈希规范化算法版本                  |

禁止新增或继续生产以下平行字段：

```text
evidence.audit
chain_index
entry_hash
previous_hash
metadata.chain_index
metadata.entry_hash
metadata.previous_hash
```

## 10. 完整策略评估 AuditEvent 示例

该记录由 `POST /v1/guard/evaluate` 内部唯一写入，不由 Adapter 再次提交。

```json
{
  "audit_id": "audit_policy_001",
  "schema_version": "0.4",
  "record_type": "policy_evaluation",
  "trace_id": "trace_001",
  "case_id": "PI-001",
  "runtime": "langgraph",
  "timestamp": "2026-08-03T02:00:00Z",
  "stage": "before_tool_call",
  "event_type": "tool_call_proposed",
  "attack_type": "indirect_prompt_injection",
  "is_malicious": true,
  "summary": "Agent 请求 read_file 读取敏感资源",
  "decision": "deny",
  "risk_score": 92,
  "severity": "critical",
  "blocked": true,
  "resource_targets": ["/private/token.txt"],
  "rule_hits": ["P001_sensitive_file_access", "P004_task_mismatch"],
  "reason": "不可信邮件诱导读取与原始任务无关的敏感文件",
  "links": {
    "event_id": "evt_001",
    "decision_id": "dec_001",
    "action_id": "call_001"
  },
  "latency_ms": 4,
  "metadata": {},
  "evidence": {
    "guard_event": {
      "event_id": "evt_001",
      "event_type": "tool_call_proposed",
      "user_task": "总结客户邮件",
      "source": {
        "source_id": "email_001",
        "type": "email",
        "label": "外部客户邮件",
        "trust_level": "untrusted"
      },
      "context_sources": [
        {
          "source_id": "email_001",
          "type": "email",
          "trust_level": "untrusted",
          "summary": "邮件正文包含要求读取私有令牌的指令"
        }
      ],
      "model_intent": "读取本地令牌文件并按邮件要求发送",
      "tool": {
        "name": "read_file",
        "category": "file",
        "call_id": "call_001",
        "arguments": {
          "path": "/private/token.txt"
        }
      },
      "normalized_resources": [
        {
          "id": "resource_001",
          "type": "file",
          "operation": "read",
          "target": "/private/token.txt",
          "sensitivity": "secret",
          "direction": "local"
        }
      ]
    },
    "guard_decision": {
      "decision_id": "dec_001",
      "decision": "deny",
      "risk_score": 92,
      "severity": "critical",
      "categories": ["sensitive_file_access", "task_mismatch"],
      "rule_hits": [
        {
          "rule_id": "P001_sensitive_file_access",
          "rule_name": "敏感文件访问",
          "severity": "critical",
          "decision": "deny",
          "reason": "目标资源被标记为 secret",
          "evidence": ["resource.sensitivity=secret"]
        }
      ],
      "reason": "不可信邮件诱导读取与原始任务无关的敏感文件",
      "risk_breakdown": {
        "aggregation_method": "max_detection_score",
        "factors": [
          {
            "rule_id": "P001_sensitive_file_access",
            "category": "sensitive_file_access",
            "label": "敏感文件访问",
            "score": 92,
            "severity": "critical",
            "decision": "deny",
            "reason": "目标资源被标记为 secret"
          }
        ],
        "final_score": 92,
        "final_decision": "deny"
      }
    },
    "policy": {
      "bundle_id": "default",
      "version": "p1",
      "revision": 7,
      "canonical_digest": "sha256:8d715...",
      "canonicalization": "json:sorted-keys:v1"
    },
    "intervention": {
      "type": "unknown",
      "reason": "策略已拒绝，尚未收到 Adapter 执行回执"
    },
    "execution": {
      "status": "unknown",
      "receipt_recorded": false,
      "invoked_at": null,
      "completed_at": null,
      "error": null,
      "tool_result_entered_context": null,
      "persisted": null
    },
    "side_effects": {
      "measurement_status": "unknown",
      "count": null,
      "summary": null
    },
    "result": {
      "disposition": "unknown",
      "summary": null,
      "sanitized": null
    },
    "approval": {
      "approval_id": null,
      "status": "not_required",
      "decision": null,
      "resolved_at": null
    }
  },
  "integrity": {
    "sequence": 1842,
    "prev_hash": "46cd...",
    "event_hash": "8f31...",
    "canonicalization": "json:v1"
  }
}
```

注意：策略评估记录中的 `decision=deny` 仍不能证明工具未调用。只有后续 runtime outcome 可以把干预确认成 `pre_execution_deny`。

## 11. `POST /v1/guard/evaluate`

### 11.1 请求

请求继续使用稳定 GuardEvent 0.3：

```http
POST /v1/guard/evaluate
Authorization: Bearer <adapter-token>
Content-Type: application/json
```

```json
{
  "schema_version": "0.3",
  "event_id": "evt_001",
  "event_type": "tool_call_proposed",
  "runtime": "langgraph",
  "trace_id": "trace_001",
  "case_id": "PI-001",
  "attack_type": "indirect_prompt_injection",
  "is_malicious": true,
  "timestamp": "2026-08-03T02:00:00Z",
  "pre_execution": true,
  "security_context": {
    "user_task": "总结客户邮件",
    "source_type": "email",
    "source_trust": "untrusted",
    "channel": "email",
    "sender_id": "external@example.invalid",
    "session_id": "session_001",
    "run_id": "run_001",
    "agent_id": "main",
    "current_step": "before_tool_call",
    "model_intent": "读取本地令牌文件",
    "context_sources": [],
    "derived_paths": ["/private/token.txt"],
    "metadata": {}
  },
  "payload": {
    "tool": {
      "name": "read_file",
      "category": "file",
      "kind": "file_read",
      "input_kind": null,
      "call_id": "call_001"
    },
    "arguments": {
      "path": "/private/token.txt"
    },
    "derived_resources": [
      {
        "resource_type": "file",
        "operation": "read",
        "target": "/private/token.txt",
        "data_classification": "secret",
        "direction": "local"
      }
    ]
  },
  "metadata": {}
}
```

### 11.2 响应

```json
{
  "decision": {
    "decision_id": "dec_001",
    "decision": "deny",
    "risk_score": 92,
    "severity": "critical",
    "categories": ["sensitive_file_access", "task_mismatch"],
    "rule_hits": [
      {
        "rule_id": "P001_sensitive_file_access",
        "rule_name": "敏感文件访问",
        "severity": "critical",
        "evidence": ["resource.sensitivity=secret"]
      }
    ],
    "reason": "不可信邮件诱导读取与原始任务无关的敏感文件",
    "safe_message": "该动作未获策略授权。",
    "approval_intent": null,
    "latency_ms": 4,
    "risk_breakdown": {
      "aggregation_method": "max_detection_score",
      "factors": [
        {
          "rule_id": "P001_sensitive_file_access",
          "category": "sensitive_file_access",
          "label": "敏感文件访问",
          "score": 92,
          "severity": "critical",
          "decision": "deny",
          "reason": "目标资源被标记为 secret"
        }
      ],
      "final_score": 92,
      "final_decision": "deny"
    }
  },
  "approval": null
}
```

### 11.3 服务端事务边界

```text
读取同一 PolicySnapshotRecord
→ 使用其中的 PolicyBundle 调用 Core
→ 创建审批（如需要）
→ 写入唯一 policy_evaluation AuditEvent
→ 写入基础 provenance
→ 返回 GuardEvaluationResponse
```

如果 AuditEvent 写入失败，接口不得返回一个看似成功但无法追溯的策略结果。事务边界和失败策略需在实现评审时明确。

## 12. `POST /v1/audit/events`

### 12.1 用途

仅用于：

- `runtime_outcome`
- `runtime_observation`
- 允许的外部 `config_audit` 写入路径
- 兼容期的 AuditEvent 0.3

不得用于重复提交 Guard API 已经写入的 `policy_evaluation`。

### 12.2 执行前拒绝回执示例

```json
{
  "audit_id": "audit_outcome_001",
  "schema_version": "0.4",
  "record_type": "runtime_outcome",
  "trace_id": "trace_001",
  "case_id": "PI-001",
  "runtime": "langgraph",
  "timestamp": "2026-08-03T02:00:00.012Z",
  "stage": "after_guard_decision",
  "event_type": "runtime_outcome",
  "attack_type": "indirect_prompt_injection",
  "is_malicious": true,
  "summary": "Adapter 确认 read_file 未被调用",
  "decision": "deny",
  "risk_score": 92,
  "severity": "critical",
  "blocked": true,
  "resource_targets": ["/private/token.txt"],
  "rule_hits": ["P001_sensitive_file_access", "P004_task_mismatch"],
  "reason": "策略拒绝后在工具调用前终止",
  "links": {
    "event_id": "evt_001",
    "decision_id": "dec_001",
    "action_id": "call_001",
    "policy_audit_id": "audit_policy_001"
  },
  "latency_ms": 1,
  "metadata": {},
  "evidence": {
    "guard_event": {
      "event_id": "evt_001",
      "event_type": "tool_call_proposed",
      "user_task": "总结客户邮件",
      "source": {
        "source_id": "email_001",
        "type": "email",
        "label": "外部客户邮件",
        "trust_level": "untrusted"
      },
      "context_sources": [],
      "model_intent": "读取本地令牌文件",
      "tool": {
        "name": "read_file",
        "category": "file",
        "call_id": "call_001",
        "arguments": {
          "path": "/private/token.txt"
        }
      },
      "normalized_resources": [
        {
          "id": "resource_001",
          "type": "file",
          "operation": "read",
          "target": "/private/token.txt",
          "sensitivity": "secret",
          "direction": "local"
        }
      ]
    },
    "guard_decision": {
      "decision_id": "dec_001",
      "decision": "deny",
      "risk_score": 92,
      "severity": "critical",
      "categories": ["sensitive_file_access", "task_mismatch"],
      "rule_hits": [],
      "reason": "不可信邮件诱导读取与原始任务无关的敏感文件",
      "risk_breakdown": null
    },
    "intervention": {
      "type": "pre_execution_deny",
      "reason": "策略拒绝后 Adapter 在工具调用前终止"
    },
    "execution": {
      "status": "not_invoked",
      "receipt_recorded": true,
      "invoked_at": null,
      "completed_at": "2026-08-03T02:00:00.012Z",
      "error": null,
      "tool_result_entered_context": false,
      "persisted": false
    },
    "side_effects": {
      "measurement_status": "measured",
      "count": 0,
      "summary": "工具未进入运行时调用入口"
    },
    "result": {
      "disposition": "not_applicable",
      "summary": "没有工具结果产生",
      "sanitized": false
    },
    "approval": {
      "approval_id": null,
      "status": "not_required",
      "decision": null,
      "resolved_at": null
    }
  }
}
```

客户端不得提交 `integrity`。Guard API 保存后在读取响应中附加该字段。

### 12.3 成功和幂等响应

首次写入和同内容重试都返回 HTTP 200：

```json
{
  "ok": true,
  "audit_id": "audit_outcome_001",
  "created": true,
  "idempotent_replay": false
}
```

同内容重试：

```json
{
  "ok": true,
  "audit_id": "audit_outcome_001",
  "created": false,
  "idempotent_replay": true
}
```

同 ID 不同内容返回 HTTP 409：

```json
{
  "error": {
    "code": "AUDIT_ID_CONFLICT",
    "message": "The audit_id is already bound to different content.",
    "details": [
      {
        "loc": ["body", "audit_id"],
        "msg": "audit_outcome_001 already exists",
        "type": "conflict"
      }
    ]
  }
}
```

比较内容时：

1. 忽略服务端输出字段 `integrity`。
2. 使用与审计哈希一致的 JSON 规范化方式。
3. 对规范化请求体计算内容摘要。
4. 同摘要视为重试，不写入新链节点，也不重复生成 provenance。
5. 不同摘要返回冲突。

Memory store 和 PostgreSQL store 必须通过同一 contract test。

## 13. 五类干预的运行时映射

| 干预         | policy decision | execution                | side effects              | result disposition          | 必要证据                                                 |
| ------------ | --------------- | ------------------------ | ------------------------- | --------------------------- | -------------------------------------------------------- |
| 执行前拒绝   | `deny`          | `not_invoked`            | 仅实测后允许 `measured/0` | `not_applicable`            | Adapter 未调用工具的回执                                 |
| 工具结果隔离 | 通常 `deny`     | 原工具通常是 `executed`  | 保留实测或未测量状态      | `quarantined`               | 结果未进入上下文或持久化                                 |
| 模型输出修订 | 由输出策略决定  | `unknown` 或关联动作事实 | `not_applicable`          | `modified`                  | 下游收到修订版本的回执                                   |
| 仅审计观察   | `null`          | `unknown`                | `unknown`                 | `unknown`                   | `record_type=runtime_observation` 和 `audit_observation` |
| 审批后放行   | 原策略为 `ask`  | `executed` 或 `failed`   | 实际测量状态              | `passed_through` 或实际处置 | `approval.status=allowed` 和执行回执                     |

### 13.1 工具结果隔离片段

```json
{
  "intervention": {
    "type": "tool_result_quarantine",
    "reason": "工具结果包含不可信持久化指令"
  },
  "execution": {
    "status": "executed",
    "receipt_recorded": true,
    "invoked_at": "2026-08-03T02:01:00Z",
    "completed_at": "2026-08-03T02:01:00.120Z",
    "error": null,
    "tool_result_entered_context": false,
    "persisted": false
  },
  "side_effects": {
    "measurement_status": "not_measured",
    "count": null,
    "summary": "未测量外部工具副作用"
  },
  "result": {
    "disposition": "quarantined",
    "summary": "工具结果未进入模型上下文或记忆",
    "sanitized": false
  }
}
```

### 13.2 模型输出修订片段

```json
{
  "intervention": {
    "type": "model_output_revision",
    "reason": "输出包含未授权凭证内容"
  },
  "execution": {
    "status": "unknown",
    "receipt_recorded": true,
    "invoked_at": null,
    "completed_at": "2026-08-03T02:02:00Z",
    "error": null,
    "tool_result_entered_context": null,
    "persisted": null
  },
  "side_effects": {
    "measurement_status": "not_applicable",
    "count": null,
    "summary": "模型输出修订不涉及工具外部副作用"
  },
  "result": {
    "disposition": "modified",
    "summary": "下游只接收删除敏感值后的输出",
    "sanitized": true
  }
}
```

### 13.3 审批后放行片段

```json
{
  "intervention": {
    "type": "approval_release",
    "reason": "人工仅本次放行"
  },
  "approval": {
    "approval_id": "app_001",
    "status": "allowed",
    "decision": "allow_once",
    "resolved_at": "2026-08-03T02:03:00Z"
  },
  "execution": {
    "status": "executed",
    "receipt_recorded": true,
    "invoked_at": "2026-08-03T02:03:00.010Z",
    "completed_at": "2026-08-03T02:03:00.110Z",
    "error": null,
    "tool_result_entered_context": true,
    "persisted": false
  },
  "side_effects": {
    "measurement_status": "measured",
    "count": 1,
    "summary": "记录到一次外部消息发送"
  },
  "result": {
    "disposition": "passed_through",
    "summary": "审批后工具结果进入后续流程",
    "sanitized": false
  }
}
```

## 14. Runtime observation 示例

```json
{
  "audit_id": "audit_observation_001",
  "schema_version": "0.4",
  "record_type": "runtime_observation",
  "trace_id": "trace_003",
  "case_id": null,
  "runtime": "openclaw",
  "timestamp": "2026-08-03T02:04:00Z",
  "stage": "message_received",
  "event_type": "runtime_observation",
  "attack_type": null,
  "is_malicious": null,
  "summary": "OpenClaw message_received observation",
  "decision": null,
  "risk_score": null,
  "severity": null,
  "blocked": null,
  "resource_targets": [],
  "rule_hits": [],
  "reason": "Observation only.",
  "links": {
    "event_id": "runtime_event_001",
    "action_id": "message_001"
  },
  "latency_ms": null,
  "metadata": {
    "openclaw_hook": "message_received"
  },
  "evidence": {
    "guard_event": {
      "event_id": "runtime_event_001",
      "event_type": "message_received",
      "user_task": "整理收到的消息",
      "source": {
        "source_id": "message_001",
        "type": "message",
        "label": "收到的消息",
        "trust_level": "untrusted"
      },
      "context_sources": [],
      "model_intent": null,
      "tool": null,
      "normalized_resources": []
    },
    "guard_decision": null,
    "policy": null,
    "intervention": {
      "type": "audit_observation",
      "reason": "该 Hook 只记录事实，不改变执行路径"
    },
    "execution": {
      "status": "unknown",
      "receipt_recorded": true,
      "invoked_at": null,
      "completed_at": "2026-08-03T02:04:00Z",
      "error": null,
      "tool_result_entered_context": null,
      "persisted": null
    },
    "side_effects": {
      "measurement_status": "unknown",
      "count": null,
      "summary": null
    },
    "result": {
      "disposition": "unknown",
      "summary": null,
      "sanitized": null
    },
    "approval": {
      "approval_id": null,
      "status": "not_required",
      "decision": null,
      "resolved_at": null
    }
  }
}
```

该事件不得进入 allow/ask/deny 指标。

## 15. Config audit 示例

配置审计继续优先由 `POST /v1/config-audit/evaluate` 产生并由 Guard API 写入 AuditEvent：

```json
{
  "audit_id": "audit_config_001",
  "schema_version": "0.4",
  "record_type": "config_audit",
  "trace_id": "config_trace_001",
  "case_id": null,
  "runtime": "openclaw",
  "timestamp": "2026-08-03T02:05:00Z",
  "stage": "before_install",
  "event_type": "config_audit",
  "attack_type": null,
  "is_malicious": null,
  "summary": "Configuration audit for plugin:example",
  "decision": "deny",
  "risk_score": 80,
  "severity": "high",
  "blocked": true,
  "resource_targets": ["plugin:example"],
  "rule_hits": ["unsigned_plugin"],
  "reason": "插件来源未经验证",
  "links": {
    "config_audit_event_id": "config_evt_001"
  },
  "latency_ms": null,
  "metadata": {
    "target_type": "plugin",
    "target_id": "example",
    "finding_count": 1
  },
  "evidence": {
    "guard_event": null,
    "guard_decision": {
      "decision_id": "config_decision_001",
      "decision": "deny",
      "risk_score": 80,
      "severity": "high",
      "categories": ["unsigned_plugin"],
      "rule_hits": [
        {
          "rule_id": "unsigned_plugin",
          "rule_name": "插件签名校验",
          "severity": "high",
          "decision": "deny",
          "reason": "插件来源未经验证",
          "evidence": ["signature.valid=false"]
        }
      ],
      "reason": "插件来源未经验证",
      "risk_breakdown": null
    },
    "policy": null,
    "intervention": {
      "type": "pre_execution_deny",
      "reason": "安装前配置审计拒绝"
    },
    "execution": {
      "status": "not_invoked",
      "receipt_recorded": true,
      "invoked_at": null,
      "completed_at": "2026-08-03T02:05:00Z",
      "error": null,
      "tool_result_entered_context": null,
      "persisted": false
    },
    "side_effects": {
      "measurement_status": "not_applicable",
      "count": null,
      "summary": "安装动作未发生"
    },
    "result": {
      "disposition": "not_applicable",
      "summary": "没有安装结果",
      "sanitized": false
    },
    "approval": {
      "approval_id": null,
      "status": "not_required",
      "decision": null,
      "resolved_at": null
    }
  }
}
```

配置审计事件同样不进入普通 Agent allow/ask/deny 指标。

## 16. `GET /v1/audit/events`

### 16.1 请求

现有 query 保持：

```http
GET /v1/audit/events?trace_id=trace_001&runtime=langgraph&decision=deny&limit=500
```

本轮不要求增加 `record_type` query。若后续调查页确有过滤需求，再以 optional query 增量评审。

### 16.2 响应

继续返回 AuditEvent 数组，不增加新的列表 envelope：

```json
[
  {
    "audit_id": "audit_policy_001",
    "schema_version": "0.4",
    "record_type": "policy_evaluation",
    "trace_id": "trace_001",
    "runtime": "langgraph",
    "timestamp": "2026-08-03T02:00:00Z",
    "stage": "before_tool_call",
    "event_type": "tool_call_proposed",
    "summary": "Agent 请求 read_file 读取敏感资源",
    "decision": "deny",
    "risk_score": 92,
    "severity": "critical",
    "blocked": true,
    "resource_targets": ["/private/token.txt"],
    "rule_hits": ["P001_sensitive_file_access"],
    "reason": "不可信邮件诱导读取敏感文件",
    "links": {
      "event_id": "evt_001",
      "decision_id": "dec_001"
    },
    "metadata": {},
    "evidence": {},
    "integrity": {
      "sequence": 1842,
      "prev_hash": "46cd...",
      "event_hash": "8f31...",
      "canonicalization": "json:v1"
    }
  }
]
```

`limit` 仍是返回窗口，不表示总数。需要判断 trace 是否完整时使用 trace 详情接口。

## 17. `GET /v1/traces/{trace_id}`

### 17.1 推荐响应

保留现有字段，新增 `audit_window`：

```json
{
  "trace_id": "trace_001",
  "audit_events": [],
  "approvals": [],
  "metrics": {
    "event_count": 1,
    "allow_count": 0,
    "deny_count": 1,
    "ask_count": 0,
    "blocked_count": 1,
    "block_rate": 1.0,
    "fpr": null,
    "fnr": 0.0,
    "average_latency_ms": 4.0
  },
  "audit_window": {
    "limit": 1000,
    "returned_count": 2,
    "has_more": false
  }
}
```

服务端推荐查询 `limit + 1` 条记录计算 `has_more`，再只返回 `limit` 条。无需为了该字段执行昂贵的 trace 总数查询。

Dashboard 展示规则：

- `has_more=false`：当前 trace 查询窗口完整。
- `has_more=true`：明确提示当前只展示部分事件。
- 字段缺失：旧 API，显示“截断状态未记录”，不得以 `false` 处理。

### 17.2 Trace metrics

Trace 响应中的 metrics 与全局指标使用相同逻辑：

- 只聚合逻辑唯一的 `policy_evaluation`；
- `runtime_outcome`、`runtime_observation`、`config_audit` 不增加策略决策数；
- `blocked_count` 保留策略介入口径，不表示实际工具阻断。

## 18. `GET /v1/audit/integrity`

现有响应保持：

```json
{
  "valid": true,
  "event_count": 1843,
  "head_hash": "90d2...",
  "first_broken_audit_id": null
}
```

Dashboard 组合：

- 全局接口的 `valid`；
- 每个返回 AuditEvent 的 `integrity`；
- trace 的 `audit_window.has_more`。

三者分别表示全局链校验、当前事件是否带链位置、当前 trace 查询是否完整，不得合并为一个未经证明的“绝对完整”结论。

## 19. 指标规则

### 19.1 新事件

以下决策指标只统计：

```text
record_type=policy_evaluation
```

并按逻辑键去重：

```text
(links.event_id, links.decision_id)
```

若任一关联 ID 缺失，回退到唯一 `audit_id`。

### 19.2 旧事件

在迁移期，缺失 `record_type` 的 0.3 事件按以下顺序分类：

1. `event_type=config_audit` → `config_audit`
2. `event_type=runtime_observation` → `runtime_observation`
3. 其他当前已知 Guard API / Adapter 策略审计 → `policy_evaluation`

该规则必须通过现有历史 fixture 验证。不能简单把所有缺失 `record_type` 的事件视为策略评估。

### 19.3 `blocked_count`

当前兼容口径：

```text
decision in (deny, ask)
```

它表示策略介入，不表示工具实际未调用。Dashboard 使用“策略介入率”。

本轮不新增“实际阻断率”字段。需要该指标时，应单独设计为：

```text
intervention=pre_execution_deny
AND execution.receipt_recorded=true
AND execution.status=not_invoked
```

## 20. Provenance

### 20.1 响应结构

顶层保持：

```json
{
  "trace_id": "trace_001",
  "nodes": [],
  "edges": []
}
```

### 20.2 节点种类

```text
task
source
context
model_intent
action
resource
rule
policy
decision
approval
runtime_result
audit
review
config_audit
```

### 20.3 稳定 ID 建议

| kind           | 建议 ID                                         |
| -------------- | ----------------------------------------------- |
| task           | `task:{trace_id}`                               |
| source         | `source:{trace_id}:{source_id-or-hash}`         |
| context        | `context:{event_id}`                            |
| model_intent   | `model_intent:{event_id}`                       |
| action         | `action:{action_id}`                            |
| resource       | `resource:{trace_id}:{canonical-resource-hash}` |
| rule           | `rule:{decision_id}:{rule_id}`                  |
| policy         | `policy:{bundle_id}:{revision-or-version}`      |
| decision       | `decision:{decision_id}`                        |
| approval       | `approval:{approval_id}`                        |
| runtime_result | `runtime_result:{audit_id}`                     |
| audit          | `audit:{audit_id}`                              |
| review         | `review:{review_id}`                            |

敏感路径、收件人或内容不得直接拼入 node ID；使用规范化值的摘要。

### 20.4 关系

建议稳定 relation：

```text
received_from
assembled_into
influenced
proposed_action
targets
detected_by
evaluated_under
evaluated_to
requested_approval
released_by
executed_as
produced
recorded_as
reviewed_by
```

边 metadata 增加展示分类：

```text
causal
detection
policy
approval
execution
audit
```

### 20.5 示例

```json
{
  "trace_id": "trace_001",
  "nodes": [
    {
      "node_id": "task:trace_001",
      "trace_id": "trace_001",
      "kind": "task",
      "ref_id": "trace_001",
      "label": "总结客户邮件",
      "timestamp": "2026-08-03T02:00:00Z",
      "metadata": {
        "phase": "input_trust",
        "summary": "原始用户任务",
        "critical": true
      }
    },
    {
      "node_id": "action:call_001",
      "trace_id": "trace_001",
      "kind": "action",
      "ref_id": "call_001",
      "label": "read_file",
      "timestamp": "2026-08-03T02:00:00Z",
      "metadata": {
        "phase": "tool_policy",
        "event_id": "evt_001",
        "summary": "请求读取 /private/token.txt",
        "critical": true
      }
    },
    {
      "node_id": "decision:dec_001",
      "trace_id": "trace_001",
      "kind": "decision",
      "ref_id": "dec_001",
      "label": "deny",
      "timestamp": "2026-08-03T02:00:00Z",
      "metadata": {
        "phase": "tool_policy",
        "risk_score": 92,
        "severity": "critical",
        "critical": true
      }
    },
    {
      "node_id": "runtime_result:audit_outcome_001",
      "trace_id": "trace_001",
      "kind": "runtime_result",
      "ref_id": "audit_outcome_001",
      "label": "not_invoked",
      "timestamp": "2026-08-03T02:00:00.012Z",
      "metadata": {
        "phase": "outcome_audit",
        "audit_id": "audit_outcome_001",
        "summary": "Adapter 确认工具未调用",
        "critical": true
      }
    }
  ],
  "edges": [
    {
      "edge_id": "edge:task:trace_001:action:call_001",
      "trace_id": "trace_001",
      "source_node_id": "task:trace_001",
      "target_node_id": "action:call_001",
      "relation": "proposed_action",
      "timestamp": "2026-08-03T02:00:00Z",
      "metadata": {
        "relation_type": "causal",
        "label": "偏离为"
      }
    },
    {
      "edge_id": "edge:action:call_001:decision:dec_001",
      "trace_id": "trace_001",
      "source_node_id": "action:call_001",
      "target_node_id": "decision:dec_001",
      "relation": "evaluated_to",
      "timestamp": "2026-08-03T02:00:00Z",
      "metadata": {
        "relation_type": "policy",
        "label": "判定"
      }
    },
    {
      "edge_id": "edge:decision:dec_001:runtime_result:audit_outcome_001",
      "trace_id": "trace_001",
      "source_node_id": "decision:dec_001",
      "target_node_id": "runtime_result:audit_outcome_001",
      "relation": "executed_as",
      "timestamp": "2026-08-03T02:00:00.012Z",
      "metadata": {
        "relation_type": "execution",
        "label": "执行结果"
      }
    }
  ]
}
```

Guard API 不返回 `x/y`、宽高、方向、折叠状态或关键路径计算结果。布局和视口控制属于 Dashboard。

## 21. 脱敏与大小边界

### 21.1 服务端必做

敏感 key 至少覆盖：

```text
token
secret
password
authorization
credential
api_key
cookie
private_key
access_key
session
nonce
```

命中敏感 key 的值替换为 `[redacted]`。字符串内容还需清洗：

- provider key；
- `key=value` 或 `key: value` 形式的凭证；
- 环境变量秘密展开；
- Authorization/Bearer 内容；
- Cookie 和私钥正文。

### 21.2 推荐默认限制

| 对象                                  | 默认限制       |
| ------------------------------------- | -------------- |
| `user_task`、`model_intent`、内容预览 | 每项 2000 字符 |
| 普通摘要、reason、规则 evidence 单项  | 每项 500 字符  |
| `context_sources`                     | 20 项          |
| `normalized_resources`                | 50 项          |
| `rule_hits` / risk factors            | 100 项         |
| 普通数组                              | 20 项          |
| 对象嵌套深度                          | 6 层           |
| 单事件 `evidence` 序列化后大小        | 64 KiB         |

最终限制需与现有审批 payload 清洗逻辑合并成同一服务端工具，不允许 Guard API、LangGraph 和 OpenClaw 各维护一套不同规则。

### 21.3 前端边界

Dashboard 继续做防御性遮盖和安全文本渲染，但前端脱敏不能替代服务端最小化。复制、导出和原始证据视图都不得恢复服务端已遮盖的值。

## 22. 写入归属和生命周期

### 22.1 策略评估

```text
Adapter
→ POST /v1/guard/evaluate
→ Guard API 读取事件时策略快照
→ Core 返回 GuardDecision
→ Guard API 写一条 policy_evaluation
→ Guard API 返回 decision / approval
```

Adapter 不再为同一 `event_id + decision_id` 调用 `POST /v1/audit/events` 写第二条策略审计。

### 22.2 运行时结果

```text
Adapter 收到 GuardDecision
→ 阻断 / 等待审批 / 执行 / 隔离 / 修订
→ 形成结构化 runtime receipt
→ POST /v1/audit/events(record_type=runtime_outcome)
```

必须覆盖所有终结路径：

- 策略拒绝且未调用；
- 审批拒绝或超时且未调用；
- 审批放行后执行成功；
- 审批放行后执行失败；
- 自动允许后执行成功；
- 自动允许后执行失败；
- 工具结果隔离；
- 模型输出修订；
- 结果丢弃；
- 无法测量副作用。

### 22.3 纯观察

没有策略评估且不改变执行路径的 Hook：

```text
Adapter / Plugin
→ POST /v1/audit/events(record_type=runtime_observation)
```

该记录不能伪造成新的 allow 决策。

## 23. 实现责任

### 23.1 AgentGuard Core

- 定义 `RiskBreakdown` 和 `RiskFactor`。
- 在 decision merge 时保存实际 detector 结果和 `max_detection_score` 聚合。
- 更新 GuardDecision model、JSON Schema 和单测。
- 不负责 AuditEvent 存储、策略 revision、digest、审批或执行回执。

### 23.2 Guard API / Control Plane

- 读取同一次策略快照完成判定和审计。
- 唯一写入 `policy_evaluation`。
- 生成有界、脱敏 evidence。
- 校验 AuditEvent 版本和 record type。
- 实现跨存储一致的 `audit_id` 幂等和冲突。
- 生成顶层 `integrity`。
- 修正指标和旧事件分类。
- 生成稳定 provenance。
- 为 trace 返回窗口完整性。

### 23.3 LangGraph Adapter

- Guard API 模式不重复写策略审计。
- 把 `ToolExecutionResult` 映射为 runtime outcome。
- 对成功、失败、未调用、审批和隔离路径都提交回执。
- 稳定生成 `audit_id` 和 links。
- 不提交 `integrity`。

### 23.4 OpenClaw Plugin

- 将执行型 Hook 的最终处置映射为 runtime outcome。
- 将只读 Hook 映射为 runtime observation。
- 结构化上报 quarantine、sanitize、revise 和持久化事实。
- 继续使用统一服务端脱敏边界，不上传无界原始 event/context。

### 23.5 Dashboard

- 同时读取历史 0.3 与冻结后的目标版本。
- 只读取顶层 `integrity`，不维护第二套链字段。
- 按 record type 区分策略、执行和观察事实。
- 缺失字段显示未记录。
- 使用 trace `audit_window.has_more` 展示截断。
- 不根据当前策略反推历史策略。
- 不根据 deny 或 blocked 推断运行时结果。

## 24. 验收矩阵

| 场景            | 必须验证                                                            |
| --------------- | ------------------------------------------------------------------- |
| 策略审计唯一性  | 同一逻辑评估只有一条 policy evaluation                              |
| AuditEvent 幂等 | 同 ID 同内容不重复入链；同 ID 不同内容返回 409                      |
| 执行前拒绝      | policy deny 与 runtime not_invoked 分别存在；只有回执后显示确认阻断 |
| 审批后放行      | 原始 ask、approval allowed、实际 execution 三项均存在               |
| 仅审计观察      | 不增加 allow/ask/deny 指标                                          |
| 工具结果隔离    | execution 可为 executed；result quarantined；不声称撤销副作用       |
| 模型输出修订    | result modified；下游接收修订结果                                   |
| 未测量副作用    | `count=null`，页面不显示 0                                          |
| 事件时策略      | bundle/version/revision/digest 与实际判定快照一致                   |
| 风险组合        | factor、final score 和 final decision 一致                          |
| 完整性          | 每条返回事件读取 `integrity`；禁止第二套链字段                      |
| Trace 截断      | 1001 条以上时 `has_more=true`，只返回上限内事件                     |
| 历史兼容        | 0.3 策略、观察和配置事件分类正确                                    |
| 指标            | outcome/observation/config 不重复计入策略决定                       |
| Provenance      | 节点 ID 稳定、边端点存在、无前端坐标、无敏感 ID                     |
| 脱敏            | 敏感 key、凭证值和超长内容不会进入浏览器可读响应                    |
| 跨端联调        | Dashboard 使用真实 Guard API fixture 完成五类干预展示               |

## 25. 契约冻结清单

冻结前需完成：

- [ ] 确认 D-01 至 D-05。
- [ ] 更新 [接口契约与事件模型](../02_core/interface_contract.md)。
- [ ] 更新 `schemas/audit_event.schema.json`。
- [ ] 更新 `schemas/guard_decision.schema.json`。
- [ ] 更新 Core、Guard API、LangGraph、OpenClaw 和 Dashboard 类型。
- [ ] 增加共享 JSON fixtures。
- [ ] Memory 和 PostgreSQL store 运行相同幂等与指标 contract tests。
- [ ] Dashboard API 模式运行真实目标 AuditEvent fixtures。
- [ ] 更新 CLI 输出兼容性测试。
- [ ] 完成前后端联合评审并记录冻结日期。
