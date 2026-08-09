import type {
  ExecutionStepCategory,
  ExecutionStepViewModel,
  NormalizedAuditEvidence,
  ProvenanceNode,
} from "../types/dashboard";

const RELATION_LABELS: Readonly<Record<string, string>> = {
  assembled_into: "汇入上下文",
  detected_by: "触发检测",
  evaluated_to: "判定",
  evaluated_under: "依据策略",
  executed_as: "形成执行结果",
  influenced: "影响",
  produced: "产生结果",
  proposed_action: "提出动作",
  recorded_as: "记录",
  received_from: "接收来源",
  released_by: "审批处置",
  requested_approval: "请求审批",
  reviewed_by: "复核",
  targets: "访问目标",
  生成审计: "审计",
  规则判断: "判断",
  风险复核: "复核",
  请求审批: "审批",
  形成结果: "结果",
  约束: "任务约束",
  进入上下文: "进入上下文",
  形成计划: "形成计划",
  请求能力: "请求能力",
  访问目标: "访问目标",
  命中规则: "命中规则",
  参与判定: "参与判定",
  策略评估: "策略评估",
  应用策略: "应用策略",
  运行时执行: "运行时执行",
  释放或拒绝: "审批处置",
  写入审计: "写入审计",
  风险组合: "风险组合",
};

export function getProvenanceRelationLabel(relation: string): string {
  return RELATION_LABELS[relation] ?? "";
}

export function getProvenanceRiskScore(metadata: Record<string, unknown>): string {
  const value = metadata.risk_score;
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

export function resolveProvenanceAuditId(
  node: ProvenanceNode | undefined,
  events: readonly NormalizedAuditEvidence[],
): string | undefined {
  if (!node) return undefined;
  if (node.kind === "audit" || node.kind === "runtime_result") {
    const direct = events.find((event) => event.auditId === node.refId);
    if (direct) return direct.auditId;
  }
  if (node.kind === "action") {
    return events.find(
      (event) => event.actionId === node.refId && event.recordType === "policy_evaluation",
    )?.auditId;
  }
  if (node.kind === "decision") {
    return events.find((event) => event.decisionId === node.refId)?.auditId;
  }
  if (node.kind === "approval") {
    return events.find((event) => event.approval.approvalId === node.refId)?.auditId;
  }
  const metadataEventId = node.metadata.event_id;
  const guardEventId =
    typeof metadataEventId === "string" && metadataEventId ? metadataEventId : node.refId;
  return events.find((event) => event.eventId === guardEventId)?.auditId;
}

export function findProvenanceNodeForEvent(
  nodes: readonly ProvenanceNode[],
  eventId: string,
): ProvenanceNode | undefined {
  return nodes.find((node) => {
    const metadataEventId = node.metadata.event_id;
    return metadataEventId === eventId || node.refId === eventId;
  });
}

export function findProvenanceNodeForAction(
  nodes: readonly ProvenanceNode[],
  actionId: string,
): ProvenanceNode | undefined {
  return nodes.find((node) => node.kind === "action" && node.refId === actionId);
}

const CATEGORY_NODE_KINDS: Readonly<Record<ExecutionStepCategory, readonly string[]>> = {
  context: ["context", "event"],
  memory: ["action", "event"],
  message: ["action", "event"],
  model_input: ["model_intent", "event", "context"],
  model_output: ["model_intent", "event"],
  tool: ["action", "event"],
  tool_result: ["action", "event"],
  unknown: ["event", "context", "model_intent"],
};

export function findProvenanceNodeForExecutionStep(
  nodes: readonly ProvenanceNode[],
  step: ExecutionStepViewModel,
): ProvenanceNode | undefined {
  if (step.actionId) {
    const action = findProvenanceNodeForAction(nodes, step.actionId);
    if (action) return action;
  }

  for (const kind of CATEGORY_NODE_KINDS[step.category]) {
    for (const eventId of step.eventIds) {
      const node = nodes.find((item) => item.kind === kind && item.refId === eventId);
      if (node) return node;
    }
  }

  if (step.decisionId) {
    const decision = nodes.find(
      (node) => node.kind === "decision" && node.refId === step.decisionId,
    );
    if (decision) return decision;
  }

  for (const auditId of [step.primaryAuditId, ...step.auditIds]) {
    if (!auditId) continue;
    const audit = nodes.find((node) => node.kind === "audit" && node.refId === auditId);
    if (audit) return audit;
  }
  return undefined;
}
