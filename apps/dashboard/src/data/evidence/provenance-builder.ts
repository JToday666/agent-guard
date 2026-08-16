import type {
  EvidenceStageId,
  NormalizedAuditEvidence,
  ProvenanceEdge,
  ProvenanceGraph,
  ProvenanceNode,
  TraceEvidenceViewModel,
} from "../../types/dashboard";
import {
  getDecisionEvidenceLabel,
  getExecutionStatusLabel,
  getInterventionLabel,
  getResultDispositionLabel,
  getSideEffectLabel,
} from "./trace-evidence.ts";

type EvidenceNodeKind =
  | "task"
  | "source"
  | "context"
  | "model_intent"
  | "action"
  | "resource"
  | "rule"
  | "policy"
  | "decision"
  | "approval"
  | "runtime_result"
  | "audit"
  | "review";

interface NodeInput {
  critical?: boolean;
  kind: EvidenceNodeKind;
  label: string;
  nodeKey?: string;
  phase: EvidenceStageId;
  refId: string;
  status?: string;
  summary?: string | null;
}

interface EdgeInput {
  critical?: boolean;
  relation: string;
  relationType: "causal" | "detection" | "policy" | "approval" | "execution" | "audit";
  source: string;
  target: string;
}

function policySummary(primary: NormalizedAuditEvidence): string {
  const parts = [
    primary.policy.bundleId,
    primary.policy.version,
    primary.policy.revision === null ? null : `r${primary.policy.revision}`,
  ].filter((value): value is string => Boolean(value));
  return parts.length ? parts.join(" / ") : "当时生效的策略未记录";
}

function approvalLabel(primary: NormalizedAuditEvidence): string {
  if (primary.approval.status === "pending") return "等待人工审批";
  if (primary.approval.status === "allowed") return "人工单次放行";
  if (primary.approval.status === "denied") return "人工拒绝";
  if (primary.approval.status === "expired") return "审批已过期";
  return "审批状态未记录";
}

function buildInputs(primary: NormalizedAuditEvidence): {
  edges: EdgeInput[];
  nodes: NodeInput[];
} {
  const nodes: NodeInput[] = [
    {
      critical: true,
      kind: "task",
      label: primary.originalTask ?? "原始任务未记录",
      phase: "input_trust",
      refId: "task",
      summary: "用户授权目标",
    },
    {
      critical: true,
      kind: "source",
      label: primary.source.label ?? primary.source.type ?? "来源未记录",
      phase: "input_trust",
      refId: "source",
      status: primary.source.trustLevel ?? "信任等级未记录",
      summary: primary.source.type,
    },
    {
      critical: true,
      kind: "context",
      label: primary.contextSources.length ? "组装运行时上下文" : "上下文来源未记录",
      phase: "context_intent",
      refId: "context",
      summary: primary.contextSources.join(" · ") || null,
    },
    {
      critical: true,
      kind: "model_intent",
      label: primary.modelIntent ?? "模型意图未记录",
      phase: "context_intent",
      refId: "model-intent",
      summary: "模型计划",
    },
    {
      critical: true,
      kind: "action",
      label: primary.toolName ?? "工具未记录",
      nodeKey: "action",
      phase: "tool_policy",
      refId: primary.actionId ?? "action",
      summary: primary.toolArguments ? "参数已脱敏记录" : "参数未记录",
    },
    {
      critical: true,
      kind: "policy",
      label: policySummary(primary),
      phase: "tool_policy",
      refId: "policy",
      status: primary.policy.digest ? `摘要 ${primary.policy.digest.slice(0, 12)}…` : undefined,
      summary: "当时生效的策略",
    },
    {
      critical: true,
      kind: "decision",
      label: getDecisionEvidenceLabel(primary.decision),
      nodeKey: "decision",
      phase: "tool_policy",
      refId: primary.decisionId ?? "decision",
      status: primary.risk.finalScore === null ? "风险未记录" : `风险 ${primary.risk.finalScore}`,
      summary: primary.decisionReason,
    },
    {
      critical: true,
      kind: "runtime_result",
      label: getInterventionLabel(primary.intervention),
      phase: "outcome_audit",
      refId: "runtime-result",
      status: getExecutionStatusLabel(primary.execution.status),
      summary: `${getResultDispositionLabel(primary.resultDisposition)} · ${getSideEffectLabel(primary.sideEffects)}`,
    },
    {
      critical: true,
      kind: "audit",
      label: primary.entryHash ? "审计记录已进入哈希链" : "审计完整性元数据未记录",
      nodeKey: `audit:${primary.auditId}`,
      phase: "outcome_audit",
      refId: primary.auditId,
      status: primary.chainIndex === null ? undefined : `链位置 ${primary.chainIndex}`,
      summary: primary.auditId,
    },
  ];

  primary.resources.forEach((resource, index) => {
    nodes.push({
      critical: index === 0,
      kind: "resource",
      label: resource.value,
      phase: "tool_policy",
      refId: `resource:${resource.id}`,
      status: resource.sensitivity ?? undefined,
      summary: [resource.type, resource.operation].filter(Boolean).join(" / ") || null,
    });
  });

  primary.ruleHits.forEach((rule, index) => {
    nodes.push({
      critical: index === 0,
      kind: "rule",
      label: rule.name ?? rule.ruleId,
      phase: "tool_policy",
      refId: `rule:${rule.ruleId}`,
      status: rule.severity === "unknown" ? undefined : rule.severity,
      summary: rule.reason,
    });
  });

  if (
    primary.approval.approvalId ||
    (primary.approval.status !== "unknown" && primary.approval.status !== "not_required")
  ) {
    nodes.push({
      critical: true,
      kind: "approval",
      label: approvalLabel(primary),
      nodeKey: `approval:${primary.approval.approvalId ?? "unknown"}`,
      phase: "outcome_audit",
      refId: primary.approval.approvalId ?? "unknown",
      status: primary.approval.status,
      summary: primary.approval.approvalId,
    });
  }

  if (primary.risk.factors.length > 1) {
    nodes.push({
      critical: false,
      kind: "review",
      label: `${primary.risk.factors.length} 个风险因子完成组合`,
      phase: "tool_policy",
      refId: "risk-review",
      status: primary.risk.aggregationMethod ?? undefined,
      summary: primary.risk.finalScore === null ? null : `最终风险 ${primary.risk.finalScore}`,
    });
  }

  const firstResource = primary.resources[0] ? `resource:${primary.resources[0].id}` : "policy";
  const firstRule = primary.ruleHits[0] ? `rule:${primary.ruleHits[0].ruleId}` : "policy";
  const hasApproval = nodes.some((node) => node.kind === "approval");
  const edges: EdgeInput[] = [
    {
      critical: true,
      relation: "约束",
      relationType: "causal",
      source: "task",
      target: "context",
    },
    {
      critical: true,
      relation: "进入上下文",
      relationType: "causal",
      source: "source",
      target: "context",
    },
    {
      critical: true,
      relation: "形成计划",
      relationType: "causal",
      source: "context",
      target: "model-intent",
    },
    {
      critical: true,
      relation: "请求能力",
      relationType: "causal",
      source: "model-intent",
      target: "action",
    },
    {
      critical: true,
      relation: "访问目标",
      relationType: "causal",
      source: "action",
      target: firstResource,
    },
  ];

  primary.resources.slice(1).forEach((resource) => {
    edges.push({
      relation: "访问目标",
      relationType: "causal",
      source: "action",
      target: `resource:${resource.id}`,
    });
  });

  if (primary.ruleHits.length) {
    edges.push({
      critical: true,
      relation: "命中规则",
      relationType: "detection",
      source: firstResource,
      target: firstRule,
    });
    primary.ruleHits.slice(1).forEach((rule) => {
      edges.push({
        relation: "命中规则",
        relationType: "detection",
        source: firstResource,
        target: `rule:${rule.ruleId}`,
      });
    });
    primary.ruleHits.forEach((rule) => {
      edges.push({
        critical: rule.ruleId === primary.ruleHits[0]?.ruleId,
        relation: "参与判定",
        relationType: "policy",
        source: `rule:${rule.ruleId}`,
        target: "decision",
      });
    });
  } else {
    edges.push({
      critical: true,
      relation: "策略评估",
      relationType: "policy",
      source: firstResource,
      target: "policy",
    });
  }

  edges.push({
    critical: true,
    relation: "应用策略",
    relationType: "policy",
    source: "policy",
    target: "decision",
  });

  if (hasApproval) {
    edges.push(
      {
        critical: true,
        relation: "请求审批",
        relationType: "approval",
        source: "decision",
        target: `approval:${primary.approval.approvalId ?? "unknown"}`,
      },
      {
        critical: true,
        relation: "释放或拒绝",
        relationType: "approval",
        source: `approval:${primary.approval.approvalId ?? "unknown"}`,
        target: "runtime-result",
      },
    );
  } else {
    edges.push({
      critical: true,
      relation: "运行时执行",
      relationType: "execution",
      source: "decision",
      target: "runtime-result",
    });
  }

  edges.push({
    critical: true,
    relation: "写入审计",
    relationType: "audit",
    source: "runtime-result",
    target: `audit:${primary.auditId}`,
  });

  if (primary.risk.factors.length > 1) {
    edges.push({
      relation: "风险组合",
      relationType: "detection",
      source: "risk-review",
      target: "decision",
    });
  }

  return { edges, nodes };
}

export function buildProvenanceGraphFromEvidence(
  evidence: TraceEvidenceViewModel,
): ProvenanceGraph {
  const primary = evidence.primary;
  if (!primary) {
    return {
      edges: [],
      nodes: [],
      traceId: evidence.traceId,
      window: {
        edgeLimit: 0,
        edgesHaveMore: null,
        hasMore: null,
        nodeLimit: 0,
        nodesHaveMore: null,
        returnedEdgeCount: 0,
        returnedNodeCount: 0,
      },
    };
  }
  const input = buildInputs(primary);
  const timestamp = primary.occurredAt;
  const nodeId = (refId: string) => `${evidence.traceId}:${refId}`;
  const nodeKey = (node: NodeInput) => node.nodeKey ?? node.refId;
  const nodes: ProvenanceNode[] = input.nodes.map((node) => ({
    kind: node.kind,
    label: node.label,
    metadata: {
      critical: node.critical ?? false,
      event_id: primary.auditId,
      phase: node.phase,
      status: node.status,
      summary: node.summary,
    },
    nodeId: nodeId(nodeKey(node)),
    refId: node.refId,
    timestamp,
    traceId: evidence.traceId,
  }));
  evidence.events
    .filter((event) => event.auditId !== primary.auditId)
    .forEach((event) => {
      const label =
        event.recordType === "policy_evaluation"
          ? "策略判定审计"
          : event.recordType === "runtime_outcome"
            ? "运行时结果审计"
            : event.recordType === "runtime_observation"
              ? "运行时观察审计"
              : "关联审计记录";
      nodes.push({
        kind: "audit",
        label,
        metadata: {
          critical: false,
          event_id: event.auditId,
          phase: event.recordType === "policy_evaluation" ? "tool_policy" : "outcome_audit",
          status: event.recordType,
          summary: event.auditId,
        },
        nodeId: nodeId(`audit:${event.auditId}`),
        refId: event.auditId,
        timestamp: event.occurredAt,
        traceId: evidence.traceId,
      });
    });
  const availableNodeIds = new Set(input.nodes.map(nodeKey));
  const edges: ProvenanceEdge[] = input.edges
    .filter((edge) => availableNodeIds.has(edge.source) && availableNodeIds.has(edge.target))
    .map((edge, index) => ({
      edgeId: `${evidence.traceId}:edge:${index}:${edge.source}:${edge.target}`,
      metadata: {
        critical: edge.critical ?? false,
        relation_type: edge.relationType,
      },
      relation: edge.relation,
      sourceNodeId: nodeId(edge.source),
      targetNodeId: nodeId(edge.target),
      timestamp,
      traceId: evidence.traceId,
    }));
  evidence.events
    .filter((event) => event.auditId !== primary.auditId)
    .forEach((event, index) => {
      const sourceRef = event.recordType === "policy_evaluation" ? "decision" : "runtime-result";
      edges.push({
        edgeId: `${evidence.traceId}:edge:audit:${index}:${event.auditId}`,
        metadata: { critical: true, relation_type: "audit" },
        relation: "写入审计",
        sourceNodeId: nodeId(sourceRef),
        targetNodeId: nodeId(`audit:${event.auditId}`),
        timestamp: event.occurredAt,
        traceId: evidence.traceId,
      });
    });
  return {
    edges,
    nodes,
    traceId: evidence.traceId,
    window: {
      edgeLimit: edges.length,
      edgesHaveMore: null,
      hasMore: null,
      nodeLimit: nodes.length,
      nodesHaveMore: null,
      returnedEdgeCount: edges.length,
      returnedNodeCount: nodes.length,
    },
  };
}
