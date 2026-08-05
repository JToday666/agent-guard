import type { AuditEventRow, ProvenanceNode } from "../types/dashboard";

const RELATION_LABELS: Readonly<Record<string, string>> = {
  evaluated_to: "判定",
  recorded_as: "记录",
  reviewed_by: "复核",
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

function stripKnownRefPrefix(refId: string): string {
  if (refId.startsWith("event:")) return refId.slice("event:".length);
  if (refId.startsWith("audit:")) return refId.slice("audit:".length);
  return refId;
}

export function getProvenanceRelationLabel(relation: string): string {
  return RELATION_LABELS[relation] ?? "";
}

export function getProvenanceRiskScore(metadata: Record<string, unknown>): string {
  const value = metadata.riskScore ?? metadata.risk_score;
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

export function resolveProvenanceEventId(
  node: ProvenanceNode | undefined,
  events: readonly Pick<AuditEventRow, "id">[],
): string | undefined {
  if (!node) return undefined;
  const eventIds = new Set(events.map((event) => event.id));
  const metadataEventId = node.metadata.event_id ?? node.metadata.eventId;
  if (typeof metadataEventId === "string" && eventIds.has(metadataEventId)) {
    return metadataEventId;
  }
  const normalizedRefId = stripKnownRefPrefix(node.refId);
  if (eventIds.has(node.refId)) return node.refId;
  return eventIds.has(normalizedRefId) ? normalizedRefId : undefined;
}

export function findProvenanceNodeForEvent(
  nodes: readonly ProvenanceNode[],
  eventId: string,
): ProvenanceNode | undefined {
  return nodes.find((node) => {
    const metadataEventId = node.metadata.event_id ?? node.metadata.eventId;
    return (
      metadataEventId === eventId ||
      node.refId === eventId ||
      stripKnownRefPrefix(node.refId) === eventId
    );
  });
}
