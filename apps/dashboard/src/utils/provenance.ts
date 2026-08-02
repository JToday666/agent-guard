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
  const normalizedRefId = stripKnownRefPrefix(node.refId);
  if (eventIds.has(node.refId)) return node.refId;
  return eventIds.has(normalizedRefId) ? normalizedRefId : undefined;
}

export function findProvenanceNodeForEvent(
  nodes: readonly ProvenanceNode[],
  eventId: string,
): ProvenanceNode | undefined {
  return nodes.find(
    (node) => node.refId === eventId || stripKnownRefPrefix(node.refId) === eventId,
  );
}
