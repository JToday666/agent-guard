import type {
  DecisionStatus,
  RiskSeverity,
  TraceSummary,
} from "../types/dashboard.ts";

export type StatusBadgeTone = "neutral" | "success" | "warning" | "danger";

export function getDecisionLabel(decision: DecisionStatus): string {
  if (decision === "deny") return "拒绝";
  if (decision === "ask") return "审批";
  return "放行";
}

export function getDecisionTone(decision: DecisionStatus): StatusBadgeTone {
  if (decision === "deny") return "danger";
  if (decision === "ask") return "warning";
  return "success";
}

export function getRiskSeverityLabel(severity: RiskSeverity): string {
  if (severity === "critical") return "严重";
  if (severity === "high") return "高";
  if (severity === "medium") return "中";
  return "低";
}

export function getRiskSeverityTone(severity: RiskSeverity): StatusBadgeTone {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  return "neutral";
}

export function getTraceStatusLabel(status: TraceSummary["status"]): string {
  if (status === "blocked") return "已阻断";
  if (status === "paused") return "等待审批";
  return "已放行";
}

export function getTraceStatusTone(
  status: TraceSummary["status"],
): StatusBadgeTone {
  if (status === "blocked") return "danger";
  if (status === "paused") return "warning";
  return "success";
}

export function formatDashboardDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}
