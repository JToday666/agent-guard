import type { DecisionStatus, RiskSeverity, TraceSummary } from "../types/dashboard";

export type StatusBadgeTone = "neutral" | "protective" | "success" | "warning" | "danger";

const dashboardDateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export function getDecisionLabel(decision: DecisionStatus): string {
  if (decision === "deny") return "拒绝";
  if (decision === "ask") return "需审批";
  if (decision === "allow") return "允许";
  return "未记录";
}

export function getDecisionTone(decision: DecisionStatus): StatusBadgeTone {
  if (decision === "deny") return "protective";
  if (decision === "ask") return "warning";
  return "neutral";
}

export function getRiskSeverityLabel(severity: RiskSeverity): string {
  if (severity === "critical") return "严重";
  if (severity === "high") return "高";
  if (severity === "medium") return "中";
  if (severity === "low") return "低";
  return "未记录";
}

export function getRiskSeverityTone(severity: RiskSeverity): StatusBadgeTone {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  return "neutral";
}

export function getTraceStatusLabel(status: TraceSummary["status"]): string {
  if (status === "denied") return "拒绝";
  if (status === "paused") return "需审批";
  if (status === "allowed") return "允许";
  return "未记录";
}

export function getTraceStatusTone(status: TraceSummary["status"]): StatusBadgeTone {
  if (status === "denied") return "protective";
  if (status === "paused") return "warning";
  return "neutral";
}

export function formatDashboardDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return dashboardDateTimeFormatter.format(date);
}

export function formatAuditHeadHash(value: string | null): string {
  return value ? `${value.slice(0, 12)}…` : "暂无链头";
}
