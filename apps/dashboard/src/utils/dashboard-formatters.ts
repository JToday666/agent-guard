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
  if (decision === "deny") return "danger";
  if (decision === "ask") return "warning";
  if (decision === "allow") return "success";
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
  if (status === "denied") return "danger";
  if (status === "paused") return "warning";
  if (status === "allowed") return "success";
  return "neutral";
}

const eventTypeLabels: Record<string, string> = {
  adapter_custom_observation: "适配器观察",
  config_audit: "配置检查",
  context_assembled: "上下文已组装",
  memory_write_proposed: "请求写入记忆",
  message_send_proposed: "请求发送消息",
  model_input_prepared: "模型输入已准备",
  model_output: "模型输出",
  model_output_produced: "模型输出已生成",
  model_output_proposed: "模型输出待确认",
  runtime_observation: "运行时观察",
  runtime_outcome: "运行结果",
  tool_call_proposed: "工具调用待确认",
  tool_result_produced: "工具结果已生成",
};

export function getEventTypeLabel(eventType: string): string {
  return eventTypeLabels[eventType] ?? eventType;
}

export function getRuntimeLabel(runtime: string): string {
  if (runtime === "langgraph") return "LangGraph";
  if (runtime === "openclaw") return "OpenClaw";
  if (!runtime || runtime === "unknown") return "未记录";
  return runtime;
}

const stageLabels: Record<string, string> = {
  after_guard_decision: "安全判断后",
  after_tool_call: "工具调用后",
  before_tool_call: "工具调用前",
  model_output_guard: "模型输出检查",
  pre_tool: "工具调用前",
  runtime_observation: "运行时观察",
  tool_call_proposed: "工具调用待确认",
  tool_result_persist: "工具结果保存",
};

export function getStageLabel(stage: string): string {
  return stageLabels[stage] ?? stage;
}

export function getTrustLevelLabel(level: string): string {
  if (level === "trusted") return "可信";
  if (level === "untrusted") return "不可信";
  if (level === "mixed") return "混合来源";
  if (!level || level === "unknown") return "未记录";
  return level;
}

const resourceTypeLabels: Record<string, string> = {
  directory: "目录",
  email: "邮件",
  email_recipient: "邮件收件人",
  file: "文件",
  model_output: "模型输出",
  shell_command: "Shell 命令",
  url: "链接",
  user_request: "用户请求",
  web_content: "网页内容",
};

export function getResourceTypeLabel(type: string): string {
  return resourceTypeLabels[type] ?? type;
}

const resourceOperationLabels: Record<string, string> = {
  emit: "输出",
  execute: "执行",
  fetch: "获取",
  list: "列出",
  read: "读取",
  send: "发送",
};

export function getResourceOperationLabel(operation: string): string {
  return resourceOperationLabels[operation] ?? operation;
}

const resourceSensitivityLabels: Record<string, string> = {
  credential: "凭据",
  dangerous: "高风险",
  external: "外部",
  external_untrusted: "不可信外部内容",
  public_workspace: "公共工作区",
  sensitive_output: "敏感输出",
  workspace: "工作区",
};

export function getResourceSensitivityLabel(sensitivity: string): string {
  return resourceSensitivityLabels[sensitivity] ?? sensitivity;
}

export function getRiskAggregationLabel(method: string): string {
  if (method === "max_detection_score") return "取最高风险分";
  return method;
}

export function formatDashboardDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return dashboardDateTimeFormatter.format(date);
}

export function formatAuditHeadHash(value: string | null): string {
  return value ? `${value.slice(0, 12)}…` : "暂无链头";
}
