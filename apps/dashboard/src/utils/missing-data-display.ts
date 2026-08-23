/**
 * 「缺失数据」三态显示助手。
 *
 * 页面显示某项数据缺失时，必须区分三种成因，禁止使用「不可用 / 未记录」等
 * 模糊语言，也绝不允许伪造数据：
 *
 * 1. not_required（正常无数据）：该事件或状态本来就不产生该数据；
 * 2. fetch_error（数据获取错误）：保留真实错误，不伪装成空值；
 * 3. not_implemented / not_enabled（功能不可用）：明确标注未实现或未启用。
 *
 * awaiting_receipt 与 not_recorded 分别表示仍在等待，以及成因未知的历史缺口。
 */

export type MissingDataKind =
  | "not_required"
  | "awaiting_receipt"
  | "not_recorded"
  | "not_implemented"
  | "not_enabled"
  | "fetch_error";

const MISSING_DATA_LABELS: Record<MissingDataKind, string> = {
  not_required: "无需该数据",
  awaiting_receipt: "等待运行时回执",
  not_recorded: "未记录",
  not_implemented: "当前版本未实现",
  not_enabled: "该功能未启用",
  fetch_error: "数据获取失败",
};

export function getMissingDataLabel(kind: MissingDataKind): string {
  return MISSING_DATA_LABELS[kind];
}

export function noDataNeeded(subject: string, reason?: string): string {
  return reason ? `无需${subject}（${reason}）` : `无需${subject}`;
}

export function notImplemented(subject: string, reason?: string): string {
  return reason ? `当前版本未实现${subject}（${reason}）` : `当前版本未实现${subject}`;
}

export function notEnabled(subject: string, reason?: string): string {
  return reason ? `${subject}未启用（${reason}）` : `${subject}未启用`;
}

export function awaitingReceipt(reason?: string): string {
  return reason
    ? `${MISSING_DATA_LABELS.awaiting_receipt}（${reason}）`
    : MISSING_DATA_LABELS.awaiting_receipt;
}

export function fetchFailed(subject: string): string {
  return `${subject}获取失败`;
}
