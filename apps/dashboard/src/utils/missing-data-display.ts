/**
 * 「缺失数据」三态显示助手。
 *
 * 页面显示某项数据缺失时，必须区分三种成因，禁止使用「不可用 / 未记录」等
 * 模糊语言，也绝不允许伪造数据：
 *
 * 1. not_required（①正常无数据）：正常情况下本来就没有该数据，
 *    例如非工具调用事件没有工具参数 → 显示「无需xx数据」类明确文案；
 * 2. fetch_error（②数据获取错误）：统一交给既有 ApiError / ErrorState 机制
 *    展示真实错误，本助手只提供兜底文案；
 * 3. not_implemented / not_enabled（③功能未实现 / 未启用）：数据无法生成，
 *    必须明确标注「当前版本未实现」「该功能未启用」。
 *
 * 另有两个过渡/保留语义：
 * - awaiting_receipt：预期有运行时回执但尚未返回；
 * - not_recorded：数据确实缺失且成因未知时保留的显式「未记录」。
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

/** ①正常无数据：`无需<subject>（<reason>）`。 */
export function noDataNeeded(subject: string, reason?: string): string {
  return reason ? `无需${subject}（${reason}）` : `无需${subject}`;
}

/** ③功能未实现：`当前版本未实现<subject>（<reason>）`。 */
export function notImplemented(subject: string, reason?: string): string {
  return reason ? `当前版本未实现${subject}（${reason}）` : `当前版本未实现${subject}`;
}

/** ③功能未启用：`<subject>未启用（<reason>）`。 */
export function notEnabled(subject: string, reason?: string): string {
  return reason ? `${subject}未启用（${reason}）` : `${subject}未启用`;
}

/** 过渡态：预期回执尚未返回。 */
export function awaitingReceipt(reason?: string): string {
  return reason
    ? `${MISSING_DATA_LABELS.awaiting_receipt}（${reason}）`
    : MISSING_DATA_LABELS.awaiting_receipt;
}

/** ②获取错误兜底文案（真实错误由 ApiError / ErrorState 展示）。 */
export function fetchFailed(subject: string): string {
  return `${subject}获取失败`;
}
