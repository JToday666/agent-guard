const RULE_LABELS: Record<string, string> = {
  P001_sensitive_file_access: "敏感文件访问",
  P004_task_mismatch: "任务与行为不一致",
  P005_external_send: "外部发送需确认",
  P005_non_whitelisted_email: "外部发送需确认",
  P103_code_execution_abuse: "危险代码执行",
  P104_memory_poisoning: "长期记忆写入风险",
};

const RULE_ID_PATTERN = /^P\d{3}(?:_|$)/;
const RULE_ID_TOKEN_PATTERN = /\bP\d{3}(?:_[A-Za-z0-9]+)*\b/g;

function titleCaseWords(value: string): string {
  const words = value
    .replace(/^P\d{3}_?/, "")
    .split("_")
    .filter(Boolean);
  if (!words.length) return "安全规则";
  return words
    .map((word, index) => (index === 0 ? word[0]?.toUpperCase() + word.slice(1) : word))
    .join(" ");
}

export function isRuleId(value: string): boolean {
  return RULE_ID_PATTERN.test(value);
}

export function ruleLabel(ruleId: string): string {
  return RULE_LABELS[ruleId] ?? titleCaseWords(ruleId);
}

export function ruleOptionLabel(ruleId: string, count: number): string {
  return `${ruleLabel(ruleId)} ${count}`;
}

export function formatRuleListForDisplay(ruleIds: readonly string[]): string {
  if (!ruleIds.length) return "未命中阻断规则";
  return ruleIds.map(ruleLabel).join("、");
}

export function formatRuleIdsInTextForDisplay(value: string): string {
  return value.replace(RULE_ID_TOKEN_PATTERN, (ruleId) => ruleLabel(ruleId));
}

function shouldMapRuleArray(fieldName: string): boolean {
  return /ruleHits|rule_hits|disabled_rules/i.test(fieldName);
}

function shouldMapRuleObjectKeys(fieldName: string): boolean {
  return /rule_overrides/i.test(fieldName);
}

export function prepareEvidenceDataForDisplay(value: unknown, fieldName = ""): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (shouldMapRuleArray(fieldName) && typeof item === "string") {
        return ruleLabel(item);
      }
      return prepareEvidenceDataForDisplay(item);
    });
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => {
        const displayKey =
          shouldMapRuleObjectKeys(fieldName) && isRuleId(key) ? ruleLabel(key) : key;
        return [displayKey, prepareEvidenceDataForDisplay(item, key)];
      }),
    );
  }

  if (typeof value === "string") {
    return shouldMapRuleArray(fieldName) ? ruleLabel(value) : formatRuleIdsInTextForDisplay(value);
  }

  return value;
}
