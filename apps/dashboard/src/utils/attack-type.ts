const ATTACK_TYPE_LABELS: Readonly<Record<string, string>> = {
  benign: "正常样本",
  code_execution_abuse: "危险代码执行",
  indirect_prompt_injection: "间接提示注入",
  memory_poisoning: "记忆中毒",
  outbound_dlp: "外发数据防泄漏",
  p1_matrix: "规则矩阵",
  prompt_injection: "提示注入",
  sensitive_file_access: "敏感文件访问",
  test: "测试样本",
  tool_hijack: "工具调用劫持",
  tool_hijacking: "工具调用劫持",
  unknown: "未分类",
};

export function getAttackTypeLabel(value: string): string {
  return ATTACK_TYPE_LABELS[value] ?? value;
}
