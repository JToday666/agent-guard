const publicCodeMessages: Readonly<Record<string, string>> = {
  AUTH_MISSING: "缺少访问凭证，请通过本机启动器重新打开 Dashboard。",
  CSRF_INVALID: "当前会话校验已失效，请刷新后重试。",
  INTERNAL_ERROR: "Guard API 暂时无法完成请求，请稍后重试。",
  INVALID_RESPONSE: "Guard API 返回了无法识别的数据，请检查服务版本后重试。",
  LAUNCH_CODE_EXPIRED: "启动链接已过期，请通过本机启动器重新打开 Dashboard。",
  LAUNCH_CODE_INVALID: "启动链接无效或已使用，请通过本机启动器重新打开 Dashboard。",
  METHOD_NOT_ALLOWED: "当前操作不受支持。",
  SESSION_EXPIRED: "监督端会话已过期，请通过本机启动器重新打开 Dashboard。",
  SESSION_INVALID: "监督端会话无效，请通过本机启动器重新打开 Dashboard。",
  SCOPE_DENIED: "当前凭证无权执行此操作。",
  TOKEN_INVALID: "访问凭证无效，请通过本机启动器重新打开 Dashboard。",
  VALIDATION_ERROR: "请求参数无效，请检查当前输入后重试。",
};

export function getPublicApiErrorMessage(status: number, code: string): string {
  const codeMessage = publicCodeMessages[code];
  if (codeMessage) return codeMessage;
  if (status === 401) return "监督端会话无效，请通过本机启动器重新打开 Dashboard。";
  if (status === 403) return "当前会话无权执行此操作。";
  if (status === 404) return "请求的资源不存在或已失效。";
  if (status === 409) return "请求状态已发生变化，请刷新后重试。";
  if (status === 422) return "请求参数无效，请检查当前输入后重试。";
  if (status === 429) return "请求过于频繁，请稍后重试。";
  if (status >= 500) return "Guard API 暂时无法完成请求，请稍后重试。";
  return status > 0 ? `请求失败（${status}）` : "无法连接 Guard API，请检查服务状态后重试。";
}
