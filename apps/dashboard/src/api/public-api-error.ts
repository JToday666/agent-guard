const publicCodeMessages: Readonly<Record<string, string>> = {
  AUTH_MISSING: "缺少访问凭证，请通过本机启动器重新打开 Dashboard。",
  CSRF_INVALID: "当前会话校验已失效，请刷新后重试。",
  INTERNAL_ERROR: "核心服务暂时无法完成请求，请稍后重试。",
  INVALID_RESPONSE: "核心服务返回的数据暂时无法识别，请稍后重试或联系管理员。",
  LAUNCH_CODE_EXPIRED: "启动链接已过期，请通过本机启动器重新打开 Dashboard。",
  LAUNCH_CODE_INVALID: "启动链接无效或已使用，请通过本机启动器重新打开 Dashboard。",
  METHOD_NOT_ALLOWED: "当前操作不受支持。",
  REQUEST_TIMEOUT: "核心服务请求超时，请稍后重试。",
  SESSION_EXPIRED: "当前会话已过期，请通过本机启动器重新打开 Dashboard。",
  SESSION_INVALID: "当前会话无效，请通过本机启动器重新打开 Dashboard。",
  SCOPE_DENIED: "当前凭证无权执行此操作。",
  TOKEN_INVALID: "访问凭证无效，请通过本机启动器重新打开 Dashboard。",
  VALIDATION_ERROR: "请求参数无效，请检查当前输入后重试。",
};

export function getPublicApiErrorMessage(status: number, code: string): string {
  const codeMessage = publicCodeMessages[code];
  if (codeMessage) return codeMessage;
  if (status === 401) return "当前会话无效，请通过本机启动器重新打开 Dashboard。";
  if (status === 403) return "当前会话无权执行此操作。";
  if (status === 404) return "请求的资源不存在或已失效。";
  if (status === 409) return "请求状态已发生变化，请刷新后重试。";
  if (status === 422) return "请求参数无效，请检查当前输入后重试。";
  if (status === 429) return "请求过于频繁，请稍后重试。";
  if (status >= 500) return "核心服务暂时无法完成请求，请稍后重试。";
  return status > 0 ? `请求失败（${status}）` : "无法连接核心服务，请检查服务状态后重试。";
}
