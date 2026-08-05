interface ApiErrorLike {
  code?: unknown;
}

const authErrorMessages: Record<string, string> = {
  LAUNCH_CODE_INVALID: "启动链接无效或已使用，请通过本机启动器重新打开 Dashboard。",
  LAUNCH_CODE_EXPIRED: "启动链接已过期，请通过本机启动器重新打开 Dashboard。",
  SESSION_INVALID: "监督端会话无效，请通过本机启动器重新打开 Dashboard。",
  SESSION_EXPIRED: "监督端会话已过期，请通过本机启动器重新打开 Dashboard。",
};

function getErrorCode(reason: unknown): string | null {
  if (!reason || typeof reason !== "object") return null;
  const code = (reason as ApiErrorLike).code;
  return typeof code === "string" ? code : null;
}

export function getAuthErrorMessage(reason: unknown): string {
  const code = getErrorCode(reason);
  if (code && authErrorMessages[code]) return authErrorMessages[code];
  return reason instanceof Error ? reason.message : "会话初始化失败";
}

export function isSessionAuthError(reason: unknown): boolean {
  const code = getErrorCode(reason);
  return code === "SESSION_INVALID" || code === "SESSION_EXPIRED";
}
