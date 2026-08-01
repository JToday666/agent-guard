interface ApiErrorLike {
  code?: unknown;
  status?: unknown;
}

export type ApprovalResolutionFailureKind = "conflict" | "session" | "failed";

export interface ApprovalResolutionFailure {
  kind: ApprovalResolutionFailureKind;
  message: string;
  shouldRefreshQueue: boolean;
}

function errorCode(reason: unknown): string | null {
  if (!reason || typeof reason !== "object") return null;
  const code = (reason as ApiErrorLike).code;
  return typeof code === "string" ? code : null;
}

function errorStatus(reason: unknown): number | null {
  if (!reason || typeof reason !== "object") return null;
  const status = (reason as ApiErrorLike).status;
  return typeof status === "number" ? status : null;
}

export function getApprovalResolutionFailure(reason: unknown): ApprovalResolutionFailure {
  const code = errorCode(reason);
  const status = errorStatus(reason);

  if (
    code === "APPROVAL_NONCE_INVALID" ||
    code === "APPROVAL_NOT_FOUND" ||
    code === "APPROVAL_DECISION_INVALID" ||
    status === 404 ||
    status === 409
  ) {
    return {
      kind: "conflict",
      message:
        code === "APPROVAL_NONCE_INVALID"
          ? "该审批凭证已失效或已被使用，队列已更新。"
          : "该审批已不在待处理状态，可能已由其他端完成。",
      shouldRefreshQueue: true,
    };
  }

  if (code === "SESSION_INVALID" || code === "SESSION_EXPIRED" || code === "CSRF_INVALID") {
    return {
      kind: "session",
      message: "监督端会话已失效，请通过本机启动器重新打开 Dashboard。",
      shouldRefreshQueue: false,
    };
  }

  return {
    kind: "failed",
    message: "审批提交失败，当前证据和选择已保留，请检查连接后重试。",
    shouldRefreshQueue: false,
  };
}
