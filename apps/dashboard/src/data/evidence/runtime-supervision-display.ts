import type { ExecutionStepViewModel } from "../../types/dashboard.ts";
import type {
  Availability,
  DecisionAuthority,
  DisplayEvidenceSemantics,
  ElementSourceMode,
  EvidenceCertainty,
} from "../../types/runtime-supervision.ts";
import { getDecisionLabel } from "../../utils/dashboard-formatters.ts";

export type SupervisionLayerKey = "decision" | "approval" | "enforcement" | "execution";
export type SupervisionTone = "neutral" | "info" | "success" | "warning" | "danger";

// RTE-05 强绑定当前不具备事件级下发资格（缺 V2.1 snapshot/revalidation 材料，
// 服务端不下发 enforcement_binding），Enforcement 面板常驻空态（门控未知/绑定未执行/
// Lease 未产生）易被误读为连线故障，故展示层整体隐藏。数据层 projectEnforcement
// 投影与类型保持不变；强绑定资格链就绪后置回 true 即可恢复。
export const SHOW_ENFORCEMENT_PANEL = false;

export interface SupervisionLayerDisplay {
  key: SupervisionLayerKey;
  label: string;
  value: string;
  detail: string;
  tone: SupervisionTone;
  availability: Availability;
}

const AVAILABILITY_LABELS: Record<Availability, string> = {
  recorded: "已记录",
  partial: "部分可用",
  // ③三态语义：unavailable 统一解释为后端未返回该层证据（未实现或未启用），
  // 不再使用模糊的「不可用」。
  unavailable: "后端未返回（未实现或未启用）",
  not_applicable: "不适用",
};

const CERTAINTY_LABELS: Record<EvidenceCertainty, string> = {
  confirmed: "已确认",
  supported: "有证据支持",
  possible: "可能",
  unknown: "未知",
};

const AUTHORITY_LABELS: Record<DecisionAuthority, string> = {
  // 演示口径：步骤检查器不再区分 official/shadow，V2 无条件按官方评判展示。
  official: "V2 官方评判",
  shadow: "V2 官方评判",
  none: "未验证权威",
};

const SOURCE_MODE_LABELS: Record<ElementSourceMode, string> = {
  live: "实时 API",
  replay: "回放数据",
  mock: "Mock Preview",
};

export function getAvailabilityLabel(value: Availability): string {
  return AVAILABILITY_LABELS[value];
}

export function getCertaintyLabel(value: EvidenceCertainty): string {
  return CERTAINTY_LABELS[value];
}

export function getAuthorityLabel(value: DecisionAuthority): string {
  return AUTHORITY_LABELS[value];
}

export function getSourceModeLabel(value: ElementSourceMode): string {
  return SOURCE_MODE_LABELS[value];
}

export function getSemanticsSummary(semantics: DisplayEvidenceSemantics): string {
  return `${getSourceModeLabel(semantics.elementSourceMode)} · ${getAuthorityLabel(semantics.decisionAuthority)} · ${getCertaintyLabel(semantics.certainty)} · ${getAvailabilityLabel(semantics.availability)}`;
}

function decisionLayer(step: ExecutionStepViewModel): SupervisionLayerDisplay {
  const presentation = step.supervision.officialDecision;
  if (presentation.availability === "partial") {
    return {
      key: "decision",
      label: "Decision",
      value: "关联冲突",
      detail: "正式判定无法唯一关联",
      tone: "danger",
      availability: presentation.availability,
    };
  }
  if (presentation.availability === "unavailable") {
    return {
      key: "decision",
      label: "Decision",
      value: "未返回",
      detail: "后端未返回该层证据（未实现或未启用），未找到正式判定证据",
      tone: "neutral",
      availability: presentation.availability,
    };
  }
  const tone: SupervisionTone =
    presentation.decision === "deny"
      ? "danger"
      : presentation.decision === "ask"
        ? "warning"
        : presentation.decision === "allow"
          ? "success"
          : "neutral";
  return {
    key: "decision",
    label: "Decision",
    value: getDecisionLabel(presentation.decision),
    detail: "当前 V2 官方评判结果",
    tone,
    availability: presentation.availability,
  };
}

function approvalLayer(step: ExecutionStepViewModel): SupervisionLayerDisplay {
  const presentation = step.supervision.approval;
  if (presentation.availability === "not_applicable") {
    return {
      key: "approval",
      label: "Approval",
      value: "无需审批",
      detail: "当前动作不需要人工审批",
      tone: "neutral",
      availability: presentation.availability,
    };
  }
  if (presentation.availability === "partial") {
    return {
      key: "approval",
      label: "Approval",
      value: "关联冲突",
      detail: "审批记录无法唯一关联",
      tone: "danger",
      availability: presentation.availability,
    };
  }
  if (presentation.availability === "unavailable") {
    return {
      key: "approval",
      label: "Approval",
      value: "未返回",
      detail: "后端未返回该层证据（未实现或未启用），审批状态未记录",
      tone: "neutral",
      availability: presentation.availability,
    };
  }
  const values = {
    pending: "待审批",
    allowed: presentation.decision === "allow_once" ? "单次放行" : "已允许",
    denied: "已拒绝",
    expired: "已过期",
    unknown: "状态未知",
  } as const;
  const tone: SupervisionTone =
    presentation.status === "denied"
      ? "danger"
      : presentation.status === "pending" || presentation.status === "expired"
        ? "warning"
        : presentation.status === "allowed"
          ? "success"
          : "neutral";
  return {
    key: "approval",
    label: "Approval",
    value: values[presentation.status],
    detail: presentation.decision === "allow_once" ? "审批不改变正式 ASK 判定" : "审批状态",
    tone,
    availability: presentation.availability,
  };
}

function enforcementLayer(step: ExecutionStepViewModel): SupervisionLayerDisplay {
  const presentation = step.supervision.enforcement;
  if (presentation.availability === "unavailable") {
    return {
      key: "enforcement",
      label: "Enforcement",
      value: "证据未返回",
      detail: "后端未返回该层证据（强绑定门控未实现或未启用）；不推断连线故障",
      tone: "neutral",
      availability: presentation.availability,
    };
  }
  if (presentation.availability === "partial") {
    return {
      key: "enforcement",
      label: "Enforcement",
      value: "证据不完整",
      detail: "不能据此确认运行时门状态",
      tone: "warning",
      availability: presentation.availability,
    };
  }
  const values = {
    evaluating: "校验中",
    allowed: "已放行",
    approval_pending: "等待审批",
    approval_released: "审批放行",
    blocked: "已阻断",
    timed_out: "已超时",
    binding_failed: "绑定失败",
    unknown: "状态未知",
  } as const;
  const tone: SupervisionTone =
    presentation.gateState === "blocked" || presentation.gateState === "binding_failed"
      ? "danger"
      : presentation.gateState === "approval_pending" || presentation.gateState === "timed_out"
        ? "warning"
        : presentation.gateState === "allowed" || presentation.gateState === "approval_released"
          ? "success"
          : "neutral";
  return {
    key: "enforcement",
    label: "Enforcement",
    value: values[presentation.gateState],
    detail: "执行前门控状态",
    tone,
    availability: presentation.availability,
  };
}

function executionLayer(step: ExecutionStepViewModel): SupervisionLayerDisplay {
  const presentation = step.supervision.execution;
  if (presentation.availability === "unavailable" && step.supervision.activityState === "running") {
    return {
      key: "execution",
      label: "Execution",
      value: "正在执行",
      detail: "仅确认已开始；终态收据尚未返回",
      tone: "info",
      availability: presentation.availability,
    };
  }
  if (presentation.availability === "partial") {
    return {
      key: "execution",
      label: "Execution",
      value: "收据冲突",
      detail: "存在多条或不一致的运行时收据",
      tone: "danger",
      availability: presentation.availability,
    };
  }
  if (presentation.availability === "unavailable") {
    return {
      key: "execution",
      label: "Execution",
      value: "收据未返回",
      detail: "后端未返回该层证据（未实现或未启用）；不能从判定推断是否调用",
      tone: "neutral",
      availability: presentation.availability,
    };
  }
  const values = {
    not_invoked: "未调用",
    executed: "已执行",
    failed: "执行失败",
    unknown: "状态未知",
  } as const;
  const tone: SupervisionTone =
    presentation.status === "failed"
      ? "danger"
      : presentation.status === "not_invoked"
        ? "info"
        : presentation.status === "executed"
          ? "success"
          : "neutral";
  return {
    key: "execution",
    label: "Execution",
    value: values[presentation.status],
    detail: presentation.receiptRecorded ? "已关联运行时收据" : "运行时结果未确认",
    tone,
    availability: presentation.availability,
  };
}

export function getSupervisionLayerDisplays(
  step: ExecutionStepViewModel,
): SupervisionLayerDisplay[] {
  return [decisionLayer(step), approvalLayer(step), enforcementLayer(step), executionLayer(step)];
}

export function getControlIntegrityLabel(
  value: ExecutionStepViewModel["supervision"]["controlIntegrity"]["status"],
): string {
  const labels = {
    no_violation_observed: "未观察到控制违例",
    suspected: "疑似控制违例",
    confirmed_violation: "已确认控制违例",
    correlation_conflict: "证据关联冲突",
    not_applicable: "不适用（检查点步骤无运行时回执）",
    unknown: "控制完整性未知",
  } as const;
  return labels[value];
}
