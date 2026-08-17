import {
  OPENCLAW_ENFORCEMENT_HOOKS,
  OPENCLAW_OBSERVATION_HOOKS,
  OPENCLAW_REQUIRED_HOOKS,
} from "../../hook-contract.mjs";
import {
  GuardApiClient,
  buildPluginConfig,
  logDiagnostic,
} from "../guard-api-client.js";
import { isDisabled } from "./enforcement.js";
import {
  OPENCLAW_EFFECTIVE_FAIL_CLOSED_HOOKS,
  OPENCLAW_EXACT_ACTION_RESIDUAL_BOUNDARY,
  OPENCLAW_HOST_REPLACE_AND_SEAL_SUPPORTED,
} from "./host-capabilities.js";
import type { EvidenceDegradationTracker } from "./state.js";

const HEARTBEAT_INTERVAL_MS = 60_000;
const RUNTIME_BINDING_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;

/**
 * RTE-03（契约 02 §11 TARGET 子集）：结构化 enforcement 能力声明。
 * 任何使 terminal closure 不成立或降级的事件都不得继续声称 C2：
 * 容量耗尽、native action id 缺失、correlation 丢失或 local_fallback
 * 关联都会使 after hook 跳过终态闭环（评审 P1）。
 */
export const C2_DEMOTION_REASONS = [
  "tool_call_state_capacity_exhausted",
  "tool_call_state_duplicate_active_id",
  "after_tool_call_missing_action_id",
  "after_tool_call_correlation_missing",
  "after_tool_call_policy_linkage_missing",
  "after_tool_call_local_fallback_correlation",
] as const;

export const C3_DEMOTION_REASONS = [
  ...C2_DEMOTION_REASONS,
  "strong_binding_operational_degradation",
] as const;

export function buildRuntimeEnforcementCapability(
  degradations?: EvidenceDegradationTracker,
  options: {
    activationEnabled?: boolean;
    enforcementMode?: "enforce" | "observe" | "disabled";
    runtimeBindingId?: string;
    hostReplaceAndSealSupported?: boolean;
  } = {},
): Record<string, unknown> {
  const snapshot = degradations?.snapshot();
  const byReason = snapshot?.byReason ?? {};
  const c2Demoted = C2_DEMOTION_REASONS.some(
    (reason) => (byReason[reason] ?? 0) > 0,
  );
  const c3Demoted = C3_DEMOTION_REASONS.some(
    (reason) => (byReason[reason] ?? 0) > 0,
  );
  const c3Enabled =
    options.activationEnabled === true &&
    options.enforcementMode === "enforce" &&
    options.hostReplaceAndSealSupported === true &&
    typeof options.runtimeBindingId === "string" &&
    RUNTIME_BINDING_IDENTIFIER.test(options.runtimeBindingId) &&
    !c3Demoted;
  return {
    contract: "1.0",
    profiles: {
      C0_observe: true,
      C1_pre_execution_enforcement: true,
      C2_execution_closure: !c2Demoted,
      C3_strong_approval_binding: c3Enabled,
      C4_result_isolation: true,
    },
    correlation: { stable_native_action_id: !c2Demoted },
    strong_approval_binding: {
      requested: options.activationEnabled === true,
      host_replace_and_seal_supported:
        options.hostReplaceAndSealSupported === true,
      residual_boundary:
        options.hostReplaceAndSealSupported === true
          ? null
          : OPENCLAW_EXACT_ACTION_RESIDUAL_BOUNDARY,
    },
    evidence_degradation: snapshot?.total ?? 0,
  };
}

export function scheduleHeartbeat(
  config: ReturnType<typeof buildPluginConfig>,
  makeClient: () => GuardApiClient,
  pluginVersion: string,
  runtimeVersion: string,
  degradations?: EvidenceDegradationTracker,
): () => void {
  if (!config.adapterToken || isDisabled(config)) {
    return () => undefined;
  }
  const submit = () => {
    void makeClient()
      .submitHeartbeat({
        pluginVersion,
        runtimeVersion: runtimeVersion.trim() ? runtimeVersion : null,
        hooks: [...OPENCLAW_REQUIRED_HOOKS],
        capabilities: {
          event_types: [
            "tool_call_proposed",
            "context_assembled",
            "model_input_prepared",
            "model_output_produced",
            "tool_result_produced",
            "memory_write_proposed",
            "message_send_proposed",
          ],
          blocking_hooks: [...OPENCLAW_ENFORCEMENT_HOOKS],
          observation_hooks: [
            ...OPENCLAW_OBSERVATION_HOOKS,
            "message_received",
            "before_prompt_build",
            "llm_input",
            "llm_output",
          ],
          redaction_hooks: [
            "tool_result_persist",
            "before_message_write",
            "before_agent_finalize",
          ],
          fail_closed_stages: [...OPENCLAW_EFFECTIVE_FAIL_CLOSED_HOOKS],
          enforcement_mode: config.enforcementMode,
          redaction: { enabled: true, preview_limit: 2_000 },
          runtime_enforcement_contract:
            buildRuntimeEnforcementCapability(degradations, {
              activationEnabled: config.strongApprovalBindingEnabled,
              enforcementMode: config.enforcementMode,
              runtimeBindingId: config.runtimeBindingId,
              hostReplaceAndSealSupported:
                OPENCLAW_HOST_REPLACE_AND_SEAL_SUPPORTED,
            }),
        },
      })
      .catch((error) => {
        logDiagnostic(config, "heartbeat submit failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      });
  };
  const initialTimer = setTimeout(submit, 0);
  const intervalTimer = setInterval(submit, HEARTBEAT_INTERVAL_MS);
  unrefTimer(initialTimer);
  unrefTimer(intervalTimer);
  return () => {
    clearTimeout(initialTimer);
    clearInterval(intervalTimer);
  };
}

export function unrefTimer(
  timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>,
): void {
  if (typeof timer === "object" && timer !== null && "unref" in timer) {
    (timer as { unref: () => void }).unref();
  }
}
