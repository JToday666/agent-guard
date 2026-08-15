import {
  OPENCLAW_ENFORCEMENT_HOOKS,
  OPENCLAW_FAIL_CLOSED_HOOKS,
  OPENCLAW_OBSERVATION_HOOKS,
  OPENCLAW_REQUIRED_HOOKS,
} from "../../hook-contract.mjs";
import {
  GuardApiClient,
  buildPluginConfig,
  logDiagnostic,
} from "../guard-api-client.js";
import { isDisabled } from "./enforcement.js";
import type { EvidenceDegradationTracker } from "./state.js";

const HEARTBEAT_INTERVAL_MS = 60_000;

/**
 * RTE-03（契约 02 §11 TARGET 子集）：结构化 enforcement 能力声明。
 * C2 在 correlation 容量耗尽时降级为 false（C1 enforcement 不受影响）。
 */
export function buildRuntimeEnforcementCapability(
  degradations?: EvidenceDegradationTracker,
): Record<string, unknown> {
  const snapshot = degradations?.snapshot();
  const capacityExhausted =
    (snapshot?.byReason.tool_call_state_capacity_exhausted ?? 0) > 0;
  return {
    contract: "1.0",
    profiles: {
      C0_observe: true,
      C1_pre_execution_enforcement: true,
      C2_execution_closure: !capacityExhausted,
      C4_result_isolation: true,
    },
    correlation: { stable_native_action_id: true },
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
          fail_closed_stages: [...OPENCLAW_FAIL_CLOSED_HOOKS],
          enforcement_mode: config.enforcementMode,
          redaction: { enabled: true, preview_limit: 2_000 },
          runtime_enforcement_contract:
            buildRuntimeEnforcementCapability(degradations),
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
