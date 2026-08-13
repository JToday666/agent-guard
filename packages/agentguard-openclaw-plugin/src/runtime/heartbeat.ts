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

const HEARTBEAT_INTERVAL_MS = 60_000;

export function scheduleHeartbeat(
  config: ReturnType<typeof buildPluginConfig>,
  makeClient: () => GuardApiClient,
  pluginVersion: string,
  runtimeVersion: string,
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
