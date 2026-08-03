const blockingHooks = ["before_tool_call", "message_sending", "before_install"];
const promptModelHooks = ["before_prompt_build", "llm_input", "llm_output"];
const observationHooks = [
  "gateway_start",
  "gateway_stop",
  "session_start",
  "session_end",
  "before_compaction",
  "after_compaction",
  "subagent_spawned",
  "subagent_ended",
  "model_call_started",
  "model_call_ended",
  "cron_changed",
  "resolve_exec_env",
];

export const OPENCLAW_BLOCKING_HOOKS = Object.freeze(blockingHooks);
export const OPENCLAW_OBSERVATION_HOOKS = Object.freeze(observationHooks);
export const OPENCLAW_ENFORCEMENT_HOOKS = Object.freeze([
  ...blockingHooks,
  "before_prompt_build",
  "llm_input",
  "before_agent_finalize",
]);
export const OPENCLAW_REQUIRED_HOOKS = Object.freeze([
  ...blockingHooks,
  "message_received",
  ...promptModelHooks,
  "tool_result_persist",
  "before_message_write",
  "before_agent_finalize",
  ...observationHooks,
]);
export const OPENCLAW_REQUIRED_HOOK_COUNT = OPENCLAW_REQUIRED_HOOKS.length;
