const primaryBlockingHooks = [
  "before_tool_call",
  "message_sending",
  "before_install",
];
const promptModelHooks = [
  "before_prompt_build",
  "before_agent_run",
  "llm_input",
  "llm_output",
];
const synchronousPersistenceHooks = [
  "tool_result_persist",
  "before_message_write",
];
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
  // RTE-03：观察型 terminal closure hook；非 fail-closed，不参与阻断。
  "after_tool_call",
];

export const OPENCLAW_OBSERVATION_HOOKS = Object.freeze(observationHooks);
export const OPENCLAW_ENFORCEMENT_HOOKS = Object.freeze([
  ...primaryBlockingHooks,
  "before_agent_run",
  "before_agent_finalize",
  ...synchronousPersistenceHooks,
]);
export const OPENCLAW_FAIL_CLOSED_HOOKS = OPENCLAW_ENFORCEMENT_HOOKS;
export const OPENCLAW_REQUIRED_HOOKS = Object.freeze([
  ...primaryBlockingHooks,
  "message_received",
  ...promptModelHooks,
  ...synchronousPersistenceHooks,
  "before_agent_finalize",
  ...observationHooks,
]);
export const OPENCLAW_REQUIRED_HOOK_COUNT = OPENCLAW_REQUIRED_HOOKS.length;
