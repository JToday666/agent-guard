import { OPENCLAW_FAIL_CLOSED_HOOKS } from "../../hook-contract.mjs";

/**
 * OpenClaw runs modifying hooks from highest to lowest numeric priority.  This
 * puts AgentGuard as late as the public API permits, but it is not a terminal
 * priority: another plugin can still register the same or a lower value.
 */
export const FINAL_ENFORCEMENT_HOOK_PRIORITY = Number.MIN_SAFE_INTEGER;

/**
 * The supported OpenClaw hook API can shallow-merge params/content, but cannot
 * atomically replace and seal the final action at the invocation boundary.
 */
export const OPENCLAW_HOST_REPLACE_AND_SEAL_SUPPORTED = false;
export const OPENCLAW_EXACT_ACTION_RESIDUAL_BOUNDARY =
  "openclaw_hook_cannot_atomically_replace_and_seal_final_action";

/**
 * OpenClaw's global runner treats message_sending handler failures/timeouts as
 * fail-open.  AgentGuard handles its own bounded failures locally, but must not
 * advertise a stronger host-level failure policy than the runtime provides.
 */
export const OPENCLAW_EFFECTIVE_FAIL_CLOSED_HOOKS = Object.freeze(
  OPENCLAW_FAIL_CLOSED_HOOKS.filter((hook) => hook !== "message_sending"),
);
