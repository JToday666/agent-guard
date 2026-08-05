/** Compatibility facade for the OpenClaw event mapping API. */

export {
  buildBeforeInstallConfigAuditEvent,
  buildContextGuardEvent,
  buildMessageSendGuardEvent,
  buildModelGuardEvent,
  buildRuntimeObservationAuditEvent,
  buildToolCallGuardEvent,
  buildToolResultGuardEvent,
} from "./mapping/index.js";
