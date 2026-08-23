import {
  DEFAULT_EVIDENCE_POLL_INTERVAL_MS,
  MIN_EVIDENCE_POLL_INTERVAL_MS,
} from "../../config/dashboard-env.ts";

export type ConditionalReadResult = "modified" | "not_modified" | "skipped" | "failed" | "aborted";

export function getTracePollBackoffMs(
  failureCount: number,
  intervalMs = DEFAULT_EVIDENCE_POLL_INTERVAL_MS,
): number {
  const normalizedFailureCount = Math.max(1, Math.floor(failureCount));
  const normalizedInterval = Math.max(MIN_EVIDENCE_POLL_INTERVAL_MS, Math.floor(intervalMs));
  return Math.min(normalizedInterval * 2 ** (normalizedFailureCount - 1), normalizedInterval * 8);
}

export function isSuccessfulConditionalRead(
  result: ConditionalReadResult,
): result is "modified" | "not_modified" {
  return result === "modified" || result === "not_modified";
}

export function isTerminalReconciliationComplete(
  traceResult: ConditionalReadResult,
  provenanceResult: ConditionalReadResult,
): boolean {
  return isSuccessfulConditionalRead(traceResult) && isSuccessfulConditionalRead(provenanceResult);
}
