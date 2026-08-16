export type ConditionalReadResult = "modified" | "not_modified" | "skipped" | "failed" | "aborted";

export const TRACE_POLL_INTERVAL_MS = 2_000;
export const TRACE_POLL_MAX_BACKOFF_MS = 16_000;

export function getTracePollBackoffMs(failureCount: number): number {
  const normalizedFailureCount = Math.max(1, Math.floor(failureCount));
  return Math.min(
    TRACE_POLL_INTERVAL_MS * 2 ** (normalizedFailureCount - 1),
    TRACE_POLL_MAX_BACKOFF_MS,
  );
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
