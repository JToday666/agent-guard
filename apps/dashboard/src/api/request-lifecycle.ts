export interface TimedRequestSignal {
  didTimeout(): boolean;
  dispose(): void;
  signal: AbortSignal;
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason instanceof DOMException && signal.reason.name === "AbortError"
    ? signal.reason
    : new DOMException("The operation was aborted.", "AbortError");
}

export function createTimedRequestSignal(
  callerSignal: AbortSignal | null | undefined,
  timeoutMs: number,
): TimedRequestSignal {
  const controller = new AbortController();
  let timeoutId: ReturnType<typeof globalThis.setTimeout> | null = null;
  let timedOut = false;

  const handleCallerAbort = () => {
    if (timeoutId !== null) {
      globalThis.clearTimeout(timeoutId);
      timeoutId = null;
    }
    controller.abort(abortReason(callerSignal!));
  };

  if (callerSignal?.aborted) {
    handleCallerAbort();
  } else {
    callerSignal?.addEventListener("abort", handleCallerAbort, { once: true });
    timeoutId = globalThis.setTimeout(() => {
      timeoutId = null;
      timedOut = true;
      controller.abort(new DOMException("The request timed out.", "TimeoutError"));
    }, timeoutMs);
  }

  return {
    didTimeout: () => timedOut,
    dispose() {
      if (timeoutId !== null) globalThis.clearTimeout(timeoutId);
      callerSignal?.removeEventListener("abort", handleCallerAbort);
    },
    signal: controller.signal,
  };
}
