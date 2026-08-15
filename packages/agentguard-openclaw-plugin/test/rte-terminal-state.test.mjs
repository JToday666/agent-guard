// PR-RTE-03 — GateState correlation lifecycle tests (contract 03 §3, §8).
//
// Evidence-layer scope: pure in-process unit tests over dist/runtime/state.js.
// They pin the RTE-03 invariants that active correlation state must not be
// silently evicted by plain FIFO pressure and that eviction follows the
// documented lifecycle instead.
import assert from "node:assert/strict";
import test from "node:test";
import {
  EvidenceDegradationTracker,
  TERMINAL_COMPLETION_GRACE_MS,
  canEvictToolCallState,
  isToolCallStateProtected,
  patchToolCallState,
  rememberToolCallState,
} from "../dist/runtime/state.js";

function makeGuardEvent(callId, eventId = "evt_rte_state_001") {
  return {
    event_id: eventId,
    schema_version: "0.4",
    record_type: "guard_event",
    event_type: "tool_call_proposed",
    trace_id: "trace_rte_state",
    timestamp: "2026-08-15T00:00:00Z",
    pre_execution: true,
    security_context: {
      agent_id: "agent_rte",
      user_task: "probe",
      source_trust: "untrusted",
      source_type: "tool",
      run_id: "run_rte",
      derived_paths: [],
    },
    payload: {
      tool: {
        name: "spike_probe",
        category: "tool",
        kind: "probe",
        input_kind: null,
        call_id: callId,
      },
      arguments: { mode: "allow" },
      derived_resources: [],
    },
    metadata: {},
  };
}

test("rememberToolCallState: native toolCallId initializes evaluating gate with native correlation", () => {
  const cache = new Map();
  rememberToolCallState(cache, makeGuardEvent("call-native-1"), {
    nativeToolCallId: "call-native-1",
    nowMs: 1000,
  });

  const state = cache.get("call-native-1");
  assert.ok(state);
  assert.equal(state.gateState, "evaluating");
  assert.equal(state.correlationSource, "native_tool_call_id");
  assert.equal(state.guardEventId, "evt_rte_state_001");
  assert.equal(state.traceId, "trace_rte_state");
  assert.equal(state.createdAtMs, 1000);
  assert.equal(state.updatedAtMs, 1000);
});

test("rememberToolCallState: missing native toolCallId degrades correlation to local_fallback", () => {
  const cache = new Map();
  rememberToolCallState(cache, makeGuardEvent("call_local_uuid"), {
    nativeToolCallId: null,
    nowMs: 1000,
  });

  const state = cache.get("call_local_uuid");
  assert.ok(state);
  assert.equal(state.correlationSource, "local_fallback");
});

test("rememberToolCallState: mismatched native toolCallId degrades correlation to local_fallback", () => {
  const cache = new Map();
  rememberToolCallState(cache, makeGuardEvent("call-a"), {
    nativeToolCallId: "call-other",
    nowMs: 1000,
  });
  assert.equal(cache.get("call-a").correlationSource, "local_fallback");
});

test("lifecycle: active gates are protected, terminal gates become evictable once the receipt is queued", () => {
  const base = {
    toolName: "t",
    toolCallId: "c",
    derivedResources: [],
    derivedPaths: [],
    toolParams: {},
    correlationSource: "native_tool_call_id",
    guardEventId: "e",
    traceId: "t",
    createdAtMs: 0,
    updatedAtMs: 0,
  };

  for (const gateState of ["evaluating", "approval_pending"]) {
    const state = { ...base, gateState };
    assert.equal(isToolCallStateProtected(state), true, gateState);
    assert.equal(canEvictToolCallState(state, Number.MAX_SAFE_INTEGER), false);
  }

  // allowed/approval_released are protected until the terminal observation.
  for (const gateState of ["allowed", "approval_released"]) {
    assert.equal(
      isToolCallStateProtected({ ...base, gateState }),
      true,
      gateState,
    );
    assert.equal(
      isToolCallStateProtected({
        ...base,
        gateState,
        terminalStatus: "executed",
      }),
      false,
      `${gateState}+terminal`,
    );
  }

  // blocked/timed_out/binding_failed + failed terminals evict only after the
  // receipt is safely queued (§8.2).
  for (const gateState of ["blocked", "timed_out", "binding_failed"]) {
    assert.equal(canEvictToolCallState({ ...base, gateState }, 1), false);
    assert.equal(
      canEvictToolCallState({ ...base, gateState, receiptQueued: true }, 1),
      true,
    );
  }
  assert.equal(
    canEvictToolCallState({ ...base, terminalStatus: "failed" }, 1),
    false,
  );
  assert.equal(
    canEvictToolCallState(
      { ...base, terminalStatus: "failed", receiptQueued: true },
      1,
    ),
    true,
  );
});

test("lifecycle: execution_completed keeps a grace TTL before eviction (§8.3)", () => {
  const state = {
    toolName: "t",
    toolCallId: "c",
    derivedResources: [],
    derivedPaths: [],
    toolParams: {},
    correlationSource: "native_tool_call_id",
    guardEventId: "e",
    traceId: "t",
    gateState: "allowed",
    terminalStatus: "executed",
    createdAtMs: 0,
    updatedAtMs: 1000,
  };
  assert.equal(canEvictToolCallState(state, 1000), false);
  assert.equal(
    canEvictToolCallState(state, 1000 + TERMINAL_COMPLETION_GRACE_MS - 1),
    false,
  );
  assert.equal(
    canEvictToolCallState(state, 1000 + TERMINAL_COMPLETION_GRACE_MS),
    true,
  );
});

test("capacity: exhausted cache never evicts protected states; degradation is recorded and C2 correlation is skipped", () => {
  const cache = new Map();
  const tracker = new EvidenceDegradationTracker();
  // Fill the cache with protected (evaluating) states.
  for (let index = 0; index < 4; index += 1) {
    rememberToolCallState(cache, makeGuardEvent(`call-keep-${index}`, "e"), {
      nativeToolCallId: `call-keep-${index}`,
      tracker,
      nowMs: index,
      limit: 4,
    });
  }
  assert.equal(cache.size, 4);

  rememberToolCallState(cache, makeGuardEvent("call-new", "e2"), {
    nativeToolCallId: "call-new",
    tracker,
    nowMs: 100,
    limit: 4,
  });

  assert.equal(cache.has("call-new"), false);
  assert.equal(cache.size, 4);
  for (let index = 0; index < 4; index += 1) {
    assert.equal(cache.has(`call-keep-${index}`), true);
  }
  const snapshot = tracker.snapshot();
  assert.equal(snapshot.total, 1);
  assert.equal(snapshot.byReason.tool_call_state_capacity_exhausted, 1);
});

test("capacity: an evictable terminal state is reclaimed instead of dropping the new call", () => {
  const cache = new Map();
  const tracker = new EvidenceDegradationTracker();
  for (let index = 0; index < 4; index += 1) {
    rememberToolCallState(cache, makeGuardEvent(`call-old-${index}`, "e"), {
      nativeToolCallId: `call-old-${index}`,
      tracker,
      nowMs: index,
      limit: 4,
    });
  }
  // First state reaches a queued blocked terminal and becomes evictable.
  patchToolCallState(cache, "call-old-0", {
    gateState: "blocked",
    receiptQueued: true,
  });

  rememberToolCallState(cache, makeGuardEvent("call-new", "e2"), {
    nativeToolCallId: "call-new",
    tracker,
    nowMs: 100,
    limit: 4,
  });

  assert.equal(cache.has("call-new"), true);
  assert.equal(cache.has("call-old-0"), false);
  assert.equal(cache.size, 4);
  assert.equal(tracker.snapshot().total, 0);
});

test("patchToolCallState: updates fields, refreshes updatedAtMs, and keeps insertion identity", () => {
  const cache = new Map();
  rememberToolCallState(cache, makeGuardEvent("call-patch", "e"), {
    nativeToolCallId: "call-patch",
    nowMs: 1000,
  });

  const patched = patchToolCallState(
    cache,
    "call-patch",
    { gateState: "allowed", policyAuditId: "audit_policy_1" },
    2000,
  );
  assert.ok(patched);
  assert.equal(patched.gateState, "allowed");
  assert.equal(patched.policyAuditId, "audit_policy_1");
  assert.equal(patched.updatedAtMs, 2000);
  assert.equal(patched.createdAtMs, 1000);
  assert.equal(cache.get("call-patch"), patched);

  assert.equal(patchToolCallState(cache, "missing", {}), undefined);
});

test("degradation tracker: counts stay bounded and snapshot exposes per-reason totals", () => {
  const tracker = new EvidenceDegradationTracker();
  tracker.record("after_tool_call_missing_action_id");
  tracker.record("after_tool_call_missing_action_id");
  tracker.record("after_tool_call_correlation_missing");

  const snapshot = tracker.snapshot();
  assert.equal(snapshot.total, 3);
  assert.equal(snapshot.byReason.after_tool_call_missing_action_id, 2);
  assert.equal(snapshot.byReason.after_tool_call_correlation_missing, 1);
});
