import assert from "node:assert/strict";
import test from "node:test";

import { deriveMetrics, groupDecisionTrend } from "./metrics.ts";

const events = [
  {
    decision: "allow",
    blocked: false,
    occurredAt: "2026-06-22T06:05:00Z",
    latencyMs: 10,
  },
  {
    decision: "deny",
    blocked: true,
    occurredAt: "2026-06-22T06:20:00Z",
    latencyMs: 30,
  },
  {
    decision: "ask",
    blocked: true,
    occurredAt: "2026-06-22T07:10:00Z",
    latencyMs: null,
  },
] as const;

test("derives count, block rate and average latency from audit events", () => {
  const metrics = deriveMetrics(events);

  assert.equal(metrics.eventCount, 3);
  assert.equal(metrics.allowCount, 1);
  assert.equal(metrics.denyCount, 1);
  assert.equal(metrics.askCount, 1);
  assert.equal(metrics.blockedCount, 2);
  assert.equal(metrics.blockRate, 2 / 3);
  assert.equal(metrics.averageLatencyMs, 20);
});

test("groups decisions into chronological buckets suited to the event span", () => {
  const firstHour = `${String(new Date("2026-06-22T06:05:00Z").getHours()).padStart(2, "0")}:00`;
  const secondHour = `${String(new Date("2026-06-22T07:10:00Z").getHours()).padStart(2, "0")}:00`;
  assert.deepEqual(groupDecisionTrend(events), [
    { label: firstHour, allow: 1, ask: 0, deny: 1 },
    { label: secondHour, allow: 0, ask: 1, deny: 0 },
  ]);
});
