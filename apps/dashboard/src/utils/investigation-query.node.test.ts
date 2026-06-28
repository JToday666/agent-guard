import assert from "node:assert/strict";
import test from "node:test";

import {
  mergeInvestigationQuery,
  normalizeInvestigationQuery,
} from "./investigation-query.ts";

test("normalizes supported investigation query values", () => {
  assert.deepEqual(
    normalizeInvestigationQuery({
      blocked: "true",
      decision: "deny",
      event_id: " event-1 ",
      page: "3",
      rule: "P001_sensitive_file_access",
      runtime: "langgraph",
      search: " sensitive file ",
      severity: "high",
    }),
    {
      attackType: "",
      blocked: "true",
      decision: "deny",
      eventId: "event-1",
      eventType: "",
      page: 3,
      rule: "P001_sensitive_file_access",
      runtime: "langgraph",
      search: "sensitive file",
      severity: "high",
      stage: "",
    },
  );
});

test("drops unsupported filters and clamps invalid pages", () => {
  assert.deepEqual(
    normalizeInvestigationQuery({
      blocked: "sometimes",
      decision: ["deny"],
      page: "-9",
      runtime: "unknown",
      severity: "urgent",
    }),
    {
      attackType: "",
      blocked: "",
      decision: "",
      eventId: "",
      eventType: "",
      page: 1,
      runtime: "",
      rule: "",
      search: "",
      severity: "",
      stage: "",
    },
  );
});

test("merges query changes while removing empty values and the first page", () => {
  assert.deepEqual(
    mergeInvestigationQuery(
      { decision: "deny", page: "4", search: "file" },
      { decision: "", event_id: "event-2", page: 1 },
    ),
    { event_id: "event-2", search: "file" },
  );
});
