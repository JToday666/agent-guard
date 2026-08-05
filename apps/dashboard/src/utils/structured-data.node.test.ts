import assert from "node:assert/strict";
import test from "node:test";

import { serializeStructuredData } from "./structured-data.ts";

test("serializes nested structured data with readable indentation", () => {
  assert.equal(
    serializeStructuredData({ event: { blocked: true }, rules: ["P001"] }),
    '{\n  "event": {\n    "blocked": true\n  },\n  "rules": [\n    "P001"\n  ]\n}',
  );
});

test("serializes circular references without throwing", () => {
  const value: Record<string, unknown> = { id: "event-1" };
  value.self = value;

  assert.equal(serializeStructuredData(value), '{\n  "id": "event-1",\n  "self": "[Circular]"\n}');
});
