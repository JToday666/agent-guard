import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const inspectorSource = readFileSync(
  new URL("./ExecutionStepInspector.vue", import.meta.url),
  "utf8",
);

test("renders the decision section as a single unconditional V2 official rail", () => {
  assert.match(inspectorSource, /<h5>V2 官方评判<\/h5>/);
  assert.match(inspectorSource, /class="execution-inspector__comparison is-single"/);
  assert.match(inspectorSource, /<span>V2 官方评判<\/span>/);
  assert.doesNotMatch(inspectorSource, /is-shadow|OFFICIAL|正式决策 \//);
});

test("prefers the recorded V2 final decision and falls back to the official projection", () => {
  assert.match(inspectorSource, /v21Assessment\.recordedFinalDecision \?\?/);
  assert.match(inspectorSource, /officialDecision\.decision/);
});

test("shows competition authority details only when the selected source is v21", () => {
  assert.match(inspectorSource, /competitionAuthority\?\.source === 'v21'/);
});
