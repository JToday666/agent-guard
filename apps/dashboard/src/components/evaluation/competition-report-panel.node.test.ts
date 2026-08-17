import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const panelSource = readFileSync(new URL("./CompetitionReportPanel.vue", import.meta.url), "utf8");
const evaluationPageSource = readFileSync(
  new URL("../../pages/EvaluationPage.vue", import.meta.url),
  "utf8",
);
const executionInspectorSource = readFileSync(
  new URL("../evidence/ExecutionStepInspector.vue", import.meta.url),
  "utf8",
);

test("renders the competition report as a read-only competition-specific panel", () => {
  assert.match(evaluationPageSource, /<CompetitionReportPanel/);
  assert.match(evaluationPageSource, /evaluationRun\.competitionReport/);
  assert.match(panelSource, /Competition profile official/);
  assert.match(panelSource, /不代表正式 C11、Gate B 或 S5-O/);
  assert.match(panelSource, /V2 selected/);
  assert.match(panelSource, /Legacy floor/);
  assert.doesNotMatch(panelSource, /@click|<(?:button|select|input)\b/);
});

test("renders competition profile and matched paths in the read-only authority panel", () => {
  const authorityPanel = executionInspectorSource.slice(
    executionInspectorSource.indexOf('data-testid="competition-authority"'),
    executionInspectorSource.indexOf('data-testid="context-manifest-panel"'),
  );

  assert.match(authorityPanel, /competitionAuthority\.profileId/);
  assert.match(authorityPanel, /competitionAuthority\.source/);
  assert.match(authorityPanel, /competitionAuthority\.mode/);
  assert.match(authorityPanel, /competitionAuthority\.matchedPathIds/);
  assert.match(authorityPanel, /competitionAuthority\.approvalRelease/);
  assert.match(authorityPanel, /Matched paths/);
  assert.doesNotMatch(authorityPanel, /@click|<(?:button|select|input)\b/);
});
