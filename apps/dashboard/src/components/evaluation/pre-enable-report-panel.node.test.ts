import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const panelSource = readFileSync(new URL("./PreEnableReportPanel.vue", import.meta.url), "utf8");
const evaluationPageSource = readFileSync(
  new URL("../../pages/EvaluationPage.vue", import.meta.url),
  "utf8",
);

test("the C10 report is embedded in the existing Evaluation page", () => {
  assert.match(evaluationPageSource, /<PreEnableReportPanel/);
  assert.match(evaluationPageSource, /:report="store\.evaluationRun\.preEnableReport"/);
  assert.match(panelSource, /CURRENT OFFICIAL/);
  assert.match(panelSource, /V2 SHADOW/);
  assert.match(panelSource, /FORMAL GATE B/);
  assert.match(panelSource, /未声明通过/);
  assert.match(panelSource, /效果仅作 observational 展示，不应用数值门槛/);
});

test("every displayed C10 ratio carries numerator and denominator", () => {
  for (const label of [
    "Receipt coverage",
    "Link conflicts",
    "Official ↔ V2 divergence",
    "Explanation coverage",
    "Benign ASK",
    "Decision label coverage",
    "Final ASR",
    "Attack outcome coverage",
    "Latency sample coverage",
  ]) {
    assert.match(panelSource, new RegExp(label));
  }
  assert.match(panelSource, /ratioCounts\(metric\.value\)/);
  assert.match(panelSource, /metric\.numerator.*metric\.denominator/s);
});

test("the report panel never dumps the untyped API extension", () => {
  assert.doesNotMatch(panelSource, /JSON\.stringify|v-html|\.raw\b|pre_enable_report/);
});
