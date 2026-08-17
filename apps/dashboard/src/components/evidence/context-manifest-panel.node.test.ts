import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const inspectorSource = readFileSync(
  new URL("./ExecutionStepInspector.vue", import.meta.url),
  "utf8",
);
const traceSource = readFileSync(new URL("./ExecutionTrace.vue", import.meta.url), "utf8");
const pageSource = readFileSync(
  new URL("../../pages/EvidenceDetailPage.vue", import.meta.url),
  "utf8",
);

test("Context Manifest stays embedded in the existing context-step inspector", () => {
  assert.match(inspectorSource, /step\.category === ['"]context['"]/);
  assert.match(inspectorSource, /data-testid="context-manifest-panel"/);
  assert.match(inspectorSource, /contextManifest\.counts\.included/);
  assert.match(inspectorSource, /contextManifest\.counts\.quarantined/);
  assert.match(inspectorSource, /contextManifest\.counts\.excluded/);
  assert.match(inspectorSource, /chunk\.safePreview/);
  assert.match(traceSource, /:context-manifest="selectedContextManifest"/);
  assert.match(
    pageSource,
    /:context-manifest-by-event-id="runtimeSupervision\.contextManifestByEventId"/,
  );
});

test("Context Manifest panel has no raw-prompt or Provenance fallback", () => {
  const panel = inspectorSource.slice(
    inspectorSource.indexOf('data-testid="context-manifest-panel"'),
    inspectorSource.indexOf("Approval Basis"),
  );
  assert.doesNotMatch(panel, /\.raw\b|raw_prompt|:provenance|provenance-/i);
  assert.match(panel, /不会从原始 Prompt、内容入口或 Provenance 推断/);
});
