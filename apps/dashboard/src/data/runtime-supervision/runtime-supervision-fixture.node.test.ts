import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  loadRuntimeSupervisionFixture,
  RuntimeSupervisionFixtureValidationError,
  runtimeSupervisionFixtureContract,
} from "./runtime-supervision-fixture.ts";

type JsonObject = Record<string, unknown>;

function readFixture(name: string): JsonObject {
  return JSON.parse(
    readFileSync(
      new URL(`../../../../../tests/fixtures/runtime_supervision/${name}`, import.meta.url),
      "utf8",
    ),
  ) as JsonObject;
}

const projectionRaw = readFixture("supervision_projection_v01.json");
const contextIngressRaw = readFixture("context_ingress_preview_v01.json");

function expectValidationError(input: unknown, expectedPath: string): void {
  assert.throws(
    () => loadRuntimeSupervisionFixture(input),
    (error: unknown) =>
      error instanceof RuntimeSupervisionFixtureValidationError && error.path === expectedPath,
  );
}

test("loads the projection fixture as a deeply frozen four-layer contract", () => {
  const fixture = loadRuntimeSupervisionFixture(projectionRaw);

  assert.equal(fixture.fixtureKind, "supervision_projection");
  if (fixture.fixtureKind !== "supervision_projection") return;
  assert.equal(fixture.metadata.fixtureSchemaVersion, "runtime-supervision-fixture/0.1");
  assert.equal(fixture.metadata.sourceMode, "mock");
  assert.equal(fixture.metadata.containsSyntheticFacts, true);
  assert.equal(fixture.metadata.safeForDemoSandbox, true);
  assert.equal(fixture.cases.length, 3);
  assert.equal(Object.isFrozen(fixture), true);
  assert.equal(Object.isFrozen(fixture.metadata.contractVersions), true);
  assert.equal(Object.isFrozen(fixture.cases[0]?.supervision.execution), true);

  const askAllowed = fixture.cases.find(({ caseId }) => caseId === "ask_allow_once_executed");
  assert.ok(askAllowed);
  assert.equal(askAllowed.supervision.officialDecision.decision, "ask");
  assert.equal(askAllowed.supervision.approval.decision, "allow_once");
  assert.equal(askAllowed.supervision.enforcement.availability, "unavailable");
  assert.equal(askAllowed.supervision.execution.status, "executed");
  assert.equal(askAllowed.supervision.execution.receiptRecorded, true);
  assert.equal(askAllowed.supervision.v21Assessment.availability, "unavailable");
  assert.equal(askAllowed.supervision.v21Assessment.decisionAuthority, "none");

  const denied = fixture.cases.find(({ caseId }) => caseId === "deny_without_runtime_proof");
  assert.ok(denied);
  assert.equal(denied.supervision.officialDecision.decision, "deny");
  assert.equal(denied.supervision.enforcement.gateState, "unknown");
  assert.equal(denied.supervision.execution.status, "unknown");
  assert.equal(denied.supervision.execution.receiptRecorded, false);

  const conflict = fixture.cases.find(({ caseId }) => caseId === "conflicting_runtime_receipts");
  assert.ok(conflict);
  assert.equal(conflict.supervision.controlIntegrity.status, "correlation_conflict");
  assert.equal(conflict.supervision.execution.status, "unknown");
  assert.equal(conflict.supervision.semantics.certainty, "unknown");
});

test("loads Web Source to Context to Model Input only as mock provenance", () => {
  const fixture = loadRuntimeSupervisionFixture(contextIngressRaw);

  assert.equal(fixture.fixtureKind, "context_ingress_preview");
  if (fixture.fixtureKind !== "context_ingress_preview") return;
  assert.equal(fixture.metadata.purpose, "ui_preview");
  assert.equal(fixture.sourceUri, "https://advisory.agentguard.test/demo/runtime-safety");
  assert.equal(fixture.fakeCredential, "DEMO_CREDENTIAL_NOT_VALID");
  assert.match(fixture.highImpactActionId, /^mock_action_/);
  assert.deepEqual(fixture.executionGraphEdges, []);
  assert.deepEqual(fixture.contentIngressSummary.normalizedCtSourceTypes, ["web"]);
  assert.deepEqual(
    fixture.provenancePresentation.nodes.map(({ nodeKind }) => nodeKind),
    ["source", "context", "model_input", "action"],
  );
  assert.equal(fixture.provenancePresentation.edges.length, 3);
  assert.ok(
    fixture.provenancePresentation.edges.every(
      ({ ctFlowRelation, wireRelation }) =>
        ctFlowRelation === "assembled_into" && wireRelation === "assembled_into",
    ),
  );
  assert.ok(
    fixture.provenancePresentation.nodes.every(
      ({ semantics }) =>
        semantics.elementSourceMode === "mock" &&
        semantics.derivedForDisplay &&
        semantics.decisionAuthority === "none",
    ),
  );
  assert.equal(Object.isFrozen(fixture.provenancePresentation.nodes), true);
  assert.equal(Object.isFrozen(fixture.provenancePresentation.edges[0]), true);
});

test("freezes the expected fixture contract versions", () => {
  assert.deepEqual(runtimeSupervisionFixtureContract, {
    fixtureSchemaVersion: "runtime-supervision-fixture/0.1",
    supervisionSchemaVersion: "runtime-supervision/0.1",
    auditSchemaVersion: "0.4",
    sourceFixturePath: "tests/fixtures/runtime_safety_trace_v04.json",
  });
  assert.equal(Object.isFrozen(runtimeSupervisionFixtureContract), true);
});

test("fails fast on unknown fields and authority upgrades", () => {
  const extraField = structuredClone(projectionRaw);
  extraField.unexpected = true;
  expectValidationError(extraField, "$");

  const liveMode = structuredClone(projectionRaw);
  liveMode.source_mode = "live";
  expectValidationError(liveMode, "$.source_mode");

  const cases = structuredClone(projectionRaw).cases as JsonObject[];
  const firstSupervision = cases[0]?.supervision as JsonObject;
  const semantics = firstSupervision.semantics as JsonObject;
  semantics.element_source_mode = "live";
  expectValidationError(
    { ...structuredClone(projectionRaw), cases },
    "$.cases[0].supervision.semantics.element_source_mode",
  );
});

test("rejects unsafe domains, live action ids, and content edges in the execution graph", () => {
  const unsafeDomain = structuredClone(contextIngressRaw);
  unsafeDomain.source_uri = "https://example.com/runtime-safety";
  expectValidationError(unsafeDomain, "$.source_uri");

  const liveAction = structuredClone(contextIngressRaw);
  liveAction.high_impact_action_id = "action_external_publish_001";
  expectValidationError(liveAction, "$.high_impact_action_id");

  const executionOverlay = structuredClone(contextIngressRaw);
  executionOverlay.execution_graph_edges = [
    {
      source_node_id: "mock_prov_web_source_001",
      target_node_id: "mock_prov_context_001",
    },
  ];
  expectValidationError(executionOverlay, "$.execution_graph_edges");
});

test("rejects a broken assembled_into provenance chain", () => {
  const brokenPath = structuredClone(contextIngressRaw);
  const presentation = brokenPath.provenance_presentation as JsonObject;
  const edges = presentation.edges as JsonObject[];
  const firstEdge = edges[0];
  assert.ok(firstEdge);
  firstEdge.wire_relation = "derived_from";
  firstEdge.ct_flow_relation = "derived_from";
  expectValidationError(brokenPath, "$.provenance_presentation.edges");
});
