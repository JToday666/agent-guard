import assert from "node:assert/strict";
import test from "node:test";

import type { V21AssessmentPresentation } from "../../types/runtime-supervision.ts";
import {
  getAuthorityLabel,
  getV21RailLabel,
  getV21Summary,
} from "./runtime-supervision-display.ts";

function assessment(overrides: Partial<V21AssessmentPresentation> = {}): V21AssessmentPresentation {
  return {
    assessmentId: "assessment-display-test",
    authorityVerification: "verified",
    availability: "recorded",
    competitionAuthority: null,
    coverage: {},
    decisionAuthority: "shadow",
    degradationIds: [],
    divergenceCategory: null,
    fastDisposition: "DEFER",
    legacyDecision: "allow",
    mode: "shadow",
    recordedFinalDecision: "allow",
    rollout: {} as V21AssessmentPresentation["rollout"],
    sourceRefs: [],
    ...overrides,
  };
}

test("shadow authority never renders an official V2 label", () => {
  const shadow = assessment({
    competitionAuthority: {
      activationRefDigest: "a".repeat(64),
      approvalRelease: "not_applicable",
      availability: "recorded",
      legacyFloorApplied: false,
      matchedPathIds: [],
      mode: "shadow",
      profileId: "competition-langgraph-v2",
      selectedDecisionId: null,
      selectionBasis: "current",
      source: "v21",
    },
  });

  assert.equal(getAuthorityLabel(shadow.decisionAuthority), "影子评估");
  assert.equal(getV21RailLabel(shadow), "V2 Shadow");
  assert.equal(getV21RailLabel(shadow).toLowerCase().includes("official"), false);
  assert.equal(getV21Summary(shadow).toLowerCase().includes("official"), false);
});

test("only verified V2 authority renders the competition official label", () => {
  const official = assessment({
    competitionAuthority: {
      activationRefDigest: "a".repeat(64),
      approvalRelease: "strong_binding_required",
      availability: "recorded",
      legacyFloorApplied: true,
      matchedPathIds: ["required_state_degradation"],
      mode: "active",
      profileId: "competition-langgraph-v2",
      selectedDecisionId: "decision-v2",
      selectionBasis: "profile_all",
      source: "v21",
    },
    decisionAuthority: "official",
    mode: "active",
  });

  assert.equal(getV21RailLabel(official), "V2 Competition Official");
  assert.match(getV21Summary(official), /Competition profile official/);
});
