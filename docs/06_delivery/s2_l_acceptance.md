# S2-L Acceptance Checklist

Status: **candidate branch accepted locally; formal exit pending merge and hosted CI**.

Acceptance run: 2026-08-16, profile `competition-sandbox-v1`, scenario
`RUNTIME-S2-CT-001`.

## Implementation

- [x] INT-RSC-CT-PROV implemented as the first serial commit.
- [x] FE-RSC-06+07 implemented as the second serial commit.
- [x] INT-RSC-CT-01 / S2-L Acceptance implemented as the third serial commit.
- [x] S1 harness, marker, and CI job remain unchanged.
- [x] S2-R, S3, Context Manifest, Memory Bridge, and RTE strong binding remain out of scope.

## Backend and rollback

- [x] `ct_transient_facts` current write is 1.1/`ct-fact-2`; 1.0/`ct-fact-1` is compatibility read.
- [x] `absent/full/budget_dropped/unsupported/invalid` are distinct.
- [x] Typed `ct-provenance/1.0` node/edge IDs and Audit EvidenceRefs are stable.
- [x] Memory and PostgreSQL atomic CT batches reject same-flow identity conflicts.
- [x] Flag-off official-response byte parity passes.
- [x] Rollback stops new CT projection and preserves committed history.
- [x] PostgreSQL store reopen reads back the committed audit and provenance graph.

## Runtime and live evidence

- [x] Trusted top-level `task_id` and `visible_source_refs` are wired; free metadata cannot grant task authority.
- [x] Tool-call, memory, message, and tool-result gateway producers are exercised before side effects/context admission.
- [x] One trace contains all seven policy event kinds.
- [x] All seven event kinds have a validated full CT envelope.
- [x] Memory and PostgreSQL each return Trace and Provenance `200 -> 304`.
- [x] Both stores emit typed nodes/edges with no missing endpoint in the acceptance projection.
- [x] Cross-store redacted semantic parity passes (`17` typed nodes, `11` typed edges).
- [x] Browser screenshots verify Live API, mixed-contract degradation, selected typed Source, trust/certainty/authority, and EvidenceRef.
- [x] Secret material is absent from evidence; readiness and key ID only are recorded.

## Formal exit

- [ ] The three serial commits are merged through their intended PRs.
- [ ] Hosted `dashboard-s2-live-e2e` passes for Memory and PostgreSQL.
- [ ] Hosted `s2-cross-store-parity` publishes `dashboard-s2-live-parity`.

S2 must not be called formally complete until the three formal-exit items are checked.
S3 remains not started.
