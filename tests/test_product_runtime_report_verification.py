"""Full keyless verification of synthetic unit materials; no real Host PASS claim."""

from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from scripts.product_runtime.evidence import EvidenceError, EvidenceStore
from scripts.product_runtime.models import AdmissionError
from scripts.product_runtime.signing import verify_request
from tests.product_runtime_report_fixture import build_report_fixture
from tests.test_product_runtime_candidate import _json, _ref

pytestmark = pytest.mark.contract


@pytest.fixture(scope="module")
def full_unit_report(tmp_path_factory):
    return build_report_fixture(tmp_path_factory.mktemp("synthetic-unit-report"))


def _verify(fixture):
    return verify_request(
        _ref(fixture.root, fixture.request_path),
        EvidenceStore(fixture.root),
        fixture.candidate.checkout,
        fixture.candidate.revision,
        clock=fixture.clock,
    )


@contextmanager
def _report_change(fixture, runtime, mutate):
    path = fixture.report_paths[runtime]
    originals = {
        path: path.read_bytes(),
        fixture.request_path: fixture.request_path.read_bytes(),
    }
    try:
        report = json.loads(path.read_bytes())
        mutate(report)
        _json(path, report)
        request = json.loads(fixture.request_path.read_bytes())
        request[runtime + "_conformance"] = _ref(fixture.root, path)
        _json(fixture.request_path, request)
        yield
    finally:
        for path, content in originals.items():
            path.write_bytes(content)


@contextmanager
def _observation_change(fixture, runtime, case_id, mutate):
    reference = fixture.observations[runtime, case_id]
    path = fixture.root / reference["path"]
    original = path.read_bytes()
    try:
        document = json.loads(original)
        mutate(document)
        _json(path, document)

        def update(report):
            case = next(case for case in report["cases"] if case["id"] == case_id)
            case["hashed_evidence"] = [_ref(fixture.root, path)]

        with _report_change(fixture, runtime, update):
            yield
    finally:
        path.write_bytes(original)


def test_full_request_verifies_actual_candidate_and_complete_52_54_case_documents(
    full_unit_report,
):
    result = _verify(full_unit_report)
    assert len(result.candidate.artifacts) == 9
    assert {
        runtime: len(value.report.cases) for runtime, value in result.reports.items()
    } == {"langgraph": 52, "openclaw": 54}
    assert result.review.reviewer_id == "unit:automated-fixture-reviewer"
    assert result.review.production_acceptance_claimed is False
    assert [entry["ask_release_mode"] for entry in result.entries] == [
        "strong_binding",
        "restricted_allow_once",
    ]
    assert all(
        value.report.product_active_enabled is False
        for value in result.reports.values()
    )
    assert all(
        case.authority_kind == "synthetic_contract_fixture"
        for value in result.reports.values()
        for case in value.report.cases
        if case.id.startswith("contract.")
    )
    assert not (full_unit_report.root / "signed").exists()


def test_keyless_cli_reads_full_unit_materials_without_signing(full_unit_report):
    fixture = full_unit_report
    script = Path(__file__).parents[1] / "scripts/product-runtime-admission.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify",
            "--request",
            fixture.request_path.relative_to(fixture.root).as_posix(),
            "--evidence-root",
            str(fixture.root),
            "--checkout",
            str(fixture.candidate.checkout),
            "--expected-source-revision",
            fixture.candidate.revision,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(result.stdout)
    assert summary["verified"] is True
    assert summary["product_active_run_completed"] is False


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    "mutation",
    ["missing", "duplicate", "skip", "false_scope", "active", "provider", "digest"],
)
def test_complete_verifier_rejects_report_claims_even_with_refreshed_raw_hash(
    full_unit_report, runtime, mutation
):
    def mutate(report):
        if mutation == "missing":
            report["cases"].pop()
        elif mutation == "duplicate":
            report["cases"][-1] = deepcopy(report["cases"][0])
        elif mutation == "skip":
            report["cases"][0]["status"] = "SKIP"
        elif mutation == "false_scope":
            report["cases"][0]["scope_id"] = report["formal_scope_id"]
        elif mutation == "active":
            report["product_active_enabled"] = True
        elif mutation == "provider":
            report["external_provider_requests"] = 1
        else:
            report["requirements_digest"] = "sha256:" + "0" * 64

    with _report_change(full_unit_report, runtime, mutate):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_report_cannot_relabel_uninstalled_consumer_as_native_host(
    full_unit_report, runtime
):
    def mutate(observation):
        observation["consumer_module"] = "unit_fixture/invented-consumer.py"

    with _observation_change(full_unit_report, runtime, "baseline.tool.write", mutate):
        with pytest.raises(AdmissionError, match="consumer_outside_case"):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_real_fixture_result_bytes_must_match_reported_host_result(
    full_unit_report, runtime
):
    def mutate(observation):
        frame = next(
            frame
            for frame in observation["frames"]
            if frame["actor"] == "host" and frame["event"] == "tool_result"
        )
        frame["data"]["result_digest"] = "sha256:" + "0" * 64

    with _observation_change(full_unit_report, runtime, "baseline.tool.write", mutate):
        with pytest.raises(AdmissionError, match="host_result_artifact_missing"):
            _verify(full_unit_report)


def test_installed_consumer_change_is_detected_before_conformance_claims(
    full_unit_report,
):
    package = next(
        p
        for p in full_unit_report.candidate.python["packages"]
        if p["distribution"] == "agentguard-langgraph-adapter"
    )
    path = Path(package["module_file"]).parent / "native_langgraph.py"
    original = path.read_bytes()
    try:
        path.write_bytes(original + b"# changed installed code\n")
        with pytest.raises(EvidenceError):
            _verify(full_unit_report)
    finally:
        path.write_bytes(original)


def test_review_authorization_and_candidate_digest_are_verified(full_unit_report):
    fixture = full_unit_report
    reference = fixture.request["review_record"]
    path = fixture.root / reference["path"]
    originals = {
        path: path.read_bytes(),
        fixture.request_path: fixture.request_path.read_bytes(),
    }
    try:
        review = json.loads(path.read_bytes())
        review["candidate_manifest_digest"] = "sha256:" + "0" * 64
        _json(path, review)
        request = json.loads(fixture.request_path.read_bytes())
        request["review_record"] = _ref(fixture.root, path)
        _json(fixture.request_path, request)
        with pytest.raises(AdmissionError):
            _verify(fixture)
    finally:
        for path, content in originals.items():
            path.write_bytes(content)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_policy_write_requires_host_terminal_artifact_not_only_invocation_count(
    full_unit_report, runtime
):
    def mutate(observation):
        frame = next(
            frame
            for frame in observation["frames"]
            if frame["actor"] == "host" and frame["event"] == "tool_result"
        )
        frame["attachments"] = []

    with _observation_change(
        full_unit_report, runtime, "contract.policy.ask.file", mutate
    ):
        with pytest.raises(AdmissionError, match="host_result_artifact_missing"):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_memory_read_cannot_pass_on_prerequisite_boolean_without_source_records(
    full_unit_report, runtime
):
    def mutate(observation):
        row = next(
            frame["data"]
            for frame in observation["frames"]
            if frame["actor"] == "consumer"
            and frame["event"] == "product_authority_selected"
        )
        row.pop("memory_prerequisite", None)

    with _observation_change(
        full_unit_report, runtime, "contract.policy.allow.memory", mutate
    ):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_command_ask_cannot_replace_both_report_ancestry_ids_with_same_invented_id(
    full_unit_report, runtime
):
    def mutate(observation):
        for frame in observation["frames"]:
            if (
                frame["actor"] == "consumer"
                and frame["event"] == "command_input_ancestry"
            ):
                frame["data"]["tool_result_policy_audit_id"] = (
                    "unit:invented-read-result"
                )
            elif frame["actor"] == "consumer" and frame["event"] == "action_proof":
                frame["data"]["ancestor_policy_audit_ids"] = [
                    "unit:invented-read-result"
                ]

    with _observation_change(
        full_unit_report, runtime, "contract.policy.ask.command", mutate
    ):
        with pytest.raises(AdmissionError):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_policy_cannot_replace_typed_target_terminal_with_postgres_row_count(
    full_unit_report, runtime
):
    def mutate(observation):
        row = next(
            frame["data"]
            for frame in observation["frames"]
            if frame["actor"] == "consumer"
            and frame["event"] == "product_authority_selected"
        )
        row.pop("terminal_evidence")

    with _observation_change(
        full_unit_report, runtime, "contract.policy.allow.file", mutate
    ):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("field", ["audit_id", "receipt_digest", "links"])
def test_postgres_target_receipt_must_match_original_typed_receipt(
    full_unit_report, runtime, field
):
    def mutate(observation):
        row = next(
            frame["data"]
            for frame in observation["frames"]
            if frame["actor"] == "postgres" and frame["event"] == "target_receipt"
        )
        if field == "links":
            row["links"]["consumption_id"] = "unit:unrelated-consumption"
        elif field == "receipt_digest":
            row[field] = "sha256:" + "0" * 64
        else:
            row[field] = "unit:unrelated-accepted-audit"

    with _observation_change(
        full_unit_report, runtime, "contract.policy.ask.file", mutate
    ):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_http_consume_cannot_claim_another_lease_while_receipt_is_valid(
    full_unit_report, runtime
):
    def mutate(observation):
        row = next(
            frame["data"]
            for frame in observation["frames"]
            if frame["actor"] == "http" and frame["event"] == "lease_consumed"
        )
        row["lease_id"] = "unit:unrelated-consumed-lease"

    with _observation_change(
        full_unit_report, runtime, "contract.policy.ask.file", mutate
    ):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(full_unit_report)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize(
    "destination",
    ["next_model_request", "subsequent_memory_writes", "subsequent_inbox_messages"],
)
def test_quarantined_memory_content_cannot_enter_any_reported_downstream(
    full_unit_report, runtime, destination
):
    fixture = full_unit_report
    reference = fixture.observations[runtime, "contract.policy.allow.memory"]
    observation = json.loads((fixture.root / reference["path"]).read_bytes())
    isolation = next(
        frame["data"]
        for frame in observation["frames"]
        if frame["event"] == "target_result_isolation"
    )
    path = fixture.root / isolation[destination]["path"]
    original = path.read_bytes()
    try:
        leaked = {"content": isolation["withheld_content"]}
        _json(
            path,
            {"messages": [leaked]} if destination == "next_model_request" else [leaked],
        )

        def mutate(document):
            frame = next(
                frame
                for frame in document["frames"]
                if frame["event"] == "target_result_isolation"
            )
            old = frame["data"][destination]
            replacement = _ref(fixture.root, path)
            frame["data"][destination] = replacement
            frame["attachments"] = [
                replacement if reference == old else reference
                for reference in frame["attachments"]
            ]

        with _observation_change(
            fixture, runtime, "contract.policy.allow.memory", mutate
        ):
            with pytest.raises((AdmissionError, EvidenceError)):
                _verify(fixture)
    finally:
        path.write_bytes(original)


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_command_prerequisite_host_cannot_read_an_unrelated_file(
    full_unit_report, runtime
):
    def mutate(observation):
        for frame in observation["frames"]:
            if (
                frame["event"] in {"tool_call_requested", "tool_invocation"}
                and frame["data"].get("role") == "prerequisite"
            ):
                frame["data"]["arguments"] = {"path": "fixture.txt"}

    with _observation_change(
        full_unit_report, runtime, "contract.policy.ask.command", mutate
    ):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(full_unit_report)


@pytest.mark.parametrize(
    "case_id", ["contract.policy.ask.file", "contract.policy.allow.memory"]
)
def test_langgraph_call_requires_its_observed_start_confirmation(
    full_unit_report, case_id
):
    def mutate(observation):
        starts = [
            frame
            for frame in observation["frames"]
            if frame["event"] == "action_start_confirmed"
        ]
        assert starts
        observation["frames"].remove(starts[0])
        for index, frame in enumerate(observation["frames"]):
            frame["sequence"] = index

    with _observation_change(full_unit_report, "langgraph", case_id, mutate):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(full_unit_report)


def test_openclaw_report_cannot_claim_authoritative_action_start(full_unit_report):
    fixture = full_unit_report
    source = fixture.observations["langgraph", "contract.policy.ask.file"]
    observation = json.loads((fixture.root / source["path"]).read_bytes())
    start = next(
        frame
        for frame in observation["frames"]
        if frame["event"] == "action_start_confirmed"
    )

    def mutate(document):
        frame = deepcopy(start)
        frame["sequence"] = len(document["frames"])
        document["frames"].append(frame)

    with _observation_change(fixture, "openclaw", "contract.policy.ask.file", mutate):
        with pytest.raises((AdmissionError, EvidenceError)):
            _verify(fixture)
