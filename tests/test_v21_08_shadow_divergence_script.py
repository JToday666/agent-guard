"""T7 离线 divergence 分析脚本测试（scripts/v21-shadow-divergence.py）。

夹具口径：经 ``DecisionEvidenceV21`` + ``decision_v21_envelope`` 构造真实
信封，再经 ``sanitize_audit_event``（§21.1/§21.2 redaction + bounded
projection）落为 policy_evaluation AuditEvent JSONL——与 T5 落盘形态逐字
同源，确保脚本解析口径建立在 redaction 后的**存活字段**上。
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_module():
    path = ROOT / "scripts" / "v21-shadow-divergence.py"
    spec = importlib.util.spec_from_file_location("v21_shadow_divergence", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_dependencies():
    from agentguard_core import AuditEvent
    from agentguard_core.decisions.divergence import classify_divergence
    from agentguard_core.decisions.evidence import (
        CoverageMap,
        DecisionEvidenceV21,
        DomainCoverage,
        decision_v21_envelope,
    )
    from guard_api.services.redaction import sanitize_audit_event

    return {
        "AuditEvent": AuditEvent,
        "classify_divergence": classify_divergence,
        "CoverageMap": CoverageMap,
        "DecisionEvidenceV21": DecisionEvidenceV21,
        "DomainCoverage": DomainCoverage,
        "decision_v21_envelope": decision_v21_envelope,
        "sanitize_audit_event": sanitize_audit_event,
    }


def _coverage(deps):
    def domain(domain_name: str):
        return deps["DomainCoverage"](
            domain=domain_name,
            status="complete",
            as_of_sequence={
                "domain": "audit",
                "producer_binding_id": "producer-fixture",
                "value": 1,
            },
            projector_version="v21-07.projector.2",
            reason_codes=[],
        )

    return deps["CoverageMap"](
        **{
            name: domain(name)
            for name in (
                "task",
                "source",
                "capability",
                "behavior",
                "dataflow",
                "memory",
                "runtime_outcome",
            )
        }
    )


def _make_envelope(
    deps,
    *,
    sequence: int,
    legacy_decision: str,
    disposition: str,
    divergence_category: str | None = ...,  # type: ignore[assignment]
) -> dict:
    if divergence_category is ...:
        divergence_category = deps["classify_divergence"](legacy_decision, disposition)
    payload = deps["DecisionEvidenceV21"](
        assessment_id=f"v21-assess-fixture-{sequence}",
        assessment_digest=f"sha256:digest-{sequence:04d}",
        snapshot_id=f"v21-snapshot-fixture-{sequence}",
        snapshot_digest=f"sha256:snapshot-{sequence:04d}",
        state_version=sequence,
        required_domains=["task", "source"],
        coverage=_coverage(deps),
        authority_status="not_required",
        matched_grant_ids=[],
        flow_status="safe",
        flow_path_refs=[],
        policy_violation_ids=[],
        signal_ids=[],
        degradation_ids=[],
        semantic_judgment_id=None,
        semantic_digest=None,
        legacy_decision=legacy_decision,
        v21_fast_disposition=disposition,
        final_decision=legacy_decision,
        mode="shadow",
        divergence_category=divergence_category,
        evidence_refs=[],
    )
    return deps["decision_v21_envelope"](payload.model_dump(mode="json"))


def _make_audit_record(
    deps,
    *,
    sequence: int,
    legacy_decision: str,
    envelope: dict | None,
    record_type: str = "policy_evaluation",
) -> dict:
    blocked = legacy_decision in {"ask", "deny"}
    event = deps["AuditEvent"](
        audit_id=f"audit-divergence-fixture-{sequence}",
        schema_version="0.4",
        record_type=record_type,
        trace_id=f"trace-divergence-{sequence}",
        summary=f"fixture evaluation {sequence}",
        decision=legacy_decision,
        risk_score=10,
        severity="low",
        blocked=blocked,
        reason="fixture",
        links={
            "event_id": f"evt-divergence-{sequence}",
            "decision_id": f"decision-divergence-{sequence}",
        },
        evidence={
            "canonical_request": {"event_id": f"evt-divergence-{sequence}"},
            **(envelope or {}),
        },
    )
    sanitized = deps["sanitize_audit_event"](event)
    return sanitized.model_dump(mode="json")


def _write_jsonl(tmp_path: Path, records: list[dict]) -> Path:
    path = tmp_path / "audit_records.jsonl"
    path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )
    return path


def _fixture_records(deps) -> list[dict]:
    """三类分叉 + parity + 两种降级 + 无信封记录 + 非 policy_evaluation 记录。"""

    records = [
        # §14 三组合（分叉）。
        _make_audit_record(
            deps,
            sequence=1,
            legacy_decision="allow",
            envelope=_make_envelope(
                deps,
                sequence=1,
                legacy_decision="allow",
                disposition="CLEAR_DENY",
            ),
        ),
        _make_audit_record(
            deps,
            sequence=2,
            legacy_decision="ask",
            envelope=_make_envelope(
                deps,
                sequence=2,
                legacy_decision="ask",
                disposition="CLEAR_ALLOW",
            ),
        ),
        _make_audit_record(
            deps,
            sequence=3,
            legacy_decision="deny",
            envelope=_make_envelope(
                deps,
                sequence=3,
                legacy_decision="deny",
                disposition="DEFER",
            ),
        ),
        # parity 对角线（divergence_category=None）。
        _make_audit_record(
            deps,
            sequence=4,
            legacy_decision="allow",
            envelope=_make_envelope(
                deps,
                sequence=4,
                legacy_decision="allow",
                disposition="CLEAR_ALLOW",
            ),
        ),
        # 两种降级类目。
        _make_audit_record(
            deps,
            sequence=5,
            legacy_decision="allow",
            envelope=_make_envelope(
                deps,
                sequence=5,
                legacy_decision="allow",
                disposition="DEFER",
                divergence_category="degraded_no_snapshot",
            ),
        ),
        _make_audit_record(
            deps,
            sequence=6,
            legacy_decision="deny",
            envelope=_make_envelope(
                deps,
                sequence=6,
                legacy_decision="deny",
                disposition="DEFER",
                divergence_category="degraded_component_failure",
            ),
        ),
        # 无信封的 policy_evaluation 记录（shadow flag off 形态）。
        _make_audit_record(deps, sequence=7, legacy_decision="allow", envelope=None),
        # 非 policy_evaluation 记录（应整体跳过）。
        _make_audit_record(
            deps,
            sequence=8,
            legacy_decision="allow",
            envelope=None,
            record_type="runtime_outcome",
        ),
    ]
    return records


def test_sanitized_envelope_survives_shallow_fields(tmp_path: Path) -> None:
    """解析口径锁定：redaction/sanitize 后存活字段支撑聚合。"""

    deps = _build_dependencies()
    record = _make_audit_record(
        deps,
        sequence=1,
        legacy_decision="allow",
        envelope=_make_envelope(
            deps,
            sequence=1,
            legacy_decision="allow",
            disposition="CLEAR_DENY",
        ),
    )
    payload = record["evidence"]["decision_v21"]["payload"]
    assert payload["divergence_category"] == "legacy_allow__v21_clear_deny"
    assert payload["legacy_decision"] == "allow"
    assert payload["v21_fast_disposition"] == "CLEAR_DENY"
    assert payload["mode"] == "shadow"
    assert payload["state_version"] == 1
    assert payload["assessment_id"] == "v21-assess-fixture-1"


def test_aggregates_grid_degraded_and_section_14(tmp_path: Path) -> None:
    module = _load_module()
    deps = _build_dependencies()
    input_path = _write_jsonl(tmp_path, _fixture_records(deps))
    output_dir = tmp_path / "out"

    exit_code = module.main(
        ["--input", str(input_path), "--output-dir", str(output_dir)]
    )

    assert exit_code == 0
    report = json.loads((output_dir / "divergence.json").read_text(encoding="utf-8"))
    assert report["ok"] is True
    assert report["totals"] == {
        "records": 8,
        "with_envelope": 6,
        "parity": 1,
        "divergent": 5,
    }
    assert report["skipped"] == {
        "no_envelope": 1,
        "non_policy_evaluation": 1,
    }
    matrix = report["matrix"]
    assert matrix["allow"]["CLEAR_DENY"] == 1
    assert matrix["ask"]["CLEAR_ALLOW"] == 1
    assert matrix["deny"]["DEFER"] == 2  # §14 分叉 + degraded_component_failure
    assert matrix["allow"]["CLEAR_ALLOW"] == 1  # parity
    assert matrix["allow"]["DEFER"] == 1  # degraded_no_snapshot
    assert report["degraded"] == {
        "degraded_component_failure": 1,
        "degraded_no_snapshot": 1,
    }
    assert report["modes"] == {"shadow": 6}
    section_14 = report["section_14"]
    assert section_14["legacy allow / v21 deny"]["count"] == 1
    assert section_14["legacy allow / v21 deny"]["cases"] == [
        {
            "event_id": "evt-divergence-1",
            "trace_id": "trace-divergence-1",
            "assessment_id": "v21-assess-fixture-1",
        }
    ]
    assert section_14["legacy ask / v21 allow"]["count"] == 1
    assert section_14["legacy ask / v21 allow"]["cases"][0]["event_id"] == (
        "evt-divergence-2"
    )
    assert section_14["legacy deny / v21 defer"]["count"] == 1
    assert section_14["legacy deny / v21 defer"]["cases"][0]["event_id"] == (
        "evt-divergence-3"
    )
    assert report["anomalies"] == []
    markdown = (output_dir / "divergence.md").read_text(encoding="utf-8")
    assert "legacy allow / v21 deny" in markdown
    assert "evt-divergence-1" in markdown


def test_no_envelope_records_are_safely_skipped(tmp_path: Path) -> None:
    module = _load_module()
    deps = _build_dependencies()
    records = [
        _make_audit_record(deps, sequence=index, legacy_decision="allow", envelope=None)
        for index in range(1, 4)
    ]
    input_path = _write_jsonl(tmp_path, records)
    output_dir = tmp_path / "out"

    exit_code = module.main(
        ["--input", str(input_path), "--output-dir", str(output_dir)]
    )

    assert exit_code == 0
    report = json.loads((output_dir / "divergence.json").read_text(encoding="utf-8"))
    assert report["ok"] is True
    assert report["totals"]["with_envelope"] == 0
    assert report["skipped"] == {"no_envelope": 3}


def test_unknown_category_and_grid_mismatch_are_flagged(tmp_path: Path) -> None:
    module = _load_module()
    deps = _build_dependencies()
    records = [
        # 未定义词表值（fail-closed，不得自造新词）。
        _make_audit_record(
            deps,
            sequence=1,
            legacy_decision="allow",
            envelope=_make_envelope(
                deps,
                sequence=1,
                legacy_decision="allow",
                disposition="CLEAR_DENY",
                divergence_category="legacy_allow__v21_clear_deny",
            ),
        ),
        _make_audit_record(
            deps,
            sequence=2,
            legacy_decision="allow",
            envelope=_make_envelope(
                deps,
                sequence=2,
                legacy_decision="allow",
                disposition="CLEAR_DENY",
                divergence_category="totally_bogus_category",
            ),
        ),
        # 词表值与九宫格组合不一致。
        _make_audit_record(
            deps,
            sequence=3,
            legacy_decision="ask",
            envelope=_make_envelope(
                deps,
                sequence=3,
                legacy_decision="ask",
                disposition="CLEAR_ALLOW",
                divergence_category="legacy_deny__v21_defer",
            ),
        ),
    ]
    input_path = _write_jsonl(tmp_path, records)
    output_dir = tmp_path / "out"

    exit_code = module.main(
        ["--input", str(input_path), "--output-dir", str(output_dir)]
    )

    assert exit_code == 1
    report = json.loads((output_dir / "divergence.json").read_text(encoding="utf-8"))
    assert report["ok"] is False
    kinds = sorted(anomaly["kind"] for anomaly in report["anomalies"])
    assert kinds == ["category_grid_mismatch", "unknown_category"]


def test_cli_subprocess_smoke(tmp_path: Path) -> None:
    deps = _build_dependencies()
    input_path = _write_jsonl(tmp_path, _fixture_records(deps))
    output_dir = tmp_path / "out"

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "v21-shadow-divergence.py"),
            "--input",
            str(input_path),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout.strip().splitlines()[-1])
    assert summary["ok"] is True
    assert (output_dir / "divergence.json").is_file()
    assert (output_dir / "divergence.md").is_file()


def test_input_and_store_are_mutually_exclusive(tmp_path: Path) -> None:
    module = _load_module()

    with pytest.raises(ValueError, match="互斥"):
        module.main(
            [
                "--input",
                str(tmp_path / "missing.jsonl"),
                "--store",
                "postgres",
                "--output-dir",
                str(tmp_path),
            ]
        )
