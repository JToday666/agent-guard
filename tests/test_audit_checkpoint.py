from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentguard_core import AuditEvent
from guard_api.services import audit_checkpoint as audit_checkpoint_module
from guard_api.services.audit_checkpoint import (
    AuditCheckpointIntegrityError,
    AuditCheckpointIoError,
    AuditCheckpointService,
)
from guard_api.storage.integrity import attach_audit_integrity, canonical_json_bytes
from guard_api.storage.memory import MemoryControlPlaneStore

SIGNING_KEY = b"checkpoint-test-key-material-32b"


def test_checkpoint_log_tracks_only_advanced_heads_and_reports_lag(tmp_path) -> None:
    store = MemoryControlPlaneStore()
    path = tmp_path / "audit-checkpoints.jsonl"
    service = _service(store, path)

    assert service.initialize().status == "empty"
    store.add_audit_event(_event("audit_checkpoint_1"))

    first = service.checkpoint()
    first_size = path.stat().st_size
    replay = service.checkpoint()

    assert first.status == "current"
    assert first.checkpoint_sequence == 1
    assert replay.status == "current"
    assert path.stat().st_size == first_size

    store.add_audit_event(_event("audit_checkpoint_2"))
    stale = service.inspect(store.verify_audit_integrity())
    current = service.checkpoint()

    assert stale.status == "stale"
    assert stale.lag == 1
    assert current.status == "current"
    assert current.checkpoint_sequence == 2
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2
    assert SIGNING_KEY.decode("ascii") not in path.read_text(encoding="utf-8")


def test_checkpoint_signature_tampering_is_reported_without_trusting_record(
    tmp_path,
) -> None:
    store = MemoryControlPlaneStore()
    store.add_audit_event(_event("audit_checkpoint_signature"))
    path = tmp_path / "audit-checkpoints.jsonl"
    service = _service(store, path)
    service.initialize()

    record = json.loads(path.read_text(encoding="utf-8"))
    record["signature"]["value"] = "A" * 43
    path.write_bytes(canonical_json_bytes(record) + b"\n")

    cached_status = service.inspect(store.verify_audit_integrity())
    restarted = _service(store, path)
    status = restarted.inspect(store.verify_audit_integrity())

    assert cached_status.status == "invalid"
    assert cached_status.error_code in {
        "AUDIT_CHECKPOINT_MUTATED",
        "AUDIT_CHECKPOINT_REPLACED",
    }
    assert status.status == "invalid"
    assert status.error_code == "AUDIT_CHECKPOINT_SIGNATURE_MISMATCH"
    with pytest.raises(
        AuditCheckpointIntegrityError,
        match="AUDIT_CHECKPOINT_SIGNATURE_MISMATCH",
    ):
        restarted.initialize()


def test_checkpoint_detects_a_validly_rehashed_database_rewrite(tmp_path) -> None:
    store = MemoryControlPlaneStore()
    store.add_audit_event(_event("audit_checkpoint_database"))
    path = tmp_path / "audit-checkpoints.jsonl"
    service = _service(store, path)
    service.initialize()

    rewritten = attach_audit_integrity(
        store.audit_events[0].model_copy(update={"reason": "rewritten"}),
        sequence=1,
        prev_hash=None,
    )
    store.audit_events[0] = rewritten
    store.audit_events_by_id[rewritten.audit_id] = rewritten

    chain_status = store.verify_audit_integrity()
    anchor_status = service.inspect(chain_status)

    assert chain_status.valid is True
    assert anchor_status.status == "invalid"
    assert anchor_status.error_code == "AUDIT_CHECKPOINT_DATABASE_MISMATCH"


def test_checkpoint_serializes_independent_service_instances(tmp_path) -> None:
    store = MemoryControlPlaneStore()
    store.add_audit_event(_event("audit_checkpoint_concurrent"))
    path = tmp_path / "audit-checkpoints.jsonl"
    services = (_service(store, path), _service(store, path))

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda service: service.checkpoint(), services))

    assert [status.status for status in statuses] == ["current", "current"]
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1
    assert _service(store, path).inspect(store.verify_audit_integrity()).status == "current"


@pytest.mark.parametrize(
    ("operation", "expected_code"),
    [
        (audit_checkpoint_module._acquire_file_lock, "AUDIT_CHECKPOINT_LOCK_FAILED"),
        (audit_checkpoint_module._release_file_lock, "AUDIT_CHECKPOINT_UNLOCK_FAILED"),
    ],
)
def test_checkpoint_lock_os_errors_have_stable_codes(
    tmp_path,
    monkeypatch,
    operation,
    expected_code,
) -> None:
    path = tmp_path / "audit-checkpoints.jsonl"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT)

    def fail_lock(*_args) -> None:
        raise OSError("simulated lock failure")

    if sys.platform == "win32":
        monkeypatch.setattr(audit_checkpoint_module.msvcrt, "locking", fail_lock)
    else:
        monkeypatch.setattr(audit_checkpoint_module.fcntl, "flock", fail_lock)
    try:
        with pytest.raises(AuditCheckpointIoError) as error:
            if operation is audit_checkpoint_module._acquire_file_lock:
                operation(descriptor, exclusive=True)
            else:
                operation(descriptor)
    finally:
        os.close(descriptor)

    assert error.value.code == expected_code


def _service(
    store: MemoryControlPlaneStore,
    path: Path,
) -> AuditCheckpointService:
    return AuditCheckpointService(
        store=store,
        path=path,
        signing_key=SIGNING_KEY,
        key_id="test-key-2026",
        clock=lambda: datetime(2026, 8, 10, tzinfo=timezone.utc),
    )


def _event(audit_id: str) -> AuditEvent:
    return AuditEvent(
        audit_id=audit_id,
        trace_id="trace_checkpoint",
        summary="checkpoint test",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="ok",
    )
