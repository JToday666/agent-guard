from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
import traceback

import pytest

from agentguard_langgraph_adapter import product_envelope_store as storage
from agentguard_langgraph_adapter.product_envelope_store import (
    MAX_RECORD_BYTES,
    MAX_RECORDS,
    MAX_TOTAL_BYTES,
    ProductEnvelopeStore,
    ProductEnvelopeStoreError,
    ProductStoreNamespace,
)

NAMESPACE = ProductStoreNamespace("langgraph", "agent", "principal", "binding:agent")
TOKEN = "hmac-sha256:" + "a" * 64
PAYLOAD = json.dumps(
    {
        "phase": "terminal_pending",
        "terminal_wire": {
            "metadata": {
                "activation_ack": {
                    "ack_token": TOKEN,
                    "issued_at": "2020-01-01T00:00:00.000000001Z",
                }
            }
        },
    },
    indent=2,
).encode()


@pytest.fixture
def opened(tmp_path):
    stores = []

    def make(**options):
        store = ProductEnvelopeStore(
            tmp_path / "queue",
            tmp_path / "private-keys" / "receipt.key",
            namespace=options.pop("namespace", NAMESPACE),
            **options,
        )
        stores.append(store)
        return store

    yield make
    for store in stores:
        store.close()


def filename(record_id="action_001"):
    return hashlib.sha256(record_id.encode()).hexdigest() + ".agq"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def rejects(code):
    return pytest.raises(ProductEnvelopeStoreError, match=f": {code}$")


def test_record_round_trip_encrypts_complete_history_and_survives_restart(
    opened, tmp_path
):
    store = opened()
    original = store.create("action_001", PAYLOAD, kind="action")
    assert store.namespace == NAMESPACE
    assert original.payload == PAYLOAD
    assert original.revision == 1
    assert store.usage().record_count == 1
    path = tmp_path / "queue" / filename()
    encrypted = path.read_bytes()
    assert TOKEN.encode() not in encrypted
    assert b"terminal_wire" not in encrypted
    assert b"issued_at" not in encrypted
    assert original.stored_bytes == len(encrypted)
    assert store.usage().stored_bytes == len(encrypted)
    assert TOKEN not in repr(original)
    assert TOKEN not in repr(store)
    assert "principal" not in repr(NAMESPACE)
    key = tmp_path / "private-keys" / "receipt.key"
    assert len(key.read_bytes()) == 32
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    assert not key.is_relative_to(path.parent)
    store.close()
    restored = opened()
    assert restored.get("action_001") == original
    assert restored.records() == (original,)
    assert restored.get("missing") is None


def test_create_idempotency_cas_and_tombstones_share_one_record(opened, tmp_path):
    store = opened(max_records=1)
    first = store.create("action_001", b'{"phase":"intent"}')
    before = (tmp_path / "queue" / filename()).read_bytes()
    assert store.create("action_001", first.payload) == first
    assert (tmp_path / "queue" / filename()).read_bytes() == before
    with rejects("record_conflict"):
        store.create("action_001", b"different")
    with rejects("record_conflict"):
        store.replace("action_001", b"next", expected_revision=2, kind="action")
    second = store.replace(
        "action_001",
        b'{"phase":"terminal_pending"}',
        expected_revision=1,
        kind="action",
    )
    assert second.revision == 2
    completed = store.replace(
        "action_001",
        b'{"completed_digest":"fixed"}',
        expected_revision=2,
        kind="tombstone",
    )
    assert completed.revision == 3
    assert completed.kind == "tombstone"
    assert store.usage().record_count == 1
    assert len(list((tmp_path / "queue").glob("*.agq"))) == 1
    with rejects("capacity_exceeded"):
        store.create("action_002", b"new")
    with rejects("record_conflict"):
        store.create("action_001", first.payload)


def test_each_ciphertext_write_uses_fresh_12_byte_nonce(opened, tmp_path):
    store = opened()
    store.create("action_001", b"same")
    store.create("action_002", b"same")
    first = json.loads((tmp_path / "queue" / filename()).read_bytes())
    second = json.loads((tmp_path / "queue" / filename("action_002")).read_bytes())
    store.replace("action_001", b"changed", expected_revision=1, kind="action")
    third = json.loads((tmp_path / "queue" / filename()).read_bytes())
    assert len({first["nonce"], second["nonce"], third["nonce"]}) == 3
    assert all(
        len(base64.b64decode(item["nonce"])) == 12 for item in (first, second, third)
    )


@pytest.mark.parametrize("field", ["agent_id", "principal_id", "runtime_binding_id"])
def test_namespace_is_authenticated_without_binding_current_activation(opened, field):
    store = opened()
    store.create("action_001", PAYLOAD)
    store.close()
    data = {
        "runtime": "langgraph",
        "agent_id": "agent",
        "principal_id": "principal",
        "runtime_binding_id": "binding:agent",
    }
    data[field] = "another"
    with rejects("namespace_mismatch"):
        opened(namespace=ProductStoreNamespace(**data))
    assert opened().get("action_001").payload == PAYLOAD


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("kind", "tombstone", "decryption_failed"),
        ("revision", 2, "decryption_failed"),
        ("format", "another", "record_invalid"),
        ("algorithm", "plaintext", "record_invalid"),
        ("nonce", base64.b64encode(b"z" * 12).decode(), "decryption_failed"),
        ("ciphertext", base64.b64encode(b"z" * 32).decode(), "decryption_failed"),
        ("namespace", "different", "namespace_mismatch"),
    ],
)
def test_envelope_tampering_fails_without_deleting_evidence(
    opened, tmp_path, field, value, expected
):
    store = opened()
    store.create("action_001", PAYLOAD)
    path = tmp_path / "queue" / filename()
    raw = json.loads(path.read_bytes())
    raw[field] = value
    changed = canonical(raw)
    path.write_bytes(changed)
    with rejects(expected):
        store.records()
    assert path.read_bytes() == changed
    store.close()
    with rejects(expected):
        opened()
    assert path.exists()


def test_ciphertext_cannot_be_moved_or_relabelled_as_another_record(opened, tmp_path):
    store = opened()
    store.create("action_001", PAYLOAD)
    source = tmp_path / "queue" / filename()
    target = tmp_path / "queue" / filename("action_002")
    source.rename(target)
    with rejects("record_invalid"):
        store.records()
    raw = json.loads(target.read_bytes())
    raw["record_id"] = "action_002"
    target.write_bytes(canonical(raw))
    with rejects("decryption_failed"):
        store.records()


def test_missing_or_changed_key_never_regenerates_existing_history(opened, tmp_path):
    store = opened()
    store.create("action_001", PAYLOAD)
    key = tmp_path / "private-keys" / "receipt.key"
    original = key.read_bytes()
    key.write_bytes(b"b" * 32)
    with rejects("key_invalid"):
        store.records()
    key.write_bytes(original)
    store.close()
    key.unlink()
    with rejects("key_missing"):
        opened()
    assert not key.exists()


@pytest.mark.parametrize(
    "target", ["queue", "private-keys", "private-keys/receipt.key", "record"]
)
def test_permissions_must_remain_private(opened, tmp_path, target):
    store = opened()
    store.create("action_001", PAYLOAD)
    path = tmp_path / ("queue/" + filename() if target == "record" else target)
    path.chmod(0o755 if path.is_dir() else 0o644)
    with rejects("permission_denied"):
        store.records()


@pytest.mark.parametrize("target", ["key", "record"])
def test_hardlinks_are_rejected(opened, tmp_path, target):
    store = opened()
    store.create("action_001", PAYLOAD)
    source = tmp_path / (
        "private-keys/receipt.key" if target == "key" else "queue/" + filename()
    )
    os.link(source, tmp_path / "duplicate")
    with rejects("permission_denied"):
        store.records()


@pytest.mark.parametrize("target", ["key", "record"])
def test_symlinks_and_fifos_never_block_or_follow_untrusted_files(
    opened, tmp_path, target
):
    store = opened()
    store.create("action_001", PAYLOAD)
    source = tmp_path / (
        "private-keys/receipt.key" if target == "key" else "queue/" + filename()
    )
    original = source.read_bytes()
    source.unlink()
    external = tmp_path / "external"
    external.write_bytes(original)
    external.chmod(0o600)
    source.symlink_to(external)
    with rejects("read_failed"):
        store.records()
    source.unlink()
    os.mkfifo(source, 0o600)
    started = time.monotonic()
    with rejects("permission_denied"):
        store.records()
    assert time.monotonic() - started < 1


def test_symlinked_directory_ancestors_and_nonseparated_key_fail(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with rejects("read_failed"):
        ProductEnvelopeStore(
            alias / "queue", real / "keys" / "key", namespace=NAMESPACE
        )
    with rejects("invalid_configuration"):
        ProductEnvelopeStore(
            real / "queue", real / "queue" / "keys" / "key", namespace=NAMESPACE
        )
    assert not (real / "queue").exists()


def test_missing_and_rolled_back_records_fail_during_store_lifetime(opened, tmp_path):
    store = opened()
    store.create("action_001", b"intent")
    path = tmp_path / "queue" / filename()
    old = path.read_bytes()
    store.replace("action_001", b"terminal", expected_revision=1, kind="action")
    path.write_bytes(old)
    with rejects("record_conflict"):
        store.records()
    path.unlink()
    with rejects("record_missing"):
        store.records()


def test_store_lock_excludes_other_instances_and_processes_until_closed(
    opened, tmp_path
):
    store = opened()
    with rejects("store_locked"):
        opened()
    script = """
from agentguard_langgraph_adapter.product_envelope_store import ProductEnvelopeStore, ProductEnvelopeStoreError, ProductStoreNamespace
import sys
try:
    ProductEnvelopeStore(sys.argv[1], sys.argv[2], namespace=ProductStoreNamespace('langgraph', 'agent', 'principal', 'binding:agent'))
except ProductEnvelopeStoreError as error:
    print(error.code)
else:
    raise SystemExit('unexpected second owner')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(tmp_path / "queue"),
            str(tmp_path / "private-keys" / "receipt.key"),
        ],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    assert result.stdout.strip() == "store_locked"
    store.close()
    assert opened().usage().record_count == 0


def test_replaced_lock_path_is_detected(opened, tmp_path):
    store = opened()
    lock = tmp_path / "queue" / ".lock"
    lock.rename(tmp_path / "old-lock")
    lock.touch(mode=0o600)
    with rejects("store_locked"):
        store.records()


@pytest.mark.parametrize("kind", ["action", "receipt", "tombstone", "breaker"])
def test_all_record_kinds_consume_the_same_count_budget(opened, kind):
    store = opened(max_records=1)
    stored = store.create("only", b"payload", kind=kind)
    assert store.usage().record_count == 1
    with rejects("capacity_exceeded"):
        store.create("next", b"payload", kind="receipt")
    assert store.replace(
        "only", b"completed", expected_revision=stored.revision, kind="tombstone"
    )


def test_size_budget_applies_to_encrypted_envelope_not_only_plaintext(opened, tmp_path):
    store = opened(max_record_bytes=1024, max_total_bytes=8192)
    stored = store.create("small", b"a" * 100)
    assert 100 < stored.stored_bytes <= 1024
    with rejects("capacity_exceeded"):
        store.create("oversize", b"a" * 1024)
    assert len(list((tmp_path / "queue").glob("*.agq"))) == 1


def test_atomic_write_reserve_keeps_temporary_and_committed_files_under_total_limit(
    opened, tmp_path, monkeypatch
):
    store = opened(max_record_bytes=1024, max_total_bytes=4096)
    index = 0
    while True:
        try:
            store.create(f"record_{index}", b"p" * 100)
        except ProductEnvelopeStoreError as error:
            assert error.code == "capacity_exceeded"
            break
        index += 1
    assert index > 1
    assert store.usage().stored_bytes <= 4096 - 1024
    real_replace = storage.os.replace
    observed = []

    def replace(*args, **kwargs):
        observed.append(
            sum(path.stat().st_size for path in (tmp_path / "queue").iterdir())
        )
        return real_replace(*args, **kwargs)

    monkeypatch.setattr(storage.os, "replace", replace)
    store.replace("record_0", b"done", expected_revision=1, kind="tombstone")
    assert observed and max(observed) <= 4096


@pytest.mark.parametrize(
    "operation", ["write", "replace", "file_fsync", "directory_fsync"]
)
def test_write_faults_never_claim_commit_or_delete_old_evidence(
    opened, tmp_path, monkeypatch, operation
):
    store = opened()
    store.create("action_001", b"intent")
    real_fsync = storage.os.fsync

    def fail(*_args, **_kwargs):
        raise OSError(TOKEN)

    def fsync(fd):
        is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if is_directory == (operation == "directory_fsync"):
            fail()
        return real_fsync(fd)

    with monkeypatch.context() as patch:
        if operation == "write":
            patch.setattr(storage.os, "write", fail)
        elif operation == "replace":
            patch.setattr(storage.os, "replace", fail)
        else:
            patch.setattr(storage.os, "fsync", fsync)
        with rejects("write_failed") as failure:
            store.replace("action_001", PAYLOAD, expected_revision=1, kind="action")
        assert TOKEN not in repr(failure.value)
        assert TOKEN not in "".join(traceback.format_exception(failure.value))
    assert (tmp_path / "queue" / filename()).exists()
    restored = store.get("action_001")
    if operation == "directory_fsync":
        # rename succeeded but durability is unknown: callers must trip their breaker.
        assert restored.payload == PAYLOAD
    else:
        assert restored.payload == b"intent"
    assert not list((tmp_path / "queue").glob(".tmp-*"))


def test_atomic_commit_fsyncs_file_before_replace_and_directory_after(
    opened, monkeypatch
):
    store = opened()
    steps = []
    real_fsync = storage.os.fsync
    real_replace = storage.os.replace

    def fsync(fd):
        steps.append(
            "directory_sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file_sync"
        )
        return real_fsync(fd)

    def replace(*args, **kwargs):
        steps.append("replace")
        return real_replace(*args, **kwargs)

    monkeypatch.setattr(storage.os, "fsync", fsync)
    monkeypatch.setattr(storage.os, "replace", replace)
    store.create("action_001", PAYLOAD)
    assert steps == ["file_sync", "replace", "directory_sync"]


def test_orphan_temporary_and_invalid_ciphertext_are_retained_for_fail_closed_recovery(
    opened, tmp_path
):
    store = opened()
    store.create("action_001", PAYLOAD)
    temporary = tmp_path / "queue" / ".tmp-interrupted"
    temporary.write_bytes(b"partial encrypted record")
    temporary.chmod(0o600)
    with rejects("orphan_temporary"):
        store.records()
    store.close()
    with rejects("orphan_temporary"):
        opened()
    assert temporary.exists()


def test_deeply_nested_corrupt_envelope_uses_fixed_error_diagnostics(opened, tmp_path):
    store = opened()
    store.create("action_001", PAYLOAD)
    path = tmp_path / "queue" / filename()
    corrupted = ("[" * 2_000 + json.dumps(TOKEN) + "]" * 2_000).encode()
    path.write_bytes(corrupted)
    with rejects("record_invalid") as failure:
        store.records()
    assert TOKEN not in "".join(traceback.format_exception(failure.value))
    assert path.read_bytes() == corrupted
    store.close()
    with rejects("record_invalid"):
        opened()
    assert path.read_bytes() == corrupted


@pytest.mark.parametrize(
    "limits",
    [
        {"max_records": MAX_RECORDS + 1},
        {"max_record_bytes": MAX_RECORD_BYTES + 1},
        {"max_total_bytes": MAX_TOTAL_BYTES + 1},
        {"max_records": True},
        {"max_total_bytes": 1024, "max_record_bytes": 1024},
    ],
)
def test_config_cannot_raise_frozen_limits(opened, limits):
    with rejects("invalid_configuration"):
        opened(**limits)


def test_payload_is_immutable_and_closed_store_cannot_be_reused(opened):
    store = opened()
    with rejects("record_invalid"):
        store.create("action_001", bytearray(PAYLOAD))
    with rejects("record_invalid"):
        store.create("../escape", PAYLOAD)
    with rejects("record_invalid"):
        store.create("action_001", PAYLOAD, kind="unknown")
    with rejects("record_missing"):
        store.replace("missing", PAYLOAD, expected_revision=1, kind="action")
    store.close()
    with rejects("store_closed"):
        store.create("action_001", PAYLOAD)
