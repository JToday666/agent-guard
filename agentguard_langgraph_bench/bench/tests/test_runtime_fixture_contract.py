from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.competition_models import (
    load_competition_profile,
)
from agentguard_langgraph_bench.bench.environment import restore_initial_sandbox
from agentguard_langgraph_bench.bench.runtime_fixture_contract import (
    RUNTIME_FIXTURE_ROOT_IDS,
    RuntimeFixtureContractError,
    build_runtime_fixture_snapshot,
)


def _small_bundle(
    root: Path,
    *,
    volatile_content: bytes = b"runtime output\n",
) -> tuple[Path, dict[str, Path]]:
    sandbox = root / "sandbox"
    (sandbox / "outbox").mkdir(parents=True)
    (sandbox / "files/docs").mkdir(parents=True)
    (sandbox / "files/docs/public.txt").write_bytes(b"public fixture\n")
    (sandbox / "api").mkdir()
    (sandbox / "api/requests.jsonl").write_bytes(volatile_content)

    alpha = root / "sources/alpha"
    alpha.mkdir(parents=True)
    (alpha / "fixture.json").write_bytes(b'{"value":1}\n')
    beta = root / "sources/beta"
    beta.mkdir(parents=True)
    (beta / "blob.bin").write_bytes(b"\x00\xfffixture")
    return sandbox, {"alpha": alpha, "beta": beta}


def test_runtime_fixture_digest_is_path_independent_and_deterministic(
    tmp_path: Path,
) -> None:
    first_sandbox, first_sources = _small_bundle(
        tmp_path / "one",
        volatile_content=b"first runtime output\n",
    )
    second_sandbox, second_sources = _small_bundle(
        tmp_path / "different-location",
        volatile_content=b"different runtime output\n",
    )

    first = build_runtime_fixture_snapshot(
        first_sandbox,
        source_roots=first_sources,
    )
    second = build_runtime_fixture_snapshot(
        second_sandbox,
        source_roots=dict(reversed(tuple(second_sources.items()))),
    )

    assert first.bundle_digest == second.bundle_digest
    assert first.public_dump() == second.public_dump()
    assert all("requests.jsonl" not in entry.relative_path for entry in first.entries)


def test_runtime_fixture_content_tamper_changes_bundle_identity(tmp_path: Path) -> None:
    sandbox, sources = _small_bundle(tmp_path)
    original = build_runtime_fixture_snapshot(sandbox, source_roots=sources)

    (sources["alpha"] / "fixture.json").write_bytes(b'{"value":2}\n')
    tampered = build_runtime_fixture_snapshot(sandbox, source_roots=sources)

    assert tampered.bundle_digest != original.bundle_digest


@pytest.mark.parametrize("unsafe_kind", ["symlink", "fifo"])
def test_runtime_fixture_rejects_non_regular_entries(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    sandbox, sources = _small_bundle(tmp_path)
    unsafe = sources["alpha"] / "unsafe"
    if unsafe_kind == "symlink":
        unsafe.symlink_to(sources["alpha"] / "fixture.json")
    else:
        os.mkfifo(unsafe)

    with pytest.raises(RuntimeFixtureContractError) as caught:
        build_runtime_fixture_snapshot(sandbox, source_roots=sources)

    assert caught.value.reason_code == "runtime_fixture_unsafe_file"


def test_runtime_fixture_requires_pristine_empty_outbox(tmp_path: Path) -> None:
    sandbox, sources = _small_bundle(tmp_path)
    (sandbox / "outbox/message.jsonl").write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuntimeFixtureContractError) as caught:
        build_runtime_fixture_snapshot(sandbox, source_roots=sources)

    assert caught.value.reason_code == "runtime_fixture_outbox_not_empty"


def test_packaged_profile_freezes_the_materialized_runtime_bundle(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    restore_initial_sandbox(sandbox)

    snapshot = build_runtime_fixture_snapshot(sandbox)
    profile = load_competition_profile()

    assert snapshot.bundle_digest == profile.dataset.runtime_fixture_bundle_digest
    assert tuple(root.root_id for root in snapshot.roots) == RUNTIME_FIXTURE_ROOT_IDS
    assert snapshot.file_count == sum(root.file_count for root in snapshot.roots)
    assert snapshot.byte_count == sum(root.byte_count for root in snapshot.roots)
