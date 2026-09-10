"""Filesystem and JSON evidence contracts; no candidate qualification evidence."""

import os

import pytest

from scripts.product_runtime.evidence import EvidenceError, EvidenceStore, sha256

pytestmark = pytest.mark.contract


def _ref(path, content):
    return {"path": path, "size": len(content), "raw_sha256": sha256(content)}


def test_raw_hash_is_distinct_from_canonical_and_shared_refs_are_allowed(tmp_path):
    content = b'{ "answer": 42 }\n'
    (tmp_path / "value.json").write_bytes(content)
    store = EvidenceStore(tmp_path, max_total_bytes=len(content))
    ref = _ref("value.json", content)
    document = store.read_json(ref)
    assert document.data == {"answer": 42}
    assert document.canonical_digest == sha256(b'{"answer":42}')
    assert document.file.raw_sha256 != document.canonical_digest
    assert store.read_file(ref) is document.file
    store.recheck_reads()


@pytest.mark.parametrize(
    "path",
    ["../value", "/value", "a//b", "a/./b", "a/../b", "a\\b", "value/", "", "a\0b"],
)
def test_noncanonical_paths_are_rejected(tmp_path, path):
    with pytest.raises(EvidenceError, match="path_invalid"):
        EvidenceStore(tmp_path).read_file(_ref(path, b"x"))


@pytest.mark.parametrize(
    "mutation", [{"size": True}, {"size": 1.0}, {"raw_sha256": "A" * 64}, {"other": 0}]
)
def test_refs_reject_coercion_and_unknown_fields(tmp_path, mutation):
    with pytest.raises(EvidenceError, match="reference_invalid"):
        EvidenceStore(tmp_path).read_file({**_ref("file", b"x"), **mutation})


@pytest.mark.parametrize(
    "content",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":1e9999}',
        b'"\xff"',
        b"[" * 66 + b"0" + b"]" * 66,
    ],
)
def test_invalid_or_unbounded_json_is_rejected(tmp_path, content):
    (tmp_path / "input.json").write_bytes(content)
    with pytest.raises(EvidenceError, match="evidence_json"):
        EvidenceStore(tmp_path).read_json(_ref("input.json", content))


def test_linked_or_special_files_and_linked_parents_are_rejected(tmp_path):
    (tmp_path / "real").write_bytes(b"data")
    (tmp_path / "symbolic").symlink_to("real")
    os.link(tmp_path / "real", tmp_path / "hard")
    os.mkfifo(tmp_path / "fifo")
    for name in ("real", "symbolic", "hard", "fifo"):
        with pytest.raises(EvidenceError):
            EvidenceStore(tmp_path).capture(name)
    (tmp_path / "directory").mkdir()
    (tmp_path / "directory" / "file").write_bytes(b"data")
    (tmp_path / "alias").symlink_to("directory", target_is_directory=True)
    with pytest.raises(EvidenceError):
        EvidenceStore(tmp_path).capture("alias/file")
    with pytest.raises(EvidenceError):
        EvidenceStore(tmp_path / "alias")


def test_recheck_detects_same_content_inode_replacement_and_parent_replacement(
    tmp_path,
):
    directory = tmp_path / "parent"
    directory.mkdir()
    path = directory / "file"
    path.write_bytes(b"original")
    store = EvidenceStore(tmp_path)
    store.capture("parent/file")
    directory.rename(tmp_path / "renamed")
    directory.mkdir()
    path.write_bytes(b"original")
    with pytest.raises(EvidenceError, match="directory_changed"):
        store.recheck_reads()
    store = EvidenceStore(tmp_path)
    store.capture("parent/file")
    replacement = directory / "replacement"
    replacement.write_bytes(b"original")
    replacement.replace(path)
    with pytest.raises(EvidenceError, match="file_changed"):
        store.recheck_reads()


def test_file_mutation_during_read_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "file"
    path.write_bytes(b"original")
    read = os.read
    changed = False

    def mutate(descriptor, size):
        nonlocal changed
        result = read(descriptor, size)
        if not changed:
            changed = True
            path.write_bytes(b"replaced")
        return result

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(EvidenceError, match="file_changed"):
        EvidenceStore(tmp_path).capture("file")


def test_conflicting_refs_limits_and_tree_additions_are_rejected(tmp_path):
    (tmp_path / "package").mkdir()
    (tmp_path / "package" / "first").write_bytes(b"first")
    (tmp_path / "second").write_bytes(b"second")
    store = EvidenceStore(tmp_path, max_total_bytes=8)
    first = store.capture("package/first")
    with pytest.raises(EvidenceError, match="reference_conflict"):
        store.read_file({**first.reference(), "raw_sha256": sha256(b"other")})
    with pytest.raises(EvidenceError, match="total_limit"):
        store.capture("second")
    with pytest.raises(EvidenceError, match="file_limit"):
        EvidenceStore(tmp_path).capture("second", max_bytes=3)
    store = EvidenceStore(tmp_path)
    store.tree("package")
    (tmp_path / "package" / "unexpected.py").write_bytes(b"changed import")
    with pytest.raises(EvidenceError, match="tree_changed"):
        store.recheck_reads()
