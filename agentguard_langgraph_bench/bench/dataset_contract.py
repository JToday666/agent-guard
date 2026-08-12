"""Immutable dataset identity and provenance for trustworthy benchmark runs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

DATASET_MANIFEST_NAME = "dataset_manifest.json"
DATASET_DIGEST_CANONICALIZATION = "utf8-lf"
DEFAULT_DIRECTORY_EXCLUDED_FILES = frozenset({"memory_poisoning_stateful.jsonl"})


class DatasetContractError(ValueError):
    """Raised when a locked dataset no longer matches its committed manifest."""


@dataclass(frozen=True, slots=True)
class DatasetSnapshot:
    dataset_id: str
    dataset_version: str
    dataset_digest: str
    dataset_locked: bool
    selected_case_digest: str
    selected_case_count: int
    manifest_path: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "dataset_version": self.dataset_version,
            "dataset_digest": self.dataset_digest,
            "dataset_locked": self.dataset_locked,
            "selected_case_digest": self.selected_case_digest,
            "selected_case_count": self.selected_case_count,
            "dataset_manifest_path": self.manifest_path,
        }


def attach_case_provenance(
    payload: dict[str, Any],
    *,
    file_path: Path,
    row_index: int,
) -> None:
    metadata = dict(payload.get("metadata") or {})
    metadata.setdefault("dataset_file", file_path.name)
    metadata.setdefault("dataset_file_stem", file_path.stem)
    metadata.setdefault("dataset_row_index", row_index)
    metadata["case_digest"] = _case_digest(payload)
    metadata["provenance"] = {
        "source": "attackbench",
        "source_path": file_path.as_posix(),
        "line": row_index,
    }
    payload["metadata"] = metadata


def build_dataset_snapshot(
    dataset_path: str | Path,
    cases: Iterable[Any],
) -> DatasetSnapshot:
    path = Path(dataset_path)
    manifest_path = _manifest_path(path)
    case_list = list(cases)
    selected_case_digest = _selected_case_digest(case_list)
    if manifest_path is None:
        return DatasetSnapshot(
            dataset_id=path.stem or "unregistered-dataset",
            dataset_version="unlocked",
            dataset_digest=_source_digest(_dataset_files(path)),
            dataset_locked=False,
            selected_case_digest=selected_case_digest,
            selected_case_count=len(case_list),
            manifest_path=None,
        )

    manifest = _read_manifest(manifest_path)
    _validate_locked_manifest(manifest_path, manifest)
    return DatasetSnapshot(
        dataset_id=str(manifest["dataset_id"]),
        dataset_version=str(manifest["dataset_version"]),
        dataset_digest=str(manifest["dataset_digest"]),
        dataset_locked=True,
        selected_case_digest=selected_case_digest,
        selected_case_count=len(case_list),
        manifest_path=str(manifest_path),
    )


def validate_dataset_source(dataset_path: str | Path) -> None:
    path = Path(dataset_path)
    manifest_path = _manifest_path(path)
    if manifest_path is not None:
        _validate_locked_manifest(manifest_path, _read_manifest(manifest_path))


def _manifest_path(path: Path) -> Path | None:
    directory = path if path.is_dir() else path.parent
    candidate = directory / DATASET_MANIFEST_NAME
    return candidate if candidate.is_file() else None


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetContractError("locked dataset manifest is unreadable") from exc
    if not isinstance(payload, dict):
        raise DatasetContractError("locked dataset manifest must be a JSON object")
    return payload


def _validate_locked_manifest(path: Path, manifest: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "dataset_id",
        "dataset_version",
        "dataset_digest",
        "digest_canonicalization",
        "dataset_locked",
        "case_count",
        "files",
    }
    if not required.issubset(manifest) or manifest.get("dataset_locked") is not True:
        raise DatasetContractError("locked dataset manifest is incomplete")
    if manifest.get("digest_canonicalization") != DATASET_DIGEST_CANONICALIZATION:
        raise DatasetContractError(
            "locked dataset digest canonicalization is unsupported"
        )
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise DatasetContractError("locked dataset manifest has no files")

    directory = path.parent
    actual_files = _dataset_files(directory)
    expected_names = [
        str(item.get("name") or "") for item in files if isinstance(item, dict)
    ]
    actual_names = [item.name for item in actual_files]
    if expected_names != actual_names:
        raise DatasetContractError("locked dataset file set does not match manifest")

    case_count = 0
    for expected, actual in zip(files, actual_files, strict=True):
        if not isinstance(expected, dict):
            raise DatasetContractError("locked dataset file entry is invalid")
        actual_count = _jsonl_case_count(actual)
        case_count += actual_count
        if expected.get("sha256") != _file_digest(actual):
            raise DatasetContractError(
                f"locked dataset file digest mismatch: {actual.name}"
            )
        if expected.get("case_count") != actual_count:
            raise DatasetContractError(
                f"locked dataset case count mismatch: {actual.name}"
            )

    if manifest.get("case_count") != case_count:
        raise DatasetContractError("locked dataset total case count mismatch")
    if manifest.get("dataset_digest") != _source_digest(actual_files):
        raise DatasetContractError("locked dataset aggregate digest mismatch")


def _dataset_files(path: Path) -> list[Path]:
    if path.is_dir():
        return [
            item
            for item in sorted(path.glob("*.jsonl"), key=lambda item: item.name)
            if item.name not in DEFAULT_DIRECTORY_EXCLUDED_FILES
        ]
    return [path]


def _source_digest(files: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_canonical_source_bytes(path))
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def _file_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(_canonical_source_bytes(path)).hexdigest()}"


def _canonical_source_bytes(path: Path) -> bytes:
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DatasetContractError(
            f"locked dataset file is not valid UTF-8: {path.name}"
        ) from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _case_digest(payload: dict[str, Any]) -> str:
    canonical = dict(payload)
    metadata = dict(canonical.get("metadata") or {})
    for key in (
        "case_digest",
        "dataset_file",
        "dataset_file_stem",
        "dataset_row_index",
        "provenance",
    ):
        metadata.pop(key, None)
    canonical["metadata"] = metadata
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _selected_case_digest(cases: Iterable[Any]) -> str:
    identities: list[dict[str, str]] = []
    for case in cases:
        metadata = getattr(case, "metadata", {}) or {}
        identities.append(
            {
                "case_id": str(getattr(case, "case_id", "")),
                "case_digest": str(metadata.get("case_digest") or ""),
                "dataset_file": str(metadata.get("dataset_file") or ""),
                "dataset_row_index": str(metadata.get("dataset_row_index") or ""),
            }
        )
    encoded = json.dumps(
        identities,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _jsonl_case_count(path: Path) -> int:
    return sum(
        1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    )
