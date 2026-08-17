"""Run the machine-owned LangGraph Operational MVP reference profile.

The profile runner is intentionally a product integration entrypoint rather
than a presentation/demo shell.  It owns configuration admission, a new
artifact root, functional contract status, and a complete SHA-256 inventory.
Effect metrics remain observable data and never decide the process exit code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


PROFILE_SCHEMA_VERSION = "reference-profile/1.0"
ARTIFACT_MANIFEST_SCHEMA_VERSION = "profile-artifact-manifest/1.0"
PROFILE_RESULT_SCHEMA_VERSION = "reference-profile-result/1.0"
PROFILE_PACKAGE_DIR = Path(__file__).resolve().parent / "profiles"
REPO_ROOT = Path(__file__).resolve().parents[2]
SUPPORTED_STORAGE = frozenset({"memory", "postgres"})
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class ExitCode(IntEnum):
    """Stable machine exit contract."""

    PASSED = 0
    FUNCTIONAL_CONTRACT_FAILED = 1
    INVALID_RUN = 2


class ProfileRunError(RuntimeError):
    """Base class for classified profile failures."""


class InvalidProfileRun(ProfileRunError):
    """Configuration, dataset, service, or artifact admission failed."""


@dataclass(frozen=True, slots=True)
class DatasetProfile:
    path: Path
    manifest: Path
    dataset_id: str
    dataset_version: str
    dataset_digest: str
    full_case_count: int
    default_case_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReceiptEligibilityProfile:
    revision: str
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class DashboardProfile:
    required: bool
    routes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReferenceProfile:
    schema_version: str
    profile_id: str
    runtime: str
    agent_adapter: str
    official_decision_source: str
    v2_decision_mode: str
    context_isolation_mode: str
    strong_binding_required: bool
    storage_default: str
    dataset: DatasetProfile
    contract_probes: tuple[str, ...]
    receipt_eligibility: ReceiptEligibilityProfile
    dashboard: DashboardProfile
    effect_metrics_mode: str
    effect_metrics_gate_exit_status: bool
    source_path: Path
    digest: str

    def public_dump(self) -> dict[str, Any]:
        """Return the exact display-safe profile identity written to artifacts."""

        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "profile_digest": self.digest,
            "runtime": self.runtime,
            "agent_adapter": self.agent_adapter,
            "official_decision_source": self.official_decision_source,
            "v2_decision_mode": self.v2_decision_mode,
            "context_isolation_mode": self.context_isolation_mode,
            "strong_binding_required": self.strong_binding_required,
            "storage_default": self.storage_default,
            "dataset": {
                "path": self.dataset.path.relative_to(REPO_ROOT).as_posix(),
                "manifest": self.dataset.manifest.relative_to(REPO_ROOT).as_posix(),
                "dataset_id": self.dataset.dataset_id,
                "dataset_version": self.dataset.dataset_version,
                "dataset_digest": self.dataset.dataset_digest,
                "full_case_count": self.dataset.full_case_count,
                "default_case_ids": list(self.dataset.default_case_ids),
            },
            "contract_probes": list(self.contract_probes),
            "receipt_eligibility": {
                "revision": self.receipt_eligibility.revision,
                "evidence_ref": self.receipt_eligibility.evidence_ref,
            },
            "dashboard": {
                "required": self.dashboard.required,
                "routes": list(self.dashboard.routes),
            },
            "effect_metrics": {
                "mode": self.effect_metrics_mode,
                "gate_exit_status": self.effect_metrics_gate_exit_status,
            },
        }


@dataclass(frozen=True, slots=True)
class RunRequest:
    profile: ReferenceProfile
    artifacts: Path
    storage: str
    full_corpus: bool
    llm_observation: bool


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Artifacts and gate result returned by the live executor."""

    contracts: Mapping[str, Mapping[str, Any]]
    metrics: Mapping[str, Any]
    artifacts: Mapping[str, Any]

    @property
    def functional_passed(self) -> bool:
        expected = set(self.contracts)
        return bool(expected) and all(
            result.get("status") == "passed" for result in self.contracts.values()
        )


Executor = Callable[[RunRequest], ExecutionResult]


class ArtifactDirectory:
    """Own a new artifact directory and write deterministic JSON artifacts."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def create(self) -> None:
        if self.root.exists():
            raise InvalidProfileRun(
                f"artifact directory must not already exist: {self.root}"
            )
        self.root.mkdir(parents=True, exist_ok=False)

    def write_json(self, relative_path: str, payload: Any) -> Path:
        path = self._path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def finalize_manifest(self) -> Path:
        manifest_path = self.root / "sha256-manifest.json"
        entries = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path == manifest_path:
                continue
            if path.is_symlink():
                raise InvalidProfileRun(
                    f"artifact directory must not contain symlinks: {path}"
                )
            entries.append(
                {
                    "relative_path": path.relative_to(self.root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": _file_sha256(path),
                }
            )
        if not entries:
            raise InvalidProfileRun("artifact manifest cannot be empty")
        self.write_json(
            manifest_path.name,
            {
                "schema_version": ARTIFACT_MANIFEST_SCHEMA_VERSION,
                "algorithm": "sha256",
                "self_excluded": manifest_path.name,
                "artifact_count": len(entries),
                "artifacts": entries,
            },
        )
        return manifest_path

    def _path(self, relative_path: str) -> Path:
        candidate = (self.root / relative_path).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            raise InvalidProfileRun(
                f"artifact path escapes the output root: {relative_path}"
            ) from None
        if candidate == self.root:
            raise InvalidProfileRun("artifact path must name a file")
        return candidate


def load_profile(profile: str, *, profile_dir: Path = PROFILE_PACKAGE_DIR) -> ReferenceProfile:
    """Load and strictly validate a packaged machine profile by ID."""

    if _PROFILE_ID.fullmatch(profile) is None:
        raise InvalidProfileRun(f"invalid profile id: {profile!r}")
    path = (profile_dir / f"{profile}.json").resolve()
    expected_parent = profile_dir.resolve()
    try:
        path.relative_to(expected_parent)
    except ValueError:
        raise InvalidProfileRun("profile path escapes the packaged profile directory") from None
    if not path.is_file():
        raise InvalidProfileRun(f"profile not found: {profile}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidProfileRun(f"profile is not valid JSON: {profile}") from exc
    if not isinstance(raw, dict):
        raise InvalidProfileRun("profile root must be a JSON object")
    return _parse_profile(raw, source_path=path)


def run(request: RunRequest, *, executor: Executor | None = None) -> ExitCode:
    """Execute one admitted profile and persist its classified result."""

    _validate_run_request(request)
    artifacts = ArtifactDirectory(request.artifacts)
    artifacts.create()
    artifacts.write_json("profile.json", request.profile.public_dump())
    selected_executor = executor or execute_live_profile
    try:
        result = selected_executor(request)
        _validate_execution_result(request.profile, result)
        artifacts.write_json(
            "contract-results.json",
            {
                "schema_version": "reference-profile-contract-results/1.0",
                "profile_id": request.profile.profile_id,
                "contracts": result.contracts,
            },
        )
        artifacts.write_json(
            "observational-metrics.json",
            {
                "schema_version": "reference-profile-metrics/1.0",
                "gate_exit_status": False,
                "metrics": result.metrics,
            },
        )
        for relative_path, payload in result.artifacts.items():
            artifacts.write_json(relative_path, payload)
        exit_code = (
            ExitCode.PASSED
            if result.functional_passed
            else ExitCode.FUNCTIONAL_CONTRACT_FAILED
        )
        artifacts.write_json(
            "result.json",
            {
                "schema_version": PROFILE_RESULT_SCHEMA_VERSION,
                "profile_id": request.profile.profile_id,
                "storage": request.storage,
                "full_corpus": request.full_corpus,
                "llm_observation": request.llm_observation,
                "status": "passed" if exit_code == ExitCode.PASSED else "failed",
                "exit_code": int(exit_code),
                "effect_metrics_gate_exit_status": False,
            },
        )
        artifacts.finalize_manifest()
        return exit_code
    except Exception:
        # A created output root is retained for diagnostics, but classified
        # invalid runs never get a success-looking result or manifest.
        raise


def execute_live_profile(request: RunRequest) -> ExecutionResult:
    """Execute the real Guard API/LangGraph profile.

    Imported lazily so profile/configuration failures retain exit code 2 even
    when optional live dependencies are unavailable.  The implementation is
    split into ``profile_runtime`` to keep the CLI/profile contract testable.
    """

    try:
        from .profile_runtime import execute_reference_profile
    except ImportError as exc:  # pragma: no cover - installation failure path
        raise InvalidProfileRun("reference profile runtime is unavailable") from exc
    return execute_reference_profile(request)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="run one machine profile")
    run_parser.add_argument("--profile", required=True)
    run_parser.add_argument("--artifacts", required=True, type=Path)
    run_parser.add_argument("--storage", choices=sorted(SUPPORTED_STORAGE), default=None)
    run_parser.add_argument("--full-corpus", action="store_true")
    run_parser.add_argument("--llm-observation", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = load_profile(args.profile)
        request = RunRequest(
            profile=profile,
            artifacts=args.artifacts,
            storage=args.storage or profile.storage_default,
            full_corpus=bool(args.full_corpus),
            llm_observation=bool(args.llm_observation),
        )
        return int(run(request))
    except InvalidProfileRun as exc:
        print(
            json.dumps(
                {
                    "status": "invalid",
                    "exit_code": int(ExitCode.INVALID_RUN),
                    "reason": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return int(ExitCode.INVALID_RUN)
    except Exception as exc:  # service/data/runtime invalidity is code 2
        print(
            json.dumps(
                {
                    "status": "invalid",
                    "exit_code": int(ExitCode.INVALID_RUN),
                    "reason": type(exc).__name__,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return int(ExitCode.INVALID_RUN)


def _parse_profile(raw: Mapping[str, Any], *, source_path: Path) -> ReferenceProfile:
    _exact_keys(
        raw,
        {
            "schema_version",
            "profile_id",
            "runtime",
            "agent_adapter",
            "official_decision_source",
            "v2_decision_mode",
            "context_isolation_mode",
            "strong_binding_required",
            "storage_default",
            "dataset",
            "contract_probes",
            "receipt_eligibility",
            "dashboard",
            "effect_metrics",
        },
        "profile",
    )
    if raw.get("schema_version") != PROFILE_SCHEMA_VERSION:
        raise InvalidProfileRun("unsupported profile schema version")
    profile_id = _required_string(raw, "profile_id", "profile")
    if source_path.stem != profile_id or _PROFILE_ID.fullmatch(profile_id) is None:
        raise InvalidProfileRun("profile id must match its packaged filename")
    _require_equal(raw, "runtime", "langgraph")
    _require_equal(raw, "agent_adapter", "langgraph-demo")
    _require_equal(raw, "official_decision_source", "current")
    _require_equal(raw, "v2_decision_mode", "shadow")
    _require_equal(raw, "context_isolation_mode", "required")
    if raw.get("strong_binding_required") is not True:
        raise InvalidProfileRun("reference profile requires strong binding")
    storage_default = _required_string(raw, "storage_default", "profile")
    if storage_default not in SUPPORTED_STORAGE:
        raise InvalidProfileRun("unsupported default storage backend")

    dataset_raw = _object(raw.get("dataset"), "dataset")
    _exact_keys(
        dataset_raw,
        {
            "path",
            "manifest",
            "dataset_id",
            "dataset_version",
            "dataset_digest",
            "full_case_count",
            "default_case_ids",
        },
        "dataset",
    )
    dataset_path = _repo_path(_required_string(dataset_raw, "path", "dataset"))
    manifest_path = _repo_path(
        _required_string(dataset_raw, "manifest", "dataset")
    )
    dataset_digest = _required_string(dataset_raw, "dataset_digest", "dataset")
    if _SHA256.fullmatch(dataset_digest) is None:
        raise InvalidProfileRun("dataset digest must be a full sha256 digest")
    full_case_count = dataset_raw.get("full_case_count")
    if not isinstance(full_case_count, int) or isinstance(full_case_count, bool) or full_case_count < 1:
        raise InvalidProfileRun("dataset full_case_count must be a positive integer")
    default_case_ids = _string_tuple(
        dataset_raw.get("default_case_ids"), "dataset.default_case_ids"
    )
    if not default_case_ids or len(default_case_ids) != len(set(default_case_ids)):
        raise InvalidProfileRun("default case ids must be non-empty and unique")

    probes = _string_tuple(raw.get("contract_probes"), "contract_probes")
    if not probes or tuple(sorted(probes)) != tuple(sorted(set(probes))):
        raise InvalidProfileRun("contract probes must be non-empty and unique")

    eligibility_raw = _object(raw.get("receipt_eligibility"), "receipt_eligibility")
    _exact_keys(eligibility_raw, {"revision", "evidence_ref"}, "receipt_eligibility")
    dashboard_raw = _object(raw.get("dashboard"), "dashboard")
    _exact_keys(dashboard_raw, {"required", "routes"}, "dashboard")
    if dashboard_raw.get("required") is not True:
        raise InvalidProfileRun("reference profile requires Dashboard Chromium")
    dashboard_routes = _string_tuple(dashboard_raw.get("routes"), "dashboard.routes")
    if not dashboard_routes:
        raise InvalidProfileRun("dashboard routes must not be empty")

    effect_raw = _object(raw.get("effect_metrics"), "effect_metrics")
    _exact_keys(effect_raw, {"mode", "gate_exit_status"}, "effect_metrics")
    if effect_raw.get("mode") != "observational" or effect_raw.get("gate_exit_status") is not False:
        raise InvalidProfileRun("effect metrics must remain non-gating observations")

    digest = "sha256:" + hashlib.sha256(
        json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    return ReferenceProfile(
        schema_version=PROFILE_SCHEMA_VERSION,
        profile_id=profile_id,
        runtime="langgraph",
        agent_adapter="langgraph-demo",
        official_decision_source="current",
        v2_decision_mode="shadow",
        context_isolation_mode="required",
        strong_binding_required=True,
        storage_default=storage_default,
        dataset=DatasetProfile(
            path=dataset_path,
            manifest=manifest_path,
            dataset_id=_required_string(dataset_raw, "dataset_id", "dataset"),
            dataset_version=_required_string(dataset_raw, "dataset_version", "dataset"),
            dataset_digest=dataset_digest,
            full_case_count=full_case_count,
            default_case_ids=default_case_ids,
        ),
        contract_probes=probes,
        receipt_eligibility=ReceiptEligibilityProfile(
            revision=_required_string(
                eligibility_raw, "revision", "receipt_eligibility"
            ),
            evidence_ref=_required_string(
                eligibility_raw, "evidence_ref", "receipt_eligibility"
            ),
        ),
        dashboard=DashboardProfile(required=True, routes=dashboard_routes),
        effect_metrics_mode="observational",
        effect_metrics_gate_exit_status=False,
        source_path=source_path,
        digest=digest,
    )


def _validate_run_request(request: RunRequest) -> None:
    if request.storage not in SUPPORTED_STORAGE:
        raise InvalidProfileRun(f"unsupported storage backend: {request.storage}")
    if request.artifacts.exists():
        raise InvalidProfileRun(
            f"artifact directory must not already exist: {request.artifacts.resolve()}"
        )
    if not request.profile.dataset.path.is_dir():
        raise InvalidProfileRun("profile dataset directory is unavailable")
    if not request.profile.dataset.manifest.is_file():
        raise InvalidProfileRun("profile dataset manifest is unavailable")
    _validate_dataset_manifest(request.profile)
    if request.storage == "postgres" and not _postgres_url():
        raise InvalidProfileRun(
            "--storage postgres requires AGENTGUARD_TEST_DATABASE_URL or AGENTGUARD_DATABASE_URL"
        )


def _validate_dataset_manifest(profile: ReferenceProfile) -> None:
    try:
        manifest = json.loads(profile.dataset.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidProfileRun("dataset manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise InvalidProfileRun("dataset manifest must be an object")
    expected = profile.dataset
    comparisons = {
        "dataset_id": expected.dataset_id,
        "dataset_version": expected.dataset_version,
        "dataset_digest": expected.dataset_digest,
        "case_count": expected.full_case_count,
        "dataset_locked": True,
    }
    mismatches = [
        key for key, value in comparisons.items() if manifest.get(key) != value
    ]
    if mismatches:
        raise InvalidProfileRun(
            "dataset manifest does not match profile: " + ", ".join(mismatches)
        )


def _validate_execution_result(
    profile: ReferenceProfile, result: ExecutionResult
) -> None:
    missing = sorted(set(profile.contract_probes) - set(result.contracts))
    extra = sorted(set(result.contracts) - set(profile.contract_probes))
    if missing or extra:
        raise InvalidProfileRun(
            f"executor contract roster mismatch; missing={missing} extra={extra}"
        )
    for probe_id, probe in result.contracts.items():
        if set(probe) - {"status", "evidence_refs", "reason_code"}:
            raise InvalidProfileRun(f"contract result has extra fields: {probe_id}")
        if probe.get("status") not in {"passed", "failed"}:
            raise InvalidProfileRun(f"contract result status is invalid: {probe_id}")
        refs = probe.get("evidence_refs")
        if not isinstance(refs, list) or not refs or not all(
            isinstance(item, str) and item for item in refs
        ):
            raise InvalidProfileRun(f"contract evidence refs are invalid: {probe_id}")
        if not isinstance(probe.get("reason_code"), str) or not probe["reason_code"]:
            raise InvalidProfileRun(f"contract reason code is invalid: {probe_id}")
    if result.metrics.get("gate_exit_status") not in {None, False}:
        raise InvalidProfileRun("effect metrics cannot gate profile exit")
    for relative_path in result.artifacts:
        if not relative_path.endswith(".json"):
            raise InvalidProfileRun(
                f"executor JSON artifact must use a .json path: {relative_path}"
            )


def _postgres_url() -> str | None:
    for name in ("AGENTGUARD_TEST_DATABASE_URL", "AGENTGUARD_DATABASE_URL"):
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return None


def _repo_path(value: str) -> Path:
    candidate = (REPO_ROOT / value).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError:
        raise InvalidProfileRun(f"profile repository path escapes root: {value}") from None
    return candidate


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise InvalidProfileRun(f"{label} must be an object")
    return value


def _required_string(payload: Mapping[str, Any], key: str, label: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise InvalidProfileRun(f"{label}.{key} must be a non-empty string")
    return value


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise InvalidProfileRun(f"{label} must be an array of non-empty strings")
    return tuple(value)


def _require_equal(payload: Mapping[str, Any], key: str, expected: str) -> None:
    if payload.get(key) != expected:
        raise InvalidProfileRun(f"profile {key} must be {expected!r}")


def _exact_keys(payload: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(payload)
    if actual != expected:
        raise InvalidProfileRun(
            f"{label} keys do not match schema; missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
