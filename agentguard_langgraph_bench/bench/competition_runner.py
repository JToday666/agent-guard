"""Strict LangGraph V2 competition runner and artifact contract.

This module owns the frozen five-arm schedule, provider/config admission,
display-safe artifacts and stable 0/1/2 exit semantics.  The live Guard API
executor is intentionally injected: LGV2-B can establish the runner contract
before LGV2-I lands the official selector and TaskFact/RTE wiring.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote, quote_plus

from pydantic import ValidationError

from .competition_models import (
    COMPETITION_CONFIG_SCHEMA_VERSION,
    COMPETITION_PROFILE_ID,
    ArmSpec,
    CompetitionSuite,
    CompetitionConfigurationError,
    CompetitionProfile,
    ContextMode,
    DetectorMode,
    OfficialDecisionSource,
    PlannerSpec,
    RteMode,
    V21Mode,
    V21RolloutMode,
    authoritative_task_digest,
    canonical_sha256,
    load_competition_profile,
)
from .dataset_contract import DatasetContractError, build_dataset_snapshot
from .dataset_loader import load_attack_cases
from .model_exchange import (
    ModelExchangeError,
    ModelExchangeEvidence,
    ModelExchangeOutcome,
    normalize_openai_base_url,
    resolve_api_key,
)
from .models import AttackCase


COMPETITION_RESULT_SCHEMA_VERSION = "competition-report/1.0"
COMPETITION_ADMISSION_SCHEMA_VERSION = "competition-admission/1.0"
COMPETITION_ARTIFACT_MANIFEST_SCHEMA_VERSION = "competition-artifact-manifest/1.0"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARM_IDS = ("A0", "A1", "A2", "A3", "A4")
_PUBLIC_CASE_KEYS = (
    "arm_id",
    "repeat_index",
    "case_id",
    "case_digest",
    "attack_type",
    "is_malicious",
    "run_valid",
    "run_status",
    "instrumentation_plan_mode",
    "llm_enabled",
    "planning_source",
    "guided_plan_applied",
    "fallback_applied",
    "model_invoked",
    "task_input_digest",
    "policy_digest",
    "round_1_source_set_digest",
    "round_1_model_input_digest",
    "tool_schema_digest",
    "observed_arm",
    "task_fact",
    "pre_model_block_evidence",
    "model_exchanges",
    "attack_success",
    "overblocked",
    "task_success",
    "v21_selected",
    "legacy_floor_applied",
    "receipt_covered",
)


class ExitCode(IntEnum):
    PASSED = 0
    FUNCTIONAL_CONTRACT_FAILED = 1
    INVALID_RUN = 2


class CompetitionRunError(RuntimeError):
    """Base class for controlled runner failures."""


class InvalidCompetitionRun(CompetitionRunError):
    """The experiment cannot support an interpretable competition result."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class ProviderRuntimeConfig:
    provider_id: str
    model: str
    base_url: str
    api_key_env: str
    api_key: str = field(repr=False, compare=False)
    temperature: float = 0.0
    request_timeout: float = 60.0
    max_retries: int = 0
    max_tool_rounds: int = 6

    def public_dump(self) -> dict[str, Any]:
        return {
            "protocol": "openai_chat_completions",
            "provider_id": self.provider_id,
            "model": self.model,
            "base_url": self.base_url,
            "endpoint_identity_digest": canonical_sha256(
                {"normalized_openai_base_url": self.base_url}
            ),
            "api_key_env": self.api_key_env,
            "credential_present": True,
            "temperature": self.temperature,
            "request_timeout": self.request_timeout,
            "max_retries": self.max_retries,
            "max_tool_rounds": self.max_tool_rounds,
        }


@dataclass(frozen=True, slots=True)
class ExperimentVariant:
    """A non-qualifying one-arm composition for contracts and demos."""

    v21_mode: V21Mode
    context_mode: ContextMode
    rte_mode: RteMode
    detector_mode: DetectorMode

    def arm_spec(self) -> ArmSpec:
        rollout_mode = self.v21_mode.rollout_mode
        return ArmSpec(
            arm_id="V0",
            guard_enabled=True,
            current_core_enabled=True,
            official_decision_source=(
                OfficialDecisionSource.CURRENT
                if rollout_mode in {None, V21RolloutMode.SHADOW}
                else OfficialDecisionSource.V21
            ),
            v21_enabled=rollout_mode is not None,
            v21_rollout_mode=rollout_mode,
            ct_projection_enabled=(
                rollout_mode is not None and self.detector_mode is DetectorMode.ON
            ),
            context_mode=self.context_mode,
            rte_mode=self.rte_mode,
            detector_mode=self.detector_mode,
        )

    def public_dump(self) -> dict[str, str]:
        return {
            "v21_mode": self.v21_mode.value,
            "context_mode": self.context_mode.value,
            "rte_mode": self.rte_mode.value,
            "detector_mode": self.detector_mode.value,
        }


@dataclass(frozen=True, slots=True)
class RunRequest:
    profile: CompetitionProfile
    artifacts: Path
    provider: ProviderRuntimeConfig
    value_sources: Mapping[str, str]
    selected_case_ids: tuple[str, ...] = ()
    variant: ExperimentVariant | None = None


@dataclass(frozen=True, slots=True)
class ArmRunRequest:
    profile: CompetitionProfile
    arm: ArmSpec
    repeat_index: int
    seed: int
    cases: tuple[AttackCase, ...]
    provider: ProviderRuntimeConfig
    artifact_directory: Path
    suite: CompetitionSuite
    qualification_eligible: bool


@dataclass(frozen=True, slots=True)
class ArmRunResult:
    rows: tuple[Mapping[str, Any], ...]
    contracts: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)


ArmExecutor = Callable[[ArmRunRequest], ArmRunResult]


class ArtifactDirectory:
    """New-root-only deterministic JSON/JSONL writer with full SHA-256 inventory."""

    def __init__(
        self,
        root: Path,
        *,
        forbidden_secrets: Sequence[str] = (),
    ) -> None:
        self.root = root.expanduser().resolve()
        self._forbidden_secret_patterns = _secret_patterns(forbidden_secrets)

    def create(self) -> None:
        if self.root.exists():
            raise InvalidCompetitionRun(
                "artifact_directory_exists",
                "artifact directory must not already exist",
            )
        self.root.mkdir(parents=True, exist_ok=False)

    def write_json(self, relative_path: str, payload: Any) -> Path:
        path = self._path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        )
        self._assert_secret_free(content.encode("utf-8"))
        path.write_text(content, encoding="utf-8")
        return path

    def write_jsonl(self, relative_path: str, rows: Sequence[Any]) -> Path:
        path = self._path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
            for row in rows
        )
        self._assert_secret_free(content.encode("utf-8"))
        path.write_text(content, encoding="utf-8")
        return path

    def finalize_manifest(self, *, status: str) -> Path:
        manifest_path = self.root / "sha256-manifest.json"
        secret_bearing_files = self._secret_bearing_files(exclude=manifest_path)
        if secret_bearing_files:
            # The output root was created exclusively for this run.  Remove only
            # files proven to contain the configured provider credential before
            # producing a safe invalid-run report; never retain or name them in
            # diagnostics.
            for path in secret_bearing_files:
                path.unlink()
            raise InvalidCompetitionRun(
                "artifact_secret_detected",
                "artifact credential scan failed",
            )
        entries: list[dict[str, Any]] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path == manifest_path:
                continue
            if path.is_symlink():
                raise InvalidCompetitionRun(
                    "artifact_symlink",
                    "artifact directory must not contain symbolic links",
                )
            entries.append(
                {
                    "relative_path": path.relative_to(self.root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": _file_sha256(path),
                }
            )
        if not entries:
            raise InvalidCompetitionRun(
                "empty_artifact_manifest", "artifact manifest cannot be empty"
            )
        self.write_json(
            manifest_path.name,
            {
                "schema_version": COMPETITION_ARTIFACT_MANIFEST_SCHEMA_VERSION,
                "algorithm": "sha256",
                "run_status": status,
                "self_excluded": manifest_path.name,
                "secret_scan": {
                    "status": "passed",
                    "files_scanned": len(entries),
                    "credential_variants_checked": len(
                        self._forbidden_secret_patterns
                    ),
                },
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
            raise InvalidCompetitionRun(
                "artifact_path_escape", "artifact path escapes the output root"
            ) from None
        if candidate == self.root:
            raise InvalidCompetitionRun(
                "artifact_path_invalid", "artifact path must name a file"
            )
        return candidate

    def _assert_secret_free(self, content: bytes) -> None:
        if self._contains_secret(content):
            raise InvalidCompetitionRun(
                "artifact_secret_detected",
                "artifact credential scan failed",
            )

    def safe_reason_code(self, value: str) -> str:
        encoded = str(value).encode("utf-8", errors="replace")
        return "artifact_secret_detected" if self._contains_secret(encoded) else value

    def _contains_secret(self, content: bytes) -> bool:
        return any(pattern in content for pattern in self._forbidden_secret_patterns)

    def _secret_bearing_files(self, *, exclude: Path) -> list[Path]:
        contaminated: list[Path] = []
        for path in sorted(self.root.rglob("*")):
            if path == exclude or path.is_symlink() or not path.is_file():
                continue
            try:
                content = path.read_bytes()
            except OSError as exc:
                raise InvalidCompetitionRun(
                    "artifact_scan_failed",
                    "artifact credential scan could not read an output file",
                ) from exc
            if self._contains_secret(content):
                contaminated.append(path)
        return contaminated


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser(
        "run", help="run the frozen LangGraph V2 competition matrix"
    )
    run_parser.add_argument("--profile", default=COMPETITION_PROFILE_ID)
    run_parser.add_argument("--config", type=Path)
    run_parser.add_argument("--artifacts", required=True, type=Path)
    run_parser.add_argument("--llm-provider-id")
    run_parser.add_argument("--llm-model")
    run_parser.add_argument("--llm-base-url")
    run_parser.add_argument("--llm-api-key-env")
    run_parser.add_argument("--temperature", type=float)
    run_parser.add_argument("--request-timeout", type=float)
    run_parser.add_argument("--max-retries", type=int)
    run_parser.add_argument("--max-tool-rounds", type=int)
    run_parser.add_argument("--repeats", type=int)
    run_parser.add_argument("--seed", type=int)
    run_parser.add_argument(
        "--suite",
        choices=[suite.value for suite in CompetitionSuite],
    )
    run_parser.add_argument(
        "--full-corpus",
        action="store_true",
        default=None,
        help="run all 70 frozen cases (mandatory for matrix/product)",
    )
    run_parser.add_argument(
        "--case-id",
        action="append",
        default=None,
        help="select a debug case for contracts/demo; repeat for multiple cases",
    )
    run_parser.add_argument(
        "--v21-mode",
        choices=[mode.value for mode in V21Mode],
    )
    run_parser.add_argument(
        "--context-mode",
        choices=[mode.value for mode in ContextMode],
    )
    run_parser.add_argument(
        "--rte-mode",
        choices=[mode.value for mode in RteMode],
    )
    run_parser.add_argument(
        "--detector-mode",
        choices=[mode.value for mode in DetectorMode],
    )
    return parser


def resolve_run_request(
    args: argparse.Namespace,
    *,
    environ: Mapping[str, str] | None = None,
) -> RunRequest:
    profile = load_competition_profile(args.profile)
    config = _load_run_config(args.config)
    value_sources: dict[str, str] = {
        "planner.provider_id": "json_profile",
        "planner.model": "json_profile",
        "planner.base_url": "json_profile",
        "planner.api_key_env": "json_profile",
        "planner.temperature": "json_profile",
        "planner.request_timeout": "json_profile",
        "planner.max_retries": "json_profile",
        "planner.max_tool_rounds": "json_profile",
        "repeats": "json_profile",
        "seed": "json_profile",
        "suite": "json_profile",
        "full_corpus": "json_profile",
        "case_ids": "default",
        "v21_mode": "suite_default",
        "context_mode": "suite_default",
        "rte_mode": "suite_default",
        "detector_mode": "suite_default",
    }

    planner_values = profile.planner.public_dump()
    for key, value in config.get("planner", {}).items():
        planner_values[key] = value
        value_sources[f"planner.{key}"] = "json_config"
    scalar_values: dict[str, Any] = {
        "repeats": config.get("repeats", profile.repeats),
        "seed": config.get("seed", profile.seed),
    }
    for key in ("repeats", "seed"):
        if key in config:
            value_sources[key] = "json_config"

    suite_value: Any = config.get("suite", profile.suite.value)
    if "suite" in config:
        value_sources["suite"] = "json_config"
    if args.suite is not None:
        suite_value = args.suite
        value_sources["suite"] = "cli"
    try:
        suite = CompetitionSuite(str(suite_value))
    except ValueError as exc:
        raise InvalidCompetitionRun(
            "configuration_invalid", "suite has an invalid value"
        ) from exc

    if args.full_corpus is not None:
        full_corpus: Any = args.full_corpus
        value_sources["full_corpus"] = "cli"
    elif "full_corpus" in config:
        full_corpus = config["full_corpus"]
        value_sources["full_corpus"] = "json_config"
    elif suite in {CompetitionSuite.MATRIX, CompetitionSuite.PRODUCT}:
        full_corpus = profile.full_corpus
    else:
        full_corpus = False
        value_sources["full_corpus"] = "suite_default"
    if not isinstance(full_corpus, bool):
        raise InvalidCompetitionRun(
            "configuration_invalid", "full_corpus must be a boolean"
        )

    raw_case_ids: Any = config.get("case_ids", ())
    if "case_ids" in config:
        value_sources["case_ids"] = "json_config"
    if args.case_id is not None:
        raw_case_ids = args.case_id
        value_sources["case_ids"] = "cli"
    if not isinstance(raw_case_ids, (list, tuple)) or not all(
        isinstance(case_id, str) and case_id for case_id in raw_case_ids
    ):
        raise InvalidCompetitionRun(
            "configuration_invalid", "case_ids must contain non-empty strings"
        )
    selected_case_ids = tuple(raw_case_ids)
    if len(selected_case_ids) != len(set(selected_case_ids)):
        raise InvalidCompetitionRun(
            "configuration_invalid", "case_ids must not contain duplicates"
        )

    variant_values: dict[str, Any] = {
        "v21_mode": V21Mode.ACTIVE.value,
        "context_mode": ContextMode.REQUIRED.value,
        "rte_mode": RteMode.ENFORCE.value,
        "detector_mode": DetectorMode.ON.value,
    }
    variant_fields = tuple(variant_values)
    explicit_variant = False
    for key in variant_fields:
        if key in config:
            variant_values[key] = config[key]
            value_sources[key] = "json_config"
            explicit_variant = True

    cli_planner = {
        "provider_id": args.llm_provider_id,
        "model": args.llm_model,
        "base_url": args.llm_base_url,
        "api_key_env": args.llm_api_key_env,
        "temperature": args.temperature,
        "request_timeout": args.request_timeout,
        "max_retries": args.max_retries,
        "max_tool_rounds": args.max_tool_rounds,
    }
    for key, value in cli_planner.items():
        if value is not None:
            planner_values[key] = value
            value_sources[f"planner.{key}"] = "cli"
    for key, value in (("repeats", args.repeats), ("seed", args.seed)):
        if value is not None:
            scalar_values[key] = value
            value_sources[key] = "cli"
    for key in variant_fields:
        value = getattr(args, key)
        if value is not None:
            variant_values[key] = value
            value_sources[key] = "cli"
            explicit_variant = True

    main_suite = suite in {CompetitionSuite.MATRIX, CompetitionSuite.PRODUCT}
    if main_suite:
        if explicit_variant:
            raise InvalidCompetitionRun(
                "variant_not_allowed_for_suite",
                "matrix/product use the frozen A0-A4 axes; overrides are only valid for contracts/demo",
            )
        if not full_corpus or selected_case_ids:
            raise InvalidCompetitionRun(
                "full_corpus_required",
                "matrix/product require the exact frozen 70-case corpus",
            )
        variant = None
    else:
        if full_corpus and selected_case_ids:
            raise InvalidCompetitionRun(
                "case_selection_conflict",
                "full_corpus and explicit case_ids are mutually exclusive",
            )
        if not full_corpus and not selected_case_ids:
            raise InvalidCompetitionRun(
                "case_selection_required",
                "contracts/demo require --full-corpus or at least one --case-id",
            )
        try:
            variant = ExperimentVariant(
                v21_mode=V21Mode(str(variant_values["v21_mode"])),
                context_mode=ContextMode(str(variant_values["context_mode"])),
                rte_mode=RteMode(str(variant_values["rte_mode"])),
                detector_mode=DetectorMode(str(variant_values["detector_mode"])),
            )
            variant.arm_spec()
        except (CompetitionConfigurationError, ValueError) as exc:
            raise InvalidCompetitionRun("configuration_invalid", str(exc)) from exc

    try:
        normalized_base_url = normalize_openai_base_url(
            str(planner_values.get("base_url") or "")
        )
        planner = PlannerSpec(
            execution_mode=str(planner_values["execution_mode"]),
            protocol=str(planner_values["protocol"]),
            provider_id=str(planner_values["provider_id"]),
            model=str(planner_values.get("model") or ""),
            base_url=normalized_base_url,
            api_key_env=str(planner_values["api_key_env"]),
            temperature=float(planner_values["temperature"]),
            request_timeout=float(planner_values["request_timeout"]),
            max_retries=_strict_int(planner_values["max_retries"], "max_retries"),
            max_tool_rounds=_strict_int(
                planner_values["max_tool_rounds"], "max_tool_rounds"
            ),
            fallback_allowed=bool(planner_values["fallback_allowed"]),
        )
        if not planner.model:
            raise CompetitionConfigurationError("planner model is required")
        effective = profile.with_overrides(
            planner=planner,
            suite=suite,
            full_corpus=full_corpus,
            repeats=_strict_int(scalar_values["repeats"], "repeats"),
            seed=_strict_int(scalar_values["seed"], "seed"),
        )
        api_key = resolve_api_key(planner.api_key_env, environ=environ)
    except (CompetitionConfigurationError, ModelExchangeError, ValueError) as exc:
        raise InvalidCompetitionRun("configuration_invalid", str(exc)) from exc

    provider = ProviderRuntimeConfig(
        provider_id=planner.provider_id,
        model=planner.model,
        base_url=planner.base_url,
        api_key_env=planner.api_key_env,
        api_key=api_key,
        temperature=planner.temperature,
        request_timeout=planner.request_timeout,
        max_retries=planner.max_retries,
        max_tool_rounds=planner.max_tool_rounds,
    )
    return RunRequest(
        profile=effective,
        artifacts=args.artifacts,
        provider=provider,
        value_sources=value_sources,
        selected_case_ids=selected_case_ids,
        variant=variant,
    )


def run(request: RunRequest, *, executor: ArmExecutor | None = None) -> ExitCode:
    """Execute and admit one frozen matrix or explicit non-qualifying variant."""

    if request.artifacts.exists():
        raise InvalidCompetitionRun(
            "artifact_directory_exists", "artifact directory must not already exist"
        )
    cases = _select_cases(_load_frozen_cases(request.profile), request)
    arms = _execution_arms(request)
    qualification_eligible = _qualification_eligible(request, cases, arms)
    selected_executor = executor or _live_executor_unavailable
    artifacts = ArtifactDirectory(
        request.artifacts,
        forbidden_secrets=(request.provider.api_key,),
    )
    artifacts.create()
    all_rows: list[dict[str, Any]] = []
    contract_failures: list[dict[str, str]] = []
    try:
        artifacts.write_json("profile.json", request.profile.public_dump())
        artifacts.write_json(
            "effective-config.json",
            {
                "schema_version": COMPETITION_CONFIG_SCHEMA_VERSION,
                "effective_config_digest": _effective_config_digest(request),
                "value_sources": dict(request.value_sources),
                "profile": request.profile.public_dump(),
                "provider": request.provider.public_dump(),
                "selected_case_ids": list(request.selected_case_ids),
                "variant": request.variant.public_dump() if request.variant else None,
            },
        )
        artifacts.write_json(
            "preflight.json",
            _preflight_payload(request, cases, arms),
        )
        artifacts.write_json("arms.json", [arm.public_dump() for arm in arms])
        artifacts.write_json("schedule.json", _schedule(request, cases, arms))

        for repeat_index in range(request.profile.repeats):
            for arm in arms:
                relative_root = f"arms/{arm.arm_id}/repeat-{repeat_index + 1}"
                arm_request = ArmRunRequest(
                    profile=request.profile,
                    arm=arm,
                    repeat_index=repeat_index,
                    seed=request.profile.seed + repeat_index,
                    cases=cases,
                    provider=request.provider,
                    artifact_directory=artifacts.root / relative_root,
                    suite=request.profile.suite,
                    qualification_eligible=qualification_eligible,
                )
                try:
                    result = selected_executor(arm_request)
                except InvalidCompetitionRun:
                    raise
                except Exception as exc:
                    raise InvalidCompetitionRun(
                        "arm_executor_failed",
                        "competition arm executor failed",
                    ) from exc
                rows, failures = _admit_arm_result(
                    result,
                    request=arm_request,
                )
                all_rows.extend(rows)
                contract_failures.extend(failures)
                _write_arm_artifacts(
                    artifacts,
                    relative_root=relative_root,
                    request=arm_request,
                    rows=rows,
                    contracts=result.contracts,
                )

        completeness = _validate_matrix(request, cases, arms, all_rows)
        expected_case_runs = _expected_case_runs(request)
        if len(all_rows) != expected_case_runs:
            raise InvalidCompetitionRun(
                "matrix_case_count_mismatch",
                "competition matrix does not contain the expected case runs",
            )
        exit_code = (
            ExitCode.FUNCTIONAL_CONTRACT_FAILED
            if contract_failures
            else ExitCode.PASSED
        )
        status = "functional_contract_failed" if contract_failures else "passed"
        artifacts.write_json("completeness.json", completeness)
        artifacts.write_json(
            "contract-results.json",
            {
                "schema_version": "competition-contract-results/1.0",
                "status": "failed" if contract_failures else "passed",
                "failures": contract_failures,
            },
        )
        artifacts.write_json(
            "admission.json",
            {
                "schema_version": COMPETITION_ADMISSION_SCHEMA_VERSION,
                "status": status,
                "expected_case_runs": expected_case_runs,
                "attempted_case_runs": len(all_rows),
                "invalid_case_runs": 0,
                "effect_metrics_gate_exit_status": False,
            },
        )
        report = _competition_report(
            request=request,
            rows=all_rows,
            status=status,
            exit_code=exit_code,
            competition_qualified=(
                exit_code is ExitCode.PASSED and qualification_eligible
            ),
        )
        artifacts.write_json("observational-metrics.json", report["arms"])
        artifacts.write_json("result.json", report)
        artifacts.finalize_manifest(status=status)
        return exit_code
    except InvalidCompetitionRun as exc:
        _write_invalid_artifacts(
            artifacts,
            request=request,
            rows=all_rows,
            reason_code=exc.reason_code,
        )
        return ExitCode.INVALID_RUN


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        request = resolve_run_request(args)
        return int(run(request))
    except InvalidCompetitionRun as exc:
        print(
            json.dumps(
                {
                    "schema_version": COMPETITION_RESULT_SCHEMA_VERSION,
                    "status": "invalid",
                    "competition_qualified": False,
                    "exit_code": int(ExitCode.INVALID_RUN),
                    "reason_code": exc.reason_code,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return int(ExitCode.INVALID_RUN)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": COMPETITION_RESULT_SCHEMA_VERSION,
                    "status": "invalid",
                    "competition_qualified": False,
                    "exit_code": int(ExitCode.INVALID_RUN),
                    "reason_code": "unexpected_runner_failure",
                    "error_type": type(exc).__name__,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return int(ExitCode.INVALID_RUN)


def _load_run_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        raw = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidCompetitionRun(
            "configuration_invalid", "competition config is invalid JSON"
        ) from exc
    if not isinstance(raw, dict):
        raise InvalidCompetitionRun(
            "configuration_invalid", "competition config root must be an object"
        )
    allowed = {
        "schema_version",
        "planner",
        "suite",
        "full_corpus",
        "case_ids",
        "v21_mode",
        "context_mode",
        "rte_mode",
        "detector_mode",
        "repeats",
        "seed",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise InvalidCompetitionRun(
            "configuration_invalid", "competition config contains unknown fields"
        )
    if raw.get("schema_version") != COMPETITION_CONFIG_SCHEMA_VERSION:
        raise InvalidCompetitionRun(
            "configuration_invalid", "competition config schema_version is invalid"
        )
    planner = raw.get("planner", {})
    if not isinstance(planner, dict):
        raise InvalidCompetitionRun(
            "configuration_invalid", "competition planner config must be an object"
        )
    allowed_planner = {
        "execution_mode",
        "protocol",
        "provider_id",
        "model",
        "base_url",
        "api_key_env",
        "temperature",
        "request_timeout",
        "max_retries",
        "max_tool_rounds",
        "fallback_allowed",
    }
    if set(planner) - allowed_planner:
        raise InvalidCompetitionRun(
            "configuration_invalid", "planner config contains unknown fields"
        )
    return raw


def _load_frozen_cases(profile: CompetitionProfile) -> tuple[AttackCase, ...]:
    try:
        if profile.dataset.manifest.parent != profile.dataset.path:
            raise InvalidCompetitionRun(
                "dataset_manifest_mismatch",
                "dataset manifest is not inside the frozen dataset directory",
            )
        cases = tuple(load_attack_cases(profile.dataset.path))
        snapshot = build_dataset_snapshot(profile.dataset.path, cases)
    except (DatasetContractError, ValueError) as exc:
        if isinstance(exc, InvalidCompetitionRun):
            raise
        raise InvalidCompetitionRun(
            "dataset_invalid", "frozen competition dataset is invalid"
        ) from exc
    if (
        len(cases) != profile.dataset.case_count
        or snapshot.dataset_id != profile.dataset.dataset_id
        or snapshot.dataset_version != profile.dataset.dataset_version
        or snapshot.dataset_digest != profile.dataset.dataset_digest
        or not snapshot.dataset_locked
    ):
        raise InvalidCompetitionRun(
            "dataset_identity_mismatch",
            "dataset does not match the frozen competition identity",
        )
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise InvalidCompetitionRun(
            "dataset_duplicate_case", "frozen dataset contains duplicate case ids"
        )
    return cases


def _select_cases(
    cases: Sequence[AttackCase], request: RunRequest
) -> tuple[AttackCase, ...]:
    if request.profile.full_corpus:
        return tuple(cases)
    by_id = {case.case_id: case for case in cases}
    unknown = [case_id for case_id in request.selected_case_ids if case_id not in by_id]
    if unknown:
        raise InvalidCompetitionRun(
            "case_selection_invalid",
            "selected case ids are not in the frozen competition dataset",
        )
    return tuple(by_id[case_id] for case_id in request.selected_case_ids)


def _execution_arms(request: RunRequest) -> tuple[ArmSpec, ...]:
    if request.variant is not None:
        return (request.variant.arm_spec(),)
    return request.profile.arms


def _qualification_eligible(
    request: RunRequest,
    cases: Sequence[AttackCase],
    arms: Sequence[ArmSpec],
) -> bool:
    return (
        request.profile.suite in {CompetitionSuite.MATRIX, CompetitionSuite.PRODUCT}
        and request.profile.full_corpus
        and not request.selected_case_ids
        and len(cases) == request.profile.dataset.case_count == 70
        and tuple(arm.arm_id for arm in arms) == _ARM_IDS
        and request.profile.is_official_active
    )


def _effective_config_digest(request: RunRequest) -> str:
    return canonical_sha256(
        {
            "profile": request.profile.public_dump(),
            "selected_case_ids": list(request.selected_case_ids),
            "variant": request.variant.public_dump() if request.variant else None,
            "provider": request.provider.public_dump(),
        }
    )


def _preflight_payload(
    request: RunRequest,
    cases: Sequence[AttackCase],
    arms: Sequence[ArmSpec],
) -> dict[str, Any]:
    return {
        "schema_version": "competition-preflight/1.0",
        "status": "passed",
        "profile_id": request.profile.profile_id,
        "profile_digest": request.profile.effective_digest,
        "effective_config_digest": _effective_config_digest(request),
        "suite": request.profile.suite.value,
        "full_corpus": request.profile.full_corpus,
        "competition_qualification_eligible": _qualification_eligible(
            request, cases, arms
        ),
        "dataset": request.profile.dataset.public_dump(),
        "case_count": len(cases),
        "case_ids": [case.case_id for case in cases],
        "arm_ids": [arm.arm_id for arm in arms],
        "expected_case_runs": _expected_case_runs(request),
        "provider": request.provider.public_dump(),
        "live_executor_dependency": "LGV2-I",
    }


def _schedule(
    request: RunRequest,
    cases: Sequence[AttackCase],
    arms: Sequence[ArmSpec],
) -> dict[str, Any]:
    return {
        "schema_version": "competition-schedule/1.0",
        "profile_id": request.profile.profile_id,
        "suite": request.profile.suite.value,
        "full_corpus": request.profile.full_corpus,
        "repeats": request.profile.repeats,
        "seed": request.profile.seed,
        "case_order": [case.case_id for case in cases],
        "passes": [
            {
                "repeat_index": repeat_index,
                "arm_id": arm.arm_id,
                "seed": request.profile.seed + repeat_index,
                "case_ids": [case.case_id for case in cases],
            }
            for repeat_index in range(request.profile.repeats)
            for arm in arms
        ],
    }


def _admit_arm_result(
    result: ArmRunResult,
    *,
    request: ArmRunRequest,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if not isinstance(result, ArmRunResult):
        raise InvalidCompetitionRun(
            "arm_result_type_invalid", "arm executor returned an invalid result type"
        )
    rows = [dict(row) for row in result.rows]
    expected_ids = [case.case_id for case in request.cases]
    actual_ids = [str(row.get("case_id") or "") for row in rows]
    if actual_ids != expected_ids:
        raise InvalidCompetitionRun(
            "arm_case_order_mismatch",
            "arm result does not match the frozen case order",
        )
    if len(rows) != len(request.cases):
        raise InvalidCompetitionRun(
            "arm_case_count_mismatch", "arm result has the wrong case count"
        )
    failures = _validate_executor_contracts(result.contracts, request)
    admitted: list[dict[str, Any]] = []
    for case, row in zip(request.cases, rows, strict=True):
        public, row_failures = _admit_case_row(row, case=case, request=request)
        admitted.append(public)
        failures.extend(row_failures)
    return admitted, failures


def _admit_case_row(
    row: Mapping[str, Any],
    *,
    case: AttackCase,
    request: ArmRunRequest,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    arm = request.arm
    identity = f"{arm.arm_id}/r{request.repeat_index}/{case.case_id}"
    expected_case_digest = str(case.metadata.get("case_digest") or "")
    expected_task_digest = canonical_sha256(case.input.payload)
    exact_values = {
        "arm_id": arm.arm_id,
        "repeat_index": request.repeat_index,
        "case_id": case.case_id,
        "case_digest": expected_case_digest,
        "attack_type": case.attack_type,
        "is_malicious": case.is_malicious,
        "instrumentation_plan_mode": "autonomous",
        "llm_enabled": True,
        "guided_plan_applied": False,
        "fallback_applied": False,
        "task_input_digest": expected_task_digest,
    }
    for key, expected in exact_values.items():
        if row.get(key) != expected:
            raise InvalidCompetitionRun(
                "case_row_identity_mismatch",
                f"case row identity or autonomous mode is invalid for {identity}",
            )
    if row.get("run_valid") is not True:
        raise InvalidCompetitionRun(
            "invalid_case_row", f"case row is invalid for {identity}"
        )
    for key in (
        "policy_digest",
        "round_1_source_set_digest",
        "round_1_model_input_digest",
        "tool_schema_digest",
    ):
        if not _is_sha256(row.get(key)):
            raise InvalidCompetitionRun(
                "case_digest_evidence_missing",
                f"case row digest evidence is invalid for {identity}",
            )

    observed = row.get("observed_arm")
    if not isinstance(observed, Mapping) or set(observed) != set(arm.public_dump()):
        raise InvalidCompetitionRun(
            "observed_arm_missing",
            f"case row has no complete observed arm evidence for {identity}",
        )
    failures: list[dict[str, str]] = []
    if dict(observed) != arm.public_dump():
        failures.append(
            {
                "contract": "observed_arm_matches_profile",
                "arm_id": arm.arm_id,
                "case_id": case.case_id,
                "reason_code": "observed_arm_mismatch",
            }
        )

    _validate_task_fact(row.get("task_fact"), case=case, request=request)
    raw_exchanges = row.get("model_exchanges")
    if not isinstance(raw_exchanges, list):
        raise InvalidCompetitionRun(
            "model_exchange_evidence_missing",
            f"model exchange evidence is missing for {identity}",
        )
    exchanges: list[ModelExchangeEvidence] = []
    try:
        exchanges = [
            ModelExchangeEvidence.model_validate(item) for item in raw_exchanges
        ]
    except ValidationError as exc:
        raise InvalidCompetitionRun(
            "model_exchange_evidence_invalid",
            f"model exchange evidence is invalid for {identity}",
        ) from exc
    successful = [item for item in exchanges if item.model_invoked]
    if exchanges and len(successful) != len(exchanges):
        raise InvalidCompetitionRun(
            "model_exchange_failed",
            f"case contains a failed model exchange for {identity}",
        )
    if successful:
        if row.get("model_invoked") is not True:
            raise InvalidCompetitionRun(
                "model_invocation_claim_mismatch",
                f"model_invoked does not match evidence for {identity}",
            )
        if row.get("planning_source") != "llm_autonomous":
            raise InvalidCompetitionRun(
                "planning_source_invalid",
                f"planning source is not autonomous for {identity}",
            )
        _validate_exchange_bindings(
            successful,
            row=row,
            case=case,
            request=request,
        )
    else:
        if row.get("model_invoked") is not False:
            raise InvalidCompetitionRun(
                "model_invocation_claim_mismatch",
                f"model_invoked does not match evidence for {identity}",
            )
        _validate_pre_model_block(row, request=request, identity=identity)

    public = {key: _json_safe(row.get(key)) for key in _PUBLIC_CASE_KEYS if key in row}
    public["model_exchanges"] = [item.public_dump() for item in exchanges]
    return public, failures


def _validate_task_fact(
    value: Any,
    *,
    case: AttackCase,
    request: ArmRunRequest,
) -> None:
    identity = f"{request.arm.arm_id}/{case.case_id}"
    if not isinstance(value, Mapping):
        raise InvalidCompetitionRun(
            "task_fact_evidence_missing",
            f"TaskFact evidence is missing for {identity}",
        )
    if not request.arm.guard_enabled:
        if dict(value) != {"status": "not_applicable"}:
            raise InvalidCompetitionRun(
                "task_fact_baseline_invalid",
                f"guard-off TaskFact evidence is invalid for {identity}",
            )
        return
    required = {
        "status",
        "task_id",
        "trace_id",
        "task_digest",
        "principal_id",
        "agent_id",
        "runtime_binding_id",
    }
    if set(value) != required:
        raise InvalidCompetitionRun(
            "task_fact_evidence_invalid",
            f"TaskFact evidence is incomplete for {identity}",
        )
    expected = {
        "status": "provisioned",
        "task_digest": authoritative_task_digest(case.input.payload),
        "principal_id": request.profile.identity.principal_id,
        "agent_id": request.profile.identity.agent_id,
        "runtime_binding_id": request.profile.identity.runtime_binding_id,
    }
    if any(value.get(key) != wanted for key, wanted in expected.items()):
        raise InvalidCompetitionRun(
            "task_fact_binding_mismatch",
            f"TaskFact binding differs from the profile for {identity}",
        )
    if not isinstance(value.get("task_id"), str) or not value.get("task_id"):
        raise InvalidCompetitionRun(
            "task_fact_identity_invalid", f"TaskFact id is invalid for {identity}"
        )
    if not isinstance(value.get("trace_id"), str) or not value.get("trace_id"):
        raise InvalidCompetitionRun(
            "task_fact_identity_invalid", f"TaskFact trace is invalid for {identity}"
        )


def _validate_exchange_bindings(
    exchanges: Sequence[ModelExchangeEvidence],
    *,
    row: Mapping[str, Any],
    case: AttackCase,
    request: ArmRunRequest,
) -> None:
    expected_transform = request.arm.context_mode is ContextMode.REQUIRED
    for index, evidence in enumerate(exchanges):
        if (
            evidence.case_id != case.case_id
            or evidence.arm_id != request.arm.arm_id
            or evidence.repeat_index != request.repeat_index
            or evidence.provider_id != request.provider.provider_id
            or evidence.model != request.provider.model
            or evidence.context_mode != request.arm.context_mode.value
            or evidence.transform_applied is not expected_transform
            or evidence.outcome is not ModelExchangeOutcome.SUCCESS
        ):
            raise InvalidCompetitionRun(
                "model_exchange_binding_mismatch",
                "model exchange does not bind to its arm, case or provider",
            )
        if evidence.attempt_index > 1 + request.provider.max_retries:
            raise InvalidCompetitionRun(
                "model_exchange_retry_overflow",
                "model exchange exceeds configured retry budget",
            )
        if evidence.tool_schema_digest != row.get("tool_schema_digest"):
            raise InvalidCompetitionRun(
                "tool_schema_digest_mismatch",
                "model exchange tool schema differs from the case row",
            )
        if index == 0 and (
            evidence.source_set_digest != row.get("round_1_source_set_digest")
            or evidence.model_input_digest != row.get("round_1_model_input_digest")
        ):
            raise InvalidCompetitionRun(
                "model_input_digest_mismatch",
                "first model exchange differs from canonical case digests",
            )
        plan_expected = request.arm.context_mode in {
            ContextMode.OBSERVE,
            ContextMode.REQUIRED,
        }
        if plan_expected != (evidence.context_plan_digest is not None):
            raise InvalidCompetitionRun(
                "context_plan_evidence_mismatch",
                "model exchange ContextPlan evidence differs from the arm",
            )


def _validate_pre_model_block(
    row: Mapping[str, Any], *, request: ArmRunRequest, identity: str
) -> None:
    if not request.arm.guard_enabled:
        raise InvalidCompetitionRun(
            "baseline_model_not_invoked",
            f"guard-off baseline did not invoke the model for {identity}",
        )
    evidence = row.get("pre_model_block_evidence")
    if not isinstance(evidence, Mapping):
        raise InvalidCompetitionRun(
            "pre_model_block_evidence_missing",
            f"zero-request row has no authenticated block for {identity}",
        )
    required = {"authenticated", "decision", "decision_id", "audit_id"}
    if (
        set(evidence) != required
        or evidence.get("authenticated") is not True
        or evidence.get("decision") not in {"deny", "ask"}
        or not isinstance(evidence.get("decision_id"), str)
        or not evidence.get("decision_id")
        or not isinstance(evidence.get("audit_id"), str)
        or not evidence.get("audit_id")
        or row.get("planning_source") != "pre_model_blocked"
    ):
        raise InvalidCompetitionRun(
            "pre_model_block_evidence_invalid",
            f"zero-request block evidence is invalid for {identity}",
        )


def _validate_executor_contracts(
    contracts: Mapping[str, Mapping[str, Any]], request: ArmRunRequest
) -> list[dict[str, str]]:
    if not isinstance(contracts, Mapping):
        raise InvalidCompetitionRun(
            "executor_contracts_invalid", "executor contracts must be an object"
        )
    failures: list[dict[str, str]] = []
    for name, payload in sorted(contracts.items()):
        if not isinstance(name, str) or not name or not isinstance(payload, Mapping):
            raise InvalidCompetitionRun(
                "executor_contracts_invalid", "executor contract entry is invalid"
            )
        status = payload.get("status")
        reason_code = payload.get("reason_code")
        if status not in {"passed", "failed"} or not isinstance(reason_code, str):
            raise InvalidCompetitionRun(
                "executor_contracts_invalid", "executor contract status is invalid"
            )
        if status == "failed":
            failures.append(
                {
                    "contract": name,
                    "arm_id": request.arm.arm_id,
                    "case_id": "",
                    "reason_code": reason_code,
                }
            )
    return failures


def _validate_matrix(
    request: RunRequest,
    cases: Sequence[AttackCase],
    arms: Sequence[ArmSpec],
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    arm_ids = tuple(arm.arm_id for arm in arms)
    expected_keys = {
        (repeat_index, arm_id, case.case_id)
        for repeat_index in range(request.profile.repeats)
        for arm_id in arm_ids
        for case in cases
    }
    actual_keys = [
        (
            int(row["repeat_index"]),
            str(row["arm_id"]),
            str(row["case_id"]),
        )
        for row in rows
    ]
    if len(actual_keys) != len(set(actual_keys)) or set(actual_keys) != expected_keys:
        raise InvalidCompetitionRun(
            "matrix_identity_mismatch",
            "competition matrix has duplicate or missing case-run identities",
        )

    task_ids: list[str] = []
    comparisons: list[dict[str, Any]] = []
    frozen_matrix = arm_ids == _ARM_IDS
    for repeat_index in range(request.profile.repeats):
        for case in cases:
            group = {
                str(row["arm_id"]): row
                for row in rows
                if row["repeat_index"] == repeat_index
                and row["case_id"] == case.case_id
            }
            source_digests = {
                str(row["round_1_source_set_digest"]) for row in group.values()
            }
            tool_digests = {str(row["tool_schema_digest"]) for row in group.values()}
            policy_digests = {str(row["policy_digest"]) for row in group.values()}
            if len(group) != len(arms):
                raise InvalidCompetitionRun(
                    "matrix_identity_mismatch",
                    "competition matrix group is incomplete",
                )
            if (
                len(source_digests) != 1
                or len(tool_digests) != 1
                or len(policy_digests) != 1
            ):
                raise InvalidCompetitionRun(
                    "cross_arm_canonical_input_mismatch",
                    "cross-arm canonical input or policy digests differ",
                )
            comparison: dict[str, Any] = {
                "repeat_index": repeat_index,
                "case_id": case.case_id,
                "source_set_digest": next(iter(source_digests)),
                "tool_schema_digest": next(iter(tool_digests)),
            }
            if frozen_matrix:
                raw_input_digests = {
                    str(group[arm_id]["round_1_model_input_digest"])
                    for arm_id in ("A0", "A1", "A2", "A3")
                }
                if len(raw_input_digests) != 1:
                    raise InvalidCompetitionRun(
                        "cross_arm_canonical_input_mismatch",
                        "cross-arm raw model input digests differ",
                    )
                comparison.update(
                    {
                        "raw_model_input_digest": next(iter(raw_input_digests)),
                        "required_model_input_digest": group["A4"][
                            "round_1_model_input_digest"
                        ],
                    }
                )
            else:
                comparison["model_input_digest"] = group[arm_ids[0]][
                    "round_1_model_input_digest"
                ]
            comparisons.append(comparison)
            for arm in arms:
                if arm.guard_enabled:
                    task_ids.append(str(group[arm.arm_id]["task_fact"]["task_id"]))
    if len(task_ids) != len(set(task_ids)):
        raise InvalidCompetitionRun(
            "task_fact_identity_reused",
            "TaskFact ids must be unique per arm, repeat and case",
        )
    return {
        "schema_version": "competition-completeness/1.0",
        "status": "passed",
        "profile_id": request.profile.profile_id,
        "suite": request.profile.suite.value,
        "full_corpus": request.profile.full_corpus,
        "competition_qualification_eligible": _qualification_eligible(
            request, cases, arms
        ),
        "expected_case_runs": _expected_case_runs(request),
        "attempted_case_runs": len(rows),
        "invalid_case_runs": 0,
        "repeats": request.profile.repeats,
        "case_count": len(cases),
        "arm_count": len(arms),
        "arm_ids": list(arm_ids),
        "case_ids": [case.case_id for case in cases],
        "canonical_comparisons": comparisons,
    }


def _write_arm_artifacts(
    artifacts: ArtifactDirectory,
    *,
    relative_root: str,
    request: ArmRunRequest,
    rows: Sequence[Mapping[str, Any]],
    contracts: Mapping[str, Mapping[str, Any]],
) -> None:
    for row in rows:
        case_id = str(row["case_id"])
        case_root = f"{relative_root}/cases/{case_id}"
        artifacts.write_json(f"{case_root}/case_result.json", row)
        artifacts.write_jsonl(
            f"{case_root}/model-exchanges.jsonl",
            list(row.get("model_exchanges") or []),
        )
    artifacts.write_json(f"{relative_root}/run.json", list(rows))
    artifacts.write_json(
        f"{relative_root}/summary.json",
        _arm_metrics(request.arm, rows),
    )
    artifacts.write_json(
        f"{relative_root}/manifest.json",
        {
            "schema_version": "competition-arm-manifest/1.0",
            "arm": request.arm.public_dump(),
            "repeat_index": request.repeat_index,
            "seed": request.seed,
            "case_count": len(rows),
            "case_ids": [row["case_id"] for row in rows],
            "contract_names": sorted(contracts),
        },
    )


def _write_invalid_artifacts(
    artifacts: ArtifactDirectory,
    *,
    request: RunRequest,
    rows: Sequence[Mapping[str, Any]],
    reason_code: str,
) -> None:
    reason_code = artifacts.safe_reason_code(reason_code)
    report = _competition_report(
        request=request,
        rows=rows,
        status="invalid",
        exit_code=ExitCode.INVALID_RUN,
        competition_qualified=False,
    )
    # Invalid diagnostics must remain writable even when malformed public
    # provider labels happened to contain the provider credential.
    report["provider_id"] = None
    report["model"] = None
    report["reason_code"] = reason_code
    artifacts.write_json(
        "admission.json",
        {
            "schema_version": COMPETITION_ADMISSION_SCHEMA_VERSION,
            "status": "invalid",
            "reason_code": reason_code,
            "expected_case_runs": _expected_case_runs(request),
            "attempted_case_runs": len(rows),
            "invalid_case_runs": max(1, _expected_case_runs(request) - len(rows)),
            "effect_metrics_gate_exit_status": False,
        },
    )
    artifacts.write_json("result.json", report)
    artifacts.finalize_manifest(status="invalid")


def _competition_report(
    *,
    request: RunRequest,
    rows: Sequence[Mapping[str, Any]],
    status: str,
    exit_code: ExitCode,
    competition_qualified: bool,
) -> dict[str, Any]:
    arms = _execution_arms(request)
    return {
        "schema_version": COMPETITION_RESULT_SCHEMA_VERSION,
        "profile_id": request.profile.profile_id,
        "suite": request.profile.suite.value,
        "full_corpus": request.profile.full_corpus,
        "variant": request.variant.public_dump() if request.variant else None,
        "status": status,
        "competition_qualified": competition_qualified,
        "exit_code": int(exit_code),
        "expected_case_runs": _expected_case_runs(request),
        "attempted_case_runs": len(rows),
        "invalid_case_runs": sum(1 for row in rows if row.get("run_valid") is not True),
        "provider_id": request.provider.provider_id,
        "model": request.provider.model,
        "effect_metrics_gate_exit_status": False,
        "effective_config_digest": _effective_config_digest(request),
        "arms": [
            _arm_metrics(
                arm,
                [row for row in rows if row.get("arm_id") == arm.arm_id],
            )
            for arm in arms
        ],
    }


def _arm_metrics(arm: ArmSpec, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    evaluable = [row for row in rows if row.get("run_valid") is True]
    malicious = [row for row in evaluable if row.get("is_malicious") is True]
    benign = [row for row in evaluable if row.get("is_malicious") is False]
    receipt_rows = [
        row for row in evaluable if isinstance(row.get("receipt_covered"), bool)
    ]
    v21_rows = [row for row in evaluable if isinstance(row.get("v21_selected"), bool)]
    floor_rows = [
        row for row in evaluable if isinstance(row.get("legacy_floor_applied"), bool)
    ]
    metrics = {
        "arm_id": arm.arm_id,
        "attempted": len(rows),
        "evaluable": len(evaluable),
        "invalid": len(rows) - len(evaluable),
        "asr": _bool_ratio(malicious, "attack_success"),
        "fpr": _bool_ratio(benign, "overblocked"),
        "benign_success": _bool_ratio(benign, "task_success"),
        "v21_selection_rate": _bool_ratio(v21_rows, "v21_selected"),
        "legacy_floor_rate": _bool_ratio(floor_rows, "legacy_floor_applied"),
        "receipt_coverage": _bool_ratio(receipt_rows, "receipt_covered"),
    }
    metrics["counts"] = {
        "malicious": len(malicious),
        "benign": len(benign),
        "attack_success": sum(row.get("attack_success") is True for row in malicious),
        "overblocked": sum(row.get("overblocked") is True for row in benign),
        "benign_success": sum(row.get("task_success") is True for row in benign),
        "v21_selected": sum(row.get("v21_selected") is True for row in v21_rows),
        "legacy_floor_applied": sum(
            row.get("legacy_floor_applied") is True for row in floor_rows
        ),
        "receipt_covered": sum(
            row.get("receipt_covered") is True for row in receipt_rows
        ),
    }
    return metrics


def _bool_ratio(rows: Sequence[Mapping[str, Any]], key: str) -> float | None:
    values = [row.get(key) for row in rows if isinstance(row.get(key), bool)]
    if not values:
        return None
    return sum(value is True for value in values) / len(values)


def _live_executor_unavailable(_: ArmRunRequest) -> ArmRunResult:
    raise InvalidCompetitionRun(
        "live_executor_unavailable",
        "live competition execution requires the LGV2-I integration",
    )


def _expected_case_runs(request: RunRequest) -> int:
    case_count = (
        request.profile.dataset.case_count
        if request.profile.full_corpus
        else len(request.selected_case_ids)
    )
    return case_count * len(_execution_arms(request)) * request.profile.repeats


def _strict_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CompetitionConfigurationError(f"{label} must be an integer")
    return value


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    raise InvalidCompetitionRun(
        "case_artifact_not_json", "case artifact contains a non-JSON value"
    )


def _secret_patterns(values: Sequence[str]) -> tuple[bytes, ...]:
    patterns: set[bytes] = set()
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        raw = value.encode("utf-8")
        encoded_values = {
            value,
            f"Bearer {value}",
            quote(value, safe=""),
            quote_plus(value, safe=""),
            base64.b64encode(raw).decode("ascii"),
            base64.urlsafe_b64encode(raw).decode("ascii"),
        }
        patterns.update(item.encode("utf-8") for item in encoded_values if item)
    return tuple(sorted(patterns))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


if __name__ == "__main__":  # pragma: no cover - exercised through main tests
    raise SystemExit(main())
