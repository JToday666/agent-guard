"""Strict public configuration models for the LangGraph V2 competition runner.

The competition configuration deliberately keeps the current decision source and
the V2 rollout mode on separate axes.  In particular, arm A1 is current-Core
official with V2 disabled; ``current`` is never encoded as a V2 mode.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence


COMPETITION_PROFILE_SCHEMA_VERSION = "competition-langgraph-profile/1.0"
COMPETITION_CONFIG_SCHEMA_VERSION = "competition-langgraph-config/1.0"
COMPETITION_PROFILE_ID = "competition-langgraph-v2"
PROFILE_PACKAGE_DIR = Path(__file__).resolve().parent / "profiles"
REPO_ROOT = Path(__file__).resolve().parents[2]

_PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARM_IDS = ("A0", "A1", "A2", "A3", "A4")


class CompetitionConfigurationError(ValueError):
    """The competition profile or one of its public overrides is invalid."""


class V21RolloutMode(str, Enum):
    SHADOW = "shadow"
    LIMITED_ENABLE = "limited_enable"
    ACTIVE = "active"


class V21Mode(str, Enum):
    OFF = "off"
    SHADOW = "shadow"
    LIMITED_ENABLE = "limited_enable"
    ACTIVE = "active"

    @property
    def rollout_mode(self) -> V21RolloutMode | None:
        return None if self is V21Mode.OFF else V21RolloutMode(self.value)


class CompetitionSuite(str, Enum):
    CONTRACTS = "contracts"
    MATRIX = "matrix"
    PRODUCT = "product"
    DEMO = "demo"


class OfficialDecisionSource(str, Enum):
    NONE = "none"
    CURRENT = "current"
    V21 = "v21"


class ContextMode(str, Enum):
    OFF = "off"
    OBSERVE = "observe"
    REQUIRED = "required"


class RteMode(str, Enum):
    OFF = "off"
    OBSERVE = "observe"
    ENFORCE = "enforce"


class DetectorMode(str, Enum):
    OFF = "off"
    ON = "on"


@dataclass(frozen=True, slots=True)
class DatasetSpec:
    path: Path
    manifest: Path
    dataset_id: str
    dataset_version: str
    dataset_digest: str
    case_count: int

    def public_dump(self) -> dict[str, Any]:
        return {
            "path": _repo_relative(self.path),
            "manifest": _repo_relative(self.manifest),
            "dataset_id": self.dataset_id,
            "dataset_version": self.dataset_version,
            "dataset_digest": self.dataset_digest,
            "case_count": self.case_count,
        }


@dataclass(frozen=True, slots=True)
class IdentitySpec:
    principal_id: str
    agent_id: str
    runtime_binding_id: str

    def __post_init__(self) -> None:
        if not self.principal_id or not self.agent_id:
            raise CompetitionConfigurationError(
                "competition identity requires principal_id and agent_id"
            )
        expected_binding = f"binding:{self.principal_id}"
        if self.runtime_binding_id != expected_binding:
            raise CompetitionConfigurationError(
                "competition runtime_binding_id must equal the server-derived "
                f"{expected_binding!r}"
            )

    def public_dump(self) -> dict[str, str]:
        return {
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "runtime_binding_id": self.runtime_binding_id,
        }


@dataclass(frozen=True, slots=True)
class PlannerSpec:
    execution_mode: str = "autonomous_llm"
    protocol: str = "openai_chat_completions"
    provider_id: str = "openai-compatible"
    model: str = ""
    base_url: str = ""
    api_key_env: str = "AGENTGUARD_LLM_API_KEY"
    temperature: float = 0.0
    request_timeout: float = 60.0
    max_retries: int = 0
    max_tool_rounds: int = 6
    fallback_allowed: bool = False

    def __post_init__(self) -> None:
        if self.execution_mode != "autonomous_llm":
            raise CompetitionConfigurationError(
                "competition planner execution_mode must be autonomous_llm"
            )
        if self.protocol != "openai_chat_completions":
            raise CompetitionConfigurationError(
                "competition planner protocol must be openai_chat_completions"
            )
        if not self.provider_id or not _PROFILE_ID.fullmatch(self.provider_id):
            raise CompetitionConfigurationError(
                "planner provider_id must be a lowercase slug"
            )
        if not _ENV_NAME.fullmatch(self.api_key_env):
            raise CompetitionConfigurationError(
                "planner api_key_env must be an explicit environment variable name"
            )
        if self.temperature != 0:
            raise CompetitionConfigurationError(
                "competition planner temperature must be zero"
            )
        if self.request_timeout <= 0:
            raise CompetitionConfigurationError(
                "planner request_timeout must be greater than zero"
            )
        if self.max_retries < 0:
            raise CompetitionConfigurationError(
                "planner max_retries must be greater than or equal to zero"
            )
        if self.max_tool_rounds <= 0:
            raise CompetitionConfigurationError(
                "planner max_tool_rounds must be greater than zero"
            )
        if self.fallback_allowed:
            raise CompetitionConfigurationError(
                "competition planner fallback must remain disabled"
            )

    def public_dump(self) -> dict[str, Any]:
        return {
            "execution_mode": self.execution_mode,
            "protocol": self.protocol,
            "provider_id": self.provider_id,
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "temperature": self.temperature,
            "request_timeout": self.request_timeout,
            "max_retries": self.max_retries,
            "max_tool_rounds": self.max_tool_rounds,
            "fallback_allowed": self.fallback_allowed,
        }


@dataclass(frozen=True, slots=True)
class ArmSpec:
    arm_id: str
    guard_enabled: bool
    current_core_enabled: bool
    official_decision_source: OfficialDecisionSource
    v21_enabled: bool
    v21_rollout_mode: V21RolloutMode | None
    ct_projection_enabled: bool
    context_mode: ContextMode
    rte_mode: RteMode
    detector_mode: DetectorMode

    def __post_init__(self) -> None:
        if self.arm_id not in {*_ARM_IDS, "V0"}:
            raise CompetitionConfigurationError(
                f"unknown competition arm: {self.arm_id}"
            )
        if self.v21_enabled != (self.v21_rollout_mode is not None):
            raise CompetitionConfigurationError(
                f"{self.arm_id} must keep v21_enabled and rollout mode consistent"
            )
        if not self.guard_enabled:
            if any(
                (
                    self.current_core_enabled,
                    self.v21_enabled,
                    self.ct_projection_enabled,
                    self.context_mode is not ContextMode.OFF,
                    self.rte_mode is not RteMode.OFF,
                    self.detector_mode is not DetectorMode.OFF,
                    self.official_decision_source is not OfficialDecisionSource.NONE,
                )
            ):
                raise CompetitionConfigurationError(
                    f"{self.arm_id} guard-off arm cannot enable guarded features"
                )
        if self.guard_enabled and not self.current_core_enabled:
            raise CompetitionConfigurationError(
                f"{self.arm_id} guarded arm must retain the current safety floor"
            )
        if self.context_mode is not ContextMode.OFF and not self.guard_enabled:
            raise CompetitionConfigurationError(
                f"{self.arm_id} context mode requires the guard"
            )
        if self.rte_mode is RteMode.ENFORCE and not self.guard_enabled:
            raise CompetitionConfigurationError(
                f"{self.arm_id} RTE enforcement requires the guard"
            )
        if self.ct_projection_enabled and not self.v21_enabled:
            raise CompetitionConfigurationError(
                f"{self.arm_id} CT projection requires V2 materials"
            )
        if self.v21_rollout_mode is V21RolloutMode.SHADOW:
            if self.official_decision_source is not OfficialDecisionSource.CURRENT:
                raise CompetitionConfigurationError(
                    f"{self.arm_id} shadow V2 must keep current official"
                )
        elif self.v21_enabled:
            if self.official_decision_source is not OfficialDecisionSource.V21:
                raise CompetitionConfigurationError(
                    f"{self.arm_id} official V2 mode must select V2 authority"
                )

    def public_dump(self) -> dict[str, Any]:
        return {
            "arm_id": self.arm_id,
            "guard_enabled": self.guard_enabled,
            "current_core_enabled": self.current_core_enabled,
            "official_decision_source": self.official_decision_source.value,
            "v21_enabled": self.v21_enabled,
            "v21_rollout_mode": (
                self.v21_rollout_mode.value if self.v21_rollout_mode else None
            ),
            "ct_projection_enabled": self.ct_projection_enabled,
            "context_mode": self.context_mode.value,
            "rte_mode": self.rte_mode.value,
            "detector_mode": self.detector_mode.value,
        }


@dataclass(frozen=True, slots=True)
class CompetitionProfile:
    schema_version: str
    profile_id: str
    runtime: str
    agent_adapter: str
    identity: IdentitySpec
    dataset: DatasetSpec
    planner: PlannerSpec
    suite: CompetitionSuite
    full_corpus: bool
    v21_rollout_mode: V21RolloutMode
    repeats: int
    seed: int
    arms: tuple[ArmSpec, ...]
    source_path: Path
    source_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != COMPETITION_PROFILE_SCHEMA_VERSION:
            raise CompetitionConfigurationError(
                "unsupported competition profile schema_version"
            )
        if self.profile_id != COMPETITION_PROFILE_ID:
            raise CompetitionConfigurationError("unsupported competition profile_id")
        if self.runtime != "langgraph" or self.agent_adapter != "langgraph-demo":
            raise CompetitionConfigurationError(
                "competition profile is LangGraph demo-adapter only"
            )
        if self.repeats <= 0:
            raise CompetitionConfigurationError("profile repeats must be positive")
        if self.dataset.case_count != 70:
            raise CompetitionConfigurationError(
                "competition profile must freeze exactly 70 cases"
            )
        if not _SHA256.fullmatch(self.dataset.dataset_digest):
            raise CompetitionConfigurationError("dataset_digest must be sha256")
        if not _SHA256.fullmatch(self.source_digest):
            raise CompetitionConfigurationError("profile source digest must be sha256")
        _validate_frozen_roster(self.arms, self.v21_rollout_mode)

    @property
    def is_official_active(self) -> bool:
        return self.v21_rollout_mode is V21RolloutMode.ACTIVE

    def with_overrides(
        self,
        *,
        planner: PlannerSpec | None = None,
        suite: CompetitionSuite | None = None,
        full_corpus: bool | None = None,
        v21_rollout_mode: V21RolloutMode | None = None,
        repeats: int | None = None,
        seed: int | None = None,
    ) -> "CompetitionProfile":
        selected_mode = v21_rollout_mode or self.v21_rollout_mode
        arms = tuple(
            _arm_with_profile_rollout(arm, selected_mode)
            if arm.arm_id in {"A3", "A4"}
            else arm
            for arm in self.arms
        )
        return replace(
            self,
            planner=planner or self.planner,
            suite=suite or self.suite,
            full_corpus=(self.full_corpus if full_corpus is None else full_corpus),
            v21_rollout_mode=selected_mode,
            repeats=self.repeats if repeats is None else repeats,
            seed=self.seed if seed is None else seed,
            arms=arms,
        )

    def public_dump(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "profile_source_digest": self.source_digest,
            "runtime": self.runtime,
            "agent_adapter": self.agent_adapter,
            "identity": self.identity.public_dump(),
            "dataset": self.dataset.public_dump(),
            "planner": self.planner.public_dump(),
            "suite": self.suite.value,
            "full_corpus": self.full_corpus,
            "v21_rollout_mode": self.v21_rollout_mode.value,
            "repeats": self.repeats,
            "seed": self.seed,
            "arms": [arm.public_dump() for arm in self.arms],
        }

    @property
    def effective_digest(self) -> str:
        return canonical_sha256(self.public_dump())


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def authoritative_task_digest(task_text: str) -> str:
    """Mirror the frozen TaskFact content projection for unconstrained cases."""

    return canonical_sha256(
        {
            "schema_version": "2.1",
            "task_summary": task_text,
            "action_constraints": [],
            "resource_constraints": [],
            "destination_constraints": [],
        }
    )


def load_competition_profile(
    profile: str = COMPETITION_PROFILE_ID,
    *,
    profile_dir: Path = PROFILE_PACKAGE_DIR,
) -> CompetitionProfile:
    if not _PROFILE_ID.fullmatch(profile):
        raise CompetitionConfigurationError(f"invalid profile id: {profile!r}")
    path = (profile_dir / f"{profile}.json").resolve()
    try:
        path.relative_to(profile_dir.resolve())
    except ValueError:
        raise CompetitionConfigurationError(
            "profile path escapes the packaged profile directory"
        ) from None
    if not path.is_file():
        raise CompetitionConfigurationError(f"profile not found: {profile}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CompetitionConfigurationError(
            "competition profile is invalid JSON"
        ) from exc
    if not isinstance(raw, Mapping):
        raise CompetitionConfigurationError(
            "competition profile root must be an object"
        )
    return parse_competition_profile(raw, source_path=path)


def parse_competition_profile(
    raw: Mapping[str, Any], *, source_path: Path
) -> CompetitionProfile:
    _exact_keys(
        raw,
        {
            "schema_version",
            "profile_id",
            "runtime",
            "agent_adapter",
            "identity",
            "dataset",
            "planner",
            "suite",
            "full_corpus",
            "v21_rollout_mode",
            "repeats",
            "seed",
            "arms",
        },
        "profile",
    )
    identity_raw = _mapping(raw.get("identity"), "identity")
    _exact_keys(
        identity_raw,
        {"principal_id", "agent_id", "runtime_binding_id"},
        "identity",
    )
    dataset_raw = _mapping(raw.get("dataset"), "dataset")
    _exact_keys(
        dataset_raw,
        {
            "path",
            "manifest",
            "dataset_id",
            "dataset_version",
            "dataset_digest",
            "case_count",
        },
        "dataset",
    )
    planner_raw = _mapping(raw.get("planner"), "planner")
    _exact_keys(
        planner_raw,
        {
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
        },
        "planner",
    )
    arms_raw = raw.get("arms")
    if not isinstance(arms_raw, Sequence) or isinstance(arms_raw, (str, bytes)):
        raise CompetitionConfigurationError("profile arms must be an array")
    arms = tuple(_parse_arm(item) for item in arms_raw)
    dataset_path = _repo_path(_required_str(dataset_raw, "path"))
    manifest_path = _repo_path(_required_str(dataset_raw, "manifest"))
    source_digest = canonical_sha256(raw)
    try:
        rollout_mode = V21RolloutMode(_required_str(raw, "v21_rollout_mode"))
    except ValueError as exc:
        raise CompetitionConfigurationError("invalid v21_rollout_mode") from exc
    return CompetitionProfile(
        schema_version=_required_str(raw, "schema_version"),
        profile_id=_required_str(raw, "profile_id"),
        runtime=_required_str(raw, "runtime"),
        agent_adapter=_required_str(raw, "agent_adapter"),
        identity=IdentitySpec(
            principal_id=_required_str(identity_raw, "principal_id"),
            agent_id=_required_str(identity_raw, "agent_id"),
            runtime_binding_id=_required_str(identity_raw, "runtime_binding_id"),
        ),
        dataset=DatasetSpec(
            path=dataset_path,
            manifest=manifest_path,
            dataset_id=_required_str(dataset_raw, "dataset_id"),
            dataset_version=_required_str(dataset_raw, "dataset_version"),
            dataset_digest=_required_str(dataset_raw, "dataset_digest"),
            case_count=_required_int(dataset_raw, "case_count"),
        ),
        planner=PlannerSpec(
            execution_mode=_required_str(planner_raw, "execution_mode"),
            protocol=_required_str(planner_raw, "protocol"),
            provider_id=_required_str(planner_raw, "provider_id"),
            model=str(planner_raw.get("model") or ""),
            base_url=str(planner_raw.get("base_url") or ""),
            api_key_env=_required_str(planner_raw, "api_key_env"),
            temperature=_required_number(planner_raw, "temperature"),
            request_timeout=_required_number(planner_raw, "request_timeout"),
            max_retries=_required_int(planner_raw, "max_retries"),
            max_tool_rounds=_required_int(planner_raw, "max_tool_rounds"),
            fallback_allowed=_required_bool(planner_raw, "fallback_allowed"),
        ),
        suite=_enum_value(CompetitionSuite, raw, "suite"),
        full_corpus=_required_bool(raw, "full_corpus"),
        v21_rollout_mode=rollout_mode,
        repeats=_required_int(raw, "repeats"),
        seed=_required_int(raw, "seed"),
        arms=arms,
        source_path=source_path.resolve(),
        source_digest=source_digest,
    )


def _parse_arm(value: Any) -> ArmSpec:
    raw = _mapping(value, "arm")
    _exact_keys(
        raw,
        {
            "arm_id",
            "guard_enabled",
            "current_core_enabled",
            "official_decision_source",
            "v21_enabled",
            "v21_rollout_mode",
            "ct_projection_enabled",
            "context_mode",
            "rte_mode",
            "detector_mode",
        },
        "arm",
    )
    mode_raw = raw.get("v21_rollout_mode")
    try:
        mode = V21RolloutMode(str(mode_raw)) if mode_raw is not None else None
        source = OfficialDecisionSource(_required_str(raw, "official_decision_source"))
        context = ContextMode(_required_str(raw, "context_mode"))
        rte = RteMode(_required_str(raw, "rte_mode"))
        detector = DetectorMode(_required_str(raw, "detector_mode"))
    except ValueError as exc:
        raise CompetitionConfigurationError(
            "arm contains an invalid enum value"
        ) from exc
    return ArmSpec(
        arm_id=_required_str(raw, "arm_id"),
        guard_enabled=_required_bool(raw, "guard_enabled"),
        current_core_enabled=_required_bool(raw, "current_core_enabled"),
        official_decision_source=source,
        v21_enabled=_required_bool(raw, "v21_enabled"),
        v21_rollout_mode=mode,
        ct_projection_enabled=_required_bool(raw, "ct_projection_enabled"),
        context_mode=context,
        rte_mode=rte,
        detector_mode=detector,
    )


def _validate_frozen_roster(
    arms: Sequence[ArmSpec], rollout_mode: V21RolloutMode
) -> None:
    if tuple(arm.arm_id for arm in arms) != _ARM_IDS:
        raise CompetitionConfigurationError(
            "competition profile must contain ordered arms A0 through A4 exactly once"
        )
    expected = _frozen_arms(rollout_mode)
    for actual, wanted in zip(arms, expected, strict=True):
        if actual != wanted:
            raise CompetitionConfigurationError(
                f"competition arm {actual.arm_id} differs from the frozen matrix"
            )


def _frozen_arms(rollout_mode: V21RolloutMode) -> tuple[ArmSpec, ...]:
    official_source = (
        OfficialDecisionSource.CURRENT
        if rollout_mode is V21RolloutMode.SHADOW
        else OfficialDecisionSource.V21
    )
    return (
        ArmSpec(
            "A0",
            False,
            False,
            OfficialDecisionSource.NONE,
            False,
            None,
            False,
            ContextMode.OFF,
            RteMode.OFF,
            DetectorMode.OFF,
        ),
        ArmSpec(
            "A1",
            True,
            True,
            OfficialDecisionSource.CURRENT,
            False,
            None,
            False,
            ContextMode.OFF,
            RteMode.ENFORCE,
            DetectorMode.ON,
        ),
        ArmSpec(
            "A2",
            True,
            True,
            OfficialDecisionSource.CURRENT,
            True,
            V21RolloutMode.SHADOW,
            True,
            ContextMode.OBSERVE,
            RteMode.ENFORCE,
            DetectorMode.ON,
        ),
        ArmSpec(
            "A3",
            True,
            True,
            official_source,
            True,
            rollout_mode,
            True,
            ContextMode.OBSERVE,
            RteMode.ENFORCE,
            DetectorMode.ON,
        ),
        ArmSpec(
            "A4",
            True,
            True,
            official_source,
            True,
            rollout_mode,
            True,
            ContextMode.REQUIRED,
            RteMode.ENFORCE,
            DetectorMode.ON,
        ),
    )


def _arm_with_profile_rollout(arm: ArmSpec, rollout_mode: V21RolloutMode) -> ArmSpec:
    source = (
        OfficialDecisionSource.CURRENT
        if rollout_mode is V21RolloutMode.SHADOW
        else OfficialDecisionSource.V21
    )
    return replace(
        arm,
        official_decision_source=source,
        v21_enabled=True,
        v21_rollout_mode=rollout_mode,
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CompetitionConfigurationError(f"{label} must be an object")
    return value


def _exact_keys(raw: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(raw)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise CompetitionConfigurationError(
            f"{label} fields are invalid: {'; '.join(details)}"
        )


def _required_str(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise CompetitionConfigurationError(f"{key} must be a non-empty string")
    return value


def _required_int(raw: Mapping[str, Any], key: str) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise CompetitionConfigurationError(f"{key} must be an integer")
    return value


def _required_number(raw: Mapping[str, Any], key: str) -> float:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CompetitionConfigurationError(f"{key} must be a number")
    return float(value)


def _required_bool(raw: Mapping[str, Any], key: str) -> bool:
    value = raw.get(key)
    if not isinstance(value, bool):
        raise CompetitionConfigurationError(f"{key} must be a boolean")
    return value


def _enum_value(enum_type: type[Enum], raw: Mapping[str, Any], key: str) -> Any:
    value = _required_str(raw, key)
    try:
        return enum_type(value)
    except ValueError as exc:
        raise CompetitionConfigurationError(f"{key} has an invalid value") from exc


def _repo_path(value: str) -> Path:
    candidate = (REPO_ROOT / value).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError:
        raise CompetitionConfigurationError(
            "profile path escapes the repository"
        ) from None
    return candidate


def _repo_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path.resolve())
