"""Runtime settings for the Guard API / Control Plane."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path

from agentguard_core import ReceiptEligibilityExpectation

DEFAULT_DATABASE_URL = "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"
DEFAULT_CONTROL_TOKEN = "demo-control-token"
DEFAULT_ENVIRONMENT = "development"
DEFAULT_STORAGE_BACKEND = "postgres"
DEFAULT_LLM_APPROVAL_BASE_URL = "https://api.openai.com/v1"
DEFAULT_V21_SEMANTIC_BASE_URL = "https://api.openai.com/v1"
SUPPORTED_STORAGE_BACKENDS = {"postgres", "memory"}
SUPPORTED_ENVIRONMENTS = {"development", "test", "production"}
SUPPORTED_V21_MODES = {"off", "shadow", "limited_enable", "active"}
DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024
MAX_CONFIGURABLE_REQUEST_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_AUDIT_CHECKPOINT_INTERVAL_SECONDS = 300
MAX_AUDIT_CHECKPOINT_INTERVAL_SECONDS = 86400

_CHECKPOINT_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_CHECKPOINT_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class GuardApiConfigurationError(RuntimeError):
    """Raised when Guard API startup configuration is unsafe."""


@dataclass(slots=True)
class GuardApiSettings:
    database_url: str = field(
        default_factory=lambda: os.getenv(
            "AGENTGUARD_DATABASE_URL", DEFAULT_DATABASE_URL
        )
    )
    storage_backend: str = field(
        default_factory=lambda: (
            os.getenv("AGENTGUARD_STORAGE_BACKEND", DEFAULT_STORAGE_BACKEND)
            .strip()
            .lower()
        )
    )
    control_token: str = field(
        default_factory=lambda: os.getenv(
            "AGENTGUARD_CONTROL_TOKEN", DEFAULT_CONTROL_TOKEN
        )
    )
    host: str = field(default_factory=lambda: os.getenv("AGENTGUARD_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("AGENTGUARD_PORT", default=8088))
    environment: str = field(
        default_factory=lambda: (
            os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT).strip().lower()
        )
    )
    browser_session_ttl_seconds: int = 3600
    launch_code_ttl_seconds: int = 300
    approval_ttl_seconds: int = 900
    browser_cookie_secure: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_BROWSER_COOKIE_SECURE",
            default=(
                os.getenv("AGENTGUARD_ENV", DEFAULT_ENVIRONMENT).strip().lower()
                == "production"
            ),
        )
    )
    max_request_body_bytes: int = field(
        default_factory=lambda: _env_int(
            "AGENTGUARD_MAX_REQUEST_BODY_BYTES",
            default=DEFAULT_MAX_REQUEST_BODY_BYTES,
        )
    )
    llm_approval_enabled: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_LLM_APPROVAL_ENABLED", default=False
        )
    )
    llm_approval_base_url: str = field(
        default_factory=lambda: os.getenv(
            "AGENTGUARD_LLM_APPROVAL_BASE_URL", DEFAULT_LLM_APPROVAL_BASE_URL
        )
    )
    llm_approval_api_key: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_LLM_APPROVAL_API_KEY")
    )
    llm_approval_model: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_LLM_APPROVAL_MODEL")
    )
    llm_approval_timeout_seconds: float = field(
        default_factory=lambda: _env_float(
            "AGENTGUARD_LLM_APPROVAL_TIMEOUT_SECONDS", default=3.0
        )
    )
    # V21-13 Stage 1 shadow semantic judgment（独立命名空间，与
    # llm_approval 解耦）：默认关闭；产物只供证据/评测，不改决策。
    v21_semantic_enabled: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_V21_SEMANTIC_ENABLED", default=False
        )
    )
    v21_semantic_base_url: str = field(
        default_factory=lambda: os.getenv(
            "AGENTGUARD_V21_SEMANTIC_BASE_URL", DEFAULT_V21_SEMANTIC_BASE_URL
        )
    )
    v21_semantic_api_key: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_V21_SEMANTIC_API_KEY"),
        repr=False,
    )
    v21_semantic_model: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_V21_SEMANTIC_MODEL")
    )
    v21_semantic_timeout_seconds: float = field(
        default_factory=lambda: _env_float(
            "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS", default=3.0
        )
    )
    v21_semantic_ttl_seconds: float = field(
        default_factory=lambda: _env_float(
            "AGENTGUARD_V21_SEMANTIC_TTL_SECONDS", default=300.0
        )
    )
    v21_semantic_sample_rate: float = field(
        default_factory=lambda: _env_float(
            "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE", default=1.0
        )
    )
    # memory guard required-checks 豁免开关（消融分析用，如 no-memory-guard
    # 臂）：逗号分隔的 action 名单，命中名单的 action 跳过 memory required
    # 检查。默认未设置（空 frozenset）时保持 competition_active 现有行为
    # 不变。
    memory_not_required_actions: frozenset[str] = field(
        default_factory=lambda: _env_str_set(
            "AGENTGUARD_MEMORY_NOT_REQUIRED_ACTIONS"
        )
    )
    audit_checkpoint_path: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_AUDIT_CHECKPOINT_PATH")
    )
    audit_checkpoint_key: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_AUDIT_CHECKPOINT_KEY"),
        repr=False,
    )
    audit_checkpoint_key_id: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_AUDIT_CHECKPOINT_KEY_ID")
    )
    task_scope_active_key_id: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID")
    )
    task_scope_keys: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_TASK_SCOPE_KEYS"),
        repr=False,
    )
    audit_checkpoint_interval_seconds: int = field(
        default_factory=lambda: _env_int(
            "AGENTGUARD_AUDIT_CHECKPOINT_INTERVAL_SECONDS",
            default=DEFAULT_AUDIT_CHECKPOINT_INTERVAL_SECONDS,
        )
    )
    # Unified V2.1 authority mode.  ``off`` is the global default; reference
    # and competition profiles must select their mode explicitly.
    v21_mode: str = field(
        default_factory=lambda: (
            os.getenv("AGENTGUARD_V21_MODE", "off").strip().lower()
        )
    )
    # A competition activation is immutable process input.  It is loaded once
    # during application construction and is never exposed through a mutation
    # endpoint.
    v21_competition_activation_path: str | None = field(
        default_factory=lambda: _optional_env(
            "AGENTGUARD_V21_COMPETITION_ACTIVATION_PATH"
        )
    )
    # shadow ActionIR 指纹专用 server secret（base64url，≥32 字节）。
    # 与 task scope keyring / audit checkpoint key 域隔离，不复用其他密钥。
    # mode enabled 而未配置时 V2 禁用（编排器返回 None），不得硬编码兜底。
    v21_shadow_server_secret: str | None = field(
        default_factory=lambda: _optional_env("AGENTGUARD_V21_SHADOW_SERVER_SECRET"),
        repr=False,
    )
    # CT-PR-03b CT 事实投影独立 flag（裁决 D3：默认 false，与 V21
    # V2 authority mode 解耦；CT flag off 时 CT 全链路不执行，evaluate 行为
    # 逐字节不变。生效另需 pipeline 材料就绪，server secret 复用
    # AGENTGUARD_V21_SHADOW_SERVER_SECRET）。
    ct_fact_projection_enabled: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_CT_FACT_PROJECTION_ENABLED", default=False
        )
    )
    # CT-PR-04 logical/physical context isolation.  Independent and default
    # off: no plan is built and the evaluate wire shape remains unchanged.
    context_builder_enabled: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_CONTEXT_BUILDER_ENABLED", default=False
        )
    )
    # RTE-05 strong approval binding rollout gate.  Default-off preserves the
    # frozen C1 evaluate/wait behavior and performs no binding/lease writes.
    rte05_strong_binding_enabled: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_RTE05_STRONG_BINDING_ENABLED", default=False
        )
    )
    # C10 profile-owned receipt population anchor.  A service may continue to
    # accept legacy EvaluationRuns with all three values unset, but a typed
    # pre-enable report is accepted only when the complete anchor is present.
    evaluation_receipt_eligibility_revision: str | None = field(
        default_factory=lambda: _optional_env(
            "AGENTGUARD_EVALUATION_RECEIPT_ELIGIBILITY_REVISION"
        )
    )
    evaluation_receipt_runtime_profile: str | None = field(
        default_factory=lambda: _optional_env(
            "AGENTGUARD_EVALUATION_RECEIPT_RUNTIME_PROFILE"
        )
    )
    evaluation_receipt_eligibility_digest: str | None = field(
        default_factory=lambda: _optional_env(
            "AGENTGUARD_EVALUATION_RECEIPT_ELIGIBILITY_DIGEST"
        )
    )

    def llm_approval_configured(self) -> bool:
        return bool(self.llm_approval_api_key and self.llm_approval_model)

    def v21_semantic_configured(self) -> bool:
        """V21-13 semantic shadow 就绪：enabled 且 api_key 与 model 齐备。"""

        return bool(
            self.v21_semantic_enabled
            and self.v21_semantic_api_key
            and self.v21_semantic_model
        )

    def evaluation_receipt_eligibility_expectation(
        self,
    ) -> ReceiptEligibilityExpectation | None:
        """Return the configured C10 anchor, or ``None`` for legacy-only mode."""

        eligibility_revision = self.evaluation_receipt_eligibility_revision
        runtime_profile = self.evaluation_receipt_runtime_profile
        eligibility_digest = self.evaluation_receipt_eligibility_digest
        values = (eligibility_revision, runtime_profile, eligibility_digest)
        if not any(values):
            return None
        if not all(values):
            raise GuardApiConfigurationError(
                "AGENTGUARD_EVALUATION_RECEIPT_ELIGIBILITY_REVISION, "
                "AGENTGUARD_EVALUATION_RECEIPT_RUNTIME_PROFILE and "
                "AGENTGUARD_EVALUATION_RECEIPT_ELIGIBILITY_DIGEST must be "
                "configured together"
            )
        assert eligibility_revision is not None
        assert runtime_profile is not None
        assert eligibility_digest is not None
        try:
            return ReceiptEligibilityExpectation(
                eligibility_revision=eligibility_revision,
                runtime_profile=runtime_profile,
                eligibility_digest=eligibility_digest,
            )
        except ValueError as exc:
            raise GuardApiConfigurationError(
                "AgentGuard evaluation receipt eligibility anchor is invalid"
            ) from exc

    def audit_cursor_signing_key(self) -> bytes:
        """从控制令牌域隔离派生 cursor HMAC 密钥，不暴露原始令牌。"""

        return hmac.new(
            self.control_token.encode("utf-8"),
            b"agentguard/audit-window-cursor/v3",
            hashlib.sha256,
        ).digest()

    def task_scope_configured(self) -> bool:
        return bool(self.task_scope_active_key_id and self.task_scope_keys)

    def task_scope_keyring(self) -> dict[str, bytes]:
        """解析独立、版本化的 SecurityStateScope HMAC keyring。"""
        if not self.task_scope_keys:
            raise GuardApiConfigurationError(
                "AGENTGUARD_TASK_SCOPE_KEYS must be configured"
            )
        try:
            raw_keyring = json.loads(self.task_scope_keys)
        except json.JSONDecodeError:
            raise GuardApiConfigurationError(
                "AGENTGUARD_TASK_SCOPE_KEYS must be a JSON object"
            ) from None
        if not isinstance(raw_keyring, dict) or not raw_keyring:
            raise GuardApiConfigurationError(
                "AGENTGUARD_TASK_SCOPE_KEYS must be a non-empty JSON object"
            )
        keyring: dict[str, bytes] = {}
        for key_id, encoded_key in raw_keyring.items():
            if not isinstance(key_id, str) or not _CHECKPOINT_KEY_ID_PATTERN.fullmatch(
                key_id
            ):
                raise GuardApiConfigurationError(
                    "AGENTGUARD_TASK_SCOPE_KEYS key ids must contain 1-64 safe "
                    "characters"
                )
            if not isinstance(encoded_key, str):
                raise GuardApiConfigurationError(
                    "AGENTGUARD_TASK_SCOPE_KEYS values must be base64url strings"
                )
            keyring[key_id] = _decode_base64url_key(
                encoded_key,
                label="AGENTGUARD_TASK_SCOPE_KEYS values",
            )
        return keyring

    def task_scope_signing_key(self) -> bytes:
        """返回 active key；control token 轮换不影响持久化 scope digest。"""
        if not self.task_scope_active_key_id:
            raise GuardApiConfigurationError(
                "AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID must be configured"
            )
        keyring = self.task_scope_keyring()
        try:
            return keyring[self.task_scope_active_key_id]
        except KeyError:
            raise GuardApiConfigurationError(
                "AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID must exist in "
                "AGENTGUARD_TASK_SCOPE_KEYS"
            ) from None

    def v21_shadow_server_secret_bytes(self) -> bytes | None:
        """解析 shadow server secret；未配置返回 None。

        形态校验与既有 checkpoint key 同口径（base64url、解码后 ≥32
        字节）；非法配置抛 ``GuardApiConfigurationError``（fail-closed，
        编排器侧收敛为 shadow 禁用，绝不用弱密钥继续产证据）。
        """

        if self.v21_shadow_server_secret is None:
            return None
        return _decode_base64url_key(
            self.v21_shadow_server_secret,
            label="AGENTGUARD_V21_SHADOW_SERVER_SECRET",
        )

    def effective_v21_mode(self) -> str:
        """Return the normalized V2.1 authority mode."""

        return self.v21_mode.strip().lower()

    def v21_enabled(self) -> bool:
        return self.effective_v21_mode() != "off"

    def audit_checkpoint_configured(self) -> bool:
        return bool(
            self.audit_checkpoint_path
            and self.audit_checkpoint_key
            and self.audit_checkpoint_key_id
        )

    def audit_checkpoint_signing_key(self) -> bytes | None:
        if self.audit_checkpoint_key is None:
            return None
        return _decode_checkpoint_key(self.audit_checkpoint_key)

    def validate_for_startup(self) -> None:
        environment = self.environment.strip().lower()
        if environment not in SUPPORTED_ENVIRONMENTS:
            supported = ", ".join(sorted(SUPPORTED_ENVIRONMENTS))
            raise GuardApiConfigurationError(
                f"AGENTGUARD_ENV must be one of: {supported}"
            )
        if self.storage_backend not in SUPPORTED_STORAGE_BACKENDS:
            supported = ", ".join(sorted(SUPPORTED_STORAGE_BACKENDS))
            raise GuardApiConfigurationError(
                f"AGENTGUARD_STORAGE_BACKEND must be one of: {supported}"
            )
        if self.v21_mode.strip().lower() not in SUPPORTED_V21_MODES:
            supported = ", ".join(sorted(SUPPORTED_V21_MODES))
            raise GuardApiConfigurationError(
                f"AGENTGUARD_V21_MODE must be one of: {supported}"
            )
        if not self.control_token.strip():
            raise GuardApiConfigurationError("AGENTGUARD_CONTROL_TOKEN cannot be empty")
        if self.storage_backend == "postgres" and not self.database_url.strip():
            raise GuardApiConfigurationError("AGENTGUARD_DATABASE_URL cannot be empty")
        if not 1 <= self.port <= 65535:
            raise GuardApiConfigurationError(
                "AGENTGUARD_PORT must be between 1 and 65535"
            )
        if (
            not 1024
            <= self.max_request_body_bytes
            <= MAX_CONFIGURABLE_REQUEST_BODY_BYTES
        ):
            raise GuardApiConfigurationError(
                "AGENTGUARD_MAX_REQUEST_BODY_BYTES must be between 1024 and 8388608"
            )
        if self.llm_approval_timeout_seconds <= 0:
            raise GuardApiConfigurationError(
                "AGENTGUARD_LLM_APPROVAL_TIMEOUT_SECONDS must be greater than zero"
            )
        # isfinite 前置校验（评审 M1）：NaN 比较恒 False、inf 通过
        # ``> 0``——不加有限性校验则 timeout=inf 使 hard deadline 静默
        # 失效、ttl=inf 使 expires_at 永不落地、sample_rate=nan 使采样
        # 门控恒 False。
        if not math.isfinite(self.v21_semantic_timeout_seconds):
            raise GuardApiConfigurationError(
                "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS must be a finite "
                "number"
            )
        if self.v21_semantic_timeout_seconds <= 0:
            raise GuardApiConfigurationError(
                "AGENTGUARD_V21_SEMANTIC_TIMEOUT_SECONDS must be greater than zero"
            )
        if not math.isfinite(self.v21_semantic_ttl_seconds):
            raise GuardApiConfigurationError(
                "AGENTGUARD_V21_SEMANTIC_TTL_SECONDS must be a finite number"
            )
        if self.v21_semantic_ttl_seconds <= 0:
            raise GuardApiConfigurationError(
                "AGENTGUARD_V21_SEMANTIC_TTL_SECONDS must be greater than zero"
            )
        if not math.isfinite(self.v21_semantic_sample_rate):
            raise GuardApiConfigurationError(
                "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE must be a finite number"
            )
        if not 0.0 <= self.v21_semantic_sample_rate <= 1.0:
            raise GuardApiConfigurationError(
                "AGENTGUARD_V21_SEMANTIC_SAMPLE_RATE must be between 0.0 and 1.0"
            )
        if (
            not 1
            <= self.audit_checkpoint_interval_seconds
            <= MAX_AUDIT_CHECKPOINT_INTERVAL_SECONDS
        ):
            raise GuardApiConfigurationError(
                "AGENTGUARD_AUDIT_CHECKPOINT_INTERVAL_SECONDS must be between "
                "1 and 86400"
            )

        checkpoint_values = (
            self.audit_checkpoint_path,
            self.audit_checkpoint_key,
            self.audit_checkpoint_key_id,
        )
        if any(checkpoint_values) and not all(checkpoint_values):
            raise GuardApiConfigurationError(
                "AGENTGUARD_AUDIT_CHECKPOINT_PATH, AGENTGUARD_AUDIT_CHECKPOINT_KEY "
                "and AGENTGUARD_AUDIT_CHECKPOINT_KEY_ID must be configured together"
            )
        if self.audit_checkpoint_configured():
            assert self.audit_checkpoint_path is not None
            assert self.audit_checkpoint_key_id is not None
            if not Path(self.audit_checkpoint_path).is_absolute():
                raise GuardApiConfigurationError(
                    "AGENTGUARD_AUDIT_CHECKPOINT_PATH must be an absolute path"
                )
            if not _CHECKPOINT_KEY_ID_PATTERN.fullmatch(self.audit_checkpoint_key_id):
                raise GuardApiConfigurationError(
                    "AGENTGUARD_AUDIT_CHECKPOINT_KEY_ID must contain 1-64 safe characters"
                )
            self.audit_checkpoint_signing_key()

        task_scope_values = (
            self.task_scope_active_key_id,
            self.task_scope_keys,
        )
        if any(task_scope_values) and not all(task_scope_values):
            raise GuardApiConfigurationError(
                "AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID and "
                "AGENTGUARD_TASK_SCOPE_KEYS must be configured together"
            )
        if self.task_scope_configured():
            self.task_scope_signing_key()

        # Validate an optional C10 anchor at startup without requiring it for
        # existing EvaluationRun producers.
        self.evaluation_receipt_eligibility_expectation()

        effective_v21_mode = self.effective_v21_mode()
        if effective_v21_mode in {"limited_enable", "active"}:
            activation_path = self.v21_competition_activation_path
            if activation_path is None:
                raise GuardApiConfigurationError(
                    "AGENTGUARD_V21_COMPETITION_ACTIVATION_PATH is required for "
                    f"V2.1 mode {effective_v21_mode}"
                )
            if not Path(activation_path).is_absolute():
                raise GuardApiConfigurationError(
                    "AGENTGUARD_V21_COMPETITION_ACTIVATION_PATH must be an "
                    "absolute path"
                )
            if self.v21_shadow_server_secret_bytes() is None:
                raise GuardApiConfigurationError(
                    "V2.1 official modes require "
                    "AGENTGUARD_V21_SHADOW_SERVER_SECRET"
                )
            if not self.task_scope_configured():
                raise GuardApiConfigurationError(
                    "V2.1 official modes require AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID "
                    "and AGENTGUARD_TASK_SCOPE_KEYS"
                )
            if (
                effective_v21_mode == "active"
                and not self.rte05_strong_binding_enabled
            ):
                raise GuardApiConfigurationError(
                    "AGENTGUARD_V21_MODE=active requires "
                    "AGENTGUARD_RTE05_STRONG_BINDING_ENABLED=true"
                )

        if self.rte05_strong_binding_enabled:
            if effective_v21_mode == "off":
                raise GuardApiConfigurationError(
                    "AGENTGUARD_RTE05_STRONG_BINDING_ENABLED requires "
                    "AGENTGUARD_V21_MODE != off"
                )
            if self.v21_shadow_server_secret_bytes() is None:
                raise GuardApiConfigurationError(
                    "AGENTGUARD_RTE05_STRONG_BINDING_ENABLED requires "
                    "AGENTGUARD_V21_SHADOW_SERVER_SECRET"
                )
            if not self.task_scope_configured():
                raise GuardApiConfigurationError(
                    "AGENTGUARD_RTE05_STRONG_BINDING_ENABLED requires "
                    "AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID and "
                    "AGENTGUARD_TASK_SCOPE_KEYS"
                )

        externally_exposed = environment == "production" or not _is_loopback_host(
            self.host
        )
        if not externally_exposed:
            return
        if self.storage_backend == "memory":
            raise GuardApiConfigurationError(
                "Externally exposed startup requires persistent storage backend: postgres"
            )
        default_variables = []
        if self.database_url.strip() == DEFAULT_DATABASE_URL:
            default_variables.append("AGENTGUARD_DATABASE_URL")
        if self.control_token.strip() == DEFAULT_CONTROL_TOKEN:
            default_variables.append("AGENTGUARD_CONTROL_TOKEN")
        if default_variables:
            names = ", ".join(default_variables)
            raise GuardApiConfigurationError(
                f"Externally exposed startup requires explicit configuration for: {names}"
            )
        if len(self.control_token.strip()) < 32:
            raise GuardApiConfigurationError(
                "Externally exposed startup requires AGENTGUARD_CONTROL_TOKEN "
                "to contain at least 32 characters"
            )
        if not self.browser_cookie_secure:
            raise GuardApiConfigurationError(
                "Externally exposed startup requires AGENTGUARD_BROWSER_COOKIE_SECURE=true"
            )
        if not self.audit_checkpoint_configured():
            raise GuardApiConfigurationError(
                "Externally exposed startup requires an authenticated external audit "
                "checkpoint"
            )
        if not self.task_scope_configured():
            raise GuardApiConfigurationError(
                "Externally exposed startup requires an independent task scope keyring"
            )


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _env_str_set(name: str) -> frozenset[str]:
    """逗号分隔 env 解析为去空白 frozenset；未设置返回空集。"""

    value = os.getenv(name)
    if value is None:
        return frozenset()
    return frozenset(item.strip() for item in value.split(",") if item.strip())


def _env_bool(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise GuardApiConfigurationError(f"{name} must be a boolean")


def _env_float(name: str, *, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        raise GuardApiConfigurationError(f"{name} must be a number") from None


def _env_int(name: str, *, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise GuardApiConfigurationError(f"{name} must be an integer") from None


def _decode_checkpoint_key(value: str) -> bytes:
    return _decode_base64url_key(
        value,
        label="AGENTGUARD_AUDIT_CHECKPOINT_KEY",
    )


def _decode_base64url_key(value: str, *, label: str) -> bytes:
    normalized = value.strip()
    if not _CHECKPOINT_KEY_PATTERN.fullmatch(normalized):
        raise GuardApiConfigurationError(f"{label} must be base64url encoded")
    padding = "=" * (-len(normalized) % 4)
    try:
        decoded = base64.b64decode(
            normalized + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        raise GuardApiConfigurationError(f"{label} must be base64url encoded") from None
    if len(decoded) < 32:
        raise GuardApiConfigurationError(f"{label} must decode to at least 32 bytes")
    return decoded


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False
