"""Runtime settings for the Guard API / Control Plane."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path

DEFAULT_DATABASE_URL = "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard"
DEFAULT_CONTROL_TOKEN = "demo-control-token"
DEFAULT_ENVIRONMENT = "development"
DEFAULT_STORAGE_BACKEND = "postgres"
DEFAULT_LLM_APPROVAL_BASE_URL = "https://api.openai.com/v1"
SUPPORTED_STORAGE_BACKENDS = {"postgres", "memory"}
SUPPORTED_ENVIRONMENTS = {"development", "test", "production"}
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
        default_factory=lambda: _optional_env(
            "AGENTGUARD_TASK_SCOPE_ACTIVE_KEY_ID"
        )
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
    # V21-08 shadow feature flag（11_决策记录_V21-08前置.md D3：默认
    # false；flag off 时 shadow 全链路不执行，evaluate 行为逐字节不变）。
    v21_shadow_enabled: bool = field(
        default_factory=lambda: _env_bool(
            "AGENTGUARD_V21_SHADOW_ENABLED", default=False
        )
    )
    # shadow ActionIR 指纹专用 server secret（base64url，≥32 字节）。
    # 与 task scope keyring / audit checkpoint key 域隔离，不复用其他密钥。
    # flag on 而未配置时 shadow 禁用（编排器返回 None），不得硬编码兜底。
    v21_shadow_server_secret: str | None = field(
        default_factory=lambda: _optional_env(
            "AGENTGUARD_V21_SHADOW_SERVER_SECRET"
        ),
        repr=False,
    )

    def llm_approval_configured(self) -> bool:
        return bool(self.llm_approval_api_key and self.llm_approval_model)

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
        raise GuardApiConfigurationError(
            f"{label} must be base64url encoded"
        )
    padding = "=" * (-len(normalized) % 4)
    try:
        decoded = base64.b64decode(
            normalized + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        raise GuardApiConfigurationError(
            f"{label} must be base64url encoded"
        ) from None
    if len(decoded) < 32:
        raise GuardApiConfigurationError(
            f"{label} must decode to at least 32 bytes"
        )
    return decoded


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False
