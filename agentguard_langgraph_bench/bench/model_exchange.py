"""Display-safe evidence for real OpenAI-compatible model exchanges."""

from __future__ import annotations

import os
import random
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .competition_models import canonical_sha256


MODEL_EXCHANGE_SCHEMA_VERSION = "model-exchange/1.0"
CANONICAL_INPUT_SCHEMA_VERSION = "canonical-planner-input/1.0"
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

# Retry policy for transient provider failures.  Only outcomes in
# ``_RETRYABLE_OUTCOMES`` are retried; protocol errors fail fast.
_RETRY_BACKOFF_BASE_SECONDS = 1.0
_RETRY_BACKOFF_CAP_SECONDS = 30.0


class ModelExchangeError(ValueError):
    """Model exchange evidence or provider configuration is invalid."""


class ModelExchangeOutcome(str, Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    TRANSPORT_ERROR = "transport_error"
    PROTOCOL_ERROR = "protocol_error"


class ModelParseStatus(str, Enum):
    VALID_TOOL_CALLS = "valid_tool_calls"
    VALID_NO_TOOL_CALL = "valid_no_tool_call"
    INVALID = "invalid"


class ModelExchangeEvidence(BaseModel):
    """No-prompt, no-response, no-secret evidence for one actual invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = MODEL_EXCHANGE_SCHEMA_VERSION
    exchange_id: str
    case_id: str
    arm_id: str
    repeat_index: int = Field(ge=0)
    round_index: int = Field(ge=1)
    execution_mode: str = "autonomous_llm"
    protocol: str = "openai_chat_completions"
    provider_id: str
    model: str
    endpoint_identity_digest: str
    source_set_digest: str
    authority_binding_digest: str
    model_input_digest: str
    tool_schema_digest: str
    request_digest: str
    response_digest: str | None = None
    provider_request_id_digest: str | None = None
    prior_exchange_digest: str | None = None
    context_mode: str
    context_plan_digest: str | None = None
    transform_applied: bool
    request_observed: bool
    response_observed: bool
    outcome: ModelExchangeOutcome
    parse_status: ModelParseStatus
    tool_call_count: int = Field(ge=0)
    tool_names: tuple[str, ...] = ()
    attempt_index: int = Field(ge=1)
    retry_count: int = Field(ge=0)
    elapsed_ms: int = Field(ge=0)
    planning_source: str = "llm_autonomous"
    guided_plan_applied: bool = False
    fallback_applied: bool = False

    @model_validator(mode="after")
    def _validate_contract(self) -> "ModelExchangeEvidence":
        if self.schema_version != MODEL_EXCHANGE_SCHEMA_VERSION:
            raise ValueError("unsupported model exchange schema")
        if self.execution_mode != "autonomous_llm":
            raise ValueError("model exchange must be autonomous")
        if self.protocol != "openai_chat_completions":
            raise ValueError("model exchange protocol is invalid")
        if self.planning_source != "llm_autonomous":
            raise ValueError("model exchange planning source is invalid")
        if self.guided_plan_applied or self.fallback_applied:
            raise ValueError("model exchange contains guided or fallback planning")
        for value in (
            self.exchange_id,
            self.endpoint_identity_digest,
            self.source_set_digest,
            self.authority_binding_digest,
            self.model_input_digest,
            self.tool_schema_digest,
            self.request_digest,
        ):
            if _SHA256.fullmatch(value) is None:
                raise ValueError("model exchange digest is invalid")
        for value in (
            self.response_digest,
            self.provider_request_id_digest,
            self.prior_exchange_digest,
            self.context_plan_digest,
        ):
            if value is not None and _SHA256.fullmatch(value) is None:
                raise ValueError("optional model exchange digest is invalid")
        if self.outcome is ModelExchangeOutcome.SUCCESS:
            if not self.request_observed or not self.response_observed:
                raise ValueError(
                    "successful exchange requires request and response evidence"
                )
            if self.response_digest is None:
                raise ValueError("successful exchange requires response digest")
            if self.parse_status is ModelParseStatus.INVALID:
                raise ValueError("successful exchange cannot have invalid parse status")
        elif self.response_observed or self.response_digest is not None:
            raise ValueError("failed exchange cannot claim a provider response")
        if self.tool_call_count != len(self.tool_names):
            raise ValueError("tool_call_count does not match tool_names")
        if self.parse_status is ModelParseStatus.VALID_TOOL_CALLS:
            if self.tool_call_count == 0:
                raise ValueError("tool-call parse status requires tool calls")
        elif self.tool_call_count:
            raise ValueError("no-tool parse status cannot include tool calls")
        return self

    @property
    def model_invoked(self) -> bool:
        return bool(
            self.outcome is ModelExchangeOutcome.SUCCESS
            and self.request_observed
            and self.response_observed
        )

    def public_dump(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


@dataclass(frozen=True, slots=True)
class CanonicalInputDigests:
    schema_version: str
    source_set_digest: str
    authority_binding_digest: str
    model_input_digest: str
    tool_schema_digest: str
    source_count: int
    message_count: int
    tool_schema_count: int

    def public_dump(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_set_digest": self.source_set_digest,
            "authority_binding_digest": self.authority_binding_digest,
            "model_input_digest": self.model_input_digest,
            "tool_schema_digest": self.tool_schema_digest,
            "source_count": self.source_count,
            "message_count": self.message_count,
            "tool_schema_count": self.tool_schema_count,
        }


class ModelExchangeInvocationError(RuntimeError):
    """A real invocation failed; the display-safe attempt evidence is retained."""

    #: Evidence of every attempt made for this logical exchange.  Empty when
    #: the caller ran with ``max_retries=0`` (the legacy single-attempt path).
    attempt_evidence: tuple["ModelExchangeEvidence", ...] = ()

    def __init__(self, evidence: ModelExchangeEvidence) -> None:
        super().__init__(f"model invocation failed: {evidence.outcome.value}")
        self.evidence = evidence


def build_canonical_input_digests(
    *,
    sources: Sequence[Any],
    authority_binding: Mapping[str, Any] | None,
    model_input: Sequence[Any],
    tool_schemas: Sequence[Any],
) -> CanonicalInputDigests:
    normalized_sources = [_jsonable(item) for item in sources]
    normalized_messages = [_jsonable_message(item) for item in model_input]
    normalized_tools = [_jsonable_tool(item) for item in tool_schemas]
    return CanonicalInputDigests(
        schema_version=CANONICAL_INPUT_SCHEMA_VERSION,
        source_set_digest=canonical_sha256(normalized_sources),
        authority_binding_digest=canonical_sha256(
            _jsonable(dict(authority_binding or {}))
        ),
        model_input_digest=canonical_sha256(normalized_messages),
        tool_schema_digest=canonical_sha256(normalized_tools),
        source_count=len(normalized_sources),
        message_count=len(normalized_messages),
        tool_schema_count=len(normalized_tools),
    )


def invoke_with_model_exchange(
    invoker: Any,
    *,
    model_input: Sequence[Any],
    sources: Sequence[Any],
    tool_schemas: Sequence[Any],
    authority_binding: Mapping[str, Any] | None,
    case_id: str,
    arm_id: str,
    repeat_index: int,
    round_index: int,
    provider_id: str,
    model: str,
    base_url: str,
    context_mode: str,
    context_plan_digest: str | None = None,
    transform_applied: bool = False,
    attempt_index: int = 1,
    retry_count: int = 0,
    prior_exchange_digest: str | None = None,
    invoke: Callable[[Any, Sequence[Any]], Any] | None = None,
    max_retries: int = 0,
    retry_sleep: Callable[[float], Any] | None = None,
    retry_rng: random.Random | None = None,
) -> tuple[Any, ModelExchangeEvidence]:
    """Invoke an OpenAI-compatible model and bind success to hashed request data.

    The caller supplies an already configured/bound ChatOpenAI-compatible object.
    Only digests, counts and controlled identifiers leave this function.

    ``max_retries=0`` (the default and the serial competition contract)
    executes exactly one attempt and is behaviourally identical to the
    pre-retry implementation.  A positive budget retries only transient
    failures (429 / 5xx-style timeouts, rate limits and transport errors)
    with exponential backoff plus jitter; every attempt emits its own
    display-safe evidence with a distinct ``attempt_index``.
    """

    if isinstance(max_retries, bool) or not isinstance(max_retries, int):
        raise ModelExchangeError("max_retries must be an integer")
    if max_retries < 0:
        raise ModelExchangeError("max_retries must be non-negative")
    if max_retries == 0:
        return _invoke_attempt(
            invoker,
            model_input=model_input,
            sources=sources,
            tool_schemas=tool_schemas,
            authority_binding=authority_binding,
            case_id=case_id,
            arm_id=arm_id,
            repeat_index=repeat_index,
            round_index=round_index,
            provider_id=provider_id,
            model=model,
            base_url=base_url,
            context_mode=context_mode,
            context_plan_digest=context_plan_digest,
            transform_applied=transform_applied,
            attempt_index=attempt_index,
            retry_count=retry_count,
            prior_exchange_digest=prior_exchange_digest,
            invoke=invoke,
        )

    sleep = retry_sleep if retry_sleep is not None else time.sleep
    rng = retry_rng if retry_rng is not None else _SHARED_RETRY_RNG
    attempt_evidence: list[ModelExchangeEvidence] = []
    total_attempts = 1 + max_retries
    for number in range(total_attempts):
        try:
            return _invoke_attempt(
                invoker,
                model_input=model_input,
                sources=sources,
                tool_schemas=tool_schemas,
                authority_binding=authority_binding,
                case_id=case_id,
                arm_id=arm_id,
                repeat_index=repeat_index,
                round_index=round_index,
                provider_id=provider_id,
                model=model,
                base_url=base_url,
                context_mode=context_mode,
                context_plan_digest=context_plan_digest,
                transform_applied=transform_applied,
                attempt_index=attempt_index + number,
                retry_count=retry_count + number,
                prior_exchange_digest=prior_exchange_digest,
                invoke=invoke,
            )
        except ModelExchangeInvocationError as exc:
            attempt_evidence.append(exc.evidence)
            exhausted = number == total_attempts - 1
            transient = exc.evidence.outcome in _RETRYABLE_OUTCOMES
            if exhausted or not transient:
                exc.attempt_evidence = tuple(attempt_evidence)
                raise
            sleep(retry_backoff_seconds(number, rng=rng))
    raise AssertionError("unreachable retry loop exit")  # pragma: no cover


def retry_backoff_seconds(
    retry_number: int,
    *,
    rng: random.Random | None = None,
    base: float = _RETRY_BACKOFF_BASE_SECONDS,
    cap: float = _RETRY_BACKOFF_CAP_SECONDS,
) -> float:
    """Exponential backoff with equal-ratio jitter for retry ``retry_number``.

    The deterministic bound for the k-th retry (0-based) is
    ``[min(cap, base * 2**k) / 2, min(cap, base * 2**k)]``.
    """

    if retry_number < 0:
        raise ModelExchangeError("retry_number must be non-negative")
    if base <= 0 or cap <= 0:
        raise ModelExchangeError("retry backoff base and cap must be positive")
    selected = rng if rng is not None else _SHARED_RETRY_RNG
    delay = min(cap, base * (2**retry_number))
    return selected.uniform(delay / 2.0, delay)


_RETRYABLE_OUTCOMES = frozenset(
    {
        ModelExchangeOutcome.TIMEOUT,
        ModelExchangeOutcome.RATE_LIMITED,
        ModelExchangeOutcome.TRANSPORT_ERROR,
    }
)
_SHARED_RETRY_RNG = random.Random()


def _invoke_attempt(
    invoker: Any,
    *,
    model_input: Sequence[Any],
    sources: Sequence[Any],
    tool_schemas: Sequence[Any],
    authority_binding: Mapping[str, Any] | None,
    case_id: str,
    arm_id: str,
    repeat_index: int,
    round_index: int,
    provider_id: str,
    model: str,
    base_url: str,
    context_mode: str,
    context_plan_digest: str | None,
    transform_applied: bool,
    attempt_index: int,
    retry_count: int,
    prior_exchange_digest: str | None,
    invoke: Callable[[Any, Sequence[Any]], Any] | None,
) -> tuple[Any, ModelExchangeEvidence]:
    """Execute exactly one provider attempt and emit its evidence."""

    endpoint = normalize_openai_base_url(base_url)
    digests = build_canonical_input_digests(
        sources=sources,
        authority_binding=authority_binding,
        model_input=model_input,
        tool_schemas=tool_schemas,
    )
    request_payload = {
        "protocol": "openai_chat_completions",
        "provider_id": provider_id,
        "model": model,
        "messages": [_jsonable_message(item) for item in model_input],
        "tools": [_jsonable_tool(item) for item in tool_schemas],
    }
    started = time.monotonic()
    selected_invoke = invoke or (lambda target, messages: target.invoke(messages))
    try:
        response = selected_invoke(invoker, model_input)
    except Exception as exc:
        elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
        outcome = _classify_failure(exc)
        evidence = _build_evidence(
            case_id=case_id,
            arm_id=arm_id,
            repeat_index=repeat_index,
            round_index=round_index,
            provider_id=provider_id,
            model=model,
            endpoint=endpoint,
            digests=digests,
            request_payload=request_payload,
            response_payload=None,
            provider_request_id=None,
            context_mode=context_mode,
            context_plan_digest=context_plan_digest,
            transform_applied=transform_applied,
            outcome=outcome,
            parse_status=ModelParseStatus.INVALID,
            tool_names=(),
            attempt_index=attempt_index,
            retry_count=retry_count,
            elapsed_ms=elapsed_ms,
            prior_exchange_digest=prior_exchange_digest,
        )
        raise ModelExchangeInvocationError(evidence) from exc

    elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
    response_payload = _response_payload(response)
    tool_names = tuple(_response_tool_names(response))
    parse_status = (
        ModelParseStatus.VALID_TOOL_CALLS
        if tool_names
        else ModelParseStatus.VALID_NO_TOOL_CALL
    )
    evidence = _build_evidence(
        case_id=case_id,
        arm_id=arm_id,
        repeat_index=repeat_index,
        round_index=round_index,
        provider_id=provider_id,
        model=model,
        endpoint=endpoint,
        digests=digests,
        request_payload=request_payload,
        response_payload=response_payload,
        provider_request_id=_provider_request_id(response),
        context_mode=context_mode,
        context_plan_digest=context_plan_digest,
        transform_applied=transform_applied,
        outcome=ModelExchangeOutcome.SUCCESS,
        parse_status=parse_status,
        tool_names=tool_names,
        attempt_index=attempt_index,
        retry_count=retry_count,
        elapsed_ms=elapsed_ms,
        prior_exchange_digest=prior_exchange_digest,
    )
    return response, evidence


def normalize_openai_base_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModelExchangeError("OpenAI-compatible base URL is required")
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ModelExchangeError("OpenAI-compatible base URL must be HTTP(S)")
    if parsed.username or parsed.password:
        raise ModelExchangeError("OpenAI-compatible base URL cannot contain userinfo")
    if parsed.query or parsed.fragment:
        raise ModelExchangeError(
            "OpenAI-compatible base URL cannot contain query or fragment"
        )
    hostname = parsed.hostname.lower()
    if parsed.scheme == "http" and hostname not in _LOOPBACK_HOSTS:
        raise ModelExchangeError(
            "unencrypted OpenAI-compatible HTTP is allowed only on loopback"
        )
    host = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        host += f":{parsed.port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, host, path, "", ""))


def resolve_api_key(env_name: str, *, environ: Mapping[str, str] | None = None) -> str:
    if not _ENV_NAME.fullmatch(env_name):
        raise ModelExchangeError("API key environment variable name is invalid")
    values = os.environ if environ is None else environ
    value = values.get(env_name, "")
    if not isinstance(value, str) or not value.strip():
        raise ModelExchangeError("OpenAI-compatible provider credential is unavailable")
    return value


def endpoint_identity_digest(base_url: str) -> str:
    return canonical_sha256(
        {"normalized_openai_base_url": normalize_openai_base_url(base_url)}
    )


def _build_evidence(
    *,
    case_id: str,
    arm_id: str,
    repeat_index: int,
    round_index: int,
    provider_id: str,
    model: str,
    endpoint: str,
    digests: CanonicalInputDigests,
    request_payload: Mapping[str, Any],
    response_payload: Mapping[str, Any] | None,
    provider_request_id: str | None,
    context_mode: str,
    context_plan_digest: str | None,
    transform_applied: bool,
    outcome: ModelExchangeOutcome,
    parse_status: ModelParseStatus,
    tool_names: tuple[str, ...],
    attempt_index: int,
    retry_count: int,
    elapsed_ms: int,
    prior_exchange_digest: str | None,
) -> ModelExchangeEvidence:
    identity = {
        "case_id": case_id,
        "arm_id": arm_id,
        "repeat_index": repeat_index,
        "round_index": round_index,
        "provider_id": provider_id,
        "model": model,
        "endpoint_identity_digest": endpoint_identity_digest(endpoint),
        "source_set_digest": digests.source_set_digest,
        "authority_binding_digest": digests.authority_binding_digest,
        "model_input_digest": digests.model_input_digest,
        "tool_schema_digest": digests.tool_schema_digest,
        "request_digest": canonical_sha256(request_payload),
        "response_digest": (
            canonical_sha256(response_payload) if response_payload is not None else None
        ),
        "outcome": outcome.value,
        "attempt_index": attempt_index,
    }
    return ModelExchangeEvidence(
        exchange_id=canonical_sha256(identity),
        case_id=case_id,
        arm_id=arm_id,
        repeat_index=repeat_index,
        round_index=round_index,
        provider_id=provider_id,
        model=model,
        endpoint_identity_digest=identity["endpoint_identity_digest"],
        source_set_digest=digests.source_set_digest,
        authority_binding_digest=digests.authority_binding_digest,
        model_input_digest=digests.model_input_digest,
        tool_schema_digest=digests.tool_schema_digest,
        request_digest=identity["request_digest"],
        response_digest=identity["response_digest"],
        provider_request_id_digest=(
            canonical_sha256({"provider_request_id": provider_request_id})
            if provider_request_id
            else None
        ),
        prior_exchange_digest=prior_exchange_digest,
        context_mode=context_mode,
        context_plan_digest=context_plan_digest,
        transform_applied=transform_applied,
        request_observed=True,
        response_observed=response_payload is not None,
        outcome=outcome,
        parse_status=parse_status,
        tool_call_count=len(tool_names),
        tool_names=tool_names,
        attempt_index=attempt_index,
        retry_count=retry_count,
        elapsed_ms=elapsed_ms,
    )


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    return str(value)


def _jsonable_message(value: Any) -> dict[str, Any]:
    if isinstance(value, tuple) and len(value) == 2:
        return {"role": str(value[0]), "content": _jsonable(value[1])}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(mode="json")
        if isinstance(dumped, Mapping):
            return {str(key): _jsonable(item) for key, item in dumped.items()}
    return {
        "role": type(value).__name__,
        "content": _jsonable(getattr(value, "content", value)),
    }


def _jsonable_tool(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    args_schema = getattr(value, "args_schema", None)
    parameters = (
        args_schema.model_json_schema()
        if args_schema is not None and hasattr(args_schema, "model_json_schema")
        else {}
    )
    if hasattr(value, "name") or args_schema is not None:
        return {
            "name": str(getattr(value, "name", type(value).__name__)),
            "description": str(getattr(value, "description", "")),
            "parameters": _jsonable(parameters),
        }
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        if isinstance(dumped, Mapping):
            return {str(key): _jsonable(item) for key, item in dumped.items()}
    return {
        "name": str(getattr(value, "name", type(value).__name__)),
        "description": str(getattr(value, "description", "")),
        "parameters": _jsonable(parameters),
    }


def _response_payload(response: Any) -> dict[str, Any]:
    if hasattr(response, "model_dump"):
        dumped = response.model_dump(mode="json")
        if isinstance(dumped, Mapping):
            return {str(key): _jsonable(item) for key, item in dumped.items()}
    return {
        "content": _jsonable(getattr(response, "content", "")),
        "tool_calls": _jsonable(getattr(response, "tool_calls", []) or []),
        "response_metadata": _jsonable(
            getattr(response, "response_metadata", {}) or {}
        ),
    }


def _response_tool_names(response: Any) -> list[str]:
    names: list[str] = []
    for call in getattr(response, "tool_calls", None) or []:
        if isinstance(call, Mapping):
            name = call.get("name")
            if name is None and isinstance(call.get("function"), Mapping):
                name = call["function"].get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return names


def _provider_request_id(response: Any) -> str | None:
    direct = getattr(response, "id", None)
    if isinstance(direct, str) and direct:
        return direct
    metadata = getattr(response, "response_metadata", None)
    if isinstance(metadata, Mapping):
        for key in ("id", "request_id", "x-request-id"):
            value = metadata.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _classify_failure(exc: BaseException) -> ModelExchangeOutcome:
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if isinstance(exc, TimeoutError) or "timeout" in name or "timed out" in text:
        return ModelExchangeOutcome.TIMEOUT
    if "ratelimit" in name or "rate limit" in text or "status code: 429" in text:
        return ModelExchangeOutcome.RATE_LIMITED
    if any(marker in name for marker in ("connection", "transport", "network")):
        return ModelExchangeOutcome.TRANSPORT_ERROR
    return ModelExchangeOutcome.PROTOCOL_ERROR
