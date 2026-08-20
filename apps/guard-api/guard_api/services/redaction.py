"""Unified server-side redaction and bounded projection for audit evidence.

Implements the frozen contract limits from 证据链与溯源 API 目标契约 §21.1/§21.2:
sensitive key coverage, credential content scrubbing, per-field character and
item caps, nesting depth, and the 64 KiB per-event evidence budget. Guard API
审批 payload 清洗与策略评估 evidence 投影必须共用本工具。

CT-PR-03b 评审裁决留痕（保真优先）：``ct_transient_facts`` typed bound
通道对 bundle 本体**免除 scrub_text**（含 ``sanitize_audit_event`` 的
前置 ``redact_structure`` 与 ``bound_ct_transient_facts_envelope`` 两
处），仅保留结构限额（array/depth/text 长度）。依据：fact_builder
生产侧契约保证 raw secret 绝不落入 fact 字段——credential 值仅以
``credential:<fingerprint>``（canonical_sha256 指纹）形态存在
（fact_builder ``_credential_fingerprints``，CT-PR-02b）。若对 bundle
本体做字符串清洗，ActionIR 来源的 URL 形态 ref 可能被
CREDENTIAL_ASSIGNMENT_RE/PROVIDER_KEY_RE 改写为 ``[redacted]``，导致
持久 bundle ≠ 在线 bundle → backfill digest 失真跳过，D4/D9 闭环被
击穿。保真守门：``tests/test_ct_state_wiring.py`` round-trip 用例
（重建 bundle digest 与信封引用恒等）。
"""

from __future__ import annotations

import json
import hashlib
import re

from agentguard_core import AuditEvent
from agentguard_core.credentials import (
    CREDENTIAL_ASSIGNMENT_RE,
    PROVIDER_KEY_RE,
    SENSITIVE_ENV_EXPANSION_RE,
)

from .competition import (
    CriticalDecisionEvidenceError,
    strict_decision_authority_envelope,
)

REDACTED = "[redacted]"

# §21.1 服务端必做敏感 key 全集。
SENSITIVE_KEY_MARKERS = (
    "token",
    "secret",
    "password",
    "authorization",
    "credential",
    "api_key",
    "cookie",
    "private_key",
    "access_key",
    "session",
    "nonce",
)

# §21.2 已冻结的默认限制；部署配置不得放宽。
CONTENT_PREVIEW_LIMIT = 2000
SUMMARY_TEXT_LIMIT = 500
CONTEXT_SOURCES_LIMIT = 20
NORMALIZED_RESOURCES_LIMIT = 50
RULE_HITS_LIMIT = 100
ARRAY_LIMIT = 20
OBJECT_KEYS_LIMIT = 100
OBJECT_KEY_TEXT_LIMIT = 128
MAX_NESTING_DEPTH = 6
MAX_EVIDENCE_BYTES = 64 * 1024

# decision_v21 信封专用 typed bound 通道限额（V21-08 评审修复，非全局放宽）：
# 信封内容均为受控短 id/digest（core 已按 D4 上限截断：signal/policy/
# degradation refs 32、flow_path_refs 16），通用 ARRAY_LIMIT=20 会把 32 条
# refs 静默截到 20、MAX_NESTING_DEPTH=6 恰好把
# evidence→decision_v21→payload→coverage→<domain>→reason_codes 这第 6 层
# 替换为 "..."，两者都与 D4「禁止静默丢失」冲突。该通道仿 guard_decision
# 的 ``_bound_typed_value`` 保护模式，只对 decision_v21 键生效；全局
# ARRAY_LIMIT / MAX_NESTING_DEPTH 冻结边界（07 §21.2）不变。
DECISION_V21_ARRAY_LIMIT = 64
DECISION_V21_MAX_DEPTH = 8

# state_delta_v21 引用信封专用 typed bound 通道限额（V21-09 D2，仿
# decision_v21 通道）：信封只存投影身份引用（短 id/digest 标量，无嵌套
# 数组），限额保守；仅对 state_delta_v21 键生效，不放宽任何全局冻结
# 限额（07 §21.2）。
STATE_DELTA_V21_ARRAY_LIMIT = 16
STATE_DELTA_V21_MAX_DEPTH = 4

# ct_transient_facts 信封专用 typed bound 通道限额（CT-PR-03b D4，仿
# state_delta_v21 通道）：信封 payload 携带 bundle 规范化 dump（三类事实
# 数组 + 嵌套 fact 模型），数组限额取宽裕上限防静默截断（D4 纪律：
# 预算吃紧由 evidence.py 降级为 digest 引用留痕，而非截断）；仅对
# ct_transient_facts 键生效，不放宽任何全局冻结限额（07 §21.2）。
CT_TRANSIENT_FACTS_ARRAY_LIMIT = 512
CT_TRANSIENT_FACTS_MAX_DEPTH = 10

_AUTHORIZATION_VALUE_RE = re.compile(
    r"(authorization\s*[:=]\s*)([^\s\"'`,;]+(?:\s+[A-Za-z0-9._~+/=-]{8,})?)",
    re.IGNORECASE,
)
_BEARER_TOKEN_RE = re.compile(r"(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_COOKIE_VALUE_RE = re.compile(r"(cookie\s*[:=]\s*)([^\r\n\"]+)", re.IGNORECASE)
_PRIVATE_KEY_BODY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)


def looks_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(marker in normalized for marker in SENSITIVE_KEY_MARKERS)


def scrub_text(value: str) -> str:
    """Scrub credential content inside a string per §21.1."""

    # 私钥块必须最先替换，避免被后续 key=value / Cookie 清洗吞掉首行。
    redacted = _PRIVATE_KEY_BODY_RE.sub(REDACTED, value)
    redacted = PROVIDER_KEY_RE.sub(f"sk-{REDACTED}", redacted)
    redacted = CREDENTIAL_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group('key')}{match.group('sep')}{REDACTED}",
        redacted,
    )
    redacted = SENSITIVE_ENV_EXPANSION_RE.sub(f"$[{REDACTED}]", redacted)
    redacted = _AUTHORIZATION_VALUE_RE.sub(rf"\g<1>{REDACTED}", redacted)
    redacted = _BEARER_TOKEN_RE.sub(rf"\g<1>{REDACTED}", redacted)
    redacted = _COOKIE_VALUE_RE.sub(rf"\g<1>{REDACTED}", redacted)
    return redacted


def redact_structure(value: object) -> object:
    """Recursively replace sensitive-key values and scrub string content."""

    if hasattr(value, "model_dump"):
        return redact_structure(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    if isinstance(value, dict):
        return {
            str(key): (
                REDACTED if looks_sensitive_key(str(key)) else redact_structure(nested)
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return scrub_text(value)
    return value


def truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}..."


def bound_value(
    value: object,
    *,
    text_limit: int = SUMMARY_TEXT_LIMIT,
    array_limit: int = ARRAY_LIMIT,
    max_depth: int = MAX_NESTING_DEPTH,
    _depth: int = 1,
) -> object:
    """Project a JSON-compatible value onto the frozen §21.2 size limits."""

    if isinstance(value, str):
        return truncate_text(value, text_limit)
    if _depth >= max_depth:
        if isinstance(value, (dict, list)):
            return "..." if value else value
        return value
    if isinstance(value, dict):
        bounded: dict[str, object] = {}
        for key, nested in list(value.items())[:OBJECT_KEYS_LIMIT]:
            bounded_key = truncate_text(scrub_text(str(key)), OBJECT_KEY_TEXT_LIMIT)
            bounded[bounded_key] = bound_value(
                nested,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        return bounded
    if isinstance(value, list):
        return [
            bound_value(
                item,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
            for item in value[:array_limit]
        ]
    return value


def bound_redacted_value(
    value: object,
    *,
    text_limit: int = SUMMARY_TEXT_LIMIT,
    array_limit: int = ARRAY_LIMIT,
    max_depth: int = MAX_NESTING_DEPTH,
) -> object:
    """Redact first, then project onto the frozen size limits."""

    return bound_value(
        redact_structure(value),
        text_limit=text_limit,
        array_limit=array_limit,
        max_depth=max_depth,
    )


def sanitize_audit_event(event: AuditEvent) -> AuditEvent:
    """Return the canonical browser-safe event that is eligible for persistence.

    Redaction must happen before audit integrity metadata is attached. This makes
    the persisted hash chain authoritative for the safe representation and avoids
    relying on every producer—or a later browser response mapper—to remember the
    same security boundary.
    """

    # CT-PR-04-M: the bounded Context Manifest is a strict typed channel.
    # Generic redaction would turn ``sensitive: bool`` into a string, truncate
    # arrays without updating global counts, and crush SequenceRef/EvidenceRef
    # containers at the generic nesting limit.  Import lazily to avoid the
    # context-manifest module's dependency on the frozen budget helpers here.
    if event.event_type == "context_manifest_recorded" or (
        isinstance(event.evidence, dict) and "context_manifest" in event.evidence
    ):
        from .context_manifest import (
            context_manifest_audit_event,
            validate_context_manifest_audit_event,
        )

        strict = validate_context_manifest_audit_event(event)
        return context_manifest_audit_event(strict)

    raw_metadata = redact_structure(event.metadata)
    metadata: dict[str, object]
    if isinstance(raw_metadata, dict):
        raw_decision = raw_metadata.pop("guard_decision", None)
        bounded_metadata = bound_value(
            raw_metadata,
            text_limit=CONTENT_PREVIEW_LIMIT,
            array_limit=ARRAY_LIMIT,
        )
        metadata = bounded_metadata if isinstance(bounded_metadata, dict) else {}
        if raw_decision is not None:
            # Replay needs the complete GuardDecision shape. Keep the dedicated
            # rule/effect collection ceiling while preserving container types.
            metadata["guard_decision"] = _bound_typed_value(
                raw_decision,
                text_limit=CONTENT_PREVIEW_LIMIT,
                array_limit=RULE_HITS_LIMIT,
            )
    else:
        metadata = {}

    evidence: dict[str, object] | None = None
    if event.evidence is not None:
        # 保真优先裁决（CT-PR-03b 评审 S3，见模块 docstring）：CT 信封
        # 在 redact_structure 之前原样取出，bundle 本体免 scrub_text；
        # 通用清洗链只处理剩余键。
        source_evidence: object = event.evidence
        ct_envelope = (
            source_evidence.get("ct_transient_facts")
            if isinstance(source_evidence, dict)
            else None
        )
        authority_envelope = (
            source_evidence.get("decision_authority")
            if isinstance(source_evidence, dict)
            else None
        )
        raw_evidence = redact_structure(event.evidence)
        if isinstance(raw_evidence, dict):
            replay_decision = raw_evidence.pop("guard_decision", None)
            # decision_v21 信封仿 guard_decision 保护模式：通用 bound 会把
            # coverage 第 6 层替换为 "..." 并静默截断 D4 refs，改走专用
            # typed bound 通道（DECISION_V21_* 限额）。
            v21_envelope = raw_evidence.pop("decision_v21", None)
            # state_delta_v21 引用信封（V21-09 D2）同源口径：走专用 typed
            # bound 通道，不经通用 bound（禁静默丢失，D4-11 号纪律）。
            state_delta_envelope = raw_evidence.pop("state_delta_v21", None)
            # ct_transient_facts 信封（CT-PR-03b D4，B1 评审修复）：同源
            # 口径走专用 typed bound 通道——通用 bound 的
            # MAX_NESTING_DEPTH=6 会把 bundle 内 fact 对象碾成 "..."，
            # 使 backfill 的 model_validate 对任何非空 bundle 恒失败。
            raw_evidence.pop("ct_transient_facts", None)
            # Critical/no-drop authority is validated from the pre-redaction
            # source and restored after the generic evidence budget pass.
            raw_evidence.pop("decision_authority", None)
        else:
            replay_decision = None
            v21_envelope = None
            state_delta_envelope = None
            authority_envelope = None
        bounded_evidence = bound_value(
            raw_evidence,
            text_limit=CONTENT_PREVIEW_LIMIT,
            array_limit=RULE_HITS_LIMIT,
        )
        if isinstance(bounded_evidence, dict) and replay_decision is not None:
            bounded_evidence["guard_decision"] = _bound_typed_value(
                replay_decision,
                text_limit=CONTENT_PREVIEW_LIMIT,
                array_limit=RULE_HITS_LIMIT,
            )
        if isinstance(bounded_evidence, dict) and v21_envelope is not None:
            bounded_evidence["decision_v21"] = _bound_typed_value(
                v21_envelope,
                text_limit=CONTENT_PREVIEW_LIMIT,
                array_limit=DECISION_V21_ARRAY_LIMIT,
                max_depth=DECISION_V21_MAX_DEPTH,
            )
        if isinstance(bounded_evidence, dict) and state_delta_envelope is not None:
            bounded_evidence["state_delta_v21"] = _bound_typed_value(
                state_delta_envelope,
                text_limit=CONTENT_PREVIEW_LIMIT,
                array_limit=STATE_DELTA_V21_ARRAY_LIMIT,
                max_depth=STATE_DELTA_V21_MAX_DEPTH,
            )
        if isinstance(bounded_evidence, dict) and ct_envelope is not None:
            # 免 scrub 的 typed bound 通道（保真优先裁决，见模块
            # docstring）：仅结构限额，bundle 本体字符串不清洗。
            bounded_evidence["ct_transient_facts"] = _bound_typed_value(
                ct_envelope,
                text_limit=CONTENT_PREVIEW_LIMIT,
                array_limit=CT_TRANSIENT_FACTS_ARRAY_LIMIT,
                max_depth=CT_TRANSIENT_FACTS_MAX_DEPTH,
            )
        evidence = (
            enforce_evidence_budget(bounded_evidence)
            if isinstance(bounded_evidence, dict)
            else {}
        )
        if authority_envelope is not None:
            strict_authority = strict_decision_authority_envelope(
                {"decision_authority": authority_envelope}
            )
            candidate = {**evidence, **strict_authority}
            if evidence_serialized_size(candidate) > MAX_EVIDENCE_BYTES:
                raise CriticalDecisionEvidenceError(
                    "critical decision authority cannot survive audit sanitization"
                )
            evidence = candidate

    return event.model_copy(
        update={
            "summary": truncate_text(scrub_text(event.summary), SUMMARY_TEXT_LIMIT),
            "resource_targets": [
                truncate_text(scrub_text(target), SUMMARY_TEXT_LIMIT)
                for target in event.resource_targets[:NORMALIZED_RESOURCES_LIMIT]
            ],
            "rule_hits": [
                truncate_text(scrub_text(rule_id), SUMMARY_TEXT_LIMIT)
                for rule_id in event.rule_hits[:RULE_HITS_LIMIT]
            ],
            "reason": truncate_text(scrub_text(event.reason), CONTENT_PREVIEW_LIMIT),
            "metadata": metadata,
            "evidence": evidence,
        }
    )


def bound_decision_v21_envelope(value: object) -> object:
    """decision_v21 信封专用 bounded 投影（typed bound 通道）。

    先 ``redact_structure``（append-only 审计证据仍受 §21.1 敏感清洗），
    再经 ``_bound_typed_value`` 以 ``DECISION_V21_*`` 限额投影：与通用
    ``bound_value`` 不同，typed 容器不会被替换为 "..."（coverage 形状
    存活），数组限额 ≥ D4 refs 上限 32（不静默截断）。不放宽任何全局
    冻结限额（07 §21.2）。
    """

    return _bound_typed_value(
        redact_structure(value),
        text_limit=SUMMARY_TEXT_LIMIT,
        array_limit=DECISION_V21_ARRAY_LIMIT,
        max_depth=DECISION_V21_MAX_DEPTH,
    )


def decision_v21_budget_dropped_reference(envelope: object) -> dict[str, object]:
    """信封预算超限的降级标记：只保留确定性 sha256 摘要引用。

    D4 禁止静默丢失：预算吃紧时 decision_v21（append-only 旁路附属
    证据）先于 replay 权威键 guard_decision 被剥离，但留 digest 引用
    供离线核对（可对照 shadow 侧重建的信封摘要）。
    """

    return budget_dropped_reference(envelope)


def budget_dropped_reference(envelope: object) -> dict[str, object]:
    """v21 信封预算超限的通用降级标记（D4 禁静默丢失留痕）。

    decision_v21 / state_delta_v21 两条 typed bound 通道共用：预算吃紧
    时旁路附属信封先于 replay 权威键 guard_decision 被剥离，但留确定性
    sha256 摘要引用供离线核对（V21-09 D2 同源口径）。
    """

    digest = hashlib.sha256(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {"_budget_dropped": True, "_envelope_sha256": f"sha256:{digest}"}


def bound_state_delta_v21_envelope(value: object) -> object:
    """state_delta_v21 引用信封专用 bounded 投影（typed bound 通道）。

    仿 ``bound_decision_v21_envelope``：先 ``redact_structure``（append-only
    审计证据仍受 §21.1 敏感清洗），再经 ``_bound_typed_value`` 以
    ``STATE_DELTA_V21_*`` 限额投影；信封只存投影身份引用（短 id/digest
    标量），不放宽任何全局冻结限额（07 §21.2）。
    """

    return _bound_typed_value(
        redact_structure(value),
        text_limit=SUMMARY_TEXT_LIMIT,
        array_limit=STATE_DELTA_V21_ARRAY_LIMIT,
        max_depth=STATE_DELTA_V21_MAX_DEPTH,
    )


def bound_ct_transient_facts_envelope(value: object) -> object:
    """ct_transient_facts 信封专用 bounded 投影（typed bound 通道）。

    仿 ``bound_state_delta_v21_envelope`` 的结构限额口径，但依保真优先
    裁决（CT-PR-03b 评审 S3，见模块 docstring）**不经
    ``redact_structure`` / scrub_text**：bundle 本体必须与在线 bundle
    逐位一致，backfill 才能以 digest 对照重建投影；raw secret 由
    fact_builder 生产侧契约保证仅以指纹形态存在。text_limit 与
    ``sanitize_audit_event`` 通道同取 ``CONTENT_PREVIEW_LIMIT``，两遍
    投影幂等（持久 bundle == 在线 bundle）。不放宽任何全局冻结限额
    （07 §21.2）。
    """

    return _bound_typed_value(
        value,
        text_limit=CONTENT_PREVIEW_LIMIT,
        array_limit=CT_TRANSIENT_FACTS_ARRAY_LIMIT,
        max_depth=CT_TRANSIENT_FACTS_MAX_DEPTH,
    )


def _bound_typed_value(
    value: object,
    *,
    text_limit: int,
    array_limit: int,
    max_depth: int = MAX_NESTING_DEPTH,
    _depth: int = 1,
) -> object:
    """Bound replay data without replacing typed containers with strings."""

    if isinstance(value, str):
        return truncate_text(value, text_limit)
    if isinstance(value, dict):
        if _depth >= max_depth:
            return {}
        bounded: dict[str, object] = {}
        for key, nested in list(value.items())[:OBJECT_KEYS_LIMIT]:
            bounded_key = truncate_text(scrub_text(str(key)), OBJECT_KEY_TEXT_LIMIT)
            bounded[bounded_key] = _bound_typed_value(
                nested,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
        return bounded
    if isinstance(value, list):
        if _depth >= max_depth:
            return []
        return [
            _bound_typed_value(
                item,
                text_limit=text_limit,
                array_limit=array_limit,
                max_depth=max_depth,
                _depth=_depth + 1,
            )
            for item in value[:array_limit]
        ]
    return value


def evidence_serialized_size(evidence: dict[str, object]) -> int:
    return len(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def enforce_evidence_budget(
    evidence: dict[str, object], *, max_bytes: int = MAX_EVIDENCE_BYTES
) -> dict[str, object]:
    """Shrink text projections until the serialized evidence fits the budget.

    超限截断投影，不拒绝写入（§21.2 / D-05）。
    """

    current = evidence
    original_size = evidence_serialized_size(evidence)
    for text_limit in (500, 200, 64, 16):
        if evidence_serialized_size(current) <= max_bytes:
            return current
        bounded = bound_value(
            current,
            text_limit=text_limit,
            array_limit=ARRAY_LIMIT,
            max_depth=MAX_NESTING_DEPTH,
        )
        current = bounded if isinstance(bounded, dict) else {}
    if evidence_serialized_size(current) <= max_bytes:
        return current

    # A large number of short keys can still exceed the byte budget after text
    # projection. Keep a deterministic commitment to the already-redacted input
    # instead of returning an oversized record or silently dropping all context.
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    fallback: dict[str, object] = {
        "_truncated": True,
        "_original_size_bytes": original_size,
        "_redacted_sha256": digest,
    }
    if evidence_serialized_size(fallback) <= max_bytes:
        return fallback
    return {}
