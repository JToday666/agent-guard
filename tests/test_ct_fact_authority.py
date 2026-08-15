"""CT-PR-01 Fact Authority Matrix 契约测试（ct-fam-1，纯函数，无接线）。

口径依据：

- 08 章 §4 五条测试口径 + 02 章 §11 Determinism Contract + §14 DoD
  中适用于纯函数模块的项（T-NoClaimUpgrade / T-NoSanitizeClaim /
  model 永不 authoritative / replay deterministic）；
- parity 断言仅限本模块消费的冻结键（source_defaults / claim_rules /
  declassification），不断言 budgets/fusion/rollout 等。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentguard_core.security_context.facts import MemoryFact
from agentguard_core.signals.models import EvidenceRef
from guard_api.security_state.fact_authority import (
    CLAIM_RULES,
    DECLASSIFICATION_RULES,
    FACT_AUTHORITY_VERSION,
    MEMORY_INHERIT,
    SOURCE_DEFAULTS,
    ProducerIdentity,
    SourceClaim,
    apply_memory_inheritance,
    normalize_source_type,
    verify_source_claim,
)

ROOT = Path(__file__).resolve().parents[1]
CT_FREEZE_DIR = ROOT / "docs" / "AgentGuard_Context_Isolation_Taint_Tracking_Final_RC"

EXTERNAL_SOURCES = ("web", "email", "rag", "tool_result", "mcp")
ALL_SOURCES = tuple(SOURCE_DEFAULTS)


@pytest.fixture(scope="module")
def freeze_yaml() -> dict:
    return json.loads(
        (CT_FREEZE_DIR / "context_taint_contract_freeze.yaml").read_text(
            encoding="utf-8"
        )
    )


def _claim(
    source_type: str = "web",
    *,
    claimed_trust: str = "unknown",
    sanitized: bool = False,
    instruction_like: bool = False,
    server_sensitive_evidence: bool = False,
    server_credential_evidence: bool = False,
) -> SourceClaim:
    return SourceClaim(
        source_id="source:test",
        scope_digest="sha256:0" * 2,
        raw_source_type=source_type,
        claimed_trust=claimed_trust,  # type: ignore[arg-type]
        sanitized=sanitized,
        instruction_like=instruction_like,
        server_sensitive_evidence=server_sensitive_evidence,
        server_credential_evidence=server_credential_evidence,
    )


def _identity(*, owner: bool = False) -> ProducerIdentity:
    return ProducerIdentity(
        runtime_authenticated=owner,
        principal_authenticated=owner,
        producer_id="principal:owner" if owner else None,
    )


def _memory_fact(trust_state: str, taints: tuple[str, ...] = ()) -> MemoryFact:
    return MemoryFact(
        memory_id="memory:test",
        change_id=None,
        change_status="committed",
        trust_state=trust_state,  # type: ignore[arg-type]
        taints=list(taints),  # type: ignore[arg-type]
        source_refs=[],
        last_write_sequence=None,
        last_read_sequence=None,
        evidence_refs=[
            EvidenceRef(
                ref_id="evidence:test",
                kind="memory_fact",
                record_type="memory_fact",
                record_id="memory:test",
                digest="sha256:0" * 2,
                redaction_state="none",
            )
        ],
    )


# ---------------------------------------------------------------------------
# A. parity 组：模块冻结常量 == 冻结 YAML（仅限本模块消费的键）
# ---------------------------------------------------------------------------


def test_fact_authority_version_is_ct_fam_1() -> None:
    assert FACT_AUTHORITY_VERSION == "ct-fam-1"


def test_source_defaults_match_freeze_yaml(freeze_yaml) -> None:
    yaml_defaults = freeze_yaml["source_defaults"]
    assert set(SOURCE_DEFAULTS) == set(yaml_defaults)
    for name, yaml_profile in yaml_defaults.items():
        profile = SOURCE_DEFAULTS[name]
        assert profile.trust == yaml_profile["trust"]
        assert profile.fact_authority == yaml_profile["fact_authority"]
        expected_taints = yaml_profile["initial_taints"]
        if expected_taints == MEMORY_INHERIT:
            assert profile.initial_taints == MEMORY_INHERIT
        else:
            assert list(profile.initial_taints) == expected_taints


def test_claim_rules_match_freeze_yaml(freeze_yaml) -> None:
    assert dict(CLAIM_RULES) == freeze_yaml["claim_rules"]


def test_declassification_rules_match_freeze_yaml(freeze_yaml) -> None:
    yaml_declass = freeze_yaml["declassification"]
    assert DECLASSIFICATION_RULES["producer"] == yaml_declass["producer"]
    assert (
        DECLASSIFICATION_RULES["adapter_sanitized_is_declassification"]
        == yaml_declass["adapter_sanitized_is_declassification"]
    )
    assert (
        DECLASSIFICATION_RULES["llm_summary_is_declassification"]
        == yaml_declass["llm_summary_is_declassification"]
    )
    assert (
        list(DECLASSIFICATION_RULES["protected_labels"])
        == yaml_declass["protected_labels"]
    )


# ---------------------------------------------------------------------------
# B. 行为组 — T-NoClaimUpgrade：external 源 claimed trusted 不可洗白
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_type", EXTERNAL_SOURCES)
def test_external_claimed_trusted_cannot_upgrade(source_type: str) -> None:
    descriptor = verify_source_claim(
        claim=_claim(source_type, claimed_trust="trusted"),
        producer_identity=_identity(),
    )
    assert descriptor.trust == "untrusted"
    assert descriptor.fact_authority == "untrusted_claim"
    assert descriptor.verification_state == "unverified"
    assert "UNTRUSTED" in descriptor.initial_taints
    assert "trusted_claim_ignored" in descriptor.reason_codes


def test_sanitized_claim_never_removes_taints() -> None:
    baseline = verify_source_claim(claim=_claim("web"), producer_identity=_identity())
    sanitized = verify_source_claim(
        claim=_claim("web", sanitized=True), producer_identity=_identity()
    )
    assert sanitized.initial_taints == baseline.initial_taints
    assert "UNTRUSTED" in sanitized.initial_taints
    assert "sanitized_claim_ignored" in sanitized.reason_codes


# ---------------------------------------------------------------------------
# B. 行为组 — authenticated owner 升级（仅 trusted/trusted_claim/verified）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_type", ("web", "file", "tool_result"))
def test_authenticated_owner_upgrades_identity_trust_only(source_type: str) -> None:
    descriptor = verify_source_claim(
        claim=_claim(source_type), producer_identity=_identity(owner=True)
    )
    assert descriptor.trust == "trusted"
    assert descriptor.fact_authority == "trusted_claim"
    assert descriptor.verification_state == "verified"
    assert "authenticated_owner_upgrade" in descriptor.reason_codes


def test_authenticated_owner_never_reaches_authoritative() -> None:
    for source_type in ALL_SOURCES:
        descriptor = verify_source_claim(
            claim=_claim(source_type), producer_identity=_identity(owner=True)
        )
        assert descriptor.fact_authority != "authoritative"


# ---------------------------------------------------------------------------
# B. 行为组 — model 源恒 model_judgment + trust=unknown
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("claimed_trust", ("trusted", "untrusted", "unknown"))
@pytest.mark.parametrize("owner", (False, True))
def test_model_source_is_always_model_judgment(claimed_trust: str, owner: bool) -> None:
    descriptor = verify_source_claim(
        claim=_claim("model", claimed_trust=claimed_trust),
        producer_identity=_identity(owner=owner),
    )
    assert descriptor.fact_authority == "model_judgment"
    assert descriptor.trust == "unknown"
    assert descriptor.fact_authority != "authoritative"


# ---------------------------------------------------------------------------
# B. 行为组 — memory 继承（02 §7）与 fail-closed
# ---------------------------------------------------------------------------


def test_memory_descriptor_is_pending_until_inheritance_applied() -> None:
    descriptor = verify_source_claim(
        claim=_claim("memory"), producer_identity=_identity()
    )
    assert descriptor.source_type == "memory"
    assert descriptor.memory_inherit_pending is True
    assert descriptor.trust == "unknown"
    assert "memory_inherit_pending_apply_memory_inheritance" in descriptor.reason_codes


def test_memory_inherits_tainted_memory_fact() -> None:
    descriptor = verify_source_claim(
        claim=_claim("memory"), producer_identity=_identity()
    )
    resolved = apply_memory_inheritance(
        descriptor, _memory_fact("tainted", ("EXTERNAL_INSTRUCTION",))
    )
    assert resolved.trust == "untrusted"
    assert resolved.fact_authority == "untrusted_claim"
    assert resolved.verification_state == "verified"
    assert resolved.memory_inherit_pending is False
    assert "UNTRUSTED" in resolved.initial_taints
    assert "EXTERNAL_INSTRUCTION" in resolved.initial_taints
    assert "memory_trust_state_tainted" in resolved.reason_codes


def test_memory_inherits_clean_memory_fact_as_trusted_claim() -> None:
    descriptor = verify_source_claim(
        claim=_claim("memory"), producer_identity=_identity()
    )
    resolved = apply_memory_inheritance(descriptor, _memory_fact("clean"))
    assert resolved.trust == "trusted"
    assert resolved.fact_authority == "trusted_claim"
    assert resolved.initial_taints == ()
    assert "memory_trust_state_clean" in resolved.reason_codes


@pytest.mark.parametrize("trust_state", ("quarantined", "unknown"))
def test_memory_quarantined_or_unknown_fails_closed(trust_state: str) -> None:
    descriptor = verify_source_claim(
        claim=_claim("memory"), producer_identity=_identity()
    )
    resolved = apply_memory_inheritance(descriptor, _memory_fact(trust_state))
    assert resolved.trust == "unknown"
    assert resolved.fact_authority != "authoritative"


def test_memory_without_memory_fact_fails_closed() -> None:
    descriptor = verify_source_claim(
        claim=_claim("memory"), producer_identity=_identity()
    )
    resolved = apply_memory_inheritance(descriptor, None)
    assert resolved.trust == "unknown"
    assert resolved.verification_state == "not_applicable"
    assert resolved.memory_inherit_pending is False
    assert "memory_fact_missing" in resolved.reason_codes


# ---------------------------------------------------------------------------
# B. 行为组 — risk-increasing claims 与 server evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_type", EXTERNAL_SOURCES)
def test_instruction_like_adds_external_instruction_taint(source_type: str) -> None:
    descriptor = verify_source_claim(
        claim=_claim(source_type, instruction_like=True), producer_identity=_identity()
    )
    assert "EXTERNAL_INSTRUCTION" in descriptor.initial_taints
    assert "UNTRUSTED" in descriptor.initial_taints


def test_credential_evidence_adds_credential_and_sensitive() -> None:
    descriptor = verify_source_claim(
        claim=_claim("web", server_credential_evidence=True),
        producer_identity=_identity(),
    )
    assert "CREDENTIAL" in descriptor.initial_taints
    assert "SENSITIVE" in descriptor.initial_taints


def test_sensitive_claim_false_cannot_prove_absence() -> None:
    descriptor = verify_source_claim(
        claim=_claim("web", server_sensitive_evidence=False),
        producer_identity=_identity(),
    )
    assert "SENSITIVE" not in descriptor.initial_taints


# ---------------------------------------------------------------------------
# B. 行为组 — normalize + fail-closed（不 raise）
# ---------------------------------------------------------------------------


def test_normalize_source_type_known_values_round_trip() -> None:
    for value in (
        "user",
        "web",
        "email",
        "tool_result",
        "mcp",
        "rag",
        "memory",
        "file",
        "model",
        "runtime",
        "other",
    ):
        normalized, unknown = normalize_source_type(value)
        assert (normalized, unknown) == (value, False)


def test_normalize_source_type_unknown_falls_back_to_other() -> None:
    assert normalize_source_type("definitely-not-a-source") == ("other", True)


def test_unknown_source_type_fails_closed_without_raising() -> None:
    descriptor = verify_source_claim(
        claim=_claim("definitely-not-a-source", claimed_trust="trusted"),
        producer_identity=_identity(owner=True),
    )
    assert descriptor.source_type == "other"
    assert descriptor.trust == "unknown"
    assert descriptor.fact_authority != "authoritative"
    assert "source_type_unknown" in descriptor.reason_codes


def test_runtime_source_without_defaults_fails_closed() -> None:
    # runtime/user 在 11 值 Literal 内但不在 8 源默认表：v1 policy 信任
    # 升级未实现，必须 fail-closed 而非放行。
    descriptor = verify_source_claim(
        claim=_claim("runtime"), producer_identity=_identity()
    )
    assert descriptor.source_type == "runtime"
    assert descriptor.trust == "unknown"
    assert descriptor.verification_state == "unverified"
    assert descriptor.fact_authority != "authoritative"
    assert "source_default_missing" in descriptor.reason_codes


# ---------------------------------------------------------------------------
# B. 行为组 — 8 源 × claim 组合参数化矩阵 + 确定性
# ---------------------------------------------------------------------------

_CLAIM_COMBOS = (
    {},
    {"claimed_trust": "trusted"},
    {"claimed_trust": "untrusted"},
    {"sanitized": True},
    {"instruction_like": True},
    {"server_sensitive_evidence": True},
    {"server_credential_evidence": True},
    {
        "claimed_trust": "trusted",
        "sanitized": True,
        "instruction_like": True,
        "server_sensitive_evidence": True,
        "server_credential_evidence": True,
    },
)


@pytest.mark.parametrize("source_type", ALL_SOURCES)
@pytest.mark.parametrize("combo", _CLAIM_COMBOS)
@pytest.mark.parametrize("owner", (False, True))
def test_claim_matrix_never_self_elevates_or_shrinks_taints(
    source_type: str, combo: dict, owner: bool
) -> None:
    descriptor = verify_source_claim(
        claim=_claim(source_type, **combo), producer_identity=_identity(owner=owner)
    )
    # CT-F0-07 / CT-Q-01：任何 claim 组合不得自取 authoritative。
    assert descriptor.fact_authority != "authoritative"

    if descriptor.memory_inherit_pending:
        pytest.skip("memory 三字段由 apply_memory_inheritance 解析")

    profile = SOURCE_DEFAULTS[source_type]
    if source_type == "model":
        assert descriptor.fact_authority == "model_judgment"
        assert descriptor.trust == "unknown"
    else:
        # Claim Monotonicity：无身份升级时 trust 只能保持或更保守；
        # claimed untrusted 是 risk-increasing，恒把 trust 压到 untrusted
        # （即使 authenticated owner 升级之后）。
        expected_trust = "trusted" if owner else profile.trust
        if combo.get("claimed_trust") == "untrusted":
            expected_trust = "untrusted"
        assert descriptor.trust == expected_trust

    # T-NoSanitizeClaim：任何组合下 taints ⊇ 默认 taints（不减）。
    default_taints = set(profile.initial_taints)  # type: ignore[arg-type]
    assert set(descriptor.initial_taints) >= default_taints


@pytest.mark.parametrize("source_type", ALL_SOURCES)
@pytest.mark.parametrize("owner", (False, True))
def test_verify_is_deterministic_for_same_input(source_type: str, owner: bool) -> None:
    kwargs = {
        "claimed_trust": "trusted",
        "sanitized": True,
        "instruction_like": True,
        "server_sensitive_evidence": True,
    }
    first = verify_source_claim(
        claim=_claim(source_type, **kwargs), producer_identity=_identity(owner=owner)
    )
    second = verify_source_claim(
        claim=_claim(source_type, **kwargs), producer_identity=_identity(owner=owner)
    )
    assert first == second
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_descriptor_is_json_serializable() -> None:
    descriptor = verify_source_claim(
        claim=_claim("web", server_credential_evidence=True),
        producer_identity=_identity(),
    )
    payload = descriptor.model_dump(mode="json")
    assert json.loads(json.dumps(payload)) == payload
