"""V21-08 T2：fusion 矩阵求值器契约测试。

覆盖：

- ``load_fusion_matrix`` 加载/缓存/schema 同口径校验（含 jsonschema
  交叉校验）与"禁止未定义 selector/disposition"；
- 冻结 ``fusion_matrix.yaml`` 全部规则（flow/influence/memory/behavior）
  与 03 §7 Markdown Source-to-Sink 表格的逐项一致性映射；
- 03 §6 七步优先级 / 8 级 priority 链与 CLEAR_DENY > DEFER > CLEAR_ALLOW；
- 10 条 ``clear_allow_requires`` 逐条"缺一即不得 CLEAR_ALLOW"；
- 03 §3 evidence group 去重不重复计权；
- 缺态/缺输入 → DEFER（绝不 fail-open）；
- 判定确定性（同输入同输出，无 wall-clock/uuid）与 legacy 导入隔离。
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agentguard_core.decisions import fusion as fusion_module
from agentguard_core.decisions.evidence import CoverageMap, DomainCoverage
from agentguard_core.decisions.fusion import (
    CLEAR_ALLOW_PROOF_REASON,
    HOSTILE_INSTRUCTION_CATEGORIES,
    FusionMatrixError,
    dedupe_evidence_groups,
    evaluate_fusion,
    load_fusion_matrix,
)
from agentguard_core.signals.models import (
    AuthorityVerdict,
    EvaluationDegradation,
    FlowVerdict,
    PolicyViolation,
    SecuritySignal,
)

ROOT = Path(__file__).resolve().parents[1]
FREEZE_DIR = ROOT / "docs" / "AgentGuard_Core_V2.1_Final_Contract_Freeze"
FUSION_MATRIX_YAML = FREEZE_DIR / "fusion_matrix.yaml"
FUSION_MATRIX_SCHEMA = FREEZE_DIR / "fusion_matrix.schema.json"
CHAPTER_03 = FREEZE_DIR / "03_判定融合与Semantic契约.md"


# ---------------------------------------------------------------------------
# 构造辅助
# ---------------------------------------------------------------------------


def _coverage(**statuses: str) -> CoverageMap:
    defaults = {
        domain: "complete"
        for domain in (
            "task",
            "source",
            "capability",
            "behavior",
            "dataflow",
            "memory",
            "runtime_outcome",
        )
    }
    defaults.update(statuses)
    return CoverageMap(
        **{
            domain: DomainCoverage(
                domain=domain,
                status=status,
                as_of_sequence=None,
                projector_version="v21-07.projector.2",
                reason_codes=[],
            )
            for domain, status in defaults.items()
        }
    )


def _authority(
    status: str = "authorized", *, mismatches: list[str] | None = None
) -> AuthorityVerdict:
    return AuthorityVerdict(
        status=status,
        matched_grant_ids=["grant-1"] if status == "authorized" else [],
        missing_capabilities=[],
        explicit_scope_mismatches=mismatches or [],
        evidence_refs=[],
    )


def _flow(
    status: str = "safe",
    *,
    taints: list[str] | None = None,
    strength: str | None = None,
    external_sink: bool = False,
    path_refs: list[str] | None = None,
) -> FlowVerdict:
    return FlowVerdict(
        status=status,
        strongest_strength=strength,
        taints=taints or [],
        external_sink=external_sink,
        path_refs=path_refs or [],
        evidence_refs=[],
    )


def _violation(
    tier: str,
    effect: str = "deny",
    *,
    rule_id: str = "R-1",
    violation_id: str | None = None,
) -> PolicyViolation:
    return PolicyViolation(
        violation_id=violation_id or f"v-{rule_id}",
        rule_id=rule_id,
        policy_tier=tier,
        effect=effect,
        reason_codes=["test"],
        evidence_refs=[],
    )


def _signal(
    signal_id: str,
    *,
    category: str = "prompt_injection",
    evidence_group: str = "group-1",
    confidence: str = "high",
    impact: str = "high",
) -> SecuritySignal:
    return SecuritySignal(
        signal_id=signal_id,
        detector_id="detector-1",
        category=category,
        scope="event",
        impact=impact,
        confidence=confidence,
        evidence_group=evidence_group,
        reason_codes=["test-signal"],
        evidence_refs=[],
        facts=[],
        tags=[],
    )


def _degradation(
    degradation_id: str = "deg-1", *, required: bool = True
) -> EvaluationDegradation:
    return EvaluationDegradation(
        degradation_id=degradation_id,
        component_id="detector-x",
        domain="dataflow",
        required_for_action=required,
        failure_kind="unavailable",
        reason_codes=["test-degradation"],
        evidence_refs=[],
    )


def _green_kwargs() -> dict:
    """CLEAR_ALLOW 证明全绿的基线输入。"""
    return {
        "impact": "low",
        "policy_violations": (),
        "signals": (),
        "degradations": (),
        "authority": _authority("authorized"),
        "flow": _flow("safe"),
        "coverage": _coverage(),
        "required_domains": ("task", "dataflow"),
        "memory_facts": (),
        "flows": (),
        "behavior_aggregates": (),
        "requires_semantic": False,
        "security_digests_valid": True,
    }


def _raw_matrix() -> dict:
    return json.loads(FUSION_MATRIX_YAML.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 加载与校验
# ---------------------------------------------------------------------------


def test_load_fusion_matrix_is_module_level_constant() -> None:
    first = load_fusion_matrix()
    second = load_fusion_matrix()
    assert first is second
    assert first.schema_version == "2.1-final-candidate"
    assert first.match_semantics == "all_matching_rules_then_highest_priority"
    assert first.disposition_priority == ("CLEAR_DENY", "DEFER", "CLEAR_ALLOW")
    assert len(first.priority) == 8
    assert first.priority[0] == "system_invariant"
    assert first.priority[-1] == "defer_default"
    assert len(first.clear_allow_requires) == 10
    assert len(first.flow_rules) == 6
    assert len(first.influence_rules) == 3
    assert len(first.memory_rules) == 2
    assert len(first.behavior_rules) == 2


def test_default_path_resolves_to_repo_freeze_dir() -> None:
    path = fusion_module.default_fusion_matrix_path()
    assert path == FUSION_MATRIX_YAML
    assert path.is_file()


# ---------------------------------------------------------------------------
# 包内副本（package data）与 docs 冻结真值一致性（wheel 部署可用，防漂移）
# ---------------------------------------------------------------------------


def test_packaged_matrix_is_byte_identical_to_freeze_truth() -> None:
    """包内副本与 docs 冻结真值逐字节一致：漂移即测试失败。

    wheel 安装（Dockerfile 部署）不含仓库 docs 目录，运行时默认加载
    走随包分发的 package data 副本；两副本任何字节差异都意味着部署
    行为与冻结契约脱钩，必须在此拦截。

    二进制口径比对：``read_text`` 的 universal newline 会把 CRLF 折叠
    为 LF，会掩盖行尾差异，故用 ``read_bytes``。
    """
    from importlib import resources

    packaged_bytes = (
        resources.files("agentguard_core.decisions.data")
        .joinpath("fusion_matrix.yaml")
        .read_bytes()
    )
    frozen_bytes = FUSION_MATRIX_YAML.read_bytes()
    assert packaged_bytes == frozen_bytes


def test_default_load_uses_packaged_copy_and_matches_docs_semantics() -> None:
    """默认加载（包内副本）与从 docs 真值显式加载语义一致。"""
    default_matrix = load_fusion_matrix()
    docs_matrix = load_fusion_matrix(FUSION_MATRIX_YAML)
    assert default_matrix.model_dump() == docs_matrix.model_dump()


def test_packaged_matrix_resource_is_importlib_resolvable() -> None:
    """importlib.resources 可解析包内副本（wheel/源码检出均可用）。"""
    from importlib import resources

    resource = (
        resources.files("agentguard_core.decisions.data")
        .joinpath("fusion_matrix.yaml")
    )
    assert resource.is_file()
    # 与 SHA256SUMS 口径无关：直接校验可解析为合法矩阵结构。
    raw = json.loads(resource.read_text(encoding="utf-8"))
    assert raw["schema_version"] == "2.1-final-candidate"


def test_fusion_matrix_passes_jsonschema_cross_check() -> None:
    """依赖无关校验与冻结 JSON Schema 同口径（交叉验证）。"""
    schema = json.loads(FUSION_MATRIX_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(_raw_matrix()))
    assert errors == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw["flow_rules"][0].update({"strength": "ultra"}),
        lambda raw: raw["flow_rules"][0].update({"disposition": "MAYBE"}),
        lambda raw: raw["flow_rules"][0].update({"sink": "orbital"}),
        lambda raw: raw["influence_rules"][0].update({"authority": "root"}),
        lambda raw: raw["memory_rules"][0].update({"taint": "GOSSIP"}),
        lambda raw: raw["behavior_rules"][0].update({"pattern": ["B9"]}),
        lambda raw: raw["behavior_rules"][0].update({"confidence": "extreme"}),
        lambda raw: raw.update({"extra_key": 1}),
        lambda raw: raw["flow_rules"][0].update({"extra": 1}),
        lambda raw: raw["flow_rules"][0].pop("disposition"),
        lambda raw: raw["priority"].pop(),
        lambda raw: raw["clear_allow_requires"].pop(),
        lambda raw: raw.update({"match_semantics": "first_match"}),
        lambda raw: raw["flow_rules"][0].update({"id": "flow-lowercase"}),
        lambda raw: raw["behavior_rules"][1].update(
            {"id": raw["behavior_rules"][0]["id"]}
        ),
    ],
)
def test_load_fusion_matrix_rejects_schema_violations(
    tmp_path: Path, mutate
) -> None:
    raw = _raw_matrix()
    mutate(raw)
    candidate = tmp_path / "fusion_matrix.yaml"
    candidate.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(FusionMatrixError):
        load_fusion_matrix(candidate)
    # 显式路径加载不影响模块级缓存。
    assert load_fusion_matrix().schema_version == "2.1-final-candidate"


def test_rule_ids_are_unique_across_groups() -> None:
    matrix = load_fusion_matrix()
    rule_ids = [
        rule.id
        for rules in (
            matrix.flow_rules,
            matrix.influence_rules,
            matrix.memory_rules,
            matrix.behavior_rules,
        )
        for rule in rules
    ]
    assert len(rule_ids) == len(set(rule_ids)) == 13


# ---------------------------------------------------------------------------
# 03 §7 Source-to-Sink Markdown 表格与机器规则逐项一致性映射
# ---------------------------------------------------------------------------


def _parse_markdown_table(section_text: str) -> list[list[str]]:
    """解析冻结文档中的 pipe 表格（跳过表头分隔行）。"""
    rows: list[list[str]] = []
    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows


def _section(name: str) -> str:
    text = CHAPTER_03.read_text(encoding="utf-8")
    marker = f"### {name}"
    start = text.index(marker)
    rest = text[start + len(marker) :]
    # 截断到下一个同级/更高级标题。
    for token in ("\n### ", "\n## ", "\n# "):
        index = rest.find(token)
        if index != -1:
            rest = rest[:index]
    return rest


def test_chapter_03_freeze_anchor_sentences_present() -> None:
    text = CHAPTER_03.read_text(encoding="utf-8")
    assert "all_matching_rules_then_highest_priority" in text or (
        "收集全部匹配规则" in text
        and "CLEAR_DENY > DEFER > CLEAR_ALLOW" in text
    )
    assert "不允许新增未定义 selector 或 disposition" in text


@pytest.mark.parametrize(
    ("rule_id", "taint", "strength", "authority", "sink", "disposition"),
    [
        (
            "FLOW-CREDENTIAL-EXACT-UNAUTHORIZED",
            "CREDENTIAL",
            "exact",
            "unauthorized",
            "external",
            "CLEAR_DENY",
        ),
        (
            "FLOW-CREDENTIAL-STRONG-UNAUTHORIZED",
            "CREDENTIAL",
            "strong",
            "unauthorized",
            "external",
            "CLEAR_DENY",
        ),
        (
            "FLOW-CREDENTIAL-POSSIBLE",
            "CREDENTIAL",
            "possible",
            "any",
            "external",
            "DEFER",
        ),
        (
            "FLOW-SENSITIVE-EXACT-UNAUTHORIZED",
            "SENSITIVE",
            "exact",
            "unauthorized",
            "external",
            "CLEAR_DENY",
        ),
        (
            "FLOW-SENSITIVE-STRONG-UNAUTHORIZED",
            "SENSITIVE",
            "strong",
            "unauthorized",
            "external",
            "DEFER",
        ),
        (
            "FLOW-SENSITIVE-POSSIBLE",
            "SENSITIVE",
            "possible",
            "any",
            "external",
            "DEFER",
        ),
    ],
)
def test_each_flow_rule_maps_to_a_chapter_7_1_row(
    rule_id: str,
    taint: str,
    strength: str,
    authority: str,
    sink: str,
    disposition: str,
) -> None:
    matrix = load_fusion_matrix()
    rule = next(rule for rule in matrix.flow_rules if rule.id == rule_id)
    # 机器规则本体与映射表一致（防止 yaml 漂移）。
    assert (
        rule.taint,
        rule.strength,
        rule.authority,
        rule.sink,
        rule.disposition,
    ) == (taint, strength, authority, sink, disposition)

    rows = _parse_markdown_table(_section("7.1 数据外发"))
    matches = []
    for row in rows[1:]:  # 跳过表头
        row_taint, row_strength, row_authority, row_sink, row_result = row
        if row_taint != taint or row_strength != strength:
            continue
        if row_sink != sink:
            continue
        if authority == "unauthorized" and "unauthorized" not in row_authority:
            continue
        if authority == "any" and "任意" not in row_authority:
            continue
        if disposition not in row_result:
            continue
        if disposition == "CLEAR_DENY" and "DEFER，除非" in row_result:
            continue
        matches.append(row)
    assert len(matches) == 1, (
        f"{rule_id} must map to exactly one §7.1 row, got {matches}"
    )


def test_authorized_taint_rows_have_no_machine_rule() -> None:
    """§7.1 的 authorized 行语义是"不因 taint 自动 deny"——不存在
    authority=authorized 的机器规则与之对应（继续检查 policy/task）。"""
    matrix = load_fusion_matrix()
    assert all(rule.authority != "authorized" for rule in matrix.flow_rules)
    rows = _parse_markdown_table(_section("7.1 数据外发"))
    authorized_rows = [row for row in rows[1:] if row[2] == "authorized"]
    assert len(authorized_rows) == 2


@pytest.mark.parametrize(
    ("rule_id", "strengths", "hostile", "authority", "disposition"),
    [
        (
            "INFLUENCE-HOSTILE-HIGH-MISMATCH",
            ("exact", "strong"),
            True,
            "unauthorized",
            "CLEAR_DENY",
        ),
        (
            "INFLUENCE-HIGH-UNKNOWN",
            ("exact", "strong"),
            "any",
            "unknown",
            "DEFER",
        ),
        ("INFLUENCE-POSSIBLE-HIGH", ("possible",), "any", "any", "DEFER"),
    ],
)
def test_each_influence_rule_maps_to_a_chapter_7_2_row(
    rule_id: str, strengths: tuple, hostile, authority: str, disposition: str
) -> None:
    matrix = load_fusion_matrix()
    rule = next(rule for rule in matrix.influence_rules if rule.id == rule_id)
    assert tuple(rule.strength) == strengths
    assert rule.hostile_instruction_evidence == hostile
    assert rule.authority == authority
    assert rule.disposition == disposition
    assert tuple(rule.impact) == ("high", "critical")

    rows = _parse_markdown_table(_section("7.2 Untrusted Influence → High Impact"))
    matches = []
    for row in rows[1:]:
        row_influence, row_authority, row_impact, row_result = row
        if not all(strength in row_influence for strength in strengths):
            continue
        if hostile is True and "hostile" not in row_influence:
            continue
        if hostile == "any" and "hostile" in row_influence:
            continue
        if authority == "unknown" and "unknown" not in row_authority:
            continue
        if authority == "unauthorized" and "mismatch" not in row_authority:
            continue
        if authority == "any" and "任意" not in row_authority:
            continue
        if "high/critical" not in row_impact:
            continue
        if disposition not in row_result:
            continue
        matches.append(row)
    assert len(matches) == 1, (
        f"{rule_id} must map to exactly one §7.2 row, got {matches}"
    )


@pytest.mark.parametrize(
    ("rule_id", "authority", "expected_result_tokens"),
    [
        (
            "MEMORY-PERSISTENT-UNTRUSTED-HIGH-UNAUTHORIZED",
            "unauthorized",
            ("PERSISTENT_UNTRUSTED", "exact/strong", "unauthorized", "CLEAR_DENY"),
        ),
        (
            "MEMORY-PERSISTENT-UNTRUSTED-HIGH-UNKNOWN",
            "unknown",
            ("PERSISTENT_UNTRUSTED", "DEFER"),
        ),
    ],
)
def test_each_memory_rule_maps_to_chapter_7_3(
    rule_id: str, authority: str, expected_result_tokens: tuple[str, ...]
) -> None:
    matrix = load_fusion_matrix()
    rule = next(rule for rule in matrix.memory_rules if rule.id == rule_id)
    assert rule.authority == authority
    assert rule.taint == "PERSISTENT_UNTRUSTED"
    assert set(rule.trust_state) == {"tainted", "quarantined"}
    assert tuple(rule.impact) == ("high", "critical")

    section = _section("7.3 Memory")
    rows = _parse_markdown_table(section)
    matches = [
        row
        for row in rows[1:]
        if all(token in "|".join(row) for token in expected_result_tokens)
    ]
    assert matches, f"{rule_id} must map to a §7.3 row"
    # §7.3 同时存在 possible → DEFER 行，与 unknown 规则的 possible
    # retrieval strength 语义一致。
    assert "possible influence" in section and "DEFER" in section


def test_behavior_rules_map_to_chapter_7_4() -> None:
    matrix = load_fusion_matrix()
    section = _section("7.4 Behavior")

    deny_rule = next(
        rule for rule in matrix.behavior_rules
        if rule.id == "BEHAVIOR-HIGH-CONFIDENCE-UNAUTHORIZED"
    )
    assert tuple(deny_rule.pattern) == ("B1", "B2", "B3", "B4", "B5")
    assert deny_rule.confidence == "high"
    assert deny_rule.authority == "unauthorized"
    assert tuple(deny_rule.impact) == ("high", "critical")
    assert deny_rule.corroborating_flow_required is True
    assert deny_rule.disposition == "CLEAR_DENY"
    assert "B1-B5" in section
    assert (
        "confidence=high + authority=unauthorized + impact=high/critical"
        " + corroborating flow"
    ) in section
    assert "CLEAR_DENY" in section

    defer_rule = next(
        rule for rule in matrix.behavior_rules if rule.id == "BEHAVIOR-ANOMALY-DEFAULT"
    )
    assert tuple(defer_rule.pattern) == ("B1", "B2", "B3", "B4", "B5", "B6")
    assert defer_rule.confidence == "any"
    assert defer_rule.authority == "any"
    assert defer_rule.impact == "any"
    assert defer_rule.corroborating_flow_required == "any"
    assert defer_rule.disposition == "DEFER"
    assert "B1-B6" in section and "DEFER" in section
    # Behavior 不创建 Authority，也不得把 unknown 升格为 unauthorized。
    assert "不能把 `unknown` 升格为 `unauthorized`" in section


def test_clear_allow_requires_match_chapter_6_step7() -> None:
    """机器真值 10 条与 03 §6 Step 7 逐条对应（顺序一致）。"""
    matrix = load_fusion_matrix()
    assert list(matrix.clear_allow_requires) == [
        "no_system_invariant_violation",
        "no_hard_deny_or_hard_ask",
        "all_required_domains_complete_or_not_applicable",
        "authority_authorized_or_not_required",
        "flow_safe_or_not_applicable",
        "no_required_degradation",
        "no_policy_required_human_review",
        "no_unresolved_high_confidence_behavior_chain",
        "no_required_semantic_ambiguity",
        "all_security_digests_valid",
    ]
    section = _section("Step 7 — CLEAR_ALLOW Proof")
    assert "全部成立才 CLEAR_ALLOW" in section


# ---------------------------------------------------------------------------
# 七步优先级 / 8 级 priority 链 / disposition 优先级
# ---------------------------------------------------------------------------


def test_priority_chain_system_invariant_wins_all() -> None:
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "critical",
            "policy_violations": (
                _violation("system_invariant", rule_id="F0-01"),
                _violation("tenant_hard_policy", rule_id="HARD-1"),
            ),
            "flow": _flow(
                "violation",
                taints=["CREDENTIAL"],
                strength="exact",
                external_sink=True,
            ),
            "authority": _authority("unauthorized"),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "CLEAR_DENY"
    # tier 0 的 system_invariant 证据必须排在 tier 1/2 之前。
    assert codes[0] == "v21-08:system_invariant:F0-01"
    assert codes.index("v21-08:hard_policy_deny:HARD-1") > 0
    assert codes.index("v21-08:flow_rule:FLOW-CREDENTIAL-EXACT-UNAUTHORIZED") > 1


def test_priority_chain_deny_codes_ordered_by_tier() -> None:
    """同时命中 tier 0/1/2/3 的 CLEAR_DENY，reason codes 按 priority 位次排列。"""
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "high",
            "policy_violations": (
                _violation("system_invariant", rule_id="F0-02"),
                _violation("system_hard_policy", rule_id="HARD-2"),
            ),
            "flow": _flow(
                "violation",
                taints=["SENSITIVE"],
                strength="exact",
                external_sink=True,
            ),
            "authority": _authority("unauthorized", mismatches=["grant-1:resource"]),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "CLEAR_DENY"
    assert codes == [
        "v21-08:system_invariant:F0-02",
        "v21-08:hard_policy_deny:HARD-2",
        "v21-08:flow_rule:FLOW-SENSITIVE-EXACT-UNAUTHORIZED",
        "v21-08:explicit_authority_mismatch",
    ]


def test_clear_deny_beats_defer() -> None:
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "policy_violations": (_violation("tenant_hard_policy", rule_id="H-3"),),
            "coverage": _coverage(dataflow="partial"),
            "degradations": (_degradation(),),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "CLEAR_DENY"
    assert codes == ["v21-08:hard_policy_deny:H-3"]


def test_defer_beats_clear_allow() -> None:
    kwargs = _green_kwargs()
    kwargs["coverage"] = _coverage(behavior="unknown")
    kwargs["required_domains"] = ("task", "dataflow", "behavior")
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:coverage_incomplete:behavior:unknown" in codes
    assert CLEAR_ALLOW_PROOF_REASON not in codes


def test_review_policy_ask_is_defer_candidate() -> None:
    kwargs = _green_kwargs()
    kwargs["policy_violations"] = (_violation("review_policy", "ask", rule_id="RV-1"),)
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:review_policy_ask:RV-1" in codes


def test_hard_policy_ask_is_defer() -> None:
    kwargs = _green_kwargs()
    kwargs["policy_violations"] = (
        _violation("system_hard_policy", "ask", rule_id="HARD-ASK"),
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:hard_policy_ask:HARD-ASK" in codes


# ---------------------------------------------------------------------------
# flow 规则逐条触发语义
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "taint", "strength", "authority_status", "disposition"),
    [
        (
            "FLOW-CREDENTIAL-EXACT-UNAUTHORIZED",
            "CREDENTIAL",
            "exact",
            "unauthorized",
            "CLEAR_DENY",
        ),
        (
            "FLOW-CREDENTIAL-STRONG-UNAUTHORIZED",
            "CREDENTIAL",
            "strong",
            "unauthorized",
            "CLEAR_DENY",
        ),
        (
            "FLOW-CREDENTIAL-POSSIBLE",
            "CREDENTIAL",
            "possible",
            "authorized",
            "DEFER",
        ),
        (
            "FLOW-SENSITIVE-EXACT-UNAUTHORIZED",
            "SENSITIVE",
            "exact",
            "unauthorized",
            "CLEAR_DENY",
        ),
        (
            "FLOW-SENSITIVE-STRONG-UNAUTHORIZED",
            "SENSITIVE",
            "strong",
            "unauthorized",
            "DEFER",
        ),
        (
            "FLOW-SENSITIVE-POSSIBLE",
            "SENSITIVE",
            "possible",
            "authorized",
            "DEFER",
        ),
    ],
)
def test_flow_rule_triggers_expected_disposition(
    rule_id: str, taint: str, strength: str, authority_status: str, disposition: str
) -> None:
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "high",
            "flow": _flow(
                "violation", taints=[taint], strength=strength, external_sink=True
            ),
            "authority": _authority(authority_status),
        }
    )
    result_disposition, codes = evaluate_fusion(**kwargs)
    assert result_disposition == disposition
    assert f"v21-08:flow_rule:{rule_id}" in codes


def test_safe_flow_matches_no_flow_rule() -> None:
    kwargs = _green_kwargs()
    kwargs["flow"] = _flow(
        "safe", taints=["CREDENTIAL"], strength="exact", external_sink=True
    )
    disposition, codes = evaluate_fusion(**kwargs)
    # safe 的 FlowVerdict 不构成 source-to-sink 违规输入 → CLEAR_ALLOW。
    assert disposition == "CLEAR_ALLOW"
    assert codes == [CLEAR_ALLOW_PROOF_REASON]


# ---------------------------------------------------------------------------
# CLEAR_ALLOW 证明：10 条 clear_allow_requires 缺一即不得 CLEAR_ALLOW
# ---------------------------------------------------------------------------


def test_clear_allow_proof_all_conditions_met() -> None:
    disposition, codes = evaluate_fusion(**_green_kwargs())
    assert disposition == "CLEAR_ALLOW"
    assert codes == [CLEAR_ALLOW_PROOF_REASON]


def test_clear_allow_reachable_with_not_applicable_flow() -> None:
    """Codex review P1-2 闭环：低影响动作 flow verdict 为
    not_applicable（当前 plan 不要求 dataflow，无危险 flow）时，
    CLEAR_ALLOW 可达——不得因 bootstrap coverage unknown 系统性 DEFER。"""
    kwargs = _green_kwargs()
    kwargs["flow"] = _flow("not_applicable")
    # 当前 plan 不要求 dataflow：required 域不含 dataflow，coverage
    # 中 dataflow 为 not_applicable（二者同源口径）。
    kwargs["required_domains"] = ("task",)
    kwargs["coverage"] = _coverage(dataflow="not_applicable")
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "CLEAR_ALLOW"
    assert codes == [CLEAR_ALLOW_PROOF_REASON]


@pytest.mark.parametrize(
    ("condition", "mutate", "expected", "expected_code"),
    [
        (
            "no_system_invariant_violation",
            lambda kwargs: kwargs.update(
                {"policy_violations": (_violation("system_invariant", rule_id="F0-03"),)}
            ),
            "CLEAR_DENY",
            "v21-08:system_invariant:F0-03",
        ),
        (
            "no_hard_deny_or_hard_ask",
            lambda kwargs: kwargs.update(
                {"policy_violations": (_violation("tenant_hard_policy", "ask", rule_id="H-4"),)}
            ),
            "DEFER",
            "v21-08:hard_policy_ask:H-4",
        ),
        (
            "all_required_domains_complete_or_not_applicable",
            lambda kwargs: kwargs.update(
                {
                    "coverage": _coverage(source="stale"),
                    "required_domains": ("task", "source"),
                }
            ),
            "DEFER",
            "v21-08:coverage_incomplete:source:stale",
        ),
        (
            "authority_authorized_or_not_required",
            lambda kwargs: kwargs.update({"authority": _authority("unknown")}),
            "DEFER",
            "v21-08:authority_unknown",
        ),
        (
            "flow_safe_or_not_applicable",
            lambda kwargs: kwargs.update({"flow": _flow("uncertain")}),
            "DEFER",
            "v21-08:clear_allow_unmet:flow_safe_or_not_applicable",
        ),
        (
            "no_required_degradation",
            lambda kwargs: kwargs.update({"degradations": (_degradation(),)}),
            "DEFER",
            "v21-08:required_degradation:deg-1",
        ),
        (
            "no_policy_required_human_review",
            lambda kwargs: kwargs.update(
                {"policy_violations": (_violation("review_policy", "ask", rule_id="RV-2"),)}
            ),
            "DEFER",
            "v21-08:review_policy_ask:RV-2",
        ),
        (
            "no_required_semantic_ambiguity",
            lambda kwargs: kwargs.update({"requires_semantic": True}),
            "DEFER",
            "v21-08:clear_allow_unmet:no_required_semantic_ambiguity",
        ),
        (
            "all_security_digests_valid",
            lambda kwargs: kwargs.update({"security_digests_valid": None}),
            "DEFER",
            "v21-08:clear_allow_unmet:all_security_digests_valid",
        ),
        (
            "all_security_digests_valid",
            lambda kwargs: kwargs.update({"security_digests_valid": False}),
            "DEFER",
            "v21-08:clear_allow_unmet:all_security_digests_valid",
        ),
    ],
)
def test_clear_allow_requires_each_condition_is_mandatory(
    condition: str, mutate, expected: str, expected_code: str
) -> None:
    kwargs = _green_kwargs()
    mutate(kwargs)
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == expected
    assert disposition != "CLEAR_ALLOW"
    # 每条被破坏的条件都必须给出确定性 reason code（无论经由前置步骤
    # 还是 Step 7 证明失败路径）。
    assert expected_code in codes


def test_high_confidence_behavior_chain_blocks_clear_allow() -> None:
    from agentguard_core.security_context.facts import BehaviorAggregate
    from agentguard_core.signals.models import SequenceRef

    window = SequenceRef(domain="audit", producer_binding_id="p", value=1)
    aggregate = BehaviorAggregate(
        aggregate_id="agg-1",
        pattern_id="B2",
        window_start=window,
        window_end=window,
        count=3,
        confidence="high",
        predecessor_refs=[],
        evidence_refs=[],
    )
    kwargs = _green_kwargs()
    kwargs["behavior_aggregates"] = (aggregate,)
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert (
        "v21-08:clear_allow_unmet:no_unresolved_high_confidence_behavior_chain"
        in codes
        or any(code.startswith("v21-08:behavior_rule:") for code in codes)
    )


# ---------------------------------------------------------------------------
# evidence group 去重（03 §3）
# ---------------------------------------------------------------------------


def test_dedupe_keeps_one_representative_per_group() -> None:
    signals = [
        _signal("s-low", confidence="low", impact="moderate"),
        _signal("s-high", confidence="high", impact="critical"),
        _signal("s-medium", confidence="medium", impact="high"),
        _signal("s-high-b", confidence="high", impact="critical"),
    ]
    representatives = dedupe_evidence_groups(signals)
    assert len(representatives) == 1
    # 最强证据：confidence high + impact critical，平手取 signal_id 最小。
    assert representatives[0].signal_id == "s-high"


def test_dedupe_preserves_distinct_groups_in_first_seen_order() -> None:
    signals = [
        _signal("s1", evidence_group="g2"),
        _signal("s2", evidence_group="g1"),
        _signal("s3", evidence_group="g2"),
    ]
    representatives = dedupe_evidence_groups(signals)
    assert [item.signal_id for item in representatives] == ["s1", "s2"]


def test_duplicate_signals_are_not_double_weighted() -> None:
    """同一底层事实的 4 个 detector signal（03 §3 例举）与单个 signal
    产出完全一致的判定与 reason codes——不重复计权。"""
    from agentguard_core.security_context.facts import FlowFact

    influence_flow = FlowFact(
        flow_id="flow-influence-1",
        scope_digest="sha256:scope",
        source_ref="source-evil",
        target_ref="action-1",
        relation="influenced_by",
        taints=["EXTERNAL_INSTRUCTION"],
        strength="exact",
        origin="observed",
        sequence=None,
        producer="test",
        evidence_refs=[],
    )
    base = _green_kwargs()
    base.update(
        {
            "impact": "critical",
            "authority": _authority("unauthorized"),
            "flows": (influence_flow,),
        }
    )

    single = dict(base, signals=(_signal("s1"),))
    quadruple = dict(
        base,
        signals=(
            _signal("s1", category="prompt_injection"),
            _signal("s2", category="external_instruction", confidence="medium"),
            _signal("s3", category="tool_hijack", confidence="low"),
            _signal("s4", category="task_mismatch", impact="low"),
        ),
    )
    disposition_one, codes_one = evaluate_fusion(**single)
    disposition_four, codes_four = evaluate_fusion(**quadruple)
    assert disposition_one == disposition_four == "CLEAR_DENY"
    assert codes_one == codes_four
    assert "v21-08:influence_rule:INFLUENCE-HOSTILE-HIGH-MISMATCH" in codes_one


def test_influence_rules_require_matching_context() -> None:
    from agentguard_core.security_context.facts import FlowFact

    influence_flow = FlowFact(
        flow_id="flow-influence-2",
        scope_digest="sha256:scope",
        source_ref="source-evil",
        target_ref="action-1",
        relation="influenced_by",
        taints=["EXTERNAL_INSTRUCTION"],
        strength="exact",
        origin="observed",
        sequence=None,
        producer="test",
        evidence_refs=[],
    )
    # hostile 规则要求 unauthorized + hostile evidence；authority unknown
    # 走 INFLUENCE-HIGH-UNKNOWN → DEFER。
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "high",
            "authority": _authority("unknown"),
            "flows": (influence_flow,),
            "signals": (_signal("s1"),),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:influence_rule:INFLUENCE-HIGH-UNKNOWN" in codes
    assert "v21-08:influence_rule:INFLUENCE-HOSTILE-HIGH-MISMATCH" not in codes

    # 无 hostile evidence（类目不在冻结集合内）→ possible 档 DEFER。
    possible_flow = influence_flow.model_copy(
        update={"flow_id": "flow-influence-3", "strength": "possible"}
    )
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "critical",
            "authority": _authority("unauthorized"),
            "flows": (possible_flow,),
            "signals": (_signal("s1", category="benign_stats"),),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:influence_rule:INFLUENCE-POSSIBLE-HIGH" in codes


def test_hostile_instruction_categories_are_frozen() -> None:
    assert HOSTILE_INSTRUCTION_CATEGORIES == frozenset(
        {"prompt_injection", "external_instruction", "tool_hijack", "task_mismatch"}
    )


# ---------------------------------------------------------------------------
# memory / behavior 规则触发
# ---------------------------------------------------------------------------


def test_memory_rule_triggers_clear_deny_for_unauthorized_high_impact() -> None:
    from agentguard_core.security_context.facts import FlowFact, MemoryFact

    memory = MemoryFact(
        memory_id="mem-1",
        change_id=None,
        change_status="committed",
        trust_state="tainted",
        taints=["PERSISTENT_UNTRUSTED"],
        source_refs=["source-evil"],
        last_write_sequence=None,
        last_read_sequence=None,
        evidence_refs=[],
    )
    retrieval = FlowFact(
        flow_id="flow-memory-1",
        scope_digest="sha256:scope",
        source_ref="mem-1",
        target_ref="action-1",
        relation="loaded_from_memory",
        taints=["PERSISTENT_UNTRUSTED"],
        strength="exact",
        origin="observed",
        sequence=None,
        producer="test",
        evidence_refs=[],
    )
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "critical",
            "authority": _authority("unauthorized"),
            "memory_facts": (memory,),
            "flows": (retrieval,),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "CLEAR_DENY"
    assert (
        "v21-08:memory_rule:MEMORY-PERSISTENT-UNTRUSTED-HIGH-UNAUTHORIZED" in codes
    )

    # authority unknown → DEFER 规则。
    kwargs["authority"] = _authority("unknown")
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:memory_rule:MEMORY-PERSISTENT-UNTRUSTED-HIGH-UNKNOWN" in codes


def test_memory_without_retrieval_link_matches_no_rule() -> None:
    from agentguard_core.security_context.facts import MemoryFact

    memory = MemoryFact(
        memory_id="mem-2",
        change_id=None,
        change_status="committed",
        trust_state="tainted",
        taints=["PERSISTENT_UNTRUSTED"],
        source_refs=[],
        last_write_sequence=None,
        last_read_sequence=None,
        evidence_refs=[],
    )
    kwargs = _green_kwargs()
    kwargs.update({"impact": "high", "memory_facts": (memory,)})
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "CLEAR_ALLOW"
    assert codes == [CLEAR_ALLOW_PROOF_REASON]


def test_behavior_rule_requires_corroborating_flow_for_clear_deny() -> None:
    from agentguard_core.security_context.facts import BehaviorAggregate
    from agentguard_core.signals.models import SequenceRef

    window = SequenceRef(domain="audit", producer_binding_id="p", value=1)
    aggregate = BehaviorAggregate(
        aggregate_id="agg-b1",
        pattern_id="B1",
        window_start=window,
        window_end=window,
        count=5,
        confidence="high",
        predecessor_refs=[],
        evidence_refs=[],
    )
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "high",
            "authority": _authority("unauthorized"),
            "behavior_aggregates": (aggregate,),
            # corroborating flow：FlowVerdict 处于 violation 态。
            "flow": _flow(
                "violation", taints=["SENSITIVE"], strength="possible",
                external_sink=True,
            ),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "CLEAR_DENY"
    assert "v21-08:behavior_rule:BEHAVIOR-HIGH-CONFIDENCE-UNAUTHORIZED" in codes

    # 无 corroborating flow → CLEAR_DENY 规则不匹配，落入默认 DEFER 规则。
    kwargs["flow"] = _flow("safe")
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:behavior_rule:BEHAVIOR-ANOMALY-DEFAULT" in codes
    assert (
        "v21-08:behavior_rule:BEHAVIOR-HIGH-CONFIDENCE-UNAUTHORIZED" not in codes
    )


# ---------------------------------------------------------------------------
# 缺态/缺输入 → DEFER（绝不 fail-open）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["authority", "flow", "coverage"])
def test_missing_input_defers(missing: str) -> None:
    kwargs = _green_kwargs()
    kwargs[missing] = None
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert f"v21-08:input_missing:{missing}" in codes


def test_all_missing_inputs_defer_and_never_allow() -> None:
    disposition, codes = evaluate_fusion(impact="low")
    assert disposition == "DEFER"
    assert "v21-08:input_missing:authority" in codes
    assert "v21-08:input_missing:flow" in codes
    assert "v21-08:input_missing:coverage" in codes


def test_missing_coverage_blocks_step4_clear_deny() -> None:
    """explicit authority mismatch 的 CLEAR_DENY 需要 capability coverage
    complete 证据；coverage 缺态时降级为 DEFER（fail-closed）。"""
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "high",
            "authority": _authority("unauthorized", mismatches=["grant-1:dest"]),
            "coverage": None,
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:explicit_authority_mismatch" not in codes


def test_explicit_authority_mismatch_requires_high_impact() -> None:
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "moderate",
            "authority": _authority("unauthorized", mismatches=["grant-1:dest"]),
        }
    )
    disposition, codes = evaluate_fusion(**kwargs)
    assert disposition == "DEFER"
    assert "v21-08:authority_unresolved" in codes


# ---------------------------------------------------------------------------
# 确定性与导入隔离
# ---------------------------------------------------------------------------


def test_evaluate_fusion_is_deterministic() -> None:
    kwargs = _green_kwargs()
    kwargs.update(
        {
            "impact": "high",
            "policy_violations": (_violation("tenant_hard_policy", rule_id="H-9"),),
            "signals": (_signal("s1"), _signal("s2", evidence_group="g2")),
            "flow": _flow(
                "violation", taints=["CREDENTIAL"], strength="exact",
                external_sink=True,
            ),
            "authority": _authority("unauthorized"),
            "coverage": _coverage(dataflow="partial"),
        }
    )
    first = evaluate_fusion(**kwargs)
    for _ in range(5):
        assert evaluate_fusion(**kwargs) == first
    # reason codes 无重复。
    assert len(first[1]) == len(set(first[1]))


@pytest.mark.parametrize(
    "relative_path",
    [
        "packages/agentguard-core/agentguard_core/decisions/fusion.py",
        "packages/agentguard-core/agentguard_core/security_context/projection/flow_verdict.py",
    ],
)
def test_new_modules_have_no_clock_uuid_or_legacy_imports(relative_path: str) -> None:
    """V21-08 新模块纪律：

    - 不 import wall-clock / uuid / random（判定确定性）；
    - 不 import legacy 判定路径（engine / decisions.policy /
      decisions.results）。
    """
    source = (ROOT / relative_path).read_text(encoding="utf-8")
    forbidden_modules = {
        "time",
        "datetime",
        "uuid",
        "random",
        "engine",
        "policy",
        "results",
    }
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module.split(".")[0]] if node.module else []
            names.extend(alias.name for alias in node.names)
        else:
            continue
        # 相对导入的顶层包名（如 pydantic/stdlib）不在禁用集合即可。
        violations = forbidden_modules.intersection(names)
        # ``policy`` 仅指 decisions.policy 模块名；此处新模块不应出现。
        assert not violations, f"{relative_path} imports forbidden {violations}"


def test_fusion_module_does_not_import_legacy_decision_path() -> None:
    source = Path(fusion_module.__file__).read_text(encoding="utf-8")
    assert "from .policy" not in source
    assert "from .results" not in source
    assert "engine" not in {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module
    }
