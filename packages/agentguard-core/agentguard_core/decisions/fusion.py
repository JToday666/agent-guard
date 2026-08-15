"""V21-08 Fusion 矩阵求值器（纯新增，零接线）。

契约依据：

- ``docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/03_判定融合与Semantic契约.md``
  §3（evidence group 去重）、§6（FastAssessment 七步优先级）、
  §7（Source-to-Sink 冻结矩阵）；
- 同目录 ``fusion_matrix.yaml``（机器真值，JSON-compatible YAML）与
  ``fusion_matrix.schema.json``；
- ``07_当前代码改造映射.md``：``decisions/fusion.py`` 是 NEW V2 fusion 落点，
  不原地重写 legacy merge（``decisions/policy.py`` 保持唯一 legacy 官方
  决策链）。

纪律（与 V21-02 AST 导入隔离守卫一致）：本模块**不 import** legacy 判定
路径（``engine`` / ``decisions.policy`` / ``decisions.results``），只依赖
冻结模型（``signals.models`` / ``security_context.facts`` /
``decisions.evidence``）与标准库。

求值语义（03 §7）：收集**全部**匹配规则，再按
``CLEAR_DENY > DEFER > CLEAR_ALLOW`` 取最高优先级
（``match_semantics = all_matching_rules_then_highest_priority``）。
缺态/缺输入一律 ``DEFER``，绝不 fail-open。

加载纪律：``fusion_matrix.yaml`` 模块级一次性加载并预编译为内存常量
（``load_fusion_matrix`` 带锁缓存），禁止每请求读文件；加载时经与
``fusion_matrix.schema.json`` 同口径的结构校验（口径对齐
``scripts/v21-contract-tools.py::_validate_schema``），禁止未定义的
selector/disposition。core 包只声明 pydantic 依赖，因此 YAML（实为
JSON-compatible）用标准库 ``json`` 解析、schema 校验用内置等价实现，
不新增第三方依赖。
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict

from ..security_context.facts import BehaviorAggregate, FlowFact, MemoryFact
from ..signals.models import (
    AuthorityVerdict,
    CoverageDomain,
    EvaluationDegradation,
    FastDisposition,
    FlowVerdict,
    ImpactClass,
    PolicyViolation,
    SecuritySignal,
)
from .evidence import CoverageMap

__all__ = [
    "CLEAR_ALLOW_PROOF_REASON",
    "DEFER_DEFAULT_REASON",
    "HOSTILE_INSTRUCTION_CATEGORIES",
    "REASON_PREFIX",
    "FusionBehaviorRule",
    "FusionFlowRule",
    "FusionInfluenceRule",
    "FusionMatrix",
    "FusionMatrixError",
    "FusionMemoryRule",
    "default_fusion_matrix_path",
    "dedupe_evidence_groups",
    "evaluate_fusion",
    "load_fusion_matrix",
]

#: reason code 统一前缀（确定性、可审计、不含 wall-clock/uuid）。
REASON_PREFIX = "v21-08:"

#: CLEAR_ALLOW 证明成立时的 reason code（03 §6 Step 7）。
CLEAR_ALLOW_PROOF_REASON = f"{REASON_PREFIX}clear_allow_proof"

#: 无任何匹配事实时的兜底 DEFER reason code（priority 链第 8 级）。
DEFER_DEFAULT_REASON = f"{REASON_PREFIX}defer_default"

#: hostile instruction evidence 的检测器类目冻结约定（03 §3 例举的四类
#: 同一底层事实：prompt injection / external instruction / tool hijack /
#: task mismatch）。SecuritySignal.category 命中任一类目即视为存在
#: hostile instruction evidence。
HOSTILE_INSTRUCTION_CATEGORIES = frozenset(
    {"prompt_injection", "external_instruction", "tool_hijack", "task_mismatch"}
)

# strength 强弱排序（越小越强）；仅用于取"最强证据"，不重算 strength。
_STRENGTH_RANK: dict[str, int] = {"exact": 0, "strong": 1, "possible": 2}

# confidence 强弱排序（越小越强）；evidence group 去重取组内最强证据。
_CONFIDENCE_RANK: dict[str, int] = {"high": 0, "medium": 1, "low": 2}

# impact 强弱排序（越小越强）。
_IMPACT_RANK: dict[str, int] = {"critical": 0, "high": 1, "moderate": 2, "low": 3}

# memory retrieval influence 相关 flow relation（确定性约定）。
_MEMORY_RETRIEVAL_RELATIONS = frozenset(
    {"loaded_from_memory", "influenced_by", "derived_from"}
)

# untrusted influence 相关 taint label（influence strength 提取口径）。
_UNTRUSTED_INFLUENCE_TAINTS = frozenset(
    {"UNTRUSTED", "EXTERNAL_INSTRUCTION", "PERSISTENT_UNTRUSTED"}
)

# flow 规则适用的 sink 判定所基于的 FlowVerdict.status 集合：
# safe/not_applicable 的 flow 不构成 source-to-sink 违规输入。
_FLOW_RULE_ACTIVE_STATUSES = frozenset({"violation", "uncertain"})


class FusionMatrixError(ValueError):
    """fusion_matrix.yaml 加载/结构校验失败（fail-closed）。"""


# ---------------------------------------------------------------------------
# 冻结矩阵模型（fusion_matrix.schema.json 逐条对应）
# ---------------------------------------------------------------------------


class FusionFlowRule(BaseModel):
    """Source-to-Sink 数据外发规则（03 §7.1）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    taint: Literal["CREDENTIAL", "SENSITIVE"]
    strength: Literal["exact", "strong", "possible", "any"]
    authority: Literal["authorized", "unauthorized", "unknown", "not_required", "any"]
    sink: Literal["external", "internal", "any"]
    disposition: FastDisposition


class FusionInfluenceRule(BaseModel):
    """Untrusted Influence → High Impact 规则（03 §7.2）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    strength: tuple[Literal["exact", "strong", "possible", "any"], ...]
    hostile_instruction_evidence: bool | Literal["any"]
    authority: Literal["authorized", "unauthorized", "unknown", "not_required", "any"]
    impact: tuple[ImpactClass, ...]
    disposition: FastDisposition


class FusionMemoryRule(BaseModel):
    """Memory 检索影响规则（03 §7.3）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    trust_state: tuple[Literal["clean", "tainted", "quarantined", "unknown"], ...]
    taint: Literal["PERSISTENT_UNTRUSTED", "UNTRUSTED", "SENSITIVE", "CREDENTIAL"]
    retrieval_strength: tuple[Literal["exact", "strong", "possible", "any"], ...]
    authority: Literal["authorized", "unauthorized", "unknown", "not_required", "any"]
    impact: tuple[ImpactClass, ...]
    disposition: FastDisposition


class FusionBehaviorRule(BaseModel):
    """Behavior 异常链规则（03 §7.4）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    pattern: tuple[Literal["B1", "B2", "B3", "B4", "B5", "B6"], ...]
    confidence: Literal["low", "medium", "high", "any"]
    authority: Literal["authorized", "unauthorized", "unknown", "not_required", "any"]
    impact: tuple[ImpactClass, ...] | Literal["any"]
    corroborating_flow_required: bool | Literal["any"]
    disposition: FastDisposition


class FusionMatrix(BaseModel):
    """冻结 fusion 矩阵（机器真值；``extra="forbid"`` 拒绝未知键）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_: str
    schema_version: str
    format: str
    match_semantics: str
    disposition_priority: tuple[FastDisposition, ...]
    selectors: dict[str, tuple[Any, ...]]
    priority: tuple[str, ...]
    flow_rules: tuple[FusionFlowRule, ...]
    influence_rules: tuple[FusionInfluenceRule, ...]
    memory_rules: tuple[FusionMemoryRule, ...]
    behavior_rules: tuple[FusionBehaviorRule, ...]
    clear_allow_requires: tuple[str, ...]

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "FusionMatrix":
        payload = dict(raw)
        # ``$schema`` 不是合法 Python 标识符，映射到 ``schema_`` 字段。
        payload["schema_"] = payload.pop("$schema")
        return cls.model_validate(payload)

    def priority_index(self, tier: str) -> int:
        """8 级 priority 链中的位次（0 = 最高）。未知层级 fail-closed。"""
        try:
            return self.priority.index(tier)
        except ValueError as exc:  # pragma: no cover - 结构校验已拦截
            raise FusionMatrixError(f"unknown priority tier: {tier!r}") from exc


# ---------------------------------------------------------------------------
# 加载与结构校验（口径对齐 scripts/v21-contract-tools.py::_validate_schema）
# ---------------------------------------------------------------------------

_REQUIRED_TOP_KEYS = (
    "$schema",
    "schema_version",
    "format",
    "match_semantics",
    "disposition_priority",
    "selectors",
    "priority",
    "flow_rules",
    "influence_rules",
    "memory_rules",
    "behavior_rules",
    "clear_allow_requires",
)

_ID_PATTERNS = {
    "flow_rules": re.compile(r"^FLOW-[A-Z0-9-]+$"),
    "influence_rules": re.compile(r"^INFLUENCE-[A-Z0-9-]+$"),
    "memory_rules": re.compile(r"^MEMORY-[A-Z0-9-]+$"),
    "behavior_rules": re.compile(r"^BEHAVIOR-[A-Z0-9-]+$"),
}

_RULE_REQUIRED_KEYS = {
    "flow_rules": ("id", "taint", "strength", "authority", "sink", "disposition"),
    "influence_rules": (
        "id",
        "strength",
        "hostile_instruction_evidence",
        "authority",
        "impact",
        "disposition",
    ),
    "memory_rules": (
        "id",
        "trust_state",
        "taint",
        "retrieval_strength",
        "authority",
        "impact",
        "disposition",
    ),
    "behavior_rules": (
        "id",
        "pattern",
        "confidence",
        "authority",
        "impact",
        "corroborating_flow_required",
        "disposition",
    ),
}

_MEMORY_TRUST_STATES = frozenset({"clean", "tainted", "quarantined", "unknown"})
_MEMORY_TAINTS = frozenset(
    {"PERSISTENT_UNTRUSTED", "UNTRUSTED", "SENSITIVE", "CREDENTIAL"}
)
_FLOW_TAINTS = frozenset({"CREDENTIAL", "SENSITIVE"})
_BEHAVIOR_PATTERNS = frozenset({"B1", "B2", "B3", "B4", "B5", "B6"})
_BEHAVIOR_CONFIDENCES = frozenset({"low", "medium", "high", "any"})


def _fail(message: str) -> FusionMatrixError:
    return FusionMatrixError(f"fusion_matrix.yaml violates schema: {message}")


def _check_selector_membership(
    selectors: dict[str, Any], selector_name: str, value: Any, context: str
) -> None:
    """禁止未定义 selector：规则取值必须落在矩阵 ``selectors`` 定义域内。"""
    allowed = selectors.get(selector_name)
    if allowed is None:
        raise _fail(f"selector group {selector_name!r} is not defined")
    if value not in allowed:
        raise _fail(
            f"{context}: value {value!r} is not a defined "
            f"{selector_name!r} selector"
        )


def _validate_raw_matrix(raw: dict[str, Any]) -> None:
    """与 ``fusion_matrix.schema.json`` 同口径的结构校验（无第三方依赖）。

    覆盖：必填键/``additionalProperties: false``、const 字段、id 正则、
    枚举成员资格、``minItems``/``uniqueItems``，以及"禁止未定义的
    selector/disposition"（03 §7）。
    """
    if not isinstance(raw, dict):
        raise _fail("top-level value must be an object")
    missing = [key for key in _REQUIRED_TOP_KEYS if key not in raw]
    if missing:
        raise _fail(f"missing required keys: {', '.join(missing)}")
    extra = [key for key in raw if key not in _REQUIRED_TOP_KEYS]
    if extra:
        raise _fail(f"additional properties not allowed: {', '.join(extra)}")

    if raw["$schema"] != "./fusion_matrix.schema.json":
        raise _fail("$schema must be './fusion_matrix.schema.json'")
    if raw["schema_version"] != "2.1-final-candidate":
        raise _fail("schema_version must be '2.1-final-candidate'")
    if raw["format"] != "json-compatible-yaml":
        raise _fail("format must be 'json-compatible-yaml'")
    if raw["match_semantics"] != "all_matching_rules_then_highest_priority":
        raise _fail(
            "match_semantics must be 'all_matching_rules_then_highest_priority'"
        )
    if list(raw["disposition_priority"]) != ["CLEAR_DENY", "DEFER", "CLEAR_ALLOW"]:
        raise _fail(
            "disposition_priority must be ['CLEAR_DENY', 'DEFER', 'CLEAR_ALLOW']"
        )

    selectors = raw["selectors"]
    if not isinstance(selectors, dict):
        raise _fail("selectors must be an object")

    priority = raw["priority"]
    if not isinstance(priority, list) or len(priority) < 8:
        raise _fail("priority must be an array with at least 8 items")
    if len(set(priority)) != len(priority):
        raise _fail("priority items must be unique")
    if not all(isinstance(item, str) for item in priority):
        raise _fail("priority items must be strings")

    dispositions = set(raw["disposition_priority"])
    seen_rule_ids: set[str] = set()
    for group in ("flow_rules", "influence_rules", "memory_rules", "behavior_rules"):
        rules = raw[group]
        if not isinstance(rules, list):
            raise _fail(f"{group} must be an array")
        if group in ("memory_rules", "behavior_rules") and len(rules) < 1:
            raise _fail(f"{group} requires at least 1 rule")
        for index, rule in enumerate(rules):
            context = f"{group}[{index}]"
            if not isinstance(rule, dict):
                raise _fail(f"{context}: rule must be an object")
            required = _RULE_REQUIRED_KEYS[group]
            missing_keys = [key for key in required if key not in rule]
            if missing_keys:
                raise _fail(f"{context}: missing keys {', '.join(missing_keys)}")
            extra_keys = [key for key in rule if key not in required]
            if extra_keys:
                raise _fail(
                    f"{context}: additional properties {', '.join(extra_keys)}"
                )
            rule_id = rule["id"]
            if not isinstance(rule_id, str) or not _ID_PATTERNS[group].match(rule_id):
                raise _fail(f"{context}: invalid rule id {rule_id!r}")
            if rule_id in seen_rule_ids:
                raise _fail(f"{context}: duplicate rule id {rule_id!r}")
            seen_rule_ids.add(rule_id)

            _check_selector_membership(
                selectors, "authority", rule["authority"], context
            )
            if rule["disposition"] not in dispositions:
                raise _fail(
                    f"{context}: disposition {rule['disposition']!r} is not defined"
                )

            if group == "flow_rules":
                if rule["taint"] not in _FLOW_TAINTS:
                    raise _fail(f"{context}: taint {rule['taint']!r} is not defined")
                _check_selector_membership(
                    selectors, "flow_strength", rule["strength"], context
                )
                _check_selector_membership(selectors, "sink", rule["sink"], context)
            elif group == "influence_rules":
                strengths = rule["strength"]
                if not isinstance(strengths, list) or not strengths:
                    raise _fail(f"{context}: strength must be a non-empty array")
                if len(set(strengths)) != len(strengths):
                    raise _fail(f"{context}: strength items must be unique")
                for value in strengths:
                    _check_selector_membership(
                        selectors, "flow_strength", value, context
                    )
                if rule["hostile_instruction_evidence"] not in (True, False, "any"):
                    raise _fail(
                        f"{context}: hostile_instruction_evidence must be "
                        "true/false/'any'"
                    )
                _check_impact_list(selectors, rule["impact"], context)
            elif group == "memory_rules":
                trust_states = rule["trust_state"]
                if not isinstance(trust_states, list) or not trust_states:
                    raise _fail(f"{context}: trust_state must be a non-empty array")
                if len(set(trust_states)) != len(trust_states):
                    raise _fail(f"{context}: trust_state items must be unique")
                for value in trust_states:
                    if value not in _MEMORY_TRUST_STATES:
                        raise _fail(
                            f"{context}: trust_state {value!r} is not defined"
                        )
                if rule["taint"] not in _MEMORY_TAINTS:
                    raise _fail(f"{context}: taint {rule['taint']!r} is not defined")
                strengths = rule["retrieval_strength"]
                if not isinstance(strengths, list) or not strengths:
                    raise _fail(
                        f"{context}: retrieval_strength must be a non-empty array"
                    )
                if len(set(strengths)) != len(strengths):
                    raise _fail(
                        f"{context}: retrieval_strength items must be unique"
                    )
                for value in strengths:
                    _check_selector_membership(
                        selectors, "flow_strength", value, context
                    )
                _check_impact_list(selectors, rule["impact"], context)
            else:  # behavior_rules
                patterns = rule["pattern"]
                if not isinstance(patterns, list) or not patterns:
                    raise _fail(f"{context}: pattern must be a non-empty array")
                if len(set(patterns)) != len(patterns):
                    raise _fail(f"{context}: pattern items must be unique")
                for value in patterns:
                    if value not in _BEHAVIOR_PATTERNS:
                        raise _fail(f"{context}: pattern {value!r} is not defined")
                if rule["confidence"] not in _BEHAVIOR_CONFIDENCES:
                    raise _fail(
                        f"{context}: confidence {rule['confidence']!r} is not defined"
                    )
                impact = rule["impact"]
                if impact != "any":
                    _check_impact_list(selectors, impact, context)
                if rule["corroborating_flow_required"] not in (True, False, "any"):
                    raise _fail(
                        f"{context}: corroborating_flow_required must be "
                        "true/false/'any'"
                    )

    clear_allow = raw["clear_allow_requires"]
    if not isinstance(clear_allow, list) or len(clear_allow) < 10:
        raise _fail("clear_allow_requires must be an array with at least 10 items")
    if len(set(clear_allow)) != len(clear_allow):
        raise _fail("clear_allow_requires items must be unique")
    if not all(isinstance(item, str) for item in clear_allow):
        raise _fail("clear_allow_requires items must be strings")


def _check_impact_list(selectors: dict[str, Any], impact: Any, context: str) -> None:
    if not isinstance(impact, list) or not impact:
        raise _fail(f"{context}: impact must be a non-empty array")
    if len(set(impact)) != len(impact):
        raise _fail(f"{context}: impact items must be unique")
    for value in impact:
        if value == "any":
            raise _fail(f"{context}: 'any' is not allowed inside an impact list")
        _check_selector_membership(selectors, "impact", value, context)


def default_fusion_matrix_path() -> Path:
    """冻结矩阵真值源路径（仓库内 ``docs`` 契约冻结目录）。

    相对本模块自身位置解析仓库根：``fusion.py`` 位于
    ``packages/agentguard-core/agentguard_core/decisions/``，向上 4 层即
    仓库根。在 worktree 中同样解析到 worktree 自身根目录，避免误读
    主工作区。
    """
    return (
        Path(__file__).resolve().parents[4]
        / "docs"
        / "AgentGuard_Core_V2.1_Final_Contract_Freeze"
        / "fusion_matrix.yaml"
    )


_FUSION_MATRIX_LOCK = threading.Lock()
_FUSION_MATRIX_CACHE: FusionMatrix | None = None


def load_fusion_matrix(path: str | Path | None = None) -> FusionMatrix:
    """加载并结构校验冻结 fusion 矩阵；默认路径模块级一次性缓存。

    - ``fusion_matrix.yaml`` 是 JSON-compatible YAML（冻结 ``format`` 字段
      声明），按仓库既有口径（``scripts/v21-contract-tools.py``）用标准库
      ``json`` 解析，不引入第三方 YAML 依赖；
    - 校验口径与 ``fusion_matrix.schema.json`` 一致（见
      ``_validate_raw_matrix``），并额外禁止未定义的 selector/disposition；
    - ``path is None`` 时结果缓存为模块级常量：一次加载，禁止每请求读盘；
      显式传入 ``path`` 不加缓存（仅供测试/工具对候选文件做校验）。
    """
    global _FUSION_MATRIX_CACHE
    with _FUSION_MATRIX_LOCK:
        if path is None and _FUSION_MATRIX_CACHE is not None:
            return _FUSION_MATRIX_CACHE
        resolved = Path(path) if path is not None else default_fusion_matrix_path()
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise FusionMatrixError(
                f"cannot read frozen fusion matrix at {resolved}: {exc}"
            ) from exc
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FusionMatrixError(
                f"{resolved.name} is not JSON-compatible YAML: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise FusionMatrixError(
                f"{resolved.name}: top-level value must be an object"
            )
        _validate_raw_matrix(raw)
        try:
            matrix = FusionMatrix.from_raw(raw)
        except Exception as exc:  # pydantic ValidationError 等
            raise FusionMatrixError(
                f"{resolved.name} failed typed validation: {exc}"
            ) from exc
        if path is None:
            _FUSION_MATRIX_CACHE = matrix
        return matrix


# ---------------------------------------------------------------------------
# Evidence group 去重（03 §3）
# ---------------------------------------------------------------------------


def dedupe_evidence_groups(signals: Sequence[SecuritySignal]) -> list[SecuritySignal]:
    """同一 ``evidence_group`` 的多个 detector signal 只保留一个代表。

    03 §3：同一底层事实（``underlying_fact_digest + causal_scope +
    primary_source_ref``，落地为 ``evidence_group`` 键）产生多个 detector
    signal 时只能作为一个 evidence group——Fusion 读取组内**最强证据**，
    不重复增加 confidence。代表选取规则（完全确定性）：

    - confidence 高者优先（high > medium > low）；
    - 其次 impact 高者优先（critical > high > moderate > low）；
    - 平手取 ``signal_id`` 字典序最小者。

    输出顺序按各 group 首次出现顺序，保证同输入同输出。
    """
    groups: dict[str, list[SecuritySignal]] = {}
    order: list[str] = []
    for signal in signals:
        if signal.evidence_group not in groups:
            groups[signal.evidence_group] = []
            order.append(signal.evidence_group)
        groups[signal.evidence_group].append(signal)

    representatives: list[SecuritySignal] = []
    for group_key in order:
        best = min(
            groups[group_key],
            key=lambda item: (
                _CONFIDENCE_RANK[item.confidence],
                _IMPACT_RANK[item.impact],
                item.signal_id,
            ),
        )
        representatives.append(best)
    return representatives


# ---------------------------------------------------------------------------
# selector 匹配原语
# ---------------------------------------------------------------------------


def _selector_matches(selector: Any, actual: Any) -> bool:
    return selector == "any" or selector == actual


def _bool_selector_matches(selector: bool | Literal["any"], actual: bool) -> bool:
    return selector == "any" or selector is actual


def _impact_selector_matches(
    selector: tuple[ImpactClass, ...] | Literal["any"], impact: ImpactClass
) -> bool:
    return selector == "any" or impact in selector


# ---------------------------------------------------------------------------
# evaluate_fusion（03 §6 七步优先级）
# ---------------------------------------------------------------------------


def evaluate_fusion(
    *,
    impact: ImpactClass,
    policy_violations: Sequence[PolicyViolation] = (),
    signals: Sequence[SecuritySignal] = (),
    degradations: Sequence[EvaluationDegradation] = (),
    authority: AuthorityVerdict | None = None,
    flow: FlowVerdict | None = None,
    coverage: CoverageMap | None = None,
    required_domains: Sequence[CoverageDomain] = (),
    memory_facts: Sequence[MemoryFact] = (),
    flows: Sequence[FlowFact] = (),
    behavior_aggregates: Sequence[BehaviorAggregate] = (),
    requires_semantic: bool = False,
    security_digests_valid: bool | None = None,
) -> tuple[FastDisposition, list[str]]:
    """按冻结矩阵求值 FastDisposition（纯函数；同输入必同输出）。

    实现 03 §6 七步优先级，映射到 ``fusion_matrix.yaml`` 的 8 级
    ``priority`` 链：

    1. system_invariant —— tier ``system_invariant``；
    2. hard policy —— tier ``hard_policy``；
    3. confirmed source-to-sink —— tier ``confirmed_source_to_sink``
       （``flow_rules``，输入为 ``FlowVerdict``）；
    4. explicit authority mismatch —— tier ``explicit_authority_mismatch``；
    5. required coverage / degradation —— tier
       ``required_coverage_or_degradation``；
    6. behavior / untrusted influence —— tier ``behavior_and_influence``
       （``influence_rules`` / ``memory_rules`` / ``behavior_rules``）；
    7. CLEAR_ALLOW proof —— tier ``clear_allow_proof``（10 条
       ``clear_allow_requires`` 全部成立才 CLEAR_ALLOW，缺一即 DEFER）；
    8. 兜底 —— tier ``defer_default``。

    匹配语义固定为 all-matching-then-highest-priority：收集全部匹配，再按
    ``CLEAR_DENY > DEFER > CLEAR_ALLOW`` 取最高 disposition；同一
    disposition 内 reason codes 按 priority 位次（高→低）与发现序去重排列。

    fail-closed 纪律：

    - ``authority`` / ``flow`` / ``coverage`` 缺态（None）各自产生
      ``input_missing`` DEFER 证据，绝不 fail-open；
    - signals 先经 ``dedupe_evidence_groups`` 去重（03 §3），同一底层事实
      不重复计权；
    - ``security_digests_valid`` 未知（None）不允许支撑 CLEAR_ALLOW；
    - 不读时钟、不生成 uuid、不触 IO，输出完全由输入决定。

    返回 ``(disposition, reason_codes)``；reason codes 全部以
    ``v21-08:`` 前缀命名，确定性可审计。
    """
    matrix = load_fusion_matrix()
    matches: list[tuple[int, FastDisposition, str]] = []

    def add_match(tier: str, disposition: FastDisposition, code: str) -> None:
        matches.append((matrix.priority_index(tier), disposition, code))

    # signals 先做 evidence group 去重（03 §3），后续步骤只用去重结果。
    grouped_signals = dedupe_evidence_groups(signals)

    authority_status = authority.status if authority is not None else None

    # 缺态输入 → DEFER（绝不 fail-open）。
    if authority is None:
        add_match(
            "required_coverage_or_degradation",
            "DEFER",
            f"{REASON_PREFIX}input_missing:authority",
        )
    if flow is None:
        add_match(
            "required_coverage_or_degradation",
            "DEFER",
            f"{REASON_PREFIX}input_missing:flow",
        )
    if coverage is None:
        add_match(
            "required_coverage_or_degradation",
            "DEFER",
            f"{REASON_PREFIX}input_missing:coverage",
        )

    # ------------------------------------------------------------------
    # Step 1 — System Invariant → CLEAR_DENY
    # ------------------------------------------------------------------
    for violation in policy_violations:
        if violation.policy_tier == "system_invariant":
            add_match(
                "system_invariant",
                "CLEAR_DENY",
                f"{REASON_PREFIX}system_invariant:{violation.rule_id}",
            )

    # ------------------------------------------------------------------
    # Step 2 — Hard Policy：deny → CLEAR_DENY；ask → DEFER 候选；
    # review_policy ask 保留为 DEFER/ASK 候选（并在 CLEAR_ALLOW 条件 7 拦截）
    # ------------------------------------------------------------------
    for violation in policy_violations:
        if violation.policy_tier in ("system_hard_policy", "tenant_hard_policy"):
            if violation.effect == "deny":
                add_match(
                    "hard_policy",
                    "CLEAR_DENY",
                    f"{REASON_PREFIX}hard_policy_deny:{violation.rule_id}",
                )
            else:
                add_match(
                    "hard_policy",
                    "DEFER",
                    f"{REASON_PREFIX}hard_policy_ask:{violation.rule_id}",
                )
        elif violation.policy_tier == "review_policy":
            add_match(
                "defer_default",
                "DEFER",
                f"{REASON_PREFIX}review_policy_ask:{violation.rule_id}",
            )

    # ------------------------------------------------------------------
    # Step 3 — Confirmed Source-to-Sink（冻结 flow_rules）
    # ------------------------------------------------------------------
    if flow is not None and flow.status in _FLOW_RULE_ACTIVE_STATUSES:
        sink = "external" if flow.external_sink else "internal"
        strength = flow.strongest_strength
        for taint in flow.taints:
            if taint not in _FLOW_TAINTS:
                continue
            for rule in matrix.flow_rules:
                if rule.taint != taint:
                    continue
                if not _selector_matches(rule.strength, strength):
                    continue
                if not _selector_matches(rule.authority, authority_status):
                    continue
                if not _selector_matches(rule.sink, sink):
                    continue
                add_match(
                    "confirmed_source_to_sink",
                    rule.disposition,
                    f"{REASON_PREFIX}flow_rule:{rule.id}",
                )

    # ------------------------------------------------------------------
    # Step 4 — Explicit Authority Mismatch
    # ------------------------------------------------------------------
    if authority is not None and authority.status == "unauthorized":
        capability_complete = (
            coverage is not None and coverage.capability.status == "complete"
        )
        explicit = bool(authority.explicit_scope_mismatches)
        if explicit and capability_complete and impact in ("high", "critical"):
            add_match(
                "explicit_authority_mismatch",
                "CLEAR_DENY",
                f"{REASON_PREFIX}explicit_authority_mismatch",
            )
        else:
            add_match(
                "explicit_authority_mismatch",
                "DEFER",
                f"{REASON_PREFIX}authority_unresolved",
            )
    elif authority is not None and authority.status == "unknown":
        add_match(
            "explicit_authority_mismatch",
            "DEFER",
            f"{REASON_PREFIX}authority_unknown",
        )

    # ------------------------------------------------------------------
    # Step 5 — Required Coverage / Degradation → DEFER
    # ------------------------------------------------------------------
    coverage_complete = True
    if coverage is not None:
        for domain in required_domains:
            status = getattr(coverage, domain).status
            if status not in ("complete", "not_applicable"):
                coverage_complete = False
                add_match(
                    "required_coverage_or_degradation",
                    "DEFER",
                    f"{REASON_PREFIX}coverage_incomplete:{domain}:{status}",
                )
    else:
        coverage_complete = False
    required_degradation = False
    for degradation in degradations:
        if degradation.required_for_action:
            required_degradation = True
            add_match(
                "required_coverage_or_degradation",
                "DEFER",
                f"{REASON_PREFIX}required_degradation:{degradation.degradation_id}",
            )

    # ------------------------------------------------------------------
    # Step 6 — Behavior / Untrusted Influence（冻结
    # influence/memory/behavior 规则）
    # ------------------------------------------------------------------
    hostile_evidence = any(
        signal.category in HOSTILE_INSTRUCTION_CATEGORIES
        for signal in grouped_signals
    )

    # 6a. untrusted influence：strength 取自 influenced_by 且携带 untrusted
    # taint 的 flow（D3：strength 由 producer 给定，只透传取最强，不推断）。
    influence_strength: str | None = None
    for fact in flows:
        if fact.relation != "influenced_by":
            continue
        if not _UNTRUSTED_INFLUENCE_TAINTS.intersection(fact.taints):
            continue
        if (
            influence_strength is None
            or _STRENGTH_RANK[fact.strength] < _STRENGTH_RANK[influence_strength]
        ):
            influence_strength = fact.strength
    if influence_strength is not None:
        for rule in matrix.influence_rules:
            if influence_strength not in rule.strength:
                continue
            if not _bool_selector_matches(
                rule.hostile_instruction_evidence, hostile_evidence
            ):
                continue
            if not _selector_matches(rule.authority, authority_status):
                continue
            if impact not in rule.impact:
                continue
            add_match(
                "behavior_and_influence",
                rule.disposition,
                f"{REASON_PREFIX}influence_rule:{rule.id}",
            )

    # 6b. memory：retrieval influence 强度取关联该 memory 的 flow 最强值。
    for memory_fact in memory_facts:
        retrieval_strength: str | None = None
        for fact in flows:
            if fact.relation not in _MEMORY_RETRIEVAL_RELATIONS:
                continue
            if memory_fact.memory_id not in (fact.source_ref, fact.target_ref):
                continue
            if (
                retrieval_strength is None
                or _STRENGTH_RANK[fact.strength] < _STRENGTH_RANK[retrieval_strength]
            ):
                retrieval_strength = fact.strength
        if retrieval_strength is None:
            continue
        for rule in matrix.memory_rules:
            if memory_fact.trust_state not in rule.trust_state:
                continue
            if rule.taint not in memory_fact.taints:
                continue
            if retrieval_strength not in rule.retrieval_strength:
                continue
            if not _selector_matches(rule.authority, authority_status):
                continue
            if impact not in rule.impact:
                continue
            add_match(
                "behavior_and_influence",
                rule.disposition,
                f"{REASON_PREFIX}memory_rule:{rule.id}",
            )

    # 6c. behavior：corroborating flow 以 FlowVerdict 违规态为准（确定性）。
    corroborating_flow_present = (
        flow is not None and flow.status == "violation"
    )
    for aggregate in behavior_aggregates:
        for rule in matrix.behavior_rules:
            if aggregate.pattern_id not in rule.pattern:
                continue
            if not _selector_matches(rule.confidence, aggregate.confidence):
                continue
            if not _selector_matches(rule.authority, authority_status):
                continue
            if not _impact_selector_matches(rule.impact, impact):
                continue
            if not _bool_selector_matches(
                rule.corroborating_flow_required, corroborating_flow_present
            ):
                continue
            add_match(
                "behavior_and_influence",
                rule.disposition,
                f"{REASON_PREFIX}behavior_rule:{rule.id}",
            )

    # ------------------------------------------------------------------
    # 聚合：CLEAR_DENY > DEFER > CLEAR_ALLOW（disposition_priority 冻结序）
    # ------------------------------------------------------------------
    def collect(disposition: FastDisposition) -> list[str]:
        selected = sorted(
            (match for match in matches if match[1] == disposition),
            key=lambda match: match[0],
        )
        codes: list[str] = []
        for _, _, code in selected:
            if code not in codes:
                codes.append(code)
        return codes

    deny_codes = collect("CLEAR_DENY")
    if deny_codes:
        return "CLEAR_DENY", deny_codes
    defer_codes = collect("DEFER")
    if defer_codes:
        return "DEFER", defer_codes

    # ------------------------------------------------------------------
    # Step 7 — CLEAR_ALLOW Proof：10 条 clear_allow_requires 全成立才放行
    # ------------------------------------------------------------------
    system_invariant_present = any(
        violation.policy_tier == "system_invariant"
        for violation in policy_violations
    )
    hard_policy_present = any(
        violation.policy_tier in ("system_hard_policy", "tenant_hard_policy")
        for violation in policy_violations
    )
    review_policy_present = any(
        violation.policy_tier == "review_policy" for violation in policy_violations
    )
    high_confidence_behavior_chain = any(
        aggregate.confidence == "high" and aggregate.pattern_id != "B6"
        for aggregate in behavior_aggregates
    )

    condition_holds: dict[str, bool] = {
        "no_system_invariant_violation": not system_invariant_present,
        "no_hard_deny_or_hard_ask": not hard_policy_present,
        "all_required_domains_complete_or_not_applicable": coverage_complete,
        "authority_authorized_or_not_required": authority is not None
        and authority.status in ("authorized", "not_required"),
        "flow_safe_or_not_applicable": flow is not None
        and flow.status in ("safe", "not_applicable"),
        "no_required_degradation": not required_degradation,
        "no_policy_required_human_review": not review_policy_present,
        "no_unresolved_high_confidence_behavior_chain": (
            not high_confidence_behavior_chain
        ),
        "no_required_semantic_ambiguity": not requires_semantic,
        "all_security_digests_valid": security_digests_valid is True,
    }

    # 以冻结 clear_allow_requires 的顺序逐条核验（顺序即真值源顺序）。
    unmet = [
        condition
        for condition in matrix.clear_allow_requires
        if condition not in condition_holds or not condition_holds[condition]
    ]
    if not unmet:
        return "CLEAR_ALLOW", [CLEAR_ALLOW_PROOF_REASON]
    return "DEFER", [f"{REASON_PREFIX}clear_allow_unmet:{name}" for name in unmet]
