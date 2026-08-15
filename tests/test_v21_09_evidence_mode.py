"""V21-09 T4：``build_decision_evidence_v21`` mode 参数化契约测试。

口径：

- ``12_决策记录_V21-09前置.md`` D1：V21-09 阶段 mode 恒 shadow；
  ``limited_enable`` / ``active`` 归 V21-11 启用范畴；
- 解除硬编码但默认语义逐字节不变：显式传 ``"shadow"`` 与默认调用的
  序列化输出必须逐字节一致（回归锚点：``test_v21_08_decision_evidence.py``
  零改动全绿）；
- 非法 mode 值被 ``DecisionEvidenceV21`` 的 pydantic Literal 校验拒绝。
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard_core.decisions.evidence import DecisionEvidenceV21
from agentguard_core.decisions.evidence_builder import (
    EvidenceMode,
    build_decision_evidence_v21,
)
from tests.test_v21_08_decision_evidence import _build_full_pipeline


def _build_kwargs(mode: EvidenceMode | None = None) -> tuple:
    """复用 V21-08 完整路径 fixture，仅按测试需要注入 mode。"""
    assessment, _evidence, coverage = _build_full_pipeline()
    kwargs: dict = {
        "legacy_decision": "ask",
        "snapshot_id": "snap-evidence-1",
        "state_version": 7,
        "coverage": coverage,
    }
    if mode is not None:
        kwargs["mode"] = mode
    return assessment, kwargs


def test_explicit_shadow_is_byte_identical_to_default() -> None:
    """显式传 ``"shadow"`` 与不传（默认）输出逐字节一致。"""
    assessment, kwargs = _build_kwargs()
    default_evidence = build_decision_evidence_v21(assessment, **kwargs)

    # 同一份 assessment 真值重建（builder 是纯函数，同输入必同输出）。
    explicit_evidence = build_decision_evidence_v21(
        assessment, **kwargs, mode="shadow"
    )

    assert explicit_evidence == default_evidence
    assert explicit_evidence.mode == "shadow"
    # 逐字节锚点：JSON 序列化串完全一致。
    assert explicit_evidence.model_dump_json() == default_evidence.model_dump_json()
    assert explicit_evidence.model_dump(mode="json") == default_evidence.model_dump(
        mode="json"
    )


def test_default_mode_remains_shadow() -> None:
    """V21-09 调用方只传默认值时，mode 恒 shadow（D1）。"""
    assessment, kwargs = _build_kwargs()
    evidence = build_decision_evidence_v21(assessment, **kwargs)
    assert evidence.mode == "shadow"
    # shadow 期冻结约定不受参数化影响。
    assert evidence.final_decision == evidence.legacy_decision
    assert evidence.semantic_judgment_id is None
    assert evidence.semantic_digest is None


@pytest.mark.parametrize("mode", ["limited_enable", "active"])
def test_v2111_mode_values_are_accepted_but_final_decision_stays_legacy(
    mode: str,
) -> None:
    """Literal 全集内的 V21-11 启用值可通过校验（预留传值通道），
    但 ``final_decision`` 恒取 legacy（shadow 期官方决策者是 legacy）。"""
    assessment, kwargs = _build_kwargs(mode=mode)  # type: ignore[arg-type]
    evidence = build_decision_evidence_v21(assessment, **kwargs)
    assert evidence.mode == mode
    assert evidence.final_decision == evidence.legacy_decision
    assert evidence.semantic_judgment_id is None
    assert evidence.semantic_digest is None


@pytest.mark.parametrize("bad_mode", ["Shadow", "SHADOW", "enabled", "", "shadow2"])
def test_invalid_mode_is_rejected_by_pydantic(bad_mode: str) -> None:
    """非法 mode 值被 DecisionEvidenceV21 的 Literal 校验 fail-closed。"""
    assessment, kwargs = _build_kwargs(mode=bad_mode)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        build_decision_evidence_v21(assessment, **kwargs)


def test_evidence_mode_alias_matches_contract_literal() -> None:
    """``EvidenceMode`` 别名与 ``DecisionEvidenceV21.mode`` Literal 全集
    逐字一致（01 §28）。"""
    from typing import Literal, get_args

    assert EvidenceMode == Literal["shadow", "limited_enable", "active"]
    contract_args = set(
        get_args(DecisionEvidenceV21.model_fields["mode"].annotation)
    )
    assert set(get_args(EvidenceMode)) == contract_args
