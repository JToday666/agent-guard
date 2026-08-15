"""CT-PR-02a TransientSecurityFacts 契约测试（ct-fact-1，无接线）。

口径依据：

- 01 章 §17 ``TransientSecurityFacts`` 字段冻结（extra=forbid、
  schema_version 默认值）；
- 01 章 §29 digest 白名单：注册 id（source_id/flow_id）与
  ``bundle_digest`` 自身不进摘要；语义字段（trust/taints/relation/
  scope_digest/event_id）必须进；
- 02 章 §11 T-FactReplay：同内容 bundle 恒产同 digest；
  JSON 可序列化（tuple 字段序列化为数组）。
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agentguard_core.security_context.facts import FlowFact, SourceFact
from guard_api.security_state.transient import (
    FACT_BUILDER_VERSION,
    TransientSecurityFacts,
    bundle_digest_projection,
    compute_bundle_digest,
)

SCOPE = "sha256:" + "0" * 64


def _source_fact(
    *,
    source_id: str = "source:web:evt-1:0",
    trust: str = "untrusted",
    taints: tuple[str, ...] = ("UNTRUSTED",),
) -> SourceFact:
    return SourceFact(
        source_id=source_id,
        scope_digest=SCOPE,
        source_type="web",
        trust=trust,  # type: ignore[arg-type]
        verification_state="unverified",
        origin="observed",
        authority="untrusted_claim",
        producer="adapter_unattributed",
        taints=list(taints),  # type: ignore[arg-type]
        first_sequence=None,
        last_sequence=None,
        evidence_refs=[],
    )


def _flow_fact(
    *,
    flow_id: str = "flow:evt-1:0",
    relation: str = "assembled_into",
) -> FlowFact:
    return FlowFact(
        flow_id=flow_id,
        scope_digest=SCOPE,
        source_ref="source:web:evt-1:0",
        target_ref="context:evt-1",
        relation=relation,  # type: ignore[arg-type]
        taints=["UNTRUSTED"],
        strength="exact",
        origin="observed",
        sequence=None,
        producer="ct-fact-builder",
        evidence_refs=[],
    )


def _bundle(**overrides) -> TransientSecurityFacts:
    base: dict = {
        "event_id": "evt-1",
        "scope_digest": SCOPE,
        "source_facts": (_source_fact(),),
        "flow_facts": (_flow_fact(),),
    }
    base.update(overrides)
    return TransientSecurityFacts(**base)


def test_fact_builder_version_is_ct_fact_1() -> None:
    assert FACT_BUILDER_VERSION == "ct-fact-1"


def test_schema_defaults_and_frozen_fields() -> None:
    bundle = _bundle()
    assert bundle.schema_version == "1.0"
    assert bundle.memory_facts == ()
    assert bundle.declassifications == ()
    assert bundle.current_action is None
    assert bundle.signals == ()
    assert bundle.degradations == ()
    assert bundle.evidence_refs == ()
    assert bundle.bundle_digest == ""


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        TransientSecurityFacts(
            **{"event_id": "evt-1", "scope_digest": SCOPE, "not_a_field": True}
        )


def test_projection_whitelist_keys() -> None:
    projection = bundle_digest_projection(_bundle())
    assert set(projection) == {
        "fact_builder_version",
        "event_id",
        "scope_digest",
        "source_facts",
        "flow_facts",
        "memory_facts",
    }
    assert projection["fact_builder_version"] == "ct-fact-1"


def test_digest_deterministic_same_content() -> None:
    # T-FactReplay：同内容两次独立构造 → 同 digest。
    assert compute_bundle_digest(_bundle()) == compute_bundle_digest(_bundle())
    assert compute_bundle_digest(_bundle()).startswith("sha256:")


def test_registration_ids_excluded_from_digest() -> None:
    # 01 §29：source_id/flow_id 是注册标识，不进安全摘要。
    baseline = compute_bundle_digest(_bundle())
    renamed = compute_bundle_digest(
        _bundle(
            source_facts=(_source_fact(source_id="source:web:evt-1:registry-renamed"),),
            flow_facts=(_flow_fact(flow_id="flow:evt-1:registry-renamed"),),
        )
    )
    assert renamed == baseline


def test_semantic_fields_change_digest() -> None:
    baseline = compute_bundle_digest(_bundle())
    assert (
        compute_bundle_digest(_bundle(source_facts=(_source_fact(trust="unknown"),)))
        != baseline
    )
    assert (
        compute_bundle_digest(
            _bundle(source_facts=(_source_fact(taints=("UNTRUSTED", "SENSITIVE")),))
        )
        != baseline
    )
    assert (
        compute_bundle_digest(
            _bundle(flow_facts=(_flow_fact(relation="influenced_by"),))
        )
        != baseline
    )
    assert compute_bundle_digest(_bundle(event_id="evt-2")) != baseline
    assert compute_bundle_digest(_bundle(scope_digest="sha256:" + "1" * 64)) != baseline


def test_bundle_digest_itself_excluded() -> None:
    # bundle_digest 自身防自引用：预置任意值不影响投影 digest。
    bare = _bundle()
    stamped = bare.model_copy(update={"bundle_digest": "sha256:" + "f" * 64})
    assert compute_bundle_digest(stamped) == compute_bundle_digest(bare)


def test_json_serializable() -> None:
    bundle = _bundle()
    bundle = bundle.model_copy(update={"bundle_digest": compute_bundle_digest(bundle)})
    dumped = bundle.model_dump(mode="json")
    assert json.dumps(dumped, sort_keys=True)
    assert isinstance(dumped["source_facts"], list)
