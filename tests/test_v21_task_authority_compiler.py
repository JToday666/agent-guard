"""V21-03 authority/ 子包契约测试（模型冻结 + Compiler 确定性 + fail-closed）。

覆盖 ``packages/agentguard-core/agentguard_core/authority``：

- 模型字段冻结断言（与 01 §4/§5 文档逐字段对齐）；
- digest 确定性 + 白名单不随 ``model_dump`` 全量泄漏；
- compiler 确定性（同输入两次输出逐字段相等）；
- fail-closed 矩阵（producer/authority/scope_digest/principal 篡改）；
- AST 守卫（compiler 不 import ``events.payloads`` / ``events.contracts``）。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agentguard_core.actions.models import (
    ActionConstraint,
    DestinationConstraint,
    ResourceConstraint,
)
from agentguard_core.authority import (
    COMPILER_VERSION,
    DERIVED_AUTHORITY_MARKER,
    CompiledTaskAuthority,
    EvaluationClock,
    SecurityStateScope,
    TaskAuthorityError,
    TaskFact,
    compile_task_authority,
    compiled_task_authority_projection,
    scope_digest_projection,
    task_digest_projection,
)

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_DIR = (
    ROOT / "packages" / "agentguard-core" / "agentguard_core" / "authority"
)

SERVER_KEY = b"v21-03-test-server-key"
OTHER_KEY = b"v21-03-test-other-server-key"


# ---------------------------------------------------------------------------
# Fixtures：构造自洽的 scope + task_fact
# ---------------------------------------------------------------------------


def _build_scope(principal_id: str = "principal_1") -> SecurityStateScope:
    partial = SecurityStateScope(
        principal_id=principal_id,
        runtime="langgraph",
        runtime_binding_id="binding_1",
        trace_id="trace_1",
        session_id="session_1",
        scope_digest="",
    )
    digest = scope_digest_projection(partial, server_key=SERVER_KEY)
    return partial.model_copy(update={"scope_digest": digest})


def _build_task_fact(scope: SecurityStateScope) -> TaskFact:
    # task_digest 白名单不含 task_digest 自身：先用占位值构造，
    # 再以真实投影回填（与服务端 task ingress 同口径）。
    pending = TaskFact(
        task_id="task_1",
        scope_digest=scope.scope_digest,
        principal_id=scope.principal_id,
        task_summary="汇总本周销售数据并生成报表",
        task_digest="sha256:pending-server-computation",
        revision=1,
        status="active",
        action_constraints=[ActionConstraint(action_types=["file.read"])],
        resource_constraints=[
            ResourceConstraint(scheme="file", op="prefix", values=["/data/"])
        ],
        destination_constraints=[
            DestinationConstraint(scheme="url", op="domain", values=["example.com"])
        ],
        created_sequence=None,
        producer="guard_api_task_ingress",
        authority="authoritative",
        evidence_refs=[],
    )
    return pending.model_copy(
        update={"task_digest": task_digest_projection(pending)}
    )


# ---------------------------------------------------------------------------
# 1. 模型字段冻结断言
# ---------------------------------------------------------------------------


def test_security_state_scope_fields_frozen() -> None:
    assert set(SecurityStateScope.model_fields) == {
        "schema_version",
        "principal_id",
        "runtime",
        "runtime_binding_id",
        "trace_id",
        "session_id",
        "scope_digest",
    }


def test_evaluation_clock_fields_frozen() -> None:
    assert set(EvaluationClock.model_fields) == {
        "evaluated_at",
        "source",
        "clock_version",
    }


def test_task_fact_fields_frozen() -> None:
    assert set(TaskFact.model_fields) == {
        "schema_version",
        "task_id",
        "scope_digest",
        "principal_id",
        "task_summary",
        "task_digest",
        "revision",
        "status",
        "action_constraints",
        "resource_constraints",
        "destination_constraints",
        "created_sequence",
        "producer",
        "authority",
        "evidence_refs",
    }


def test_compiled_task_authority_fields_frozen() -> None:
    assert set(CompiledTaskAuthority.model_fields) == {
        "schema_version",
        "task_id",
        "task_revision",
        "principal_id",
        "scope_digest",
        "status",
        "action_constraints",
        "resource_constraints",
        "destination_constraints",
        "derived_authority",
        "compiler_version",
        "compiled_digest",
    }


def test_evaluation_clock_source_literal_is_authoritative() -> None:
    clock = EvaluationClock(evaluated_at="2026-08-14T00:00:00Z", clock_version="1")
    assert clock.source == "guard_api_authoritative_clock"


# ---------------------------------------------------------------------------
# 2. digest 确定性 + 白名单不泄漏
# ---------------------------------------------------------------------------


def test_scope_digest_is_deterministic_and_keyed() -> None:
    scope = _build_scope()
    assert scope_digest_projection(scope, server_key=SERVER_KEY) == (
        scope_digest_projection(scope, server_key=SERVER_KEY)
    )
    # 不同 server_key 必须产生不同 digest（keyed，而非裸 JCS sha256）。
    assert scope_digest_projection(scope, server_key=SERVER_KEY) != (
        scope_digest_projection(scope, server_key=OTHER_KEY)
    )
    assert scope.scope_digest.startswith("hmac-sha256:")


def test_scope_digest_ignores_trace_id() -> None:
    # trace_id 是关联维度、非稳定 scope 身份：改变 trace_id 不应改变 digest。
    scope_a = _build_scope()
    scope_b = scope_a.model_copy(update={"trace_id": "trace_other"})
    assert scope_digest_projection(scope_a, server_key=SERVER_KEY) == (
        scope_digest_projection(scope_b, server_key=SERVER_KEY)
    )


def test_task_digest_is_deterministic_and_prefix() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    assert task_digest_projection(fact) == task_digest_projection(fact)
    assert task_digest_projection(fact).startswith("sha256:")


def test_task_digest_excludes_self_referential_and_unstable_fields() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    # 篡改 task_digest/evidence_refs 不影响投影（白名单排除）。
    mutated = fact.model_copy(
        update={"task_digest": "sha256:other", "evidence_refs": []}
    )
    assert task_digest_projection(fact) == task_digest_projection(mutated)


@pytest.mark.parametrize(
    ("model_cls", "forbidden"),
    [
        (SecurityStateScope, {"trace_id", "scope_digest"}),
        (TaskFact, {"task_digest", "evidence_refs"}),
        (CompiledTaskAuthority, {"compiled_digest"}),
    ],
)
def test_digest_whitelist_is_field_subset_and_excludes_unstable(
    model_cls: type, forbidden: set[str]
) -> None:
    whitelist = model_cls.digest_fields()
    # 白名单必须是模型字段的真子集（不随 model_dump 全量泄漏）。
    assert whitelist <= set(model_cls.model_fields)
    assert whitelist < set(model_cls.model_fields)
    # 不得包含非稳定/自引用字段（01 §29 禁止项）。
    assert whitelist.isdisjoint(forbidden)


# ---------------------------------------------------------------------------
# 3. compiler 确定性
# ---------------------------------------------------------------------------


def test_compile_is_deterministic_field_by_field() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)

    first = compile_task_authority(fact, scope, server_key=SERVER_KEY)
    second = compile_task_authority(fact, scope, server_key=SERVER_KEY)

    assert first == second
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.compiled_digest.startswith("sha256:")


def test_compile_passthrough_and_marker() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)

    compiled = compile_task_authority(fact, scope, server_key=SERVER_KEY)

    assert compiled.task_id == fact.task_id
    assert compiled.task_revision == fact.revision
    assert compiled.principal_id == fact.principal_id
    assert compiled.scope_digest == fact.scope_digest
    assert compiled.status == fact.status
    assert compiled.action_constraints == fact.action_constraints
    assert compiled.resource_constraints == fact.resource_constraints
    assert compiled.destination_constraints == fact.destination_constraints
    assert compiled.derived_authority == DERIVED_AUTHORITY_MARKER
    assert compiled.compiler_version == COMPILER_VERSION


def test_projection_keys_match_digest_whitelist() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    projection = compiled_task_authority_projection(fact)
    assert set(projection) == CompiledTaskAuthority.digest_fields()


def test_compile_sensitive_to_constraint_change() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    baseline = compile_task_authority(fact, scope, server_key=SERVER_KEY)

    # 扩权后必须同步重算 task_digest（合法修订路径），digest 才会变化。
    widened_body = fact.model_copy(
        update={
            "action_constraints": [
                ActionConstraint(action_types=["file.read", "file.write"])
            ]
        }
    )
    widened = widened_body.model_copy(
        update={"task_digest": task_digest_projection(widened_body)}
    )
    changed = compile_task_authority(widened, scope, server_key=SERVER_KEY)
    assert baseline.compiled_digest != changed.compiled_digest


def test_compile_rejects_constraint_tampering_via_task_digest() -> None:
    # R2 纵深防御：约束被篡改后未重算 task_digest → 编译拒绝。
    scope = _build_scope()
    fact = _build_task_fact(scope)
    tampered = fact.model_copy(
        update={
            "action_constraints": [
                ActionConstraint(action_types=["file.read", "file.write", "shell.exec"])
            ]
        }
    )
    with pytest.raises(TaskAuthorityError) as exc:
        compile_task_authority(tampered, scope, server_key=SERVER_KEY)
    assert exc.value.reason_code == "v21-03:task_digest_mismatch"


def test_compile_rejects_stale_task_digest_placeholder() -> None:
    # 伪造 TaskFact 携带任意占位/外部 task_digest 均被拒绝。
    scope = _build_scope()
    fact = _build_task_fact(scope)
    forged = fact.model_copy(update={"task_digest": "sha256:" + "0" * 64})
    with pytest.raises(TaskAuthorityError) as exc:
        compile_task_authority(forged, scope, server_key=SERVER_KEY)
    assert exc.value.reason_code == "v21-03:task_digest_mismatch"


# ---------------------------------------------------------------------------
# 4. fail-closed 矩阵
# ---------------------------------------------------------------------------


def test_fail_closed_on_producer_tampering() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    tampered = fact.model_copy(update={"producer": "adapter_self_report"})
    with pytest.raises(TaskAuthorityError) as exc:
        compile_task_authority(tampered, scope, server_key=SERVER_KEY)
    assert exc.value.reason_code == "v21-03:invalid_producer"


def test_fail_closed_on_authority_tampering() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    tampered = fact.model_copy(update={"authority": "trusted_claim"})
    with pytest.raises(TaskAuthorityError) as exc:
        compile_task_authority(tampered, scope, server_key=SERVER_KEY)
    assert exc.value.reason_code == "v21-03:invalid_authority"


def test_fail_closed_on_scope_digest_tampering() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    tampered = fact.model_copy(update={"scope_digest": "hmac-sha256:deadbeef"})
    with pytest.raises(TaskAuthorityError) as exc:
        compile_task_authority(tampered, scope, server_key=SERVER_KEY)
    assert exc.value.reason_code == "v21-03:scope_digest_mismatch"


def test_fail_closed_on_principal_mismatch() -> None:
    scope = _build_scope(principal_id="principal_1")
    fact = _build_task_fact(scope)
    # task_fact 声明了另一个 principal，与 scope 不一致。
    mismatched = fact.model_copy(update={"principal_id": "principal_other"})
    with pytest.raises(TaskAuthorityError) as exc:
        compile_task_authority(mismatched, scope, server_key=SERVER_KEY)
    assert exc.value.reason_code == "v21-03:principal_mismatch"


def test_fail_closed_on_wrong_server_key() -> None:
    scope = _build_scope()
    fact = _build_task_fact(scope)
    # 用错误 server_key 重算 digest 必然 mismatch → fail-closed。
    with pytest.raises(TaskAuthorityError) as exc:
        compile_task_authority(fact, scope, server_key=OTHER_KEY)
    assert exc.value.reason_code == "v21-03:scope_digest_mismatch"


# ---------------------------------------------------------------------------
# 5. AST 守卫：compiler 不得依赖 events（判定路径 payload/contract）
# ---------------------------------------------------------------------------


def _import_references(source: str) -> list[str]:
    """收集源码中所有 import 引用的模块名与 alias 名。"""
    references: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            references.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            references.append(node.module or "")
            references.extend(alias.name for alias in node.names)
    return references


def _assert_no_events_references(relative_path: str, references: list[str]) -> None:
    for reference in references:
        assert (
            "events" not in reference
        ), f"{relative_path} imports the decision-path events module {reference!r}"
        assert reference not in {
            "payloads",
            "contracts",
        }, f"{relative_path} imports the decision-path events module {reference!r}"


@pytest.mark.parametrize("relative_path", ["compiler.py", "models.py"])
def test_authority_does_not_reference_events(relative_path: str) -> None:
    source = (AUTHORITY_DIR / relative_path).read_text(encoding="utf-8")
    _assert_no_events_references(relative_path, _import_references(source))


@pytest.mark.parametrize(
    "sample_source",
    [
        "from ..events import payloads",
        "from ..events.contracts import GuardEvent",
        "import agentguard_core.events.payloads",
    ],
)
def test_events_guard_detects_relative_and_alias_imports(
    sample_source: str,
) -> None:
    # 守卫自身的负例验证：上述任一样例源码都必须被识别为违规。
    with pytest.raises(AssertionError):
        _assert_no_events_references("sample.py", _import_references(sample_source))
