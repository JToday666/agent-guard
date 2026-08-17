"""V21-02 contract tests: ActionIR 字段冻结、canonical JSON 黄金向量、指纹参与/排除。"""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from agentguard_core import GuardEvent
from agentguard_core.actions import (
    CANONICALIZATION_VERSION,
    NORMALIZER_VERSION,
    ActionConstraint,
    ActionEffect,
    ActionIR,
    ApiResource,
    ArgumentConstraint,
    CanonicalArgument,
    CanonicalArguments,
    CanonicalizationError,
    DestinationConstraint,
    EmailResource,
    FileResource,
    MemoryResource,
    OtherResource,
    ProcessResource,
    ResourceBase,
    ResourceConstraint,
    ToolResource,
    UrlResource,
    audit_fingerprint,
    audit_projection,
    authorization_fingerprint,
    authorization_projection,
    build_action_ir,
    canonical_hmac_sha256,
    canonical_json,
    canonical_sha256,
    matches_action,
    matches_argument,
    matches_destination,
    matches_resource,
    normalize_arguments,
)

SECRET = b"v21-02-contract-test-secret"


def _sample_event(arguments: dict | None = None, tool: str = "read_file") -> GuardEvent:
    return GuardEvent.model_validate(
        {
            "event_type": "tool_call_proposed",
            "trace_id": "trace_contract",
            "runtime": "openclaw",
            "security_context": {"agent_id": "agent_a", "user_task": "read docs"},
            "payload": {
                "tool": {"name": tool},
                "arguments": (
                    arguments
                    if arguments is not None
                    else {"path": "/data/report.md", "limit": 10}
                ),
                "derived_resources": [],
            },
        }
    )


# ---------------------------------------------------------------------------
# canonical JSON 黄金向量（受限类型域内参考值）
# ---------------------------------------------------------------------------


def test_canonical_json_golden_vectors() -> None:
    assert (
        canonical_json({"b": 1, "a": [True, None, "x"]})
        == '{"a":[true,null,"x"],"b":1}'
    )
    assert (
        canonical_json({"o": {"z": 1, "a": {"m": [1, 2]}}})
        == '{"o":{"a":{"m":[1,2]},"z":1}}'
    )
    # ensure_ascii=False：非 ASCII 原样输出。
    assert canonical_json({"中文": "值"}) == '{"中文":"值"}'
    # 紧凑分隔符 + JSON 字符串转义。
    assert canonical_json({"s": 'a"b'}) == '{"s":"a\\"b"}'
    assert canonical_json({}) == "{}"
    assert canonical_json([]) == "[]"
    assert canonical_json(-7) == "-7"


def test_canonical_json_rejects_float_and_unknown_types() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"v": 1.5})
    with pytest.raises(CanonicalizationError):
        canonical_json([0.0])
    with pytest.raises(CanonicalizationError):
        canonical_json({"v": object()})
    with pytest.raises(CanonicalizationError):
        canonical_json({1: "non-str key"})


def test_canonical_sha256_golden_digest() -> None:
    expected = "sha256:" + hashlib.sha256(b'{"a":[true,null,"x"],"b":1}').hexdigest()
    assert canonical_sha256({"b": 1, "a": [True, None, "x"]}) == expected


def test_canonical_hmac_sha256_is_keyed_and_prefixed() -> None:
    first = canonical_hmac_sha256(SECRET, {"a": 1})
    second = canonical_hmac_sha256(SECRET, {"a": 1})
    other_key = canonical_hmac_sha256(b"other-secret", {"a": 1})
    assert first == second
    assert first.startswith("hmac-sha256:")
    assert first != other_key


# ---------------------------------------------------------------------------
# 字段集冻结断言（对齐 01 文档各模型）
# ---------------------------------------------------------------------------


def test_action_ir_field_set_is_frozen() -> None:
    assert set(ActionIR.model_fields) == {
        "schema_version",
        "event_id",
        "action_id",
        "trace_id",
        "task_id",
        "task_revision",
        "scope_digest",
        "principal_id",
        "runtime",
        "runtime_binding_id",
        "agent_id",
        "branch_id",
        "parent_event_ids",
        "runtime_sequence",
        "tool_name",
        "action_type",
        "effects",
        "impact",
        "resources",
        "destinations",
        "data_refs",
        "canonical_arguments",
        "argument_digest",
        "authorization_fingerprint",
        "audit_fingerprint",
        "normalizer_version",
    }


def test_action_effect_field_set_is_frozen() -> None:
    assert set(ActionEffect.model_fields) == {
        "mutates_state",
        "external_communication",
        "persistence",
        "privilege_use",
        "destructive",
        "reversible",
        "data_egress",
        "code_execution",
        "network_access",
    }


def test_canonical_argument_field_sets_are_frozen() -> None:
    assert set(CanonicalArgument.model_fields) == {
        "json_pointer",
        "value",
        "security_relevant",
    }
    assert set(CanonicalArguments.model_fields) == {
        "items",
        "canonicalization_version",
        "argument_digest",
    }


def test_constraint_dsl_field_sets_are_frozen() -> None:
    assert set(ActionConstraint.model_fields) == {"op", "action_types"}
    assert set(ArgumentConstraint.model_fields) == {"json_pointer", "op", "value"}
    assert set(ResourceConstraint.model_fields) == {"scheme", "op", "values"}
    assert set(DestinationConstraint.model_fields) == {"scheme", "op", "values"}


def test_resource_model_field_sets_are_frozen() -> None:
    base_fields = {
        "resource_id",
        "canonical_id",
        "display_summary",
        "resolution_status",
        "normalizer_version",
    }
    assert set(ResourceBase.model_fields) == base_fields
    assert set(FileResource.model_fields) == base_fields | {
        "kind",
        "normalized_path",
        "platform",
        "case_sensitive",
        "symlink_resolution",
        "final_path",
    }
    url_fields = base_fields | {
        "kind",
        "scheme",
        "host_ascii",
        "port",
        "normalized_path",
        "query_keys",
        "security_query_arguments",
        "redirect_policy",
    }
    assert set(UrlResource.model_fields) == url_fields
    assert set(ApiResource.model_fields) == url_fields | {"method"}
    assert set(EmailResource.model_fields) == base_fields | {
        "kind",
        "normalized_address",
        "domain_ascii",
    }
    assert set(MemoryResource.model_fields) == base_fields | {
        "kind",
        "memory_id",
        "namespace",
    }
    assert set(ProcessResource.model_fields) == base_fields | {
        "kind",
        "executable",
        "interpreter",
    }
    assert set(ToolResource.model_fields) == base_fields | {
        "kind",
        "tool_name",
        "tool_schema_digest",
        "provider_binding_id",
    }
    assert set(OtherResource.model_fields) == base_fields | {
        "kind",
        "type_name",
        "stable_identifier",
    }


def test_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ActionEffect(unknown_field=True)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        CanonicalArgument(
            json_pointer="/a",
            value=1,
            security_relevant=False,
            extra="x",  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        ResourceConstraint(scheme="file", op="exact", values=[], extra=1)  # type: ignore[call-arg]


def test_canonical_argument_strict_mode_forbids_coercion() -> None:
    text_item = CanonicalArgument.model_validate(
        {"json_pointer": "/v", "value": "123", "security_relevant": True}
    )
    int_item = CanonicalArgument.model_validate(
        {"json_pointer": "/v", "value": 123, "security_relevant": True}
    )
    assert isinstance(text_item.value, str)
    assert isinstance(int_item.value, int)
    assert not isinstance(int_item.value, bool)
    # strict：int 不隐式协变为 float；bool 不接受 int。
    assert isinstance(int_item.value, int) and int_item.value == 123
    with pytest.raises(ValidationError):
        CanonicalArgument.model_validate(
            {"json_pointer": True, "value": 1, "security_relevant": False}
        )


# ---------------------------------------------------------------------------
# builder / 指纹契约
# ---------------------------------------------------------------------------


def test_build_action_ir_is_deterministic() -> None:
    event = _sample_event()
    first = build_action_ir(
        event, server_secret=SECRET, task_id="task_1", task_revision=1
    )
    second = build_action_ir(
        event, server_secret=SECRET, task_id="task_1", task_revision=1
    )
    assert first == second
    assert first.authorization_fingerprint.startswith("hmac-sha256:")
    assert first.audit_fingerprint.startswith("sha256:")
    assert first.schema_version == "2.1"
    assert first.normalizer_version == NORMALIZER_VERSION
    assert first.canonical_arguments.canonicalization_version == (
        CANONICALIZATION_VERSION
    )


def test_argument_digest_is_consistent_between_ir_and_arguments() -> None:
    ir = build_action_ir(_sample_event(), server_secret=SECRET)
    assert ir.argument_digest == ir.canonical_arguments.argument_digest


def test_authorization_fingerprint_excludes_display_and_noise_fields() -> None:
    event = _sample_event()
    ir = build_action_ir(event, server_secret=SECRET)

    # display text 变更不影响授权指纹（resource 投影剔除 display_summary）。
    display_changed = ir.model_copy(
        update={
            "resources": [
                resource.model_copy(update={"display_summary": "OTHER DISPLAY"})
                for resource in ir.resources
            ]
        }
    )
    assert authorization_fingerprint(SECRET, display_changed) == (
        ir.authorization_fingerprint
    )

    # random/noise id 类字段不参与授权指纹（只投影白名单天然排除）。
    noise_changed = ir.model_copy(
        update={
            "event_id": "evt_other",
            "action_id": "act_other",
            "trace_id": "trace_other",
        }
    )
    assert authorization_fingerprint(SECRET, noise_changed) == (
        ir.authorization_fingerprint
    )

    # audit 指纹承担关联职责：event_id 变更必须改变 audit 指纹。
    assert audit_fingerprint(noise_changed) != ir.audit_fingerprint


def test_authorization_fingerprint_reacts_to_identity_changes() -> None:
    event = _sample_event()
    ir = build_action_ir(event, server_secret=SECRET, task_id="task_1")

    task_changed = ir.model_copy(update={"task_id": "task_2"})
    assert authorization_fingerprint(SECRET, task_changed) != (
        ir.authorization_fingerprint
    )

    effect_changed = ir.model_copy(
        update={"effects": ActionEffect(code_execution=True)}
    )
    assert authorization_fingerprint(SECRET, effect_changed) != (
        ir.authorization_fingerprint
    )

    # security query/argument 变更必须改变授权指纹。
    other_argument_ir = build_action_ir(
        _sample_event(arguments={"api_key": "other-value"}),
        server_secret=SECRET,
        task_id="task_1",
    )
    assert other_argument_ir.authorization_fingerprint != ir.authorization_fingerprint


def test_different_secrets_produce_different_authorization_fingerprints() -> None:
    ir = build_action_ir(_sample_event(), server_secret=SECRET)
    assert authorization_fingerprint(b"another-secret", ir) != (
        ir.authorization_fingerprint
    )
    with pytest.raises(ValueError):
        authorization_fingerprint(b"", ir)


# ---------------------------------------------------------------------------
# 指纹白名单 == 实际投影键契约（M5）
# ---------------------------------------------------------------------------


def test_authorization_projection_keys_match_whitelist() -> None:
    ir = build_action_ir(_sample_event(), server_secret=SECRET, task_id="task_1")
    assert set(authorization_projection(ir)) == (
        ActionIR.authorization_fingerprint_fields()
    )


def test_audit_projection_keys_match_whitelist() -> None:
    ir = build_action_ir(_sample_event(), server_secret=SECRET, task_id="task_1")
    assert set(audit_projection(ir)) == ActionIR.audit_fingerprint_fields()


# ---------------------------------------------------------------------------
# Constraint DSL 行为契约（M6）
# ---------------------------------------------------------------------------


def _contract_file_resource() -> FileResource:
    return FileResource(
        resource_id="res_1",
        canonical_id="file:///data/report.md",
        display_summary="/data/report.md",
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        normalized_path="/data/report.md",
        platform="posix",
        case_sensitive=True,
        symlink_resolution="resolved",
        final_path="/data/report.md",
    )


def _url_destination(host_ascii: str) -> UrlResource:
    return UrlResource(
        resource_id="res_1",
        canonical_id=f"https://{host_ascii}/",
        display_summary=f"https://{host_ascii}/",
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        scheme="https",
        host_ascii=host_ascii,
        port=443,
        normalized_path="/",
        query_keys=[],
        security_query_arguments=[],
        redirect_policy="forbid",
    )


def test_matches_action_hit_and_miss() -> None:
    constraint = ActionConstraint(op="in", action_types=["tool_call", "model_call"])
    assert matches_action(constraint, "tool_call") is True
    assert matches_action(constraint, "model_call") is True
    assert matches_action(constraint, "memory_write") is False


def test_matches_resource_exact_prefix_in_and_scheme_mismatch() -> None:
    resources = [_contract_file_resource()]
    exact = ResourceConstraint(
        scheme="file", op="exact", values=["file:///data/report.md"]
    )
    prefix = ResourceConstraint(scheme="file", op="prefix", values=["file:///data/"])
    member = ResourceConstraint(
        scheme="file", op="in", values=["file:///other.md", "file:///data/report.md"]
    )
    assert matches_resource(exact, resources) is True
    assert matches_resource(prefix, resources) is True
    assert matches_resource(member, resources) is True
    # scheme 不匹配：即使 canonical_id 命中也返回 False。
    wrong_scheme = ResourceConstraint(
        scheme="url", op="exact", values=["file:///data/report.md"]
    )
    assert matches_resource(wrong_scheme, resources) is False


def test_matches_destination_domain_op_covers_subdomains_only() -> None:
    constraint = DestinationConstraint(
        scheme="url", op="domain", values=["example.com"]
    )
    assert matches_destination(constraint, [_url_destination("a.example.com")]) is True
    assert matches_destination(constraint, [_url_destination("example.com")]) is True
    # 形似域名不是子域：绝不匹配。
    assert (
        matches_destination(constraint, [_url_destination("evilexample.com")]) is False
    )


def test_unknown_constraint_ops_fail_closed() -> None:
    resources = [_contract_file_resource()]
    destinations = [_url_destination("example.com")]
    unknown_resource_op = ResourceConstraint.model_construct(
        scheme="file", op="regex", values=[".*"]
    )
    assert matches_resource(unknown_resource_op, resources) is False
    unknown_destination_op = DestinationConstraint.model_construct(
        scheme="url", op="regex", values=[".*"]
    )
    assert matches_destination(unknown_destination_op, destinations) is False
    arguments = CanonicalArguments(
        items=[
            CanonicalArgument(
                json_pointer="/token", value="abc", security_relevant=True
            )
        ],
        canonicalization_version=CANONICALIZATION_VERSION,
        argument_digest="sha256:test",
    )
    unknown_argument_op = ArgumentConstraint.model_construct(
        json_pointer="/token", op="regex", value=".*"
    )
    assert matches_argument(unknown_argument_op, arguments) is False


# ---------------------------------------------------------------------------
# security_relevant 可见性与指针排序/golden digest（M7/M8）
# ---------------------------------------------------------------------------


def test_argument_constraint_cannot_see_non_security_relevant_items() -> None:
    # /note 非 security key：值相同、指针相同，但 security_relevant=False 不可见。
    result = normalize_arguments({"note": "secret-value"})
    constraint = ArgumentConstraint(json_pointer="/note", op="eq", value="secret-value")
    assert matches_argument(constraint, result.canonical) is False


def test_json_pointer_items_sorted_with_golden_argument_digest() -> None:
    result = normalize_arguments({"z": 1, "a": 2, "m": 3})
    # 无序输入 → 指针序列固定为码点排序。
    assert [item.json_pointer for item in result.canonical.items] == [
        "/a",
        "/m",
        "/z",
    ]
    # golden 向量：排序回归会静默改变 digest，必须硬断言固定值。
    assert result.canonical.argument_digest == (
        "sha256:75067e7a455ef28907e924d8d42f80c689491050059b18f7b3812850f9267f5a"
    )


def test_argument_eq_requires_exact_type_no_int_float_cross_match() -> None:
    arguments = CanonicalArguments(
        items=[CanonicalArgument(json_pointer="/key", value=1, security_relevant=True)],
        canonicalization_version=CANONICALIZATION_VERSION,
        argument_digest="sha256:test",
    )
    # int 与 float 不互等（无隐式协变）。
    float_constraint = ArgumentConstraint(json_pointer="/key", op="eq", value=1.0)
    assert matches_argument(float_constraint, arguments) is False
    int_constraint = ArgumentConstraint(json_pointer="/key", op="eq", value=1)
    assert matches_argument(int_constraint, arguments) is True


def test_destination_constraint_values_are_casefolded() -> None:
    destinations = [_url_destination("example.com")]
    # host_ascii 恒小写：约束侧大写不得静默不匹配。
    upper_domain = DestinationConstraint(
        scheme="url", op="domain", values=["EXAMPLE.COM"]
    )
    assert matches_destination(upper_domain, destinations) is True
    upper_exact = DestinationConstraint(
        scheme="url", op="exact", values=["EXAMPLE.COM"]
    )
    assert matches_destination(upper_exact, destinations) is True


# ---------------------------------------------------------------------------
# builder：指纹跨事件稳定性、destinations 拆分（M4/C5）
# ---------------------------------------------------------------------------


def _model_input_event(event_id: str) -> GuardEvent:
    return GuardEvent.model_validate(
        {
            "event_type": "model_input_prepared",
            "event_id": event_id,
            "trace_id": "trace_m4",
            "runtime": "openclaw",
            "security_context": {"agent_id": "agent_a", "user_task": "m4"},
            "payload": {
                "phase": "input",
                "content_preview": "hello",
                "provider": "openai",
                "model": "gpt-x",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": True,
            },
        }
    )


def test_authorization_fingerprint_is_stable_across_event_ids() -> None:
    # 除 event_id 外完全相同的非 tool_call 事件：授权指纹必须相等。
    first_ir = build_action_ir(_model_input_event("evt_m4_1"), server_secret=SECRET)
    second_ir = build_action_ir(_model_input_event("evt_m4_2"), server_secret=SECRET)
    assert first_ir.authorization_fingerprint == second_ir.authorization_fingerprint
    # audit 指纹承担关联职责：event_id 变更必须改变 audit 指纹。
    assert first_ir.audit_fingerprint != second_ir.audit_fingerprint


def test_model_input_action_ir_carries_canonical_visible_source_refs() -> None:
    event = _model_input_event("evt_m4_visible_refs")
    event = event.model_copy(
        update={
            "security_context": event.security_context.model_copy(
                update={
                    "visible_source_refs": (
                        "source:user:evt_context:1",
                        "source:runtime:evt_context:0",
                        "source:user:evt_context:1",
                    )
                }
            )
        }
    )

    action_ir = build_action_ir(event, server_secret=SECRET)

    assert action_ir.data_refs[:4] == [
        "event:evt_m4_visible_refs",
        "trace:trace_m4",
        "source:runtime:evt_context:0",
        "source:user:evt_context:1",
    ]


def test_truncated_arguments_keep_full_value_identity_commitment() -> None:
    prefix = "x" * 4096
    first = normalize_arguments({"content": prefix + "a"})
    second = normalize_arguments({"content": prefix + "b"})

    assert first.partial is True
    assert second.partial is True
    assert first.canonical.items[0].value != second.canonical.items[0].value
    assert first.canonical.argument_digest != second.canonical.argument_digest

    first_ir = build_action_ir(
        _sample_event(
            {"path": "/data/report.md", "content": prefix + "a"}, "write_file"
        ),
        server_secret=SECRET,
    )
    second_ir = build_action_ir(
        _sample_event(
            {"path": "/data/report.md", "content": prefix + "b"}, "write_file"
        ),
        server_secret=SECRET,
    )
    assert first_ir.authorization_fingerprint != second_ir.authorization_fingerprint


def test_file_operations_have_distinct_effects_and_authorization_identity() -> None:
    path = {"path": "/data/report.md"}
    write_ir = build_action_ir(_sample_event(path, "write_file"), server_secret=SECRET)
    create_ir = build_action_ir(
        _sample_event(path, "create_file"), server_secret=SECRET
    )
    delete_ir = build_action_ir(
        _sample_event(path, "delete_file"), server_secret=SECRET
    )

    assert write_ir.effects.reversible is None
    assert create_ir.effects.reversible is True
    assert delete_ir.effects.destructive is True
    assert delete_ir.effects.reversible is False
    assert delete_ir.impact == "critical"
    assert (
        len(
            {
                write_ir.authorization_fingerprint,
                create_ir.authorization_fingerprint,
                delete_ir.authorization_fingerprint,
            }
        )
        == 3
    )


def test_payload_derived_resources_are_canonicalized_and_bound() -> None:
    def event(target: str) -> GuardEvent:
        return GuardEvent.model_validate(
            {
                "event_type": "tool_call_proposed",
                "event_id": "evt_derived",
                "trace_id": "trace_derived",
                "runtime": "openclaw",
                "security_context": {
                    "agent_id": "agent_a",
                    "user_task": "browse",
                },
                "payload": {
                    "tool": {
                        "name": "custom_browser",
                        "call_id": "call_derived",
                    },
                    "arguments": {"query": "same"},
                    "derived_resources": [
                        {
                            "resource_type": "browser",
                            "operation": "navigate",
                            "target": target,
                            "direction": "outbound",
                        }
                    ],
                },
            }
        )

    first = build_action_ir(event("https://one.example/path"), server_secret=SECRET)
    second = build_action_ir(event("https://two.example/path"), server_secret=SECRET)

    assert len(first.destinations) == 1
    assert isinstance(first.destinations[0], UrlResource)
    assert first.destinations[0].host_ascii == "one.example"
    assert first.authorization_fingerprint != second.authorization_fingerprint


def test_action_id_preserves_payload_identity() -> None:
    tool_call = GuardEvent.model_validate(
        {
            "event_type": "tool_call_proposed",
            "event_id": "evt_call",
            "trace_id": "trace_action",
            "runtime": "openclaw",
            "payload": {
                "tool": {"name": "read_file", "call_id": "call_action_001"},
                "arguments": {"path": "/data/report.md"},
                "derived_resources": [],
            },
        }
    )
    assert build_action_ir(tool_call, server_secret=SECRET).action_id == (
        "call_action_001"
    )

    tool_result = GuardEvent.model_validate(
        {
            "event_type": "tool_result_produced",
            "event_id": "evt_result",
            "trace_id": "trace_action",
            "runtime": "openclaw",
            "payload": {
                "tool": {"name": "read_file", "call_id": "call_action_001"},
                "result": {
                    "content_preview": "ok",
                    "content_type": "text/plain",
                    "size_bytes": 2,
                },
                "will_enter_context": False,
                "will_persist": False,
                "sanitized": False,
                "contains_sensitive_data": False,
                "contains_instruction_like_text": False,
                "derived_resources": [],
            },
        }
    )
    assert build_action_ir(tool_result, server_secret=SECRET).action_id == (
        "call_action_001"
    )

    memory = GuardEvent.model_validate(
        {
            "event_type": "memory_write_proposed",
            "event_id": "evt_memory",
            "trace_id": "trace_action",
            "runtime": "langgraph",
            "payload": {
                "memory": {
                    "namespace": "main",
                    "key": "answer",
                    "value_preview": "value",
                    "source_trust": "trusted",
                    "operation": "write",
                },
                "will_persist": True,
                "requires_approval": False,
                "action_id": "call_memory_001",
            },
        }
    )
    assert build_action_ir(memory, server_secret=SECRET).action_id == (
        "call_memory_001"
    )

    message = GuardEvent.model_validate(
        {
            "event_type": "message_send_proposed",
            "event_id": "evt_message",
            "trace_id": "trace_action",
            "runtime": "openclaw",
            "payload": {
                "channel": "email",
                "recipient": "reviewer@example.test",
                "content_preview": "weekly status",
                "contains_sensitive_data": False,
                "sanitized": False,
                "derived_resources": [],
            },
        }
    )
    assert build_action_ir(message, server_secret=SECRET).action_id == (
        "act_evt_message"
    )


def _tool_event(tool: str, arguments: dict) -> GuardEvent:
    return GuardEvent.model_validate(
        {
            "event_type": "tool_call_proposed",
            "trace_id": "trace_dest",
            "runtime": "openclaw",
            "security_context": {"agent_id": "agent_a", "user_task": "dest"},
            "payload": {
                "tool": {"name": tool},
                "arguments": arguments,
                "derived_resources": [],
            },
        }
    )


def test_destinations_split_for_api_and_email_tools() -> None:
    api_ir = build_action_ir(
        _tool_event(
            "call_api",
            {"url": "https://api.example.com/v1", "method": "POST"},
        ),
        server_secret=SECRET,
    )
    # url/api/email 归 destinations，不进 resources。
    assert api_ir.resources == []
    assert len(api_ir.destinations) == 1
    api_destination = api_ir.destinations[0]
    assert isinstance(api_destination, ApiResource)
    assert api_destination.host_ascii == "api.example.com"
    assert api_destination.method == "POST"

    email_ir = build_action_ir(
        _tool_event("send_email", {"to": "User@Example.com"}),
        server_secret=SECRET,
    )
    assert email_ir.resources == []
    assert len(email_ir.destinations) == 1
    email_destination = email_ir.destinations[0]
    assert isinstance(email_destination, EmailResource)
    assert email_destination.domain_ascii == "example.com"
