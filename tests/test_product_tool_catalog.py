"""Signed catalog/Core contracts; synthetic activation, zero tool execution.

OpenClaw schemas are the captured B01 pinned SDK/native model-visible inventory.
LangGraph descriptors are explicitly synthetic until the separate B06 host PR.
"""

from __future__ import annotations

from dataclasses import replace
import json
import os

import pytest

from agentguard_core.actions.builder import build_action_ir
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.fingerprints import authorization_projection
from agentguard_core.actions.models import (
    NORMALIZER_VERSION,
    PRODUCT_TOOL_NORMALIZER_VERSION,
    ToolResource,
)
from agentguard_core.actions.normalize import normalize_arguments
from agentguard_core.actions.product_tools import (
    PRODUCT_TOOL_NAMES,
    ProductToolError,
    langgraph_host_inventory_digest,
    product_command_script_digest,
    product_model_visible_tools,
    product_runtime_profile_digest,
    product_tool_resource_identity,
)
from agentguard_core.events import GuardEvent
from guard_api.services.product_tool_catalog import (
    ProductToolCatalogError,
    load_product_tool_catalog,
)
from tests.support.product_activation import (
    product_activation_ack_for_status,
    product_runtime_status_for_activation,
)
from tests.support.product_tool_catalog import catalog_fixture, resign_catalog_document

pytestmark = pytest.mark.contract


@pytest.fixture
def data(tmp_path):
    return catalog_fixture(tmp_path)


def arguments(name, runtime):
    return {
        "read": {"path": "fixture.txt"},
        "write": {"path": "output.txt", "content": "complete private content"},
        "edit": {
            "path": "fixture.txt",
            "edits": [{"oldText": "before", "newText": "after"}],
        },
        "exec": {
            "command": (
                "python marker.py" if runtime == "langgraph" else "node marker.mjs"
            )
        },
        "process": {"action": "list"},
        "agentguard_memory_read": {"key": "test.key"},
        "agentguard_memory_write": {
            "key": "test.key",
            "value": "complete private memory",
        },
        "message": {
            "action": "send",
            "channel": "agentguard-fixture",
            "target": "fixture-inbox",
            "message": "complete private message",
        },
    }[name]


def event_for(data, name="read", runtime="langgraph", args=None):
    args = arguments(name, runtime) if args is None else args
    metadata = {}
    event_type = "tool_call_proposed"
    if name == "agentguard_memory_write":
        event_type = "memory_write_proposed"
        profile = next(
            row for row in data.document["runtimes"] if row["runtime"] == runtime
        )
        payload = {
            "memory": {
                "namespace": profile["execution"]["memory_namespace"],
                "key": args["key"],
                "value_preview": args["value"],
                "source_trust": "unknown",
                "operation": "write",
            },
            "action_id": "call_fixture",
            "will_persist": True,
            "requires_approval": False,
        }
        metadata["product_tool_call"] = {"tool_name": name, "call_id": "call_fixture"}
    elif name == "message":
        event_type = "message_send_proposed"
        payload = {
            "channel": args["channel"],
            "recipient": args["target"],
            "content_preview": args["message"],
        }
        metadata["product_tool_call"] = {"tool_name": name, "call_id": "call_fixture"}
    else:
        payload = {
            "tool": {
                "name": name,
                "call_id": "call_fixture",
                "category": "untrusted-claim",
                "kind": "read_file",
            },
            "arguments": args,
            "derived_resources": [
                {
                    "resource_type": "file",
                    "operation": "delete",
                    "target": "/invented/target",
                    "direction": "outbound",
                }
            ],
        }
    return GuardEvent.model_validate(
        {
            "event_id": "evt_fixture",
            "event_type": event_type,
            "runtime": runtime,
            "trace_id": "trace_fixture",
            "pre_execution": True,
            "security_context": {
                "agent_id": "main",
                "user_task": "synthetic contract action",
                "source_type": "model",
                "source_trust": "unknown",
            },
            "payload": payload,
            "metadata": metadata,
        }
    )


def resolve(data, event):
    return load_product_tool_catalog(str(data.path), activation=data.bundle).resolve(
        event, activation=data.bundle
    )


def action(data, event, tool=None):
    return build_action_ir(
        event,
        server_secret=data.fixture.server_secret,
        task_id="task",
        task_revision=1,
        scope_digest=canonical_sha256("scope"),
        principal_id=data.bundle.runtime_entry(event.runtime).principal_id,
        runtime_binding_id=data.bundle.runtime_entry(event.runtime).runtime_binding_id,
        product_tool=tool,
    )


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
@pytest.mark.parametrize("name", PRODUCT_TOOL_NAMES)
def test_real_names_complete_arguments_and_signed_semantics(data, runtime, name):
    event = event_for(data, name, runtime)
    tool = resolve(data, event)
    assert tool is not None
    ir = action(data, event, tool)
    assert tool.arguments() == arguments(name, runtime)
    assert (
        tool.argument_digest
        == normalize_arguments(tool.arguments()).canonical.argument_digest
        == ir.argument_digest
    )
    assert tool.original_arguments_digest == canonical_sha256(tool.arguments())
    assert ir.normalizer_version == PRODUCT_TOOL_NORMALIZER_VERSION
    assert ir.tool_name == name
    assert event.security_context.source_type == "model"
    assert event.security_context.source_trust == "unknown"
    resource = next(item for item in ir.resources if isinstance(item, ToolResource))
    assert resource.canonical_id == product_tool_resource_identity(
        name, tool.descriptor_digest, tool.semantics_digest
    )
    assert resource.tool_schema_digest == tool.input_schema_digest
    assert resource.provider_binding_id == tool.runtime_binding_id
    assert not any("invented" in item.canonical_id for item in ir.resources)
    if name in {"read", "process", "agentguard_memory_read"}:
        assert not any(value is True for value in ir.effects.model_dump().values())
    if name in {"write", "edit", "agentguard_memory_write", "exec"}:
        assert ir.effects.mutates_state and ir.effects.persistence
        assert ir.effects.reversible is None
    if name == "exec":
        assert ir.effects.code_execution
        assert any("command-marker.txt" in item.canonical_id for item in ir.resources)
    if name == "message":
        assert (
            ir.effects.data_egress
            and ir.effects.external_communication
            and ir.effects.network_access
        )
        assert any("127.0.0.1" in item.canonical_id for item in ir.destinations)


def test_actual_openclaw_edit_and_process_schema_capture(data):
    inventory = data.document["runtimes"][1]["inventory"]
    edit = inventory["input_schemas"]["edit"]
    assert edit["required"] == ["path", "edits"]
    assert edit["properties"]["edits"]["items"]["required"] == ["oldText", "newText"]
    assert (
        "kill"
        in inventory["input_schemas"]["process"]["properties"]["action"]["description"]
    )
    assert inventory["plugin_order"] == [
        "openclaw-core",
        "agentguard-product-runtime-fixture",
    ]


@pytest.mark.parametrize(
    "name,field",
    [
        ("write", "content"),
        ("agentguard_memory_write", "value"),
        ("message", "message"),
    ],
)
def test_complete_data_changes_authorization_even_past_old_preview(data, name, field):
    args = arguments(name, "langgraph")
    args[field] = "x" * 6000 + "A"
    first = event_for(data, name, args=args)
    one = action(data, first, resolve(data, first))
    args[field] = "x" * 6000 + "B"
    second = event_for(data, name, args=args)
    two = action(data, second, resolve(data, second))
    assert one.argument_digest != two.argument_digest
    assert one.authorization_fingerprint != two.authorization_fingerprint


def test_snapshots_do_not_expose_private_content_or_accept_mutated_event(data):
    event = event_for(data, "write")
    tool = resolve(data, event)
    assert tool is not None
    assert "complete private content" not in repr(tool)
    changed = tool.arguments()
    changed["content"] = "mutation"
    assert tool.arguments()["content"] == "complete private content"
    event.payload.arguments["content"] = "mutation"
    with pytest.raises(ProductToolError, match="product_tool_binding_mismatch"):
        action(data, event, tool)


@pytest.mark.parametrize(
    "change",
    [
        {"_effects_json": "{}"},
        {"_resources_json": "[]"},
        {"_arguments_json": '{"path":"output.txt","content":"changed"}'},
        {"descriptor_digest": canonical_sha256("other descriptor")},
        {"input_schema_digest": canonical_sha256("other schema")},
        {"inventory_digest": canonical_sha256("other inventory")},
        {"semantics_digest": canonical_sha256("other semantics")},
        {"argument_digest": canonical_sha256("other arguments")},
        {"original_arguments_digest": canonical_sha256("other original arguments")},
        {"event_id": "evt_other"},
        {"event_type": "message_send_proposed"},
        {"call_id": "call_other"},
        {"tool_name": "read"},
        {"_issuance_authenticator": ""},
    ],
)
def test_copied_tool_cannot_keep_issuance_while_changing_semantics(data, change):
    event = event_for(data, "write")
    tool = resolve(data, event)
    assert tool is not None
    copied = replace(tool, **change)
    with pytest.raises(ProductToolError, match="product_tool_binding_mismatch"):
        action(data, event, copied)
    assert action(data, event, tool).effects.mutates_state
    assert tool._issuance_authenticator not in repr(tool)


def test_repeated_binding_of_same_event_is_equal_and_valid(data):
    event = event_for(data, "write")
    first, second = resolve(data, event), resolve(data, event)
    assert first is not second and first == second
    assert action(data, event, first) == action(data, event, second)
    other = event.model_copy(update={"event_id": "evt_other"})
    copied = replace(
        first,
        _event_digest=canonical_sha256(other.model_dump(mode="json")),
        event_id=other.event_id,
    )
    with pytest.raises(ProductToolError, match="product_tool_binding_mismatch"):
        action(data, other, copied)


def test_legacy_fingerprint_projection_and_claimed_descriptor_do_not_activate(data):
    event = event_for(data)
    event.metadata["descriptor_digest"] = canonical_sha256("claim")
    event.metadata["product_tool"] = {"read_only": True}
    ir = action(data, event)
    assert ir.normalizer_version == NORMALIZER_VERSION
    projection = authorization_projection(ir)
    assert "normalizer_version" not in projection and "tool_name" not in projection
    assert ir.effects.mutates_state  # Existing conservative path stays unchanged.


@pytest.mark.parametrize(
    "name,args",
    [
        ("read", {"path": "../escape.txt"}),
        ("read", {"path": "/tmp/escape.txt"}),
        ("read", {"path": "fixture.txt", "offset": 1}),
        ("read", {"path": 1}),
        ("write", {"path": "output.txt", "content": False}),
        ("process", {"action": "kill"}),
        ("process", {"action": "list", "sessionId": "other"}),
        ("exec", {"command": "python marker.py; echo unsafe"}),
        ("exec", {"command": "python marker.py", "env": {"X": "Y"}}),
        ("edit", {"path": "fixture.txt", "oldText": "old", "newText": "new"}),
        ("edit", {"path": "fixture.txt", "edits": []}),
        ("edit", {"path": "fixture.txt", "edits": [{"oldText": "", "newText": "new"}]}),
        ("agentguard_memory_read", {"key": "bad/key"}),
    ],
)
@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_actual_schema_and_isolated_argument_allowlist_both_required(
    data, name, args, runtime
):
    with pytest.raises(
        ProductToolCatalogError, match="product_tool_catalog_action_invalid"
    ):
        resolve(data, event_for(data, name, runtime, args))


@pytest.mark.parametrize(
    "mutation", ["namespace", "identity", "call_id", "destination", "pre_execution"]
)
def test_special_events_need_real_identity_and_signed_destination(data, mutation):
    event = event_for(
        data, "message" if mutation == "destination" else "agentguard_memory_write"
    )
    if mutation == "namespace":
        event.payload.memory.namespace = "/other/memory.sqlite"
    elif mutation == "identity":
        event.metadata.clear()
    elif mutation == "call_id":
        event.metadata["product_tool_call"]["call_id"] = "other"
    elif mutation == "destination":
        event.payload.recipient = "external-recipient"
    else:
        event.pre_execution = False
    with pytest.raises(
        ProductToolCatalogError, match="product_tool_catalog_action_invalid"
    ):
        resolve(data, event)


@pytest.mark.parametrize(
    "field", ["root", "inbox_url", "script_digest", "memory_namespace"]
)
def test_execution_profile_drift_is_not_just_an_inventory_claim(data, field):
    row = data.document["runtimes"][0]
    row["execution"][field] += "drift"
    data.path.write_text(json.dumps(data.document))
    with pytest.raises(ProductToolCatalogError):
        load_product_tool_catalog(str(data.path), activation=data.bundle)


@pytest.mark.parametrize(
    "field",
    [
        "principal_id",
        "adapter_artifact_digest",
        "profile_digest",
        "capability_report_digest",
    ],
)
def test_frozen_activation_rejects_identity_drift_even_without_ack_fields(data, field):
    catalog = load_product_tool_catalog(str(data.path), activation=data.bundle)
    rows = list(data.bundle.runtimes)
    rows[0] = rows[0].model_copy(update={field: canonical_sha256("drift")})
    modified = data.bundle.model_copy(update={"runtimes": rows})
    with pytest.raises(ProductToolCatalogError, match="product_tool_catalog_drift"):
        catalog.verify_current(modified)


@pytest.mark.parametrize(
    "field",
    [
        "agent_id",
        "runtime_binding_id",
        "activation_ref_digest",
        "capability_digest",
        "host_inventory_digest",
        "tool_inventory_digest",
    ],
)
def test_ack_must_match_original_signed_runtime_identity(data, field):
    fixture = replace(data.fixture, bundle=data.bundle)
    ack = product_activation_ack_for_status(
        fixture, product_runtime_status_for_activation(fixture, "langgraph")
    )
    catalog = load_product_tool_catalog(str(data.path), activation=data.bundle)
    catalog.verify_current(data.bundle, ack)
    changed = ack.model_copy(update={field: canonical_sha256("drift")})
    with pytest.raises(ProductToolCatalogError, match="product_tool_catalog_drift"):
        catalog.verify_current(data.bundle, changed)


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "schema",
        "order",
        "missing",
        "duplicate",
        "host",
        "semantic",
        "unknown_keyword",
        "external_ref",
    ],
)
def test_even_signed_inventory_requires_known_sources_schema_and_order(data, mutation):
    inventory = data.document["runtimes"][0]["inventory"]
    tool = inventory["tools"][0]
    if mutation == "source":
        tool["source_id"] = "unregistered-plugin"
    elif mutation == "schema":
        tool["input_schema"]["properties"]["key"]["type"] = "integer"
    elif mutation == "order":
        inventory["tools"].reverse()
    elif mutation == "missing":
        inventory["tools"].pop()
    elif mutation == "duplicate":
        inventory["tools"][1] = tool
    elif mutation == "host":
        inventory["model_visible_tools"].reverse()
    elif mutation == "semantic":
        tool["operation"] = "delete"
    elif mutation == "unknown_keyword":
        tool["execution_schema"]["unevaluatedProperties"] = False
    elif mutation == "external_ref":
        tool["execution_schema"]["$ref"] = "https://invalid/schema.json"
    if mutation != "host":
        inventory["model_visible_tools"] = product_model_visible_tools(
            inventory["tools"]
        )
    resign_catalog_document(data)
    with pytest.raises(ProductToolCatalogError, match="product_tool_catalog_invalid"):
        load_product_tool_catalog(str(data.path), activation=data.bundle)


@pytest.mark.parametrize("mode", [0o644, 0o400, 0o666])
def test_private_catalog_file_permissions(data, mode):
    data.path.chmod(mode)
    with pytest.raises(
        ProductToolCatalogError, match="product_tool_catalog_unreadable"
    ):
        load_product_tool_catalog(str(data.path), activation=data.bundle)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "parent"])
def test_private_owned_regular_file_and_nofollow_path(data, kind):
    if kind == "parent":
        data.path.parent.chmod(0o755)
    else:
        saved = data.path.with_name("original.json")
        data.path.rename(saved)
        if kind == "symlink":
            data.path.symlink_to(saved)
        elif kind == "hardlink":
            os.link(saved, data.path)
        elif kind == "fifo":
            os.mkfifo(data.path, 0o600)
        else:
            data.path.mkdir(mode=0o700)
    with pytest.raises(
        ProductToolCatalogError, match="product_tool_catalog_unreadable"
    ):
        load_product_tool_catalog(str(data.path), activation=data.bundle)


def test_observations_still_recheck_catalog_and_atomic_replacement(data):
    catalog = load_product_tool_catalog(str(data.path), activation=data.bundle)
    event = GuardEvent.model_validate(
        {
            "event_type": "model_output_produced",
            "runtime": "langgraph",
            "trace_id": "trace",
            "pre_execution": False,
            "payload": {
                "phase": "output",
                "content_preview": "safe",
                "contains_instruction_like_text": False,
                "contains_sensitive_data": False,
                "sanitized": False,
            },
        }
    )
    assert catalog.resolve(event, activation=data.bundle) is None
    replacement = data.path.with_name("replacement.json")
    replacement.write_bytes(data.path.read_bytes())
    replacement.chmod(0o600)
    replacement.replace(data.path)
    with pytest.raises(ProductToolCatalogError, match="product_tool_catalog_drift"):
        catalog.resolve(event, activation=data.bundle)


def test_signed_profile_commits_model_visible_order_and_actual_script(data):
    row = data.document["runtimes"][0]
    entry = data.bundle.runtime_entry("langgraph").model_dump(mode="json")
    assert (
        product_runtime_profile_digest(entry, row["execution"])
        == entry["profile_digest"]
    )
    tools = row["inventory"]["model_visible_tools"]
    assert langgraph_host_inventory_digest(tools) != langgraph_host_inventory_digest(
        list(reversed(tools))
    )
    assert (
        product_command_script_digest("langgraph")
        == "sha256:fab7ee02a5f5501c14b58f1c0a90b976c0be00248f4cc60f676f420948f61271"
    )
    assert product_command_script_digest("langgraph") != product_command_script_digest(
        "openclaw"
    )


@pytest.mark.parametrize("event_type", ["tool_call_proposed", "memory_write_proposed"])
def test_signed_openclaw_message_cannot_use_another_event_category(data, event_type):
    inventory = data.document["runtimes"][1]["inventory"]
    message = next(tool for tool in inventory["tools"] if tool["tool_id"] == "message")
    assert message["event_type"] == "message_send_proposed"
    message["event_type"] = event_type
    resign_catalog_document(data)
    with pytest.raises(ProductToolCatalogError, match="product_tool_catalog_invalid"):
        load_product_tool_catalog(str(data.path), activation=data.bundle)
