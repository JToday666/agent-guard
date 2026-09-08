"""Signed synthetic activation for catalog contracts; never candidate evidence."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from agentguard_core import (
    build_product_activation_bundle,
    build_residual_risk_acceptance,
    build_rollout_admission_record,
    RuntimeActivationEntryV1,
)
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.product_tools import (
    PRODUCT_TOOL_NAMES,
    PRODUCT_TOOL_SEMANTICS_VERSION,
    langgraph_host_inventory_digest,
    product_command_script_digest,
    product_model_visible_tools,
    product_runtime_profile_digest,
)
from agentguard_core.decisions.product import (
    OpenClawFrozenToolV1,
    build_openclaw_inventory_digests,
)
from tests.support.product_activation import build_test_product_activation

_SEMANTICS = {
    "agentguard_memory_read": ("memory", "memory_read", "read"),
    "agentguard_memory_write": ("memory", "memory_write", "write"),
    "edit": ("file", "file_edit", "write"),
    "exec": ("code", "command_exec", "execute"),
    "message": ("message", "local_message_send", "send"),
    "process": ("code", "process_list", "read"),
    "read": ("file", "file_read", "read"),
    "write": ("file", "file_write", "write"),
}


def catalog_fixture(tmp_path: Path):
    fixture = build_test_product_activation()
    captured = json.loads(
        (
            Path(__file__).parents[1]
            / "fixtures/product_tools/openclaw-2026.7.1-2-inventory.json"
        ).read_text()
    )
    rows, runtime_entries = [], []
    source = "agentguard-langgraph-adapter:isolated-product-tools-v1"
    for runtime in ("langgraph", "openclaw"):
        root = str(tmp_path / runtime)
        execution = {
            "root": root,
            "memory_namespace": root + "/memory.sqlite",
            "inbox_url": "http://127.0.0.1:18431/inbox",
            "script_digest": product_command_script_digest(runtime),
        }
        entry = fixture.bundle.runtime_entry(runtime).model_dump(mode="json")
        if runtime == "openclaw":
            inventory = {
                key: captured[key] for key in ("tools", "input_schemas", "plugin_order")
            }
            entry.update(
                {
                    key: value
                    for key, value in captured["digests"].items()
                    if key != "schema_version"
                }
            )
        else:
            # Explicit synthetic LangGraph descriptors test the independent
            # server format. B06 separately compares actual StructuredTools.
            tools = []
            binding = canonical_sha256(
                {
                    "root": root,
                    "inbox_url": execution["inbox_url"],
                    "script_digest": execution["script_digest"],
                    "source_id": source,
                }
            )
            for name in PRODUCT_TOOL_NAMES:
                schema = json.loads(json.dumps(captured["input_schemas"][name]))
                if name == "exec":
                    schema = {
                        "type": "object",
                        "required": ["command"],
                        "properties": {
                            "command": {"type": "string", "const": "python marker.py"}
                        },
                        "additionalProperties": False,
                    }
                tools.append(
                    {
                        "tool_id": name,
                        "source_id": source,
                        "description": "Synthetic catalog contract tool.",
                        "input_schema": schema,
                        "execution_schema": json.loads(json.dumps(schema)),
                        "event_type": {
                            "message": "message_send_proposed",
                            "agentguard_memory_write": "memory_write_proposed",
                        }.get(name, "tool_call_proposed"),
                        "category": "synthetic",
                        "kind": "synthetic",
                        "operation": "synthetic",
                        "execution_binding_digest": binding,
                        "fixture_id": f"langgraph:{name}:isolated-v1",
                    }
                )
                tools[-1].update(
                    zip(
                        ("category", "kind", "operation"), _SEMANTICS[name], strict=True
                    )
                )
            inventory = {
                "tools": tools,
                "model_visible_tools": product_model_visible_tools(tools),
            }
            entry["tool_inventory_digest"] = canonical_sha256(tools)
            entry["host_inventory_digest"] = langgraph_host_inventory_digest(
                inventory["model_visible_tools"]
            )
        entry["profile_digest"] = product_runtime_profile_digest(entry, execution)
        runtime_entries.append(entry)
        rows.append(
            {"runtime": runtime, "execution": execution, "inventory": inventory}
        )
    oc = runtime_entries[1]
    risk_values = fixture.bundle.residual_risk_acceptance.digest_projection()
    for key in (
        "profile_digest",
        "host_inventory_digest",
        "plugin_inventory_digest",
        "plugin_order_inventory_digest",
        "tool_inventory_digest",
    ):
        risk_values[key] = oc[key]
    risk = build_residual_risk_acceptance(
        server_secret=fixture.server_secret, **risk_values
    )
    oc["residual_risk_acceptance_digest"] = risk.acceptance_ref_digest
    admission_values = fixture.bundle.rollout_admission_record.digest_projection()
    admission_values["tool_inventory_digest"] = oc["tool_inventory_digest"]
    admission = build_rollout_admission_record(
        server_secret=fixture.server_secret, **admission_values
    )
    values = fixture.bundle.digest_projection()
    values.update(
        runtimes=[
            RuntimeActivationEntryV1.model_validate(entry) for entry in runtime_entries
        ],
        rollout_admission_record=admission,
        residual_risk_acceptance=risk,
        rollout_admission_digest=admission.admission_ref_digest,
    )
    bundle = build_product_activation_bundle(
        server_secret=fixture.server_secret, **values
    )
    document = {
        "schema_version": "1.0",
        "semantics_version": PRODUCT_TOOL_SEMANTICS_VERSION,
        "runtimes": rows,
    }
    directory = tmp_path / "catalog"
    directory.mkdir(mode=0o700)
    path = directory / "tools.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    return SimpleNamespace(path=path, bundle=bundle, document=document, fixture=fixture)


def resign_catalog_document(data):
    """Sign deliberately mutated contract fixtures; never real admission."""
    entries = []
    for row in data.document["runtimes"]:
        entry = data.bundle.runtime_entry(row["runtime"]).model_dump(mode="json")
        inventory = row["inventory"]
        if row["runtime"] == "langgraph":
            entry["tool_inventory_digest"] = canonical_sha256(inventory["tools"])
            entry["host_inventory_digest"] = langgraph_host_inventory_digest(
                inventory["model_visible_tools"]
            )
        else:
            entry.update(
                build_openclaw_inventory_digests(
                    tools=[
                        OpenClawFrozenToolV1.model_validate(tool)
                        for tool in inventory["tools"]
                    ],
                    plugin_order=inventory["plugin_order"],
                ).model_dump(exclude={"schema_version"})
            )
        entry["profile_digest"] = product_runtime_profile_digest(
            entry, row["execution"]
        )
        entries.append(entry)
    risk_values = data.bundle.residual_risk_acceptance.digest_projection()
    for key in (
        "profile_digest",
        "host_inventory_digest",
        "plugin_inventory_digest",
        "plugin_order_inventory_digest",
        "tool_inventory_digest",
    ):
        risk_values[key] = entries[1][key]
    risk = build_residual_risk_acceptance(
        server_secret=data.fixture.server_secret, **risk_values
    )
    entries[1]["residual_risk_acceptance_digest"] = risk.acceptance_ref_digest
    admission_values = data.bundle.rollout_admission_record.digest_projection()
    admission_values["tool_inventory_digest"] = entries[1]["tool_inventory_digest"]
    admission = build_rollout_admission_record(
        server_secret=data.fixture.server_secret, **admission_values
    )
    values = data.bundle.digest_projection()
    values.update(
        runtimes=[RuntimeActivationEntryV1.model_validate(entry) for entry in entries],
        rollout_admission_record=admission,
        residual_risk_acceptance=risk,
        rollout_admission_digest=admission.admission_ref_digest,
    )
    data.bundle = build_product_activation_bundle(
        server_secret=data.fixture.server_secret, **values
    )
    data.path.write_text(json.dumps(data.document))
    return data.bundle
