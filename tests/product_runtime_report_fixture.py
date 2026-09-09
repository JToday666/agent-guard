"""Complete synthetic unit documents, never real Host or qualification evidence.

The temporary Git SHA, archive formats, retained file trees and Core replay are
real test operations. All observation records describe controlled unit fixtures.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.product_tools import PRODUCT_TOOL_SEMANTICS_VERSION
from agentguard_core.actions.product_tools import product_tool_arguments
from agentguard_core.decisions.product import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    PRODUCT_EVENT_TYPES,
)
from scripts.product_runtime.conformance import (
    PINS,
    derive_activation_target,
    policy_templates,
)
from scripts.product_runtime.candidate import verify_candidate
from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.requirements import (
    POLICY_GROUPS,
    RUNTIMES,
    requirements_digest,
    requirements_document,
    requirements_for,
    REQUIREMENTS_VERSION,
)
from scripts.product_runtime.signing import CONTRACT_FILES
from tests.support.product_activation import (
    build_test_product_activation,
    build_test_runtime_capability,
    product_activation_ack_for_status,
    product_runtime_status_for_activation,
)
from tests.support.product_tool_catalog import catalog_fixture
from tests.test_product_runtime_candidate import (
    unit_candidate,
    _absolute,
    _json,
    _ref,
    _refresh,
)

LG_CONSUMERS = (
    "native_tools.py",
    "native_langgraph.py",
    "activation_ack.py",
    "activation_session.py",
    "core_client.py",
    "product_outbox.py",
    "product_envelope_store.py",
    "product_action_barrier.py",
    "execution_template.py",
    "native_events.py",
    "model_boundary.py",
    "product_composition.py",
    "strong_binding.py",
)
OC_CONSUMERS = (
    "product-runtime/factory.mjs",
    "product-runtime/baseline-profile.mjs",
    "dist/runtime/activation-ack.js",
    "dist/runtime/activation-session.js",
    "dist/runtime/product-receipt-outbox.js",
    "dist/runtime/product-envelope-store.js",
    "dist/runtime/product-action-runtime.js",
    "dist/runtime/product-content-runtime.js",
    "dist/runtime/product-composition.js",
)
HOOKS = [
    "before_tool_call",
    "after_tool_call",
    "tool_result_persist",
    "message_sending",
    "llm_input",
    "llm_output",
    "agent_end",
]


def _document(root: Path, name: str, value: Any) -> dict:
    return _ref(root, _json(root / name, value))


def _consumer(fixture: SimpleNamespace, runtime: str, case_id: str) -> tuple[str, dict]:
    if case_id.startswith("baseline."):
        module = (
            "native_langgraph.py"
            if runtime == "langgraph"
            else "product-runtime/factory.mjs"
        )
    elif case_id.startswith("contract.ack."):
        module = (
            "activation_ack.py"
            if runtime == "langgraph"
            else "dist/runtime/activation-ack.js"
        )
    elif case_id.startswith("contract.receipt.") or case_id.endswith(
        "unknown_no_reexecution"
    ):
        module = (
            "product_outbox.py"
            if runtime == "langgraph"
            else "dist/runtime/product-receipt-outbox.js"
        )
    elif case_id.startswith("contract.event."):
        module = (
            "native_langgraph.py"
            if runtime == "langgraph"
            else "dist/runtime/product-content-runtime.js"
        )
    elif case_id.startswith(
        ("contract.policy.", "contract.approval.", "contract.binding.")
    ) or case_id.endswith("duplicate_action"):
        module = (
            "execution_template.py"
            if runtime == "langgraph"
            else "dist/runtime/product-action-runtime.js"
        )
    else:
        module = (
            "product_composition.py"
            if runtime == "langgraph"
            else "dist/runtime/product-composition.js"
        )
    if runtime == "langgraph":
        package = next(
            p
            for p in fixture.python["packages"]
            if p["distribution"] == "agentguard-langgraph-adapter"
        )
        root = Path(package["module_file"]).parent
        path = root / module
        module = "agentguard_langgraph_adapter/" + module
    else:
        lane = next(row for row in fixture.node["lanes"] if row["lane"] == "product")
        path = Path(lane["plugin_root"]) / module
    return module, _ref(fixture.root, path)


def _observation(fixture, runtime, requirement, candidate_digest, adapter_digest):
    module, file = _consumer(fixture, runtime, requirement.id)
    baseline = requirement.id.startswith("baseline.")
    return {
        "schema_version": "agentguard-product-case-observation/1",
        "runtime": runtime,
        "source_revision": fixture.revision,
        "candidate_manifest_digest": candidate_digest,
        "adapter_artifact_digest": adapter_digest,
        "case_id": requirement.id,
        "scope_id": f"unit:{runtime}:{requirement.id}",
        "process_id": 101,
        "consumer_module": module,
        "consumer_file": file,
        "entrypoint": (
            "StateGraph.ToolNode" if runtime == "langgraph" else "openclaw.agentCommand"
        )
        if baseline
        else "unit_fixture.contract_replay",
        "authority_kind": "none" if baseline else "synthetic_contract_fixture",
    }


def build_report_fixture(tmp_path: Path) -> SimpleNamespace:
    """Assemble actual schemas and files around explicitly synthetic observations."""
    from tests.product_runtime_case_fixture import build_case_fixture
    from tests.test_product_runtime_policy_evidence import make_policy_replay

    repository = Path(__file__).parents[1]
    contracts = {name: (repository / name).read_bytes() for name in CONTRACT_FILES}
    extra_python = {
        "agentguard-langgraph-adapter": {
            "agentguard_langgraph_adapter/"
            + name: b"# Synthetic unit consumer; no real Host execution claim.\n"
            for name in LG_CONSUMERS
        },
        "aegis-agentguard-core": {
            "agentguard_core/actions/product_tools.py": contracts[
                "packages/agentguard-core/agentguard_core/actions/product_tools.py"
            ]
        },
    }
    fixture = unit_candidate.__wrapped__(
        tmp_path,
        extra_sources=contracts,
        extra_python=extra_python,
        extra_node={
            name: b"// Synthetic unit consumer; no real Host execution claim.\n"
            for name in OC_CONSUMERS
        },
    )
    root = fixture.root
    catalog_root = root / "unit-catalog-materials"
    catalog_root.mkdir(mode=0o700)
    catalog = catalog_fixture(catalog_root).document
    capabilities = {
        runtime: build_test_runtime_capability(runtime, active=False).model_dump(
            mode="json"
        )
        for runtime in RUNTIMES
    }
    for lane in fixture.node["lanes"]:
        if lane["lane"] == "product":
            lane["product_inspection"].update(
                inventory=deepcopy(catalog["runtimes"][1]["inventory"]),
                capabilityConsumers=[
                    {
                        key: event[key]
                        for key in ("event_type", "enforcement", "residual_boundaries")
                    }
                    for event in capabilities["openclaw"]["events"]
                ],
                residualBoundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
            )
            worker_path = Path(lane["evidence_file"]["path"])
            _json(
                worker_path,
                {
                    key: value
                    for key, value in lane.items()
                    if key not in {"lane", "evidence_file"}
                },
            )
            lane["evidence_file"] = _absolute(worker_path)
    _refresh(fixture)
    verified_candidate = verify_candidate(
        _ref(root, fixture.manifest_path),
        EvidenceStore(root),
        fixture.checkout,
        fixture.revision,
    )
    digest = verified_candidate.canonical_digest
    catalog_ref = _document(root, "materials/tool-catalog.json", catalog)
    installation_ref = _ref(root, fixture.installation_path)
    templates = policy_templates()
    policies = {
        group: PolicyBundle.model_validate(value) for group, value in templates.items()
    }
    policy_refs = [
        {
            "id": group,
            "policy_bundle": _document(
                root, f"materials/policy-{group}.json", templates[group]
            ),
        }
        for group in POLICY_GROUPS
    ]
    report_policies = [
        {"id": group, "policy_digest": canonical_sha256(templates[group])}
        for group in POLICY_GROUPS
    ]
    reports, report_paths, observations, matrix_rows = {}, {}, {}, []
    activation_fixture = build_test_product_activation()
    for runtime in RUNTIMES:
        row = next(item for item in catalog["runtimes"] if item["runtime"] == runtime)
        inventory = row["inventory"]
        observed = capabilities[runtime]
        artifact = next(
            item
            for item in fixture.manifest["artifacts"]
            if item["distribution"]
            == (
                "agentguard-langgraph-adapter"
                if runtime == "langgraph"
                else "@agentguard-ai/openclaw-plugin"
            )
            and item["kind"] == ("wheel" if runtime == "langgraph" else "npm_tgz")
        )
        adapter_digest = artifact["file"]["raw_sha256"]
        product_ref = _document(
            root, f"materials/{runtime}/product-inventory.json", inventory
        )
        baseline = deepcopy(inventory)
        visible = (
            baseline["model_visible_tools"]
            if runtime == "langgraph"
            else [
                {
                    "name": tool["tool_id"],
                    "parameters": baseline["input_schemas"][tool["tool_id"]],
                }
                for tool in baseline["tools"]
            ]
        )
        collection = {
            "runtime": runtime,
            "authority_kind": "none",
            "factory_inventory": baseline,
            "model_visible_tools": visible,
            "catalog_rpc_is_authority": False,
        }
        collection_ref = _document(
            root, f"materials/{runtime}/baseline-collection.json", collection
        )
        baseline_document = {
            "schema_version": "agentguard-native-baseline-inventory/1",
            "runtime": runtime,
            "mapping_version": "agentguard-native-baseline-to-product/1",
            "inventory": baseline,
            "model_visible_tools": visible,
            "logical_recipient": "fixture-inbox@agentguard.invalid"
            if runtime == "langgraph"
            else "fixture-inbox",
            "collection_evidence": collection_ref,
        }
        baseline_ref = _document(
            root, f"materials/{runtime}/baseline-inventory.json", baseline_document
        )
        consumers = []
        for event in observed["events"]:
            module, file = _consumer(
                fixture, runtime, "contract.event." + event["event_type"]
            )
            consumers.append(
                {
                    key: event[key]
                    for key in ("event_type", "enforcement", "residual_boundaries")
                }
                | {
                    "consumer_module": module,
                    "consumer_file": file,
                    "entrypoint": "unit_fixture.registration",
                    "scope_id": f"unit:{runtime}:registration",
                    "process_id": 100,
                }
            )
        hooks = [] if runtime == "langgraph" else HOOKS
        registration = {
            "schema_version": "agentguard-product-consumer-registration/1",
            "source_revision": fixture.revision,
            "runtime": runtime,
            "product_active_enabled": False,
            "registered_event_types": list(PRODUCT_EVENT_TYPES),
            "capability_report_digest": observed["report_digest"],
            "inventory": inventory,
            "consumers": consumers,
            "hook_execution_order": hooks,
        }
        registration_ref = _document(
            root, f"materials/{runtime}/registration.json", registration
        )
        observed_ref = _document(
            root,
            f"materials/{runtime}/observed-capability.json",
            {
                "kind": "observed_inactive_product_composition",
                "report": observed,
                "registration_evidence": registration_ref,
            },
        )
        target_ref = _document(
            root,
            f"materials/{runtime}/activation-target.json",
            {
                "kind": "derived_activation_target",
                "observed_report_digest": observed["report_digest"],
                "report": derive_activation_target(observed).model_dump(mode="json"),
            },
        )
        hook_ref = _document(
            root,
            f"materials/{runtime}/hook-order.json",
            {
                "schema_version": "agentguard-product-hook-order/1",
                "runtime": runtime,
                "tool_source_order": [
                    "agentguard-langgraph-adapter:isolated-product-tools-v1"
                ]
                if runtime == "langgraph"
                else inventory["plugin_order"],
                "hook_execution_order": hooks,
                "consumer_registration_order": list(PRODUCT_EVENT_TYPES),
                "registration_evidence": registration_ref,
            },
        )
        materials = {
            "installation": installation_ref,
            "baseline_inventory": baseline_ref,
            "product_inventory": product_ref,
            "observed_capability": observed_ref,
            "activation_target_capability": target_ref,
            "hook_order": hook_ref,
            "tool_catalog": catalog_ref,
        }
        baseline_material = {
            "product_active_enabled": False,
            "authority_kind": "none",
            "runtime_version": PINS[runtime][0],
            "adapter_artifact_digest": adapter_digest,
            "inventory_digest": canonical_sha256(baseline_document),
            "installation_digest": canonical_sha256(fixture.aggregate),
        }
        ack = product_activation_ack_for_status(
            activation_fixture,
            product_runtime_status_for_activation(activation_fixture, runtime),
        ).model_dump(mode="json")
        cases = []
        for requirement in requirements_for(runtime):
            observation = _observation(
                fixture, runtime, requirement, digest, adapter_digest
            )
            if requirement.validator == "policy_chain":
                replay = make_policy_replay(
                    root / "unit-policy-evidence" / runtime / requirement.id,
                    runtime=runtime,
                    group=requirement.policy_group,
                    category=requirement.subject,
                    candidate_manifest_digest=digest,
                    adapter_artifact_digest=adapter_digest,
                    scope_id=observation["scope_id"],
                    evidence_root=root,
                )
                if (
                    requirement.subject == "memory"
                    and requirement.policy_group == "allow"
                ):
                    from tests.product_runtime_memory_fixture import (
                        build_memory_prerequisite,
                    )

                    first_write = build_memory_prerequisite(
                        replay.root / "first-write", replay, evidence_root=root
                    )
                    replay = first_write.read
                    replay.memory_prerequisite_fixture = first_write
                case = _policy_case(
                    root, requirement, observation, replay, report_policies
                )
            else:
                case = build_case_fixture(
                    root,
                    requirement,
                    observation,
                    baseline_material=baseline_material,
                    ack=ack,
                    capability=observed,
                )
            cases.append(case)
            observations[runtime, requirement.id] = case["hashed_evidence"][0]
        report = {
            "schema_version": "agentguard-product-conformance/1",
            "phase": "pre_activation",
            "runtime": runtime,
            "source_revision": fixture.revision,
            "candidate_manifest_digest": digest,
            "requirements_version": REQUIREMENTS_VERSION,
            "requirements_digest": requirements_digest(),
            "runtime_version": PINS[runtime][0],
            "adapter_version": PINS[runtime][1],
            "adapter_artifact_digest": adapter_digest,
            "product_active_enabled": False,
            "external_provider_requests": 0,
            "complete": True,
            "exit_code": 0,
            "formal_scope_id": f"unit:reserved-formal:{runtime}",
            "materials": materials,
            "policies": report_policies,
            "cases": cases,
            "totals": {
                "required": len(cases),
                "passed": len(cases),
                "failed": 0,
                "skipped": 0,
            },
        }
        report_path = root / f"reports/{runtime}.json"
        _json(report_path, report)
        reports[runtime], report_paths[runtime] = report, report_path
        matrix_evidence = _document(
            root,
            f"materials/{runtime}/matrix-evidence.json",
            {
                "runtime": runtime,
                "source_revision": fixture.revision,
                "c3_atomic_replace_and_seal": runtime == "langgraph",
                "residual_boundaries": []
                if runtime == "langgraph"
                else list(OPENCLAW_RESIDUAL_BOUNDARIES),
            },
        )
        matrix_rows.append(
            {
                "runtime": runtime,
                "observed": observed_ref,
                "activation_target": target_ref,
                "cf_13": "PASS" if runtime == "langgraph" else "NOT_SUPPORTED",
                "evidence": matrix_evidence,
            }
        )
    matrix_ref = _document(
        root,
        "materials/capability-matrix.json",
        {
            "schema_version": "agentguard-product-capability-matrix/1",
            "source_revision": fixture.revision,
            "candidate_manifest_digest": digest,
            "runtimes": matrix_rows,
        },
    )
    dataset_ref = _document(
        root,
        "materials/dataset.json",
        {
            "schema_version": "agentguard-product-dataset/1",
            "source_revision": fixture.revision,
            "requirements": requirements_document(),
            "policies": templates,
        },
    )
    contract_ref = _document(
        root,
        "materials/contract.json",
        {
            "schema_version": "agentguard-product-contract/1",
            "source_revision": fixture.revision,
            "semantics_version": PRODUCT_TOOL_SEMANTICS_VERSION,
            "files": [
                {
                    "source_path": name,
                    "file": _ref(
                        root,
                        _write_contract(
                            root / f"materials/contract-source/{index}", contracts[name]
                        ),
                    ),
                }
                for index, name in enumerate(CONTRACT_FILES)
            ],
        },
    )
    review = {
        "schema_version": "agentguard-product-signing-review/1",
        "source_revision": fixture.revision,
        "candidate_manifest_digest": digest,
        "reviewer_id": "unit:automated-fixture-reviewer",
        "reviewer_kind": "ai_reviewer",
        "review_completed": True,
        "authorization_source": "unit_fixture:pytest",
        "authorization_text": "Synthetic unit fixture only; no real Host qualification, human review, deployment or production risk acceptance.",
        "policy_groups": list(POLICY_GROUPS),
        "runtimes": list(RUNTIMES),
        "scope": "fixed_isolated_profiles",
        "production_acceptance_claimed": False,
        "long_term_validation_claimed": False,
    }
    review_ref = _document(root, "materials/review.json", review)
    clock = datetime.now(timezone.utc)
    identities = [
        {
            "runtime": runtime,
            "principal_id": "unit-principal",
            "agent_id": capabilities[runtime]["agent_id"],
            "runtime_binding_id": capabilities[runtime]["runtime_binding_id"],
            "canary_cohort": "unit-fixture-only",
        }
        for runtime in RUNTIMES
    ]
    request = {
        "schema_version": "agentguard-product-signing-request/1",
        "source_revision": fixture.revision,
        "candidate_manifest": _ref(root, fixture.manifest_path),
        "langgraph_conformance": _ref(root, report_paths["langgraph"]),
        "openclaw_conformance": _ref(root, report_paths["openclaw"]),
        "capability_matrix": matrix_ref,
        "tool_catalog": catalog_ref,
        "dataset_manifest": dataset_ref,
        "contract_manifest": contract_ref,
        "review_record": review_ref,
        "policy_groups": policy_refs,
        "runtime_identities": identities,
        "issued_at": (clock - timedelta(minutes=1)).isoformat(),
        "expires_at": (clock + timedelta(days=1)).isoformat(),
        "signer_key_id": "unit-signer-only",
    }
    request_path = root / "signing-request.json"
    _json(request_path, request)
    return SimpleNamespace(
        candidate=fixture,
        root=root,
        request=request,
        request_path=request_path,
        request_ref=_ref(root, request_path),
        reports=reports,
        report_paths=report_paths,
        observations=observations,
        clock=clock,
        policies=policies,
    )


def _write_contract(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o644)
    return path


def _policy_case(root, requirement, observation, replay, report_policies):
    """Controlled Host/effect frames around independently reconstructed Core data."""
    from tests.product_runtime_case_fixture import _sqlite
    from tests.product_runtime_terminal_fixture import build_policy_terminal

    terminal = build_policy_terminal(
        replay.root / "target-terminal", replay, evidence_root=root
    )

    directory = replay.root / "observation-materials"
    directory.mkdir(mode=0o700)
    frames = []
    serial = 0

    def artifact(value):
        nonlocal serial
        serial += 1
        content = (
            value
            if isinstance(value, bytes)
            else json.dumps(value, sort_keys=True).encode()
        )
        return _ref(root, _write_contract(directory / f"artifact-{serial}", content))

    def add(actor, event, data, attachments=()):
        frames.append(
            {
                "sequence": len(frames),
                "actor": actor,
                "event": event,
                "data": data,
                "attachments": list(attachments),
            }
        )

    def start_confirmation(start, invocation_id):
        if start is not None:
            add(
                "http",
                "action_start_confirmed",
                {
                    "invocation_id": invocation_id,
                    "audit_id": start.start_audit_id,
                    "start": start.reference,
                    "confirmed_at": start.confirmation["confirmed_at"],
                },
                [start.reference],
            )

    row = deepcopy(replay.row)
    invocation = f"unit:target:{observation['runtime']}:{requirement.id}"
    row["target_invocation_id"] = invocation
    command_input = None
    if requirement.subject == "command" and requirement.policy_group == "ask":
        prior_read = replay.prior_read
        read_name, _read_call, read_args = product_tool_arguments(prior_read.event)
        if read_name != "read" or read_args != {"path": "command-marker.txt"}:
            raise ValueError("command prerequisite must read its fixed marker resource")
        result_event = next(
            event
            for event in replay.history["events"]
            if event["event_id"] == prior_read.result_parent.links["event_id"]
        )
        command_input = result_event["payload"]["result"]["content_preview"].encode()
        read_before, read_after = artifact(command_input), artifact(command_input)
        read_id = "unit:command-read:" + observation["runtime"]
        read_effect = {
            "kind": "read_result",
            "phase": "before",
            "target": read_args["path"],
            "count": 0,
            "content_digest": read_before["raw_sha256"],
            "invocation_id": read_id,
        }
        add("effect", "snapshot", read_effect, [read_before])
        read_call = {
            "tool_name": read_name,
            "arguments": read_args,
            "invocation_id": read_id,
            "role": "prerequisite",
        }
        add("model", "tool_call_requested", read_call)
        start_confirmation(prior_read.start, read_id)
        add(
            "host",
            "tool_invocation",
            read_call
            | {"invoked_at": prior_read.receipt.evidence.execution.invoked_at},
        )
        original_read_result = artifact(command_input)
        add(
            "host",
            "tool_result",
            {
                "invocation_id": read_id,
                "is_error": False,
                "result_digest": original_read_result["raw_sha256"],
            },
            [original_read_result],
        )
        add(
            "effect",
            "snapshot",
            read_effect | {"phase": "after", "count": 1},
            [read_after],
        )
    for parent in replay.parents:
        authority = parent.evidence["decision_authority"]["payload"]
        add(
            "consumer",
            "upstream_authority",
            {
                "event_type": parent.event_type,
                "authority": authority,
                "scope_id": observation["scope_id"],
                "receipt_confirmed": True,
                "policy_audit_id": parent.audit_id,
            },
        )
    add(
        "consumer",
        "product_authority_selected",
        row,
        [row["replay"], terminal.reference],
    )
    add(
        "http",
        "evaluate_exchange",
        {
            "method": "POST",
            "path": "/v1/guard/evaluate",
            "status": 200,
            "request": row["event"],
            "request_wire": json.dumps(row["event"], sort_keys=True),
            "policy_audit_id": row["policy_audit_id"],
            "authority_digest": canonical_sha256(row["authority"]),
        },
    )
    name, _call_id, args = product_tool_arguments(replay.event)
    read_audits = [
        item["audit_id"]
        for item in replay.history["audits"]
        if item["event_type"] == "tool_result_produced"
    ]
    add(
        "consumer",
        "action_proof",
        {
            "event_id": replay.event.event_id,
            "arguments_digest": canonical_sha256(args),
            "model_output_policy_audit_id": replay.parents[-1].audit_id,
            "coverage": deepcopy(replay.replay["coverage"]),
            "dataflow": replay.replay["coverage"]["dataflow"]["status"],
            "ancestor_policy_audit_ids": read_audits,
        },
    )
    if requirement.subject == "memory" and requirement.policy_group == "allow":
        first_write = replay.memory_prerequisite_fixture
        if "memory_prerequisite" not in row:
            raise ValueError(
                "synthetic memory fixture needs its approved write records"
            )
        add(
            "consumer",
            "memory_prerequisite",
            {
                "selected_decision": first_write.write.authority.selected_decision.decision,
                "terminal_committed": True,
                "scope_id": observation["scope_id"],
                "memory_fact_id": row["memory_fact_id"],
                "prerequisite": row["memory_prerequisite"],
            },
            [row["memory_prerequisite"]],
        )
        writer_name, _writer_call, writer_args = product_tool_arguments(
            first_write.write.event
        )
        write_id = "unit:approved-first-write:" + observation["runtime"]
        empty_ref = artifact(_sqlite("memory", []))
        written_ref = artifact(
            _sqlite("memory", [(writer_args["key"], writer_args["value"])])
        )
        write_effect = {
            "kind": "memory",
            "phase": "before",
            "target": "unit-target:memory",
            "count": 0,
            "content_digest": empty_ref["raw_sha256"],
            "invocation_id": write_id,
        }
        add("effect", "snapshot", write_effect, [empty_ref])
        write_call = {
            "tool_name": writer_name,
            "arguments": writer_args,
            "invocation_id": write_id,
            "role": "prerequisite",
        }
        add("model", "tool_call_requested", write_call)
        start_confirmation(first_write.start, write_id)
        add(
            "host",
            "tool_invocation",
            write_call
            | {"invoked_at": first_write.receipt.evidence.execution.invoked_at},
        )
        write_result = artifact({"ok": True, "key": writer_args["key"]})
        add(
            "host",
            "tool_result",
            {
                "invocation_id": write_id,
                "is_error": False,
                "result_digest": write_result["raw_sha256"],
            },
            [write_result],
        )
        add(
            "effect",
            "snapshot",
            write_effect
            | {
                "phase": "after",
                "count": 1,
                "content_digest": written_ref["raw_sha256"],
            },
            [written_ref],
        )
    if requirement.subject == "command" and requirement.policy_group == "ask":
        if not read_audits:
            raise ValueError("synthetic command fixture needs its read-result audit")
        add(
            "consumer",
            "command_input_ancestry",
            {
                "source_tool": "read",
                "taint": "UNTRUSTED",
                "scope_id": observation["scope_id"],
                "tool_result_policy_audit_id": read_audits[-1],
            },
        )
    if requirement.policy_group == "ask":
        add(
            "http",
            "approval_resolved",
            {
                "resolution": "allow_once",
                "policy_audit_id": row["policy_audit_id"],
                "approval_id": terminal.approval.approval_id,
            },
        )
        add(
            "http",
            "lease_consumed",
            {
                "approval_id": terminal.approval.approval_id,
                "ok": True,
                "release_mode": terminal.binding.release_mode,
                "lease_id": terminal.lease.lease_id,
                "consumption_id": terminal.consumption.consumption_id,
            },
        )
    kind = requirement.subject
    before = b"synthetic unit file contents\n"
    after = before
    result = {"ok": True}
    if name == "read":
        result = before
    elif name == "write":
        after = args["content"].encode()
    elif name == "exec":
        before = command_input or b""
        after = before + b"isolated command executed\n"
        result = {"exit_code": 0, "stdout": "unit marker output"}
    elif name.startswith("agentguard_memory_"):
        if name.endswith("read"):
            _name, _call, original_write = product_tool_arguments(
                replay.memory_prerequisite_fixture.write.event
            )
            if original_write["key"] != args["key"]:
                raise ValueError(
                    "synthetic memory read must consume its actual first write"
                )
            value = original_write["value"]
        else:
            value = args["value"]
        before = _sqlite(
            "memory", [(args["key"], value)] if name.endswith("read") else []
        )
        after = _sqlite("memory", [(args["key"], value)])
        result = (
            {"key": args["key"], "value": value}
            if name.endswith("read")
            else {"ok": True, "key": args["key"]}
        )
    elif name == "message":
        before = _sqlite("messages", [])
        after = _sqlite(
            "messages", [(1, "unit:message", args["target"], args["message"])]
        )
        result = {"ok": True, "messageId": "unit:message"}
    if requirement.policy_group == "deny":
        after = before
    before_ref, after_ref = artifact(before), artifact(after)
    effect = {
        "kind": kind,
        "phase": "before",
        "target": (
            "command-marker.txt"
            if name == "exec"
            else f"unit-target:{requirement.subject}"
        ),
        "count": 0,
        "content_digest": before_ref["raw_sha256"],
        "invocation_id": invocation,
    }
    add("effect", "snapshot", effect, [before_ref])
    if requirement.policy_group != "deny":
        call = {
            "tool_name": name,
            "invocation_id": invocation,
            "arguments": args,
            "role": "target",
        }
        add("model", "tool_call_requested", call)
        start_confirmation(terminal.start, invocation)
        add(
            "host",
            "tool_invocation",
            call | {"invoked_at": terminal.receipt.evidence.execution.invoked_at},
        )
        result_ref = artifact(result)
        add(
            "host",
            "tool_result",
            {
                "invocation_id": invocation,
                "is_error": False,
                "result_digest": result_ref["raw_sha256"],
            },
            [result_ref],
        )
        if name == "agentguard_memory_read":
            withheld = result["value"]
            placeholder = "[AgentGuard: memory result quarantined]"
            released = artifact(placeholder)
            next_request = artifact(
                {
                    "messages": [
                        {
                            "role": "tool",
                            "tool_call_id": _call_id,
                            "content": placeholder,
                        }
                    ]
                }
            )
            subsequent_memory, subsequent_inbox = artifact([]), artifact([])
            add(
                "consumer",
                "target_result_isolation",
                {
                    "invocation_id": invocation,
                    "disposition": "quarantined",
                    "original_result_digest": result_ref["raw_sha256"],
                    "withheld_content": withheld,
                    "released_result": released,
                    "next_model_request": next_request,
                    "subsequent_memory_writes": subsequent_memory,
                    "subsequent_inbox_messages": subsequent_inbox,
                    "published_original": False,
                },
                [released, next_request, subsequent_memory, subsequent_inbox],
            )
    add(
        "effect",
        "snapshot",
        effect
        | {
            "phase": "after",
            "count": int(requirement.policy_group != "deny"),
            "content_digest": after_ref["raw_sha256"],
        },
        [after_ref],
    )
    add(
        "postgres",
        "target_receipt",
        {
            "policy_audit_id": row["policy_audit_id"],
            "event_id": replay.event.event_id,
            "row_count": 1,
            "audit_id": terminal.receipt.audit_id,
            "links": terminal.receipt.links.model_dump(mode="json"),
            "receipt_digest": canonical_sha256(
                terminal.receipt.model_dump(mode="json")
            ),
        },
        [terminal.document["receipt"], terminal.document["accepted"]],
    )
    observation = deepcopy(observation) | {"frames": frames}
    reference = _document(
        root, directory.relative_to(root).as_posix() + "/observation.json", observation
    )
    return {
        "id": requirement.id,
        "status": "PASS",
        "evidence_kind": "deterministic_contract",
        "model_kind": "controlled_local",
        "authority_kind": "synthetic_contract_fixture",
        "execution_scope": "isolated_contract_fixture",
        "scope_id": observation["scope_id"],
        "policy_group": requirement.policy_group,
        "policy_digest": next(
            row["policy_digest"]
            for row in report_policies
            if row["id"] == requirement.policy_group
        ),
        "invocation_count": sum(
            row["actor"] == "host" and row["event"] == "tool_invocation"
            for row in frames
        ),
        "effects": [
            canonical_sha256(row["data"])
            for row in frames
            if row["actor"] == "effect" and row["event"] == "snapshot"
        ],
        "receipt_disposition": "confirmed",
        "hashed_evidence": [reference],
    }
