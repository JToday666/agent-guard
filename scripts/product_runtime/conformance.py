"""Offline validation of observed pre-activation facts, never a report producer.

The records are evidence from a reviewed runner, not cryptographic attestation of
a host. Hashes protect those records against substitution; installation checks
bind their named consumers to the actual candidate. No PASS-only input qualifies.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Any

from agentguard_core import GuardEngine, PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.product_tools import product_tool_arguments
from agentguard_core.actions.product_tools import (
    PRODUCT_TOOL_NAMES,
    product_model_visible_tools,
)
from agentguard_core.decisions.product import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    PRODUCT_EVENT_TYPES,
    ProductDecisionAuthorityEvidenceV1,
    ActivationAckV1,
    RuntimeCapabilityReportV2,
    build_runtime_capability_report,
)
from agentguard_core.events import GuardEvent
from agentguard_core.decisions import FastAssessment
from agentguard_core.decisions.shadow import compute_assessment_digest
from agentguard_core.decisions.models import RuntimeOutcomeReceipt
from guard_api.services.policy import validate_policy_bundle

from .candidate import VerifiedCandidate
from .evidence import EvidenceStore, VerifiedDocument, object_fields, strict_json
from .models import (
    AdmissionError,
    CaseResult,
    ConformanceReport,
    Observation,
    read_model,
)
from .requirements import (
    COMPOSITION_COMPONENTS,
    NEGATIVE_REASONS,
    POLICY_GROUPS,
    REQUIREMENTS_VERSION,
    Requirement,
    requirements_digest,
    requirements_for,
)

PINS = {"langgraph": ("1.2.7", "0.1.0rc1"), "openclaw": ("2026.7.1-2", "0.1.0-rc.1")}
DISTRIBUTIONS = {
    "langgraph": "agentguard-langgraph-adapter",
    "openclaw": "@agentguard-ai/openclaw-plugin",
}


def require(condition: bool, code: str = "conformance_evidence_invalid") -> None:
    if not condition:
        raise AdmissionError(code)


def exact(value: Any, expected: Any) -> bool:
    return canonical_sha256(value) == canonical_sha256(expected)


def _utc(value: Any) -> datetime:
    from datetime import timedelta

    require(type(value) is str)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() == timedelta(0))
    return parsed


def _ack(value: Any, runtime: str) -> ActivationAckV1:
    parsed = ActivationAckV1.model_validate(value, strict=True)
    require(exact(parsed.model_dump(mode="json"), value) and parsed.runtime == runtime)
    return parsed


def _ack_header(headers: Any, ack: ActivationAckV1, *, required: bool = True) -> None:
    require(type(headers) is dict and all(type(key) is str for key in headers))
    carriers = [
        value
        for key, value in headers.items()
        if isinstance(key, str) and key.lower() == "x-agentguard-activation-ack"
    ]
    require(carriers == [ack.ack_token] or (not required and not carriers))


def policy_templates() -> dict[str, dict[str, Any]]:
    """Only these complete, valid policies are in this admission's scope."""
    from agentguard_core.policies import RuleOverride

    allow, ask, deny = PolicyBundle(), PolicyBundle(), PolicyBundle()
    allow.allowed_email_domains.append("agentguard.invalid")
    deny.dangerous_command_markers.extend(["python marker.py", "node marker.mjs"])
    deny.rule_overrides.update(
        {
            key: RuleOverride(decision="deny")
            for key in ("P005_external_send", "P104_memory_poisoning")
        }
    )
    result = {"allow": allow, "ask": ask, "deny": deny}
    for policy in result.values():
        require(not validate_policy_bundle(policy), "admission_policy_invalid")
    return {key: policy.model_dump(mode="json") for key, policy in result.items()}


def derive_activation_target(value: Any) -> RuntimeCapabilityReportV2:
    observed = RuntimeCapabilityReportV2.model_validate(value)
    require(exact(observed.model_dump(mode="json"), value))
    require(observed.active is False and observed.supported is True)
    projected = observed.model_dump(mode="json", exclude={"report_digest"})
    projected["active"] = True
    for event in projected["events"]:
        require(event["active"] is False)
        event["active"] = True
    return build_runtime_capability_report(**projected)


@dataclass(frozen=True)
class VerifiedConformance:
    report: ConformanceReport
    document: VerifiedDocument
    observed_capability: RuntimeCapabilityReportV2
    activation_target: RuntimeCapabilityReportV2
    inventory: dict[str, Any]


class Facts:
    def __init__(self, observation: Observation, store: EvidenceStore) -> None:
        self.observation = observation
        self.store = store
        self.rows = observation.frames
        require([row.sequence for row in self.rows] == list(range(len(self.rows))))
        for row in self.rows:
            pending: list[Any] = [row.data]
            while pending:
                value = pending.pop()
                if type(value) is dict:
                    for key, item in value.items():
                        if key in {
                            "count",
                            "attempts",
                            "concurrent_callers",
                            "maximum_inflight",
                            "process_id",
                            "state_version",
                        } or key.endswith(
                            ("_count", "_requests", "_invocations", "_posts")
                        ):
                            require(type(item) is int and item >= 0)
                        if type(item) in {dict, list}:
                            pending.append(item)
                elif type(value) is list:
                    pending.extend(item for item in value if type(item) in {dict, list})
            for attachment in row.attachments:
                store.read_file(attachment)

    def all(self, actor: str, event: str) -> list[dict[str, Any]]:
        return [
            row.data for row in self.rows if row.actor == actor and row.event == event
        ]

    def one(self, actor: str, event: str) -> dict[str, Any]:
        found = self.all(actor, event)
        require(len(found) == 1, "conformance_observation_missing_or_duplicate")
        return found[0]

    def order(self, *events: tuple[str, str]) -> None:
        indices = []
        for actor, event in events:
            found = [
                row.sequence
                for row in self.rows
                if row.actor == actor and row.event == event
            ]
            require(len(found) == 1)
            indices.append(found[0])
        require(indices == sorted(set(indices)))


def _installed_consumer(
    observation: Observation, candidate: VerifiedCandidate, store: EvidenceStore
) -> None:
    observed = store.read_file(observation.consumer_file)
    runtime, case = observation.runtime, observation.case_id
    family = (
        "baseline"
        if case.startswith("baseline.")
        else (
            "ack"
            if case.startswith("contract.ack.")
            else (
                "receipt"
                if case.startswith("contract.receipt.")
                or case.endswith("unknown_no_reexecution")
                else (
                    "event"
                    if case.startswith("contract.event.")
                    else (
                        "action"
                        if case.startswith(
                            (
                                "contract.policy.",
                                "contract.approval.",
                                "contract.binding.",
                            )
                        )
                        or case.endswith("duplicate_action")
                        else "composition"
                    )
                )
            )
        )
    )
    lg = {
        "baseline": ("native_tools.py", "native_langgraph.py"),
        "ack": (
            "activation_ack.py",
            "activation_session.py",
            "core_client.py",
            "product_outbox.py",
        ),
        "receipt": (
            "product_outbox.py",
            "product_envelope_store.py",
            "product_action_barrier.py",
            "execution_template.py",
        ),
        "event": (
            "native_langgraph.py",
            "native_events.py",
            "model_boundary.py",
            "product_composition.py",
        ),
        "action": ("native_langgraph.py", "execution_template.py", "strong_binding.py"),
        "composition": ("product_composition.py",),
    }
    oc = {
        "baseline": (
            "product-runtime/factory.mjs",
            "product-runtime/baseline-profile.mjs",
        ),
        "ack": (
            "dist/runtime/activation-ack.js",
            "dist/runtime/activation-session.js",
            "dist/runtime/product-receipt-outbox.js",
        ),
        "receipt": (
            "dist/runtime/product-receipt-outbox.js",
            "dist/runtime/product-envelope-store.js",
            "dist/runtime/product-action-runtime.js",
        ),
        "event": (
            "dist/runtime/product-content-runtime.js",
            "dist/runtime/product-action-runtime.js",
            "dist/runtime/product-composition.js",
        ),
        "action": ("dist/runtime/product-action-runtime.js",),
        "composition": ("dist/runtime/product-composition.js",),
    }
    allowed = (
        tuple("agentguard_langgraph_adapter/" + name for name in lg[family])
        if runtime == "langgraph"
        else oc[family]
    )
    require(observation.consumer_module in allowed, "conformance_consumer_outside_case")
    if runtime == "langgraph":
        packages = candidate.installation_reports["python"].data["packages"]
        selected = [
            row for row in packages if row["distribution"] == DISTRIBUTIONS[runtime]
        ]
    else:
        selected = [
            row
            for row in candidate.installation_reports["openclaw"].data["lanes"]
            if row["lane"] == "product"
        ]
    require(len(selected) == 1)
    package = selected[0]
    matching = [row for row in package["files"] if row["path"] == str(observed.path)]
    require(
        len(matching) == 1
        and matching[0]["raw_sha256"] == observed.raw_sha256
        and matching[0]["size"] == observed.size,
        "conformance_consumer_not_installed",
    )
    root = (
        Path(package["plugin_root"])
        if runtime == "openclaw"
        else Path(package["module_file"]).parent.parent
    )
    require(
        observed.path == root / observation.consumer_module,
        "conformance_consumer_path_mismatch",
    )


def _invocations(facts: Facts, case: CaseResult) -> list[dict[str, Any]]:
    calls = facts.all("host", "tool_invocation")
    require(len(calls) == case.invocation_count)
    ids = [row["invocation_id"] for row in calls]
    require(len(ids) == len(set(ids)))
    effects = facts.all("effect", "snapshot")
    require([canonical_sha256(row) for row in effects] == case.effects)
    for row in effects:
        object_fields(
            row,
            {"kind", "phase", "target", "count", "content_digest", "invocation_id"},
            "conformance_effect_invalid",
        )
        require(type(row["count"]) is int and row["count"] >= 0)
        require(row["phase"] in {"before", "after", "recovered"})
        require(
            row["kind"]
            in {"file", "command", "memory", "message", "read_result", "process_result"}
        )
        frame = next(
            frame
            for frame in facts.rows
            if frame.actor == "effect"
            and frame.event == "snapshot"
            and frame.data is row
        )
        require(bool(frame.attachments), "conformance_effect_artifact_missing")
        require(
            row["content_digest"]
            in {facts.store.read_file(ref).raw_sha256 for ref in frame.attachments}
        )
    return calls


def _native(
    facts: Facts, case: CaseResult, tool: str, *, check_entrypoint: bool = True
) -> None:
    require(case.invocation_count == 1 and case.model_kind == "controlled_local")
    request = facts.one("model", "tool_call_requested")
    call = facts.one("host", "tool_invocation")
    result = facts.one("host", "tool_result")
    require(call["tool_name"] == request["tool_name"] == tool)
    require(
        call["invocation_id"] == request["invocation_id"] == result["invocation_id"]
    )
    require(
        exact(call["arguments"], request["arguments"]) and result["is_error"] is False
    )
    require(
        not check_entrypoint
        or facts.observation.entrypoint
        == (
            "StateGraph.ToolNode"
            if facts.observation.runtime == "langgraph"
            else "openclaw.agentCommand"
        )
    )
    facts.order(
        ("model", "tool_call_requested"),
        ("host", "tool_invocation"),
        ("host", "tool_result"),
    )
    before, after = facts.all("effect", "snapshot")
    require(
        before["phase"] == "before"
        and after["phase"] == "after"
        and before["target"] == after["target"]
    )
    require(after["invocation_id"] == call["invocation_id"])
    require(after["count"] == before["count"] + 1)
    result_frame = next(
        frame
        for frame in facts.rows
        if frame.actor == "host" and frame.event == "tool_result"
    )
    require(
        result["result_digest"]
        in {facts.store.read_file(ref).raw_sha256 for ref in result_frame.attachments},
        "conformance_host_result_artifact_missing",
    )
    result_bytes = next(
        facts.store.read_file(ref).content
        for ref in result_frame.attachments
        if ref.raw_sha256 == result["result_digest"]
    )

    def snapshot_bytes(snapshot: dict[str, Any]) -> bytes:
        frame = next(
            frame
            for frame in facts.rows
            if frame.actor == "effect"
            and frame.event == "snapshot"
            and frame.data is snapshot
        )
        return next(
            facts.store.read_file(ref).content
            for ref in frame.attachments
            if ref.raw_sha256 == snapshot["content_digest"]
        )

    original, content = snapshot_bytes(before), snapshot_bytes(after)
    args = call["arguments"]
    # A command/write result is a structured Host response. It is not the bytes
    # written to disk; both artifacts must remain independently committed.
    if tool in {"write", "exec"}:
        if tool == "write":
            require(content == args["content"].encode("utf-8"))
        else:
            require(content == original + b"isolated command executed\n")
            require(
                args["command"]
                == (
                    "python marker.py"
                    if facts.observation.runtime == "langgraph"
                    else "node marker.mjs"
                )
            )
    elif tool == "edit":
        expected = original.decode("utf-8")
        # Both pinned tools support the edits form used by this isolated suite.
        require(type(args["edits"]) is list and bool(args["edits"]))
        for edit in args["edits"]:
            require(
                type(edit["oldText"]) is str
                and bool(edit["oldText"])
                and expected.count(edit["oldText"]) == 1
            )
            expected = expected.replace(edit["oldText"], edit["newText"], 1)
        require(content.decode("utf-8") == expected)
    elif tool == "read":
        require(original == content)
        text_result = _host_text(result_bytes)
        require(text_result == original.decode("utf-8"))
    elif tool in {"agentguard_memory_read", "agentguard_memory_write"}:
        before_rows = _sqlite_rows(
            original, "SELECT key,value FROM memory ORDER BY key"
        )
        after_rows = _sqlite_rows(content, "SELECT key,value FROM memory ORDER BY key")
        if tool == "agentguard_memory_write":
            require(not any(row[0] == args["key"] for row in before_rows))
            require(after_rows == sorted(before_rows + [(args["key"], args["value"])]))
        else:
            require(before_rows == after_rows)
            selected = [row[1] for row in after_rows if row[0] == args["key"]]
            body = strict_json(_host_text(result_bytes).encode())
            require(
                body["key"] == args["key"]
                and body["value"] == (selected[0] if selected else None)
            )
    elif tool == "message":
        before_rows = _sqlite_rows(
            original, "SELECT message_id,target,text FROM messages ORDER BY sequence"
        )
        after_rows = _sqlite_rows(
            content, "SELECT message_id,target,text FROM messages ORDER BY sequence"
        )
        require(
            after_rows[:-1] == before_rows and len(after_rows) == len(before_rows) + 1
        )
        row = after_rows[-1]
        require(row[1:] == (args["target"], args["message"]))
        require(
            args["target"]
            == (
                "fixture-inbox@agentguard.invalid"
                if facts.observation.runtime == "langgraph" or not check_entrypoint
                else "fixture-inbox"
            )
        )
        require(args["channel"] == "agentguard-fixture" and args["action"] == "send")
        body = strict_json(_host_text(result_bytes).encode())
        require(body["messageId"] == row[0])
    elif tool == "process":
        require(args["action"] == "list" and original == content)
        observed_processes = strict_json(content)
        body = _host_text(result_bytes)
        if facts.observation.runtime == "langgraph":
            require(exact(strict_json(body.encode())["processes"], observed_processes))
            require(
                all(
                    row["exit_code"] == 0 and row["sequence"] == index + 1
                    for index, row in enumerate(observed_processes)
                )
            )
        else:
            require(
                type(observed_processes) is dict
                and observed_processes["commands"] == []
            )
            require(body == observed_processes["host_list_text"] and bool(body))


def _host_text(content: bytes) -> str:
    """Read the actual Host text, accepting OC's documented text block wrapper."""
    text = content.decode("utf-8")
    try:
        value = strict_json(content)
    except ValueError:
        return text
    if type(value) is dict and type(value.get("content")) is list:
        blocks = value["content"]
        require(
            bool(blocks)
            and all(
                block.get("type") == "text" and type(block.get("text")) is str
                for block in blocks
            )
        )
        return "\n".join(block["text"] for block in blocks)
    return text


def _sqlite_rows(content: bytes, query: str) -> list[tuple[Any, ...]]:
    require(
        content.startswith(b"SQLite format 3\x00"),
        "conformance_sqlite_snapshot_invalid",
    )
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(content)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        steps = 0

        def progress() -> int:
            nonlocal steps
            steps += 1000
            return int(steps > 100_000)

        connection.set_progress_handler(progress, 1000)
        table = "memory" if "FROM memory " in query else "messages"
        schema = connection.execute(
            "SELECT type,sql FROM sqlite_schema WHERE name=?", (table,)
        ).fetchone()
        require(
            schema is not None
            and schema[0] == "table"
            and type(schema[1]) is str
            and schema[1].upper().startswith("CREATE TABLE "),
            "conformance_sqlite_schema_invalid",
        )
        require(connection.execute("PRAGMA quick_check").fetchone() == ("ok",))
        rows = connection.execute(query).fetchmany(1001)
        require(len(rows) <= 1000)
        return rows
    except sqlite3.Error:
        raise AdmissionError("conformance_sqlite_snapshot_invalid") from None
    finally:
        connection.close()


def _baseline_inventory(
    value: Any, product: Any, runtime: str, store: EvidenceStore
) -> None:
    value = object_fields(
        value,
        {
            "schema_version",
            "runtime",
            "mapping_version",
            "inventory",
            "model_visible_tools",
            "logical_recipient",
            "collection_evidence",
        },
        "conformance_baseline_inventory_invalid",
    )
    require(
        value["schema_version"] == "agentguard-native-baseline-inventory/1"
        and value["runtime"] == runtime
        and value["mapping_version"] == "agentguard-native-baseline-to-product/1"
    )
    baseline = value["inventory"]
    require([tool["tool_id"] for tool in baseline["tools"]] == list(PRODUCT_TOOL_NAMES))
    if runtime == "langgraph":
        require(value["logical_recipient"] == "fixture-inbox@agentguard.invalid")
        require(
            exact(
                value["model_visible_tools"],
                product_model_visible_tools(baseline["tools"]),
            )
        )
        for before, after in zip(baseline["tools"], product["tools"], strict=True):
            # The separately isolated baseline root has its own execution binding.
            require(
                exact(
                    {
                        key: item
                        for key, item in before.items()
                        if key != "execution_binding_digest"
                    },
                    {
                        key: item
                        for key, item in after.items()
                        if key != "execution_binding_digest"
                    },
                )
            )
    else:
        require(value["logical_recipient"] == "fixture-inbox")
        require(set(baseline["input_schemas"]) == set(PRODUCT_TOOL_NAMES))
        require(
            [item["name"] for item in value["model_visible_tools"]]
            == list(PRODUCT_TOOL_NAMES)
        )
        for tool in value["model_visible_tools"]:
            require(exact(tool["parameters"], baseline["input_schemas"][tool["name"]]))
        for name in PRODUCT_TOOL_NAMES:
            before = baseline["input_schemas"][name]
            after = product["input_schemas"][name]
            if name != "message":
                require(exact(before, after))
            else:
                # Pinned legacy tool exposes more message actions; Product uses send.
                before_properties = dict(before["properties"])
                after_properties = dict(after["properties"])
                before_action, after_action = before_properties.pop(
                    "action"
                ), after_properties.pop("action")
                require(
                    "send" in before_action.get("enum", [])
                    and after_action.get("enum") == ["send"]
                )
                require(exact(before_properties, after_properties))
                require(
                    exact(
                        {
                            key: item
                            for key, item in before.items()
                            if key != "properties"
                        },
                        {
                            key: item
                            for key, item in after.items()
                            if key != "properties"
                        },
                    )
                )
    collection = store.read_json(value["collection_evidence"]).data
    require(collection["runtime"] == runtime and collection["authority_kind"] == "none")
    require(
        exact(collection["factory_inventory"], baseline)
        and exact(collection["model_visible_tools"], value["model_visible_tools"])
    )
    require(collection["catalog_rpc_is_authority"] is False)


def _receipt(
    facts: Facts, *, permanent: int | None = None, restart: bool = False
) -> None:
    original = facts.one("journal", "durable_receipt")
    object_fields(
        original,
        {"audit_id", "wire", "wire_digest", "activation_ack", "ack_digest", "phase"},
        "conformance_receipt_invalid",
    )
    require(type(original["wire"]) is str)
    payload = strict_json(original["wire"].encode("utf-8"))
    receipt = RuntimeOutcomeReceipt.model_validate(payload, strict=True)
    ack = ActivationAckV1.model_validate(original["activation_ack"], strict=True)
    require(exact(ack.model_dump(mode="json"), original["activation_ack"]))
    require(receipt.runtime == facts.observation.runtime == ack.runtime)
    require(receipt.metadata.activation_ack is not None)
    require(exact(payload["metadata"]["activation_ack"], original["activation_ack"]))
    require(
        original["wire_digest"]
        == hashlib.sha256(original["wire"].encode("utf-8")).hexdigest()
    )
    require(original["audit_id"] == payload["audit_id"])
    require(original["ack_digest"] == canonical_sha256(original["activation_ack"]))
    exchanges = facts.all("http", "receipt_exchange")
    require(bool(exchanges))
    for exchange in exchanges:
        require(exchange["audit_id"] == original["audit_id"])
        require(
            exchange["wire_digest"] == original["wire_digest"]
            and exchange["ack_digest"] == original["ack_digest"]
        )
        require(
            exchange["wire"] == original["wire"]
            and exact(exchange["activation_ack"], original["activation_ack"])
        )
        # The audit API's historical carrier is the immutable receipt body.
        # A captured optional header must agree; SDKs do not send one here.
        _ack_header(exchange["headers"], ack, required=False)
        require(_utc(exchange["observed_at"]) >= _utc(receipt.timestamp))
    if permanent is not None:
        require(
            exchanges[0]["status"] == permanent
            and exchanges[0]["response"].get("ok") is not True
        )
        rejected = facts.one("journal", "permanent_rejected")
        require(
            rejected["wire_digest"] == original["wire_digest"]
            and rejected["breaker"] is True
        )
        for operation in ("automatic_drain", "duplicate_submit", "restart"):
            passive = [
                row
                for row in facts.all("journal", "passive_recovery")
                if row["operation"] == operation
            ]
            require(
                len(passive) == 1
                and passive[0]["additional_posts"] == 0
                and passive[0]["additional_invocations"] == 0
            )
        removed = facts.one("http", "fault_removed")
        require(
            removed["fault_kind"] == "injected_transport_rejection"
            and removed["audit_id"] == original["audit_id"]
        )
        reconcile = facts.one("journal", "explicit_reconcile")
        require(
            reconcile["audit_id"] == original["audit_id"]
            and reconcile["expected_wire_digest"] == original["wire_digest"]
        )
        facts.order(
            ("journal", "durable_receipt"),
            ("journal", "permanent_rejected"),
            ("http", "fault_removed"),
            ("journal", "explicit_reconcile"),
            ("journal", "confirmed"),
        )
    if restart or permanent is not None:
        recovery = facts.one("consumer", "receipts_only_worker")
        require(
            recovery["process_id"] != facts.observation.process_id
            and recovery["model_requests"] == 0
            and recovery["tool_invocations"] == 0
        )
    final = exchanges[-1]
    require(
        final["status"] in {200, 201}
        and final["response"]["ok"] is True
        and final["response"]["audit_id"] == original["audit_id"]
    )
    confirmed = facts.one("journal", "confirmed")
    pg = facts.one("postgres", "receipt_row")
    require(confirmed["audit_id"] == pg["audit_id"] == original["audit_id"])
    require(confirmed["wire_digest"] == pg["wire_digest"] == original["wire_digest"])
    require(pg["row_count"] == 1 and pg["ack_digest"] == original["ack_digest"])
    require(pg["links"] == payload["links"])
    before, after = facts.all("effect", "recovery_count")
    require(
        before["phase"] == "before"
        and after["phase"] == "after"
        and before["count"] == after["count"]
    )


def _blocked(facts: Facts, *, expected_reason: str) -> None:
    fault = facts.one("consumer", "fault_input")
    result = facts.one("consumer", "rejected")
    object_fields(fault, {"case", "input"}, "conformance_fault_invalid")
    require(fault["case"] == expected_reason and bool(fault["input"]))
    require(
        result["reason_code"] in NEGATIVE_REASONS[expected_reason]
        and result["new_invocations"] == 0
    )
    value = fault["input"]
    if expected_reason.startswith("ack."):
        ack = ActivationAckV1.model_validate(value["activation_ack"], strict=True)
        require(ack.runtime == facts.observation.runtime)
        if expected_reason == "ack.expiry":
            now = datetime.fromisoformat(value["now"].replace("Z", "+00:00"))
            expiry = datetime.fromisoformat(ack.expires_at.replace("Z", "+00:00"))
            require(now.tzinfo is not None and now >= expiry)
            if ack.runtime == "langgraph":
                from agentguard_langgraph_adapter.activation_ack import (
                    ActivationAckV1 as ClientAck,
                    ProductActivationError,
                )

                client = ClientAck.model_validate(value["activation_ack"])
                try:
                    client.remaining_seconds(now=now)
                except ProductActivationError as error:
                    require(error.code == result["reason_code"])
                else:
                    raise AdmissionError("conformance_expired_ack_accepted")
        else:
            expected = value["expected_identity"]
            fields = {
                "runtime",
                "runtime_version",
                "plugin_version",
                "agent_id",
                "runtime_binding_id",
                "profile_id",
                "activation_ref_digest",
                "capability_digest",
                "host_inventory_digest",
                "plugin_inventory_digest",
                "plugin_order_inventory_digest",
                "tool_inventory_digest",
            }
            object_fields(expected, fields, "conformance_expected_identity_invalid")
            require(any(expected[key] != getattr(ack, key) for key in fields))
    elif expected_reason == "config.incomplete_blocked":
        require(value["required_components"] == list(COMPOSITION_COMPONENTS))
        configured = value["configured_components"]
        require(
            type(configured) is list
            and len(set(configured)) == len(configured)
            and set(configured) < set(COMPOSITION_COMPONENTS)
        )
    elif expected_reason == "inventory.drift_blocked":
        require(canonical_sha256(value["before"]) != canonical_sha256(value["after"]))
    elif expected_reason == "approval.timeout":
        require(
            value["resolution"] is None
            and _utc(value["requested_at"])
            < _utc(value["expires_at"])
            <= _utc(value["observed_at"])
        )
    elif expected_reason == "approval.invalid_release":
        require(
            value["release_mode"] in {"forbidden", "not_applicable"}
            and value["requested_resolution"] == "allow_once"
        )
    elif expected_reason == "receipt.payload_conflict":
        first, second = (
            strict_json(value[key].encode("utf-8"))
            for key in ("original_wire", "attempted_wire")
        )
        require(
            first["audit_id"] == second["audit_id"]
            and value["original_wire"] != value["attempted_wire"]
        )
    elif expected_reason == "receipt.decrypt_failure":
        before, after = (
            facts.store.read_file(value[key])
            for key in ("original_envelope", "corrupted_envelope")
        )
        require(before.raw_sha256 != after.raw_sha256 and before.size == after.size)
        require(value["failure_stage"] == "aes_gcm_authentication")
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import json

        key = facts.store.read_file(value["synthetic_spool_key"]).content
        require(len(key) == 32)
        valid, corrupt = strict_json(before.content), strict_json(after.content)
        fields = {
            "format",
            "algorithm",
            "namespace",
            "record_id",
            "kind",
            "revision",
            "nonce",
            "ciphertext",
        }
        object_fields(valid, fields, "conformance_envelope_invalid")
        object_fields(corrupt, fields, "conformance_envelope_invalid")
        header = {
            key: item
            for key, item in valid.items()
            if key not in {"nonce", "ciphertext"}
        }
        require(
            header["format"] == "agentguard.product-envelope.v1"
            and header["algorithm"] == "AES-256-GCM"
        )
        require(
            exact(
                {key: item for key, item in valid.items() if key != "ciphertext"},
                {key: item for key, item in corrupt.items() if key != "ciphertext"},
            )
        )
        aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        nonce = base64.b64decode(valid["nonce"], validate=True)
        require(len(nonce) == 12)
        AESGCM(key).decrypt(
            nonce, base64.b64decode(valid["ciphertext"], validate=True), aad
        )
        try:
            AESGCM(key).decrypt(
                nonce, base64.b64decode(corrupt["ciphertext"], validate=True), aad
            )
        except InvalidTag:
            pass
        else:
            raise AdmissionError("conformance_decrypt_fault_not_observed")
    elif expected_reason == "receipt.pending_blocks_side_effect":
        require(
            type(value["pending_count"]) is int
            and value["pending_count"] > 0
            and value["terminal_confirmed"] is False
        )
    elif expected_reason in {
        "receipt.start_confirmation_required",
        "release.confirmation_required",
    }:
        require(
            value["server_confirmed"] is False
            and value["delivery_disposition"]
            in {"queued_durable", "permanent_rejected", "failed"}
        )
        require(
            value["stage"]
            == (
                "invocation_start"
                if facts.observation.runtime == "langgraph"
                else "gate_release"
            )
        )
    elif expected_reason.startswith("binding."):
        require(
            canonical_sha256(value["original_action"])
            != canonical_sha256(value["attempted_action"])
        )
    else:
        raise AdmissionError("conformance_negative_case_unknown")
    require(not facts.all("host", "tool_invocation"))
    facts.order(("consumer", "fault_input"), ("consumer", "rejected"))


def _protocol(facts: Facts, case: CaseResult, subject: str) -> None:
    if subject in {
        "receipt.permanent_409",
        "receipt.permanent_422",
        "receipt.network_queue",
        "receipt.restart_drain_only",
        "ack.historical_receipt",
    }:
        _receipt(
            facts,
            permanent=int(subject[-3:]) if "permanent_" in subject else None,
            restart=subject == "receipt.restart_drain_only",
        )
        require(case.receipt_disposition == "confirmed")
        if subject == "receipt.network_queue":
            require(facts.one("journal", "queued_durable")["server_confirmed"] is False)
        if subject == "ack.historical_receipt":
            time = facts.one("http", "historical_window")
            original = facts.one("journal", "durable_receipt")
            original_ack = _ack(original["activation_ack"], facts.observation.runtime)
            require(
                time["issued_at"] == original_ack.issued_at
                and time["ack_expires_at"] == original_ack.expires_at
            )
            require(
                _utc(time["issued_at"])
                <= _utc(time["evaluation_at"])
                < _utc(time["ack_expires_at"])
                <= _utc(time["delivery_at"])
            )
            require(
                _utc(time["delivery_at"])
                == _utc(facts.all("http", "receipt_exchange")[-1]["observed_at"])
            )
    elif subject == "receipt.disk_failure":
        rows = facts.all("journal", "disk_failure")
        require(
            [row["stage"] for row in rows] == ["pre_action", "confirmation_persist"]
        )
        require(
            rows[0]["new_invocations"] == 0 and rows[0]["evaluation_started"] is False
        )
        require(
            rows[1]["terminal_durable"] is True and rows[1]["server_confirmed"] is True
        )
        require(all(row["errno"] in {"EACCES", "ENOSPC", "EIO"} for row in rows))
        _receipt(facts, restart=True)
    elif subject == "ack.single_flight":
        row = facts.one("http", "heartbeat_concurrency")
        require(
            type(row["concurrent_callers"]) is int and row["concurrent_callers"] >= 2
        )
        require(row["request_count"] == row["maximum_inflight"] == 1)
        require(
            len(row["returned_ack_digests"]) == row["concurrent_callers"]
            and len(set(row["returned_ack_digests"])) == 1
        )
        heartbeat = facts.one("http", "heartbeat_exchange")
        actual_ack = _ack(
            heartbeat["response"]["activation_ack"], facts.observation.runtime
        )
        require(heartbeat["status"] == 200)
        require(len(row["returned_acks"]) == row["concurrent_callers"])
        require(
            row["returned_ack_digests"]
            == [
                canonical_sha256(facts.store.read_json(ref).data)
                for ref in row["returned_acks"]
            ]
        )
        require(
            all(
                exact(
                    _ack(
                        facts.store.read_json(ref).data, facts.observation.runtime
                    ).model_dump(mode="json"),
                    actual_ack.model_dump(mode="json"),
                )
                for ref in row["returned_acks"]
            )
        )
    elif subject in {"ack.immutable_action_snapshot", "ack.consume_retry_fixed"}:
        exchanges = facts.all(
            "http",
            (
                "consume_exchange"
                if subject.endswith("consume_retry_fixed")
                else "action_exchange"
            ),
        )
        require(
            len(exchanges) >= 2
            and len({canonical_sha256(row["request"]) for row in exchanges}) == 1
            and len({row["request_wire"] for row in exchanges}) == 1
        )
        require(
            len({canonical_sha256(row["activation_ack"]) for row in exchanges}) == 1
        )
        for exchange in exchanges:
            require(type(exchange["request_wire"]) is str)
            require(
                exact(
                    strict_json(exchange["request_wire"].encode("utf-8")),
                    exchange["request"],
                )
            )
            parsed_ack = _ack(exchange["activation_ack"], facts.observation.runtime)
            _ack_header(exchange["headers"], parsed_ack)
            require(
                _utc(parsed_ack.issued_at)
                <= _utc(exchange["observed_at"])
                < _utc(parsed_ack.expires_at)
            )
            if subject.endswith("consume_retry_fixed"):
                from guard_api.models import (
                    ExecutionLeaseConsumeRequest,
                    RestrictedExecutionLeaseConsumeRequest,
                )

                model = (
                    ExecutionLeaseConsumeRequest
                    if facts.observation.runtime == "langgraph"
                    else RestrictedExecutionLeaseConsumeRequest
                )
                parsed_request = model.model_validate(exchange["request"], strict=True)
                require(
                    exact(parsed_request.model_dump(mode="json"), exchange["request"])
                )
            else:
                require(
                    GuardEvent.model_validate(exchange["request"]).runtime
                    == facts.observation.runtime
                )
        refreshed = facts.one("http", "refreshed_ack")
        _ack(refreshed["activation_ack"], facts.observation.runtime)
        require(
            canonical_sha256(refreshed["activation_ack"])
            != canonical_sha256(exchanges[0]["activation_ack"])
        )
    elif subject == "duplicate_action":
        require(case.invocation_count == 1)
        row = facts.one("consumer", "duplicate_action")
        require(row["attempts"] >= 2 and row["additional_invocations"] == 0)
        require(
            len(set(row["action_ids"])) == 1
            and len(row["action_ids"]) == row["attempts"]
        )
    elif subject == "unknown_no_reexecution":
        unknown = facts.one("journal", "unknown")
        require(
            unknown["terminal_observed"] is False
            and unknown["intent_durable"] is True
            and unknown["breaker"] is True
        )
        require(unknown["additional_invocations"] == unknown["drain_posts"] == 0)
        require(facts.one("postgres", "release_gate")["row_count"] == 1)
        require(
            not facts.all("host", "tool_result")
            and case.receipt_disposition == "unknown_retained"
        )
    elif subject == "residual_boundaries":
        row = facts.one("consumer", "capability_observed")
        require(
            row["c3_atomic_replace_and_seal"] is False
            and row["cf_13"] == "NOT_SUPPORTED"
        )
        require(row["residual_boundaries"] == list(OPENCLAW_RESIDUAL_BOUNDARIES))
    else:
        _blocked(facts, expected_reason=subject)
        if subject in {"binding.strong", "binding.restricted"}:
            row = facts.one("consumer", "binding_proof")
            require(
                row["mode"]
                == (
                    "strong_binding"
                    if subject == "binding.strong"
                    else "restricted_allow_once"
                )
            )
            require(row["original_action_digest"] != row["attempted_action_digest"])
        if subject.startswith("receipt.") or subject == "release.confirmation_required":
            require(facts.one("journal", "breaker")["open"] is True)


def _event(facts: Facts, event_type: str) -> None:
    row = facts.one("consumer", "event_evaluated")
    event = GuardEvent.model_validate(row["event"])
    require(
        event.event_type == event_type and event.runtime == facts.observation.runtime
    )
    require(row["event_digest"] == canonical_sha256(row["event"]))
    require(
        row["policy_audit_id"]
        == facts.one("postgres", "event_receipt")["policy_audit_id"]
    )
    if event_type in {
        "context_assembled",
        "model_input_prepared",
        "model_output_produced",
        "tool_result_produced",
    }:
        raw = facts.one("consumer", "quarantined_content")
        sentinel = raw["original"]
        require(type(sentinel) is str and len(sentinel) >= 8)
        require(_contains_sentinel(event.payload.model_dump(mode="json"), sentinel))
        next_request = facts.one("model", "next_request")
        request = facts.store.read_json(next_request["body"]).data
        require(
            type(request) is dict
            and type(request.get("messages")) is list
            and bool(request["messages"])
        )
        require(exact(request, raw["next_model_input"]))
        require(
            next_request["request_id"] != raw["original_request_id"]
            and type(next_request["request_id"]) is str
            and bool(next_request["request_id"])
        )
        memory = facts.store.read_json(raw["memory_snapshot"]).data
        inbox = facts.store.read_json(raw["inbox_snapshot"]).data
        require(type(memory) is list and type(inbox) is list)
        require(
            exact(memory, raw["memory_values"]) and exact(inbox, raw["inbox_values"])
        )
        require(
            not _contains_sentinel(request, sentinel)
            and not _contains_sentinel(memory, sentinel)
            and not _contains_sentinel(inbox, sentinel)
        )
        require(raw["disposition"] == "isolated")


def _contains_sentinel(value: Any, sentinel: str, depth: int = 0) -> bool:
    if depth > 32:
        return True
    if type(value) is str:
        if sentinel in value:
            return True
        # ToolMessage content commonly contains serialized JSON. Match its
        # actual strings too, including escaped quotes/newlines/unicode.
        if value.lstrip().startswith(("{", "[", '"')):
            try:
                decoded = strict_json(value.encode("utf-8"))
            except (ValueError, RecursionError):
                return False
            return _contains_sentinel(decoded, sentinel, depth + 1)
        return False
    if type(value) is list:
        return any(_contains_sentinel(item, sentinel, depth + 1) for item in value)
    if type(value) is dict:
        return any(
            _contains_sentinel(key, sentinel, depth + 1)
            or _contains_sentinel(item, sentinel, depth + 1)
            for key, item in value.items()
        )
    return False


def _target_result_isolation(
    facts: Facts, receipt: RuntimeOutcomeReceipt, target_id: str
) -> None:
    disposition = receipt.evidence.result.disposition
    if disposition == "unknown" and receipt.runtime == "openclaw":
        checkpoints = facts.all("consumer", "target_result_isolation")
        target = next(
            call
            for call in facts.all("host", "tool_invocation")
            if call["invocation_id"] == target_id
        )
        if not checkpoints:
            require(target["tool_name"] != "agentguard_memory_read")
            return
        require(len(checkpoints) == 1)
        # OpenClaw's after-action receipt does not attest result publication;
        # its separate content checkpoint supplies this observation.
        disposition = checkpoints[0]["disposition"]
        require(disposition in {"quarantined", "modified"})
    if disposition not in {"quarantined", "modified"}:
        return
    evidence = facts.one("consumer", "target_result_isolation")
    require(
        evidence["invocation_id"] == target_id
        and evidence["disposition"] == disposition
    )
    results = [
        frame
        for frame in facts.rows
        if frame.actor == "host"
        and frame.event == "tool_result"
        and frame.data["invocation_id"] == target_id
    ]
    require(len(results) == 1)
    result = results[0]
    require(evidence["original_result_digest"] == result.data["result_digest"])
    artifacts = [facts.store.read_file(ref) for ref in result.attachments]
    originals = [
        file for file in artifacts if file.raw_sha256 == result.data["result_digest"]
    ]
    require(len(originals) == 1)
    original = _host_text(originals[0].content)
    sentinel = evidence["withheld_content"]
    require(type(sentinel) is str and len(sentinel) >= 8)
    require(_contains_sentinel(original, sentinel))
    released = facts.store.read_json(evidence["released_result"]).data
    request = facts.store.read_json(evidence["next_model_request"]).data
    memory = facts.store.read_json(evidence["subsequent_memory_writes"]).data
    inbox = facts.store.read_json(evidence["subsequent_inbox_messages"]).data
    require(
        type(request) is dict
        and type(request.get("messages")) is list
        and bool(request["messages"])
    )
    require(type(memory) is list and type(inbox) is list)
    require(
        all(
            not _contains_sentinel(value, sentinel)
            for value in (released, request, memory, inbox)
        )
    )
    if disposition == "quarantined":
        require(evidence["published_original"] is False)
        require(receipt.evidence.execution.tool_result_entered_context is not True)
    else:
        require(
            (
                receipt.evidence.result.sanitized is True
                or receipt.evidence.result.disposition == "unknown"
            )
            and evidence["sanitized"] is True
        )


def _native_observed_call(
    facts: Facts, case: CaseResult, tool: str, call: dict[str, Any]
) -> None:
    selected = [
        frame
        for frame in facts.rows
        if frame.data.get("invocation_id") == call["invocation_id"]
        and (frame.actor, frame.event)
        in {
            ("model", "tool_call_requested"),
            ("host", "tool_invocation"),
            ("host", "tool_result"),
            ("effect", "snapshot"),
        }
    ]
    subset = facts.observation.model_copy(
        update={
            "frames": [
                frame.model_copy(update={"sequence": index})
                for index, frame in enumerate(selected)
            ]
        }
    )
    single = case.model_copy(
        update={"invocation_count": 1, "model_kind": "controlled_local"}
    )
    _native(Facts(subset, facts.store), single, tool, check_entrypoint=False)


def _observed_start(
    facts: Facts, call: dict[str, Any], receipt: RuntimeOutcomeReceipt, reference: Any
) -> None:
    frames = [
        frame
        for frame in facts.rows
        if frame.actor == "http"
        and frame.event == "action_start_confirmed"
        and frame.data["invocation_id"] == call["invocation_id"]
    ]
    require(len(frames) == 1)
    frame = frames[0]
    require(exact(frame.data["start"], reference))
    require(frame.data["audit_id"] == receipt.links.parent_audit_id)
    start = facts.store.read_json(reference).data
    confirmation = facts.store.read_json(start["confirmation"]).data
    require(_utc(frame.data["confirmed_at"]) == _utc(confirmation["confirmed_at"]))
    require(receipt.evidence.execution.invoked_at is not None)
    require(call["invoked_at"] == receipt.evidence.execution.invoked_at)
    require(_utc(frame.data["confirmed_at"]) <= _utc(call["invoked_at"]))
    invocations = [
        row
        for row in facts.rows
        if row.actor == "host"
        and row.event == "tool_invocation"
        and row.data["invocation_id"] == call["invocation_id"]
    ]
    require(len(invocations) == 1 and frame.sequence < invocations[0].sequence)


def _registration(
    materials: dict[str, VerifiedDocument],
    report: ConformanceReport,
    observed: RuntimeCapabilityReportV2,
    candidate: VerifiedCandidate,
    store: EvidenceStore,
) -> None:
    observed_doc = materials["observed_capability"].data
    registration_doc = store.read_json(observed_doc["registration_evidence"])
    registration = object_fields(
        registration_doc.data,
        {
            "schema_version",
            "source_revision",
            "runtime",
            "product_active_enabled",
            "registered_event_types",
            "capability_report_digest",
            "inventory",
            "consumers",
            "hook_execution_order",
        },
        "conformance_registration_invalid",
    )
    require(
        registration["schema_version"] == "agentguard-product-consumer-registration/1"
    )
    require(
        registration["source_revision"] == report.source_revision
        and registration["runtime"] == report.runtime
    )
    require(
        registration["product_active_enabled"] is False
        and registration["registered_event_types"] == list(PRODUCT_EVENT_TYPES)
    )
    require(registration["capability_report_digest"] == observed.report_digest)
    require(exact(registration["inventory"], materials["product_inventory"].data))
    require(
        [row["event_type"] for row in registration["consumers"]]
        == list(PRODUCT_EVENT_TYPES)
    )
    for row, capability in zip(registration["consumers"], observed.events, strict=True):
        object_fields(
            row,
            {
                "event_type",
                "enforcement",
                "residual_boundaries",
                "consumer_module",
                "consumer_file",
                "entrypoint",
                "scope_id",
                "process_id",
            },
            "conformance_registration_consumer_invalid",
        )
        require(
            row["enforcement"] == capability.enforcement
            and row["residual_boundaries"] == capability.residual_boundaries
        )
        require(row["scope_id"] != report.formal_scope_id)
        probe = read_model(
            Observation,
            {
                "schema_version": "agentguard-product-case-observation/1",
                "runtime": report.runtime,
                "source_revision": report.source_revision,
                "candidate_manifest_digest": report.candidate_manifest_digest,
                "adapter_artifact_digest": report.adapter_artifact_digest,
                "case_id": f"contract.event.{row['event_type']}",
                "scope_id": row["scope_id"],
                "process_id": row["process_id"],
                "consumer_module": row["consumer_module"],
                "consumer_file": row["consumer_file"],
                "entrypoint": row["entrypoint"],
                "authority_kind": "synthetic_contract_fixture",
                "frames": [
                    {
                        "sequence": 0,
                        "actor": "consumer",
                        "event": "registration",
                        "data": {},
                        "attachments": [],
                    }
                ],
            },
        )
        _installed_consumer(probe, candidate, store)
    hook = object_fields(
        materials["hook_order"].data,
        {
            "schema_version",
            "runtime",
            "tool_source_order",
            "hook_execution_order",
            "consumer_registration_order",
            "registration_evidence",
        },
        "conformance_hook_order_invalid",
    )
    require(
        hook["schema_version"] == "agentguard-product-hook-order/1"
        and hook["runtime"] == report.runtime
    )
    require(
        store.read_json(hook["registration_evidence"]).canonical_digest
        == registration_doc.canonical_digest
    )
    require(hook["consumer_registration_order"] == list(PRODUCT_EVENT_TYPES))
    if report.runtime == "openclaw":
        expected_hooks = [
            "before_tool_call",
            "after_tool_call",
            "tool_result_persist",
            "message_sending",
            "llm_input",
            "llm_output",
            "agent_end",
        ]
        require(
            hook["tool_source_order"]
            == materials["product_inventory"].data["plugin_order"]
        )
        lane = next(
            row
            for row in candidate.installation_reports["openclaw"].data["lanes"]
            if row["lane"] == "product"
        )
        inspection = lane["product_inspection"]
        require(exact(inspection["inventory"], registration["inventory"]))
        require(
            exact(
                inspection["capabilityConsumers"],
                [
                    {
                        key: row[key]
                        for key in ("event_type", "enforcement", "residual_boundaries")
                    }
                    for row in registration["consumers"]
                ],
            )
        )
        require(
            inspection["residualBoundaries"] == list(OPENCLAW_RESIDUAL_BOUNDARIES)
            and inspection["active"] is False
        )
    else:
        # Native StateGraph has explicit consumers, not OpenClaw hook callbacks.
        expected_hooks = []
        require(
            hook["tool_source_order"]
            == ["agentguard-langgraph-adapter:isolated-product-tools-v1"]
        )
    require(
        hook["hook_execution_order"]
        == registration["hook_execution_order"]
        == expected_hooks
    )


def _policy(
    facts: Facts,
    case: CaseResult,
    requirement: Requirement,
    policies: dict[str, PolicyBundle],
) -> None:
    row = facts.one("consumer", "product_authority_selected")
    from .policy_evidence import verify_policy_evidence
    from .policy_terminal import verify_policy_terminal

    verify_policy_evidence(
        row,
        runtime=facts.observation.runtime,
        scope_id=facts.observation.scope_id,
        policy=policies[str(requirement.policy_group)],
        store=facts.store,
        candidate_manifest_digest=facts.observation.candidate_manifest_digest,
        adapter_artifact_digest=facts.observation.adapter_artifact_digest,
    )
    require("terminal_evidence" in row, "conformance_policy_terminal_invalid")
    target_receipt = verify_policy_terminal(
        row["terminal_evidence"],
        row=row,
        runtime=facts.observation.runtime,
        scope_id=facts.observation.scope_id,
        policy=policies[str(requirement.policy_group)],
        store=facts.store,
        candidate_manifest_digest=facts.observation.candidate_manifest_digest,
        adapter_artifact_digest=facts.observation.adapter_artifact_digest,
    )
    event = GuardEvent.model_validate(row["event"])
    authority = ProductDecisionAuthorityEvidenceV1.model_validate(row["authority"])
    require(exact(authority.model_dump(mode="json"), row["authority"]))
    require(
        authority.event_id == event.event_id
        and authority.event_type == event.event_type
        and authority.runtime == event.runtime == facts.observation.runtime
    )
    require(
        authority.policy_digest == case.policy_digest
        and authority.selected_decision.decision == requirement.policy_group
    )
    assessment = FastAssessment.model_validate(row["assessment"])
    require(compute_assessment_digest(assessment) == assessment.assessment_digest)
    require(
        assessment.assessment_id == authority.assessment_id
        and assessment.assessment_digest == authority.assessment_digest
    )
    require(
        assessment.event_id == event.event_id
        and assessment.snapshot_digest == authority.snapshot_digest
    )
    require(assessment.policy_digest == authority.policy_digest)
    require(
        exact(
            GuardEngine().finalize(assessment).model_dump(mode="json"),
            authority.raw_v21_decision.model_dump(mode="json"),
        )
    )
    exchange = facts.one("http", "evaluate_exchange")
    require(
        exchange["method"] == "POST"
        and exchange["path"] == "/v1/guard/evaluate"
        and exchange["status"] == 200
    )
    require(
        exact(
            GuardEvent.model_validate(exchange["request"]).model_dump(mode="json"),
            row["event"],
        )
        and exchange["policy_audit_id"] == row["policy_audit_id"]
    )
    require(
        type(exchange["request_wire"]) is str
        and exact(
            strict_json(exchange["request_wire"].encode("utf-8")), exchange["request"]
        )
    )
    require(exchange["authority_digest"] == canonical_sha256(row["authority"]))
    actual_current = GuardEngine().evaluate(
        event, policies[str(requirement.policy_group)]
    )
    require(actual_current.decision == authority.current_decision.decision)
    require(
        exact(
            [hit.model_dump(mode="json") for hit in actual_current.rule_hits],
            [
                hit.model_dump(mode="json")
                for hit in authority.current_decision.rule_hits
            ],
        )
    )
    name, _, args = product_tool_arguments(event)
    expected = {
        "file": "write" if requirement.policy_group == "ask" else "read",
        "command": "exec",
        "memory": (
            "agentguard_memory_read"
            if requirement.policy_group == "allow"
            else "agentguard_memory_write"
        ),
        "message": "message",
    }[requirement.subject]
    require(name == expected)
    if requirement.subject == "file":
        require(
            args["path"]
            == {"allow": "fixture.txt", "ask": "output.txt", "deny": "private.txt"}[
                str(requirement.policy_group)
            ]
        )
    upstream = facts.all("consumer", "upstream_authority")
    require(
        [item["event_type"] for item in upstream]
        == ["context_assembled", "model_input_prepared", "model_output_produced"]
    )
    for item in upstream:
        selected = ProductDecisionAuthorityEvidenceV1.model_validate(item["authority"])
        require(
            selected.event_type == item["event_type"]
            and selected.policy_digest == case.policy_digest
            and selected.selected_decision.decision == "allow"
        )
        require(
            selected.runtime == authority.runtime
            and selected.profile_digest == authority.profile_digest
            and selected.decision_authority.activation_ref_digest
            == authority.decision_authority.activation_ref_digest
        )
        require(item["scope_id"] == facts.observation.scope_id)
        require(
            item["receipt_confirmed"] is True
            and item["policy_audit_id"] in row["upstream_policy_audit_ids"]
        )
    proof = facts.one("consumer", "action_proof")
    require(
        proof["event_id"] == event.event_id
        and proof["arguments_digest"] == canonical_sha256(args)
    )
    require(proof["model_output_policy_audit_id"] == upstream[-1]["policy_audit_id"])
    replay_evidence = facts.store.read_json(row["replay"]).data
    require(exact(proof["coverage"], replay_evidence["coverage"]))
    require(proof["dataflow"] == replay_evidence["coverage"]["dataflow"]["status"])
    if requirement.policy_group != "deny":
        require(proof["dataflow"] == "complete")
    target_calls = [
        call
        for call in facts.all("host", "tool_invocation")
        if call["role"] == "target"
    ]
    require(len(target_calls) == (0 if requirement.policy_group == "deny" else 1))
    prerequisite_expected = (
        requirement.subject == "memory" and requirement.policy_group == "allow"
    ) or (requirement.subject == "command" and requirement.policy_group == "ask")
    prerequisite_calls = [
        call
        for call in facts.all("host", "tool_invocation")
        if call["role"] == "prerequisite"
    ]
    require(len(prerequisite_calls) == int(prerequisite_expected))
    require(
        len(facts.all("host", "tool_invocation"))
        == len(target_calls) + len(prerequisite_calls)
    )
    if event.runtime == "openclaw" or requirement.policy_group == "deny":
        require(not facts.all("http", "action_start_confirmed"))
    for call in target_calls:
        require(call["tool_name"] == name and exact(call["arguments"], args))
        target_id = call["invocation_id"]
        selected = [
            frame
            for frame in facts.rows
            if frame.data.get("invocation_id") == target_id
            and (frame.actor, frame.event)
            in {
                ("model", "tool_call_requested"),
                ("host", "tool_invocation"),
                ("host", "tool_result"),
                ("effect", "snapshot"),
            }
        ]
        subset = facts.observation.model_copy(
            update={
                "frames": [
                    frame.model_copy(update={"sequence": index})
                    for index, frame in enumerate(selected)
                ]
            }
        )
        target_case = case.model_copy(
            update={"invocation_count": 1, "model_kind": "controlled_local"}
        )
        _native(Facts(subset, facts.store), target_case, name, check_entrypoint=False)
        _target_result_isolation(facts, target_receipt, target_id)
        if event.runtime == "langgraph":
            terminal_document = facts.store.read_json(row["terminal_evidence"]).data
            _observed_start(facts, call, target_receipt, terminal_document["start"])
    if requirement.policy_group == "deny":
        snapshots = [
            frame.data
            for frame in facts.rows
            if frame.actor == "effect"
            and frame.event == "snapshot"
            and frame.data["invocation_id"] == row["target_invocation_id"]
        ]
        require(
            len(snapshots) == 2
            and [item["phase"] for item in snapshots] == ["before", "after"]
        )
        require(
            exact(
                {key: item for key, item in snapshots[0].items() if key != "phase"},
                {key: item for key, item in snapshots[1].items() if key != "phase"},
            )
        )
    if requirement.policy_group == "ask":
        approval, consume = facts.one("http", "approval_resolved"), facts.one(
            "http", "lease_consumed"
        )
        require(
            approval["resolution"] == "allow_once"
            and approval["policy_audit_id"] == row["policy_audit_id"]
        )
        require(
            consume["approval_id"] == approval["approval_id"]
            and consume["ok"] is True
            and approval["approval_id"] == target_receipt.links.approval_id
            and consume["lease_id"] == target_receipt.links.lease_id
            and consume["consumption_id"] == target_receipt.links.consumption_id
        )
        require(
            consume["release_mode"]
            == (
                "strong_binding"
                if event.runtime == "langgraph"
                else "restricted_allow_once"
            )
        )
    if requirement.subject == "memory" and requirement.policy_group == "allow":
        from .memory_prerequisite import verify_memory_prerequisite

        require("memory_prerequisite" in row, "conformance_memory_prerequisite_invalid")
        memory_fact = verify_memory_prerequisite(
            row["memory_prerequisite"],
            read_row=row,
            runtime=facts.observation.runtime,
            scope_id=facts.observation.scope_id,
            policy=policies["allow"],
            store=facts.store,
            candidate_manifest_digest=facts.observation.candidate_manifest_digest,
            adapter_artifact_digest=facts.observation.adapter_artifact_digest,
        )
        first = facts.one("consumer", "memory_prerequisite")
        require(
            first["selected_decision"] == "ask" and first["terminal_committed"] is True
        )
        require(
            first["scope_id"] == facts.observation.scope_id
            and first["memory_fact_id"] == row["memory_fact_id"]
            and row["memory_fact_id"] == memory_fact.memory_id
        )
        prerequisite = facts.store.read_json(row["memory_prerequisite"]).data
        write_row = facts.store.read_json(prerequisite["write_policy"]).data
        write_event = GuardEvent.model_validate(write_row["event"])
        write_name, _, write_args = product_tool_arguments(write_event)
        require(
            prerequisite_calls[0]["tool_name"] == write_name
            and exact(prerequisite_calls[0]["arguments"], write_args)
        )
        _native_observed_call(facts, case, write_name, prerequisite_calls[0])
        if event.runtime == "langgraph":
            first_receipt = RuntimeOutcomeReceipt.model_validate(
                facts.store.read_json(prerequisite["receipt"]).data, strict=True
            )
            _observed_start(
                facts, prerequisite_calls[0], first_receipt, prerequisite["start"]
            )
    if requirement.subject == "command" and requirement.policy_group == "ask":
        read = facts.one("consumer", "command_input_ancestry")
        require(
            read["source_tool"] == "read"
            and read["taint"] == "UNTRUSTED"
            and read["scope_id"] == facts.observation.scope_id
        )
        require(
            read["tool_result_policy_audit_id"] in proof["ancestor_policy_audit_ids"]
        )
        # The displayed read ancestry must identify the same typed records and
        # sources already reconstructed by the complete policy replay above.
        from agentguard_core import AuditEvent
        from guard_api.services.ct_projection import decode_ct_transient_facts
        from guard_api.services.product_model_content import read_product_tool_result
        from .policy_evidence import PolicyHistory, PolicyReplay

        replay = read_model(PolicyReplay, facts.store.read_json(row["replay"]).data)
        history = read_model(PolicyHistory, facts.store.read_json(replay.history).data)
        audits = [AuditEvent.model_validate(item) for item in history.audits]
        candidates = [
            item
            for item in audits
            if item.audit_id == read["tool_result_policy_audit_id"]
            and item.record_type == "policy_evaluation"
            and item.event_type == "tool_result_produced"
        ]
        require(len(candidates) == 1)
        original = candidates[0]
        result = read_product_tool_result(original)
        require(result.native_tool_name == "read")
        prior_rows = [facts.store.read_json(ref).data for ref in replay.prior_actions]
        require(
            sum(
                item.get("policy_audit_id") == result.parent_policy_audit_id
                for item in prior_rows
            )
            == 1
        )
        decoded = decode_ct_transient_facts(original)
        require(decoded.kind == "full" and decoded.bundle is not None)
        assert decoded.bundle is not None
        require(
            any(
                source.source_id in replay.product_data["source_refs"]
                and source.source_type == "tool_result"
                and source.trust == "untrusted"
                and "UNTRUSTED" in source.taints
                for source in decoded.bundle.source_facts
            )
        )
        require(
            set(proof["ancestor_policy_audit_ids"]).issubset(
                {
                    item.audit_id
                    for item in audits
                    if item.record_type == "policy_evaluation"
                }
            )
        )
        require(
            proof["model_output_policy_audit_id"]
            == replay.product_data["model_output_audit_id"]
        )
        prior_row = next(
            item
            for item in prior_rows
            if item["policy_audit_id"] == result.parent_policy_audit_id
        )
        prior_event = GuardEvent.model_validate(prior_row["event"])
        prior_name, _, prior_args = product_tool_arguments(prior_event)
        require(prior_name == "read" and prerequisite_calls[0]["tool_name"] == "read")
        require(exact(prerequisite_calls[0]["arguments"], prior_args))
        _native_observed_call(facts, case, "read", prerequisite_calls[0])
        if event.runtime == "langgraph":
            prior_receipt = RuntimeOutcomeReceipt.model_validate(
                facts.store.read_json(prior_row["receipt"]).data, strict=True
            )
            _observed_start(
                facts, prerequisite_calls[0], prior_receipt, prior_row["start"]
            )
        source_events = [
            GuardEvent.model_validate(item)
            for item in history.events
            if item["event_id"] == original.links["event_id"]
        ]
        require(len(source_events) == 1)
        require(source_events[0].event_type == "tool_result_produced")
        source_body = source_events[0].payload.model_dump(mode="json")["result"][
            "content_preview"
        ]
        host_frames = [
            frame
            for frame in facts.rows
            if frame.actor == "host"
            and frame.event == "tool_result"
            and frame.data["invocation_id"] == prerequisite_calls[0]["invocation_id"]
        ]
        require(len(host_frames) == 1)
        host_result = host_frames[0]
        matching = [
            facts.store.read_file(ref)
            for ref in host_result.attachments
            if ref.raw_sha256 == host_result.data["result_digest"]
        ]
        require(len(matching) == 1 and _host_text(matching[0].content) == source_body)
    require(case.receipt_disposition == "confirmed")
    receipt = facts.one("postgres", "target_receipt")
    require(
        receipt["policy_audit_id"] == row["policy_audit_id"]
        and receipt["event_id"] == event.event_id
        and receipt["row_count"] == 1
        and receipt["audit_id"] == target_receipt.audit_id
        and exact(receipt["links"], target_receipt.links.model_dump(mode="json"))
        and receipt["receipt_digest"]
        == canonical_sha256(target_receipt.model_dump(mode="json"))
    )


def verify_pre_activation(
    document: VerifiedDocument,
    candidate: VerifiedCandidate,
    policies: dict[str, PolicyBundle],
    store: EvidenceStore,
) -> VerifiedConformance:
    report = read_model(ConformanceReport, document.data)
    require(
        report.source_revision == candidate.manifest["source_revision"]
        and report.candidate_manifest_digest == candidate.canonical_digest
    )
    require((report.runtime_version, report.adapter_version) == PINS[report.runtime])
    artifact = next(
        item
        for item in candidate.artifacts
        if item.distribution == DISTRIBUTIONS[report.runtime]
        and item.kind in {"wheel", "npm_tgz"}
    )
    require(report.adapter_artifact_digest == artifact.raw_sha256)
    require(
        report.requirements_version == REQUIREMENTS_VERSION
        and report.requirements_digest == requirements_digest()
    )
    expected = requirements_for(report.runtime)
    require(
        [case.id for case in report.cases] == [item.id for item in expected],
        "conformance_case_set_invalid",
    )
    require(
        report.totals.model_dump()
        == {
            "required": len(expected),
            "passed": len(expected),
            "failed": 0,
            "skipped": 0,
        }
    )
    require([item.id for item in report.policies] == list(POLICY_GROUPS))
    policy_digests = {
        key: canonical_sha256(policy.model_dump(mode="json"))
        for key, policy in policies.items()
    }
    require(
        all(item.policy_digest == policy_digests[item.id] for item in report.policies)
    )
    materials = {
        key: store.read_json(ref) for key, ref in report.materials.model_dump().items()
    }
    _baseline_inventory(
        materials["baseline_inventory"].data,
        materials["product_inventory"].data,
        report.runtime,
        store,
    )
    require(
        materials["installation"].canonical_digest
        == candidate.installation_evidence.canonical_digest
    )
    observed_doc = object_fields(
        materials["observed_capability"].data,
        {"kind", "report", "registration_evidence"},
        "capability_observation_invalid",
    )
    require(observed_doc["kind"] == "observed_inactive_product_composition")
    observed = RuntimeCapabilityReportV2.model_validate(observed_doc["report"])
    target = derive_activation_target(observed_doc["report"])
    derived = object_fields(
        materials["activation_target_capability"].data,
        {"kind", "observed_report_digest", "report"},
        "capability_target_invalid",
    )
    require(
        derived["kind"] == "derived_activation_target"
        and derived["observed_report_digest"] == observed.report_digest
        and exact(derived["report"], target.model_dump(mode="json"))
    )
    _registration(materials, report, observed, candidate, store)
    scopes: set[str] = set()
    for case, requirement in zip(report.cases, expected, strict=True):
        require(case.status == "PASS", "conformance_case_not_passed")
        baseline = requirement.id.startswith("baseline.")
        require(
            case.evidence_kind
            == ("native_baseline" if baseline else "deterministic_contract")
        )
        require(
            case.authority_kind
            == ("none" if baseline else "synthetic_contract_fixture")
        )
        require(
            case.execution_scope
            == ("native_baseline" if baseline else "isolated_contract_fixture")
        )
        require(case.scope_id != report.formal_scope_id)
        require(
            case.policy_group == requirement.policy_group
            and case.policy_digest
            == (
                policy_digests[requirement.policy_group]
                if requirement.policy_group
                else None
            )
        )
        require(len(case.hashed_evidence) == 1)
        observation = read_model(
            Observation, store.read_json(case.hashed_evidence[0]).data
        )
        require(
            (
                observation.runtime,
                observation.source_revision,
                observation.candidate_manifest_digest,
                observation.adapter_artifact_digest,
                observation.case_id,
                observation.scope_id,
                observation.authority_kind,
            )
            == (
                report.runtime,
                report.source_revision,
                report.candidate_manifest_digest,
                report.adapter_artifact_digest,
                case.id,
                case.scope_id,
                case.authority_kind,
            )
        )
        _installed_consumer(observation, candidate, store)
        facts = Facts(observation, store)
        _invocations(facts, case)
        if requirement.validator == "native_invocation":
            _native(facts, case, requirement.subject)
        elif requirement.validator == "baseline_material":
            row = facts.one("consumer", "baseline_material")
            require(
                row["product_active_enabled"] is False
                and row["authority_kind"] == "none"
            )
            require(
                row["runtime_version"] == report.runtime_version
                and row["adapter_artifact_digest"] == report.adapter_artifact_digest
            )
            require(
                row["inventory_digest"]
                == materials["baseline_inventory"].canonical_digest
            )
            require(
                row["installation_digest"] == materials["installation"].canonical_digest
            )
        elif requirement.validator == "event_consumer":
            _event(facts, requirement.subject)
        elif requirement.validator == "policy_chain":
            _policy(facts, case, requirement, policies)
        else:
            _protocol(facts, case, requirement.subject)
        scopes.add(case.scope_id)
    require(report.formal_scope_id not in scopes)
    return VerifiedConformance(
        report, document, observed, target, materials["product_inventory"].data
    )
