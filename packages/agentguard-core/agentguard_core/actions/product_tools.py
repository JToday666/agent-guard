"""Server-verified semantics for the eight isolated Product runtime tools.

This module never accepts effects from an event. The API first verifies the
signed inventory/profile, then binds its immutable descriptor to one complete
event. A verified tool describes execution semantics, never content trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
import json
import hashlib
import hmac
from pathlib import PurePosixPath
import re
import secrets
from typing import Any, Mapping

from ..events.contracts import GuardEvent
from ..events.payloads import MemoryEventPayload, MessageSendPayload, ToolCallPayload
from .canonical_json import canonical_json_bytes, canonical_sha256
from .models import ActionEffect
from .normalize import normalize_arguments

PRODUCT_TOOL_SEMANTICS_VERSION = "isolated-product-tools-2"
PRODUCT_INBOX_TARGET = "fixture-inbox@agentguard.invalid"
PRODUCT_TOOL_NAMES = (
    "agentguard_memory_read",
    "agentguard_memory_write",
    "edit",
    "exec",
    "message",
    "process",
    "read",
    "write",
)
_ISSUER = object()
# Process-local authentication of the compiler's immutable object projection.
# No registry, persistence, wire authority or external signing key is involved.
_ISSUANCE_KEY = secrets.token_bytes(32)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\.txt\Z")
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PROFILE_FIELDS = (
    "runtime",
    "runtime_version",
    "plugin_version",
    "profile_id",
    "agent_id",
    "runtime_binding_id",
    "principal_id",
    "adapter_artifact_digest",
    "capability_report_digest",
    "host_inventory_digest",
    "plugin_inventory_digest",
    "plugin_order_inventory_digest",
    "tool_inventory_digest",
)


def langgraph_host_inventory_digest(model_visible_tools: list[dict[str, Any]]) -> str:
    return canonical_sha256(
        {
            "schema_version": "1.0",
            "runtime": "langgraph",
            "model_visible_tools": model_visible_tools,
        }
    )


def product_model_visible_tools(
    descriptors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Cross-check the pinned LangChain 1.4.8 StructuredTool wire projection.

    Runtime collection must still capture the actual bound array. This pure
    restricted conversion merely rejects a catalog whose two projections differ.
    """

    def dereference(value: Any, root: dict[str, Any], depth: int = 0) -> Any:
        if depth > 32:
            raise ProductToolError("product_tool_schema_invalid")
        if type(value) is list:
            return [dereference(item, root, depth + 1) for item in value]
        if type(value) is not dict:
            return value
        if "$ref" in value:
            ref = value["$ref"]
            if type(ref) is not str or not ref.startswith("#/$defs/"):
                raise ProductToolError("product_tool_schema_invalid")
            selected: Any = root
            for token in ref[2:].split("/"):
                selected = selected[token.replace("~1", "/").replace("~0", "~")]
            return dereference(
                {
                    **selected,
                    **{key: item for key, item in value.items() if key != "$ref"},
                },
                root,
                depth + 1,
            )
        return {key: dereference(item, root, depth + 1) for key, item in value.items()}

    def remove_titles(value: dict[str, Any], parent: str = "") -> dict[str, Any]:
        return {
            key: remove_titles(item, key) if type(item) is dict else item
            for key, item in value.items()
            if key != "title" or type(item) is dict and parent == "properties"
        }

    result = []
    for descriptor in descriptors:
        raw = descriptor["input_schema"]
        schema = dereference(raw, raw)
        for key in ("$defs", "definitions", "title", "description"):
            schema.pop(key, None)
        result.append(
            {
                "type": "function",
                "function": {
                    "name": descriptor["tool_id"],
                    "description": descriptor["description"],
                    "parameters": remove_titles(schema),
                },
            }
        )
    return result


def product_command_script(runtime: str) -> bytes:
    if runtime == "langgraph":
        return (
            "from pathlib import Path\n"
            "import json, os\n"
            "p = Path('command-marker.txt')\n"
            "fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)\n"
            "try:\n"
            "    os.write(fd, b'isolated command executed\\n')\n"
            "    os.fsync(fd)\n"
            "finally:\n"
            "    os.close(fd)\n"
            "print(json.dumps({'ok': True, 'marker': str(p)}))\n"
        ).encode()
    if runtime == "openclaw":
        return (
            "import fs from 'node:fs';\n"
            "const p = 'command-marker.txt';\n"
            "const fd = fs.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW, 0o600);\n"
            "try { fs.writeSync(fd, 'isolated command executed\\n'); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }\n"
            "process.stdout.write(JSON.stringify({ok: true, marker: p}) + '\\n');\n"
        ).encode()
    raise ProductToolError("product_tool_profile_invalid")


def product_command_script_digest(runtime: str) -> str:
    return "sha256:" + hashlib.sha256(product_command_script(runtime)).hexdigest()


class ProductToolError(ValueError):
    """Fixed failures; never stringify an event, argument or descriptor."""

    def __init__(self, code: str = "product_tool_invalid") -> None:
        self.code = code
        super().__init__(code)


def product_tool_resource_identity(
    tool_name: str, descriptor_digest: str, semantics_digest: str
) -> str:
    if tool_name not in PRODUCT_TOOL_NAMES or not all(
        type(value) is str and _DIGEST.fullmatch(value)
        for value in (descriptor_digest, semantics_digest)
    ):
        raise ProductToolError()
    return (
        f"tool:{tool_name}:descriptor:{descriptor_digest}:semantics:{semantics_digest}"
    )


def _wire(value: Any) -> str:
    try:
        # The Core canonical encoder rejects floats/custom values and binds
        # complete strings. JSON round-tripping gives fresh private snapshots.
        canonical_sha256(value)
        result = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(result.encode("utf-8")) > 512 * 1024:
            raise ValueError
        return result
    except Exception:
        raise ProductToolError() from None


def _execution(value: Mapping[str, Any], runtime: str) -> dict[str, Any]:
    data = json.loads(_wire(dict(value)))
    if set(data) != {"root", "inbox_url", "script_digest", "memory_namespace"}:
        raise ProductToolError("product_tool_profile_invalid")
    root = data["root"]
    if (
        type(root) is not str
        or not root.startswith("/")
        or root == "/"
        or str(PurePosixPath(root)) != root
        or ".." in PurePosixPath(root).parts
        or "\\" in root
        or "\x00" in root
        or type(data["inbox_url"]) is not str
        or re.fullmatch(
            r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/inbox", data["inbox_url"]
        )
        is None
        or not 1 <= int(data["inbox_url"].split(":")[-1].split("/")[0]) <= 65535
        or type(data["script_digest"]) is not str
        or _DIGEST.fullmatch(data["script_digest"]) is None
        or data["script_digest"] != product_command_script_digest(runtime)
        or data["memory_namespace"] != root + "/memory.sqlite"
        or runtime not in {"langgraph", "openclaw"}
    ):
        raise ProductToolError("product_tool_profile_invalid")
    return data


def product_runtime_profile_digest(
    entry: Mapping[str, Any], execution: Mapping[str, Any]
) -> str:
    """The signed runtime profile commits identity, inventory and execution.

    ``profile_digest`` and candidate manifest hashes are intentionally absent
    from this projection, avoiding self-reference during signing.
    """
    try:
        identity = {key: entry[key] for key in _PROFILE_FIELDS}
        profile = _execution(execution, identity["runtime"])
        return canonical_sha256(
            {
                "schema_version": "1.0",
                "semantics_version": PRODUCT_TOOL_SEMANTICS_VERSION,
                "identity": identity,
                "execution": profile,
            }
        )
    except Exception:
        raise ProductToolError("product_tool_profile_invalid") from None


def product_tool_arguments(event: GuardEvent) -> tuple[str, str, dict[str, Any]]:
    """Project the actual tool's complete original arguments from its event.

    Special memory/message events retain a small, untrusted identity selector;
    the catalog and model-output verifier independently validate that selector.
    """
    payload = event.payload
    if isinstance(payload, ToolCallPayload):
        name, call_id, args = payload.tool.name, payload.tool.call_id, payload.arguments
    elif isinstance(payload, (MemoryEventPayload, MessageSendPayload)):
        selector = event.metadata.get("product_tool_call")
        if type(selector) is not dict or set(selector) != {"tool_name", "call_id"}:
            raise ProductToolError("product_tool_identity_required")
        name, call_id = selector["tool_name"], selector["call_id"]
        if isinstance(payload, MemoryEventPayload):
            if (
                name != "agentguard_memory_write"
                or call_id != payload.action_id
                or payload.memory.operation != "write"
            ):
                raise ProductToolError("product_tool_identity_mismatch")
            args = {"key": payload.memory.key, "value": payload.memory.value_preview}
        else:
            if name != "message":
                raise ProductToolError("product_tool_identity_mismatch")
            args = {
                "action": "send",
                "channel": payload.channel,
                "target": payload.recipient,
                "message": payload.content_preview,
            }
    else:
        raise ProductToolError("product_tool_event_invalid")
    if (
        name not in PRODUCT_TOOL_NAMES
        or type(call_id) is not str
        or not _ID.fullmatch(call_id)
    ):
        raise ProductToolError("product_tool_identity_mismatch")
    return name, call_id, json.loads(_wire(args))


def _validate_arguments(name: str, args: dict[str, Any], runtime: str) -> None:
    keys = {
        "read": {"path"},
        "write": {"path", "content"},
        "edit": {"path", "edits"},
        "exec": {"command"},
        "process": {"action"},
        "agentguard_memory_read": {"key"},
        "agentguard_memory_write": {"key", "value"},
        "message": {"action", "channel", "target", "message"},
    }[name]
    if set(args) != keys:
        raise ProductToolError("product_tool_arguments_invalid")
    for key, value in args.items():
        if key != "edits" and (type(value) is not str or len(value) > 32768):
            raise ProductToolError("product_tool_arguments_invalid")
    if "path" in args and not _FILE.fullmatch(args["path"]):
        raise ProductToolError("product_tool_arguments_invalid")
    if "key" in args and not _KEY.fullmatch(args["key"]):
        raise ProductToolError("product_tool_arguments_invalid")
    if name == "exec" and args["command"] != (
        "python marker.py" if runtime == "langgraph" else "node marker.mjs"
    ):
        raise ProductToolError("product_tool_command_forbidden")
    if name == "process" and args["action"] != "list":
        raise ProductToolError("product_tool_process_forbidden")
    if name == "message" and (args["action"], args["channel"], args["target"]) != (
        "send",
        "agentguard-fixture",
        PRODUCT_INBOX_TARGET,
    ):
        raise ProductToolError("product_tool_destination_forbidden")
    if name == "edit":
        edits = args["edits"]
        if type(edits) is not list or not 1 <= len(edits) <= 8:
            raise ProductToolError("product_tool_arguments_invalid")
        for edit in edits:
            if (
                type(edit) is not dict
                or set(edit) != {"oldText", "newText"}
                or any(
                    type(value) is not str or len(value) > 32768
                    for value in edit.values()
                )
                or not edit["oldText"]
            ):
                raise ProductToolError("product_tool_arguments_invalid")


def _pointers(value: Any, prefix: str = "") -> tuple[str, ...]:
    if type(value) is dict:
        return tuple(
            pointer
            for key in sorted(value)
            for pointer in _pointers(
                value[key], prefix + "/" + key.replace("~", "~0").replace("/", "~1")
            )
        )
    if type(value) is list:
        return tuple(
            pointer
            for index, item in enumerate(value)
            for pointer in _pointers(item, prefix + "/" + str(index))
        )
    return (prefix,)


@dataclass(frozen=True, slots=True)
class VerifiedProductTool:
    runtime: str
    runtime_binding_id: str
    tool_name: str
    call_id: str
    event_id: str
    event_type: str
    descriptor_digest: str
    input_schema_digest: str
    inventory_digest: str
    semantics_digest: str
    argument_digest: str
    original_arguments_digest: str
    _arguments_json: str = field(repr=False)
    _resources_json: str = field(repr=False)
    _effects_json: str = field(repr=False)
    _event_digest: str = field(repr=False)
    _issuer: object = field(repr=False)
    _issuance_authenticator: str = field(repr=False)

    def arguments(self) -> dict[str, Any]:
        return json.loads(self._arguments_json)

    def required_argument_pointers(self) -> tuple[str, ...]:
        return _pointers(self.arguments())

    def resource_inputs(self) -> list[dict[str, Any]]:
        return json.loads(self._resources_json)

    def effects(self) -> ActionEffect:
        return ActionEffect.model_validate_json(self._effects_json)

    def assert_matches(
        self, event: GuardEvent, *, runtime_binding_id: str | None
    ) -> None:
        try:
            if (
                type(self) is not VerifiedProductTool
                or self._issuer is not _ISSUER
                or not hmac.compare_digest(
                    self._issuance_authenticator, _authenticate_tool(self)
                )
                or event.runtime != self.runtime
                or runtime_binding_id != self.runtime_binding_id
                or canonical_sha256(event.model_dump(mode="json")) != self._event_digest
            ):
                raise ValueError
        except Exception:
            raise ProductToolError("product_tool_binding_mismatch") from None


def _authenticate_tool(tool: VerifiedProductTool) -> str:
    projection = {
        item.name: getattr(tool, item.name)
        for item in fields(tool)
        if item.name not in {"_issuer", "_issuance_authenticator"}
    }
    return hmac.new(
        _ISSUANCE_KEY,
        b"agentguard/product-tool-object/v1\x00" + canonical_json_bytes(projection),
        hashlib.sha256,
    ).hexdigest()


def bind_verified_product_tool(
    event: GuardEvent,
    *,
    runtime_binding_id: str,
    inventory_digest: str,
    descriptor: Mapping[str, Any],
    execution: Mapping[str, Any],
) -> VerifiedProductTool:
    """API-internal factory; inputs must come from the verified local catalog."""
    name, call_id, args = product_tool_arguments(event)
    profile = _execution(execution, event.runtime)
    if descriptor.get("tool_id") != name:
        raise ProductToolError("product_tool_identity_mismatch")
    _validate_arguments(name, args, event.runtime)
    expected_event = {
        "agentguard_memory_write": "memory_write_proposed",
        "message": "message_send_proposed",
    }.get(name, "tool_call_proposed")
    if event.event_type != expected_event or event.pre_execution is not True:
        raise ProductToolError("product_tool_event_invalid")
    if (
        isinstance(event.payload, MemoryEventPayload)
        and event.payload.memory.namespace != profile["memory_namespace"]
    ):
        raise ProductToolError("product_tool_resource_mismatch")
    effects: dict[str, Any] = {}
    resources: list[dict[str, Any]] = []
    if name in {"read", "write", "edit"}:
        resources.append(
            {"kind": "file", "target": profile["root"] + "/" + args["path"]}
        )
        if name != "read":
            effects = {"mutates_state": True, "persistence": True}
    elif name.startswith("agentguard_memory_"):
        resources.append(
            {
                "kind": "memory",
                "target": args["key"],
                "memory_namespace": profile["memory_namespace"],
            }
        )
        if name.endswith("write"):
            effects = {"mutates_state": True, "persistence": True}
    elif name == "exec":
        effects = {"code_execution": True, "mutates_state": True, "persistence": True}
        resources.extend(
            [
                {"kind": "process", "target": args["command"]},
                {
                    "kind": "file",
                    "target": profile["root"]
                    + "/"
                    + ("marker.py" if event.runtime == "langgraph" else "marker.mjs"),
                },
                {"kind": "file", "target": profile["root"] + "/command-marker.txt"},
            ]
        )
    elif name == "message":
        effects = {
            "external_communication": True,
            "data_egress": True,
            "network_access": True,
        }
        resources.append(
            {"kind": "api", "target": profile["inbox_url"], "method": "POST"}
        )
    descriptor_digest = canonical_sha256(dict(descriptor))
    schema_digest = (
        canonical_sha256(descriptor["input_schema"])
        if "input_schema" in descriptor
        else descriptor.get("input_schema_digest")
    )
    if type(schema_digest) is not str or not _DIGEST.fullmatch(schema_digest):
        raise ProductToolError("product_tool_schema_invalid")
    semantics_digest = canonical_sha256(
        {
            "version": PRODUCT_TOOL_SEMANTICS_VERSION,
            "inventory_digest": inventory_digest,
            "descriptor_digest": descriptor_digest,
            "execution": profile,
        }
    )
    issued = VerifiedProductTool(
        runtime=event.runtime,
        runtime_binding_id=runtime_binding_id,
        tool_name=name,
        call_id=call_id,
        event_id=event.event_id,
        event_type=event.event_type,
        descriptor_digest=descriptor_digest,
        input_schema_digest=schema_digest,
        inventory_digest=inventory_digest,
        semantics_digest=semantics_digest,
        argument_digest=normalize_arguments(args).canonical.argument_digest,
        original_arguments_digest=canonical_sha256(args),
        _arguments_json=_wire(args),
        _resources_json=_wire(resources),
        _effects_json=_wire(ActionEffect(**effects).model_dump(mode="json")),
        _event_digest=canonical_sha256(event.model_dump(mode="json")),
        _issuer=_ISSUER,
        _issuance_authenticator="",
    )
    # Only the binder issues authentication. Dataclass replacement, unchecked
    # construction and private-field changes never trigger re-signing.
    object.__setattr__(issued, "_issuance_authenticator", _authenticate_tool(issued))
    return issued
