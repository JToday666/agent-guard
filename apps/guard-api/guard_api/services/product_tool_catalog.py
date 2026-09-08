"""Protected, signed-inventory-bound Product tool semantics (no activation path)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.product_tools import (
    PRODUCT_TOOL_NAMES,
    PRODUCT_TOOL_SEMANTICS_VERSION,
    VerifiedProductTool,
    bind_verified_product_tool,
    langgraph_host_inventory_digest,
    product_model_visible_tools,
    product_runtime_profile_digest,
    product_tool_arguments,
)
from agentguard_core.decisions.activation_ack import ActivationAckV1
from agentguard_core.decisions.product import (
    OpenClawFrozenToolV1,
    ProductActivationBundleV1,
    build_openclaw_inventory_digests,
)
from agentguard_core.events.contracts import GuardEvent

_MAX_BYTES = 512 * 1024
_LG_SOURCE = "agentguard-langgraph-adapter:isolated-product-tools-v1"
_LG_SEMANTICS = {
    "agentguard_memory_read": ("tool_call_proposed", "memory", "memory_read", "read"),
    "agentguard_memory_write": (
        "memory_write_proposed",
        "memory",
        "memory_write",
        "write",
    ),
    "edit": ("tool_call_proposed", "file", "file_edit", "write"),
    "exec": ("tool_call_proposed", "code", "command_exec", "execute"),
    "message": ("message_send_proposed", "message", "local_message_send", "send"),
    "process": ("tool_call_proposed", "code", "process_list", "read"),
    "read": ("tool_call_proposed", "file", "file_read", "read"),
    "write": ("tool_call_proposed", "file", "file_write", "write"),
}
_SCALAR_KEYS = {
    "read": ("path",),
    "write": ("path", "content"),
    "edit": ("path",),
    "exec": ("command",),
    "process": ("action",),
    "agentguard_memory_read": ("key",),
    "agentguard_memory_write": ("key", "value"),
    "message": ("action", "channel", "target", "message"),
}
_SCHEMA_KEYS = {
    "$ref",
    "$defs",
    "$schema",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "anyOf",
    "oneOf",
    "allOf",
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "minimum",
    "patternProperties",
}


class ProductToolCatalogError(ValueError):
    def __init__(self, code: str = "product_tool_catalog_invalid") -> None:
        self.code = code
        super().__init__(code)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _read(path: str) -> tuple[dict[str, Any], tuple[int, ...]]:
    directory_fd = descriptor = None
    try:
        target = Path(path)
        if not target.is_absolute() or str(target) != path or ".." in target.parts:
            raise ValueError
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for component in target.parts[1:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        parent = os.fstat(directory_fd)
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError
        descriptor = os.open(
            target.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= _MAX_BYTES
        ):
            raise ValueError
        chunks: list[bytes] = []
        count = 0
        while chunk := os.read(descriptor, min(65536, _MAX_BYTES + 1 - count)):
            chunks.append(chunk)
            count += len(chunk)
            if count > _MAX_BYTES:
                raise ValueError
        after = os.fstat(descriptor)
        current = os.stat(target.name, dir_fd=directory_fd, follow_symlinks=False)

        def fingerprint(info: os.stat_result) -> tuple[int, ...]:
            return (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        if fingerprint(before) != fingerprint(after) or fingerprint(
            after
        ) != fingerprint(current):
            raise ValueError
        value = json.loads(b"".join(chunks), object_pairs_hook=_pairs)
        if type(value) is not dict:
            raise ValueError
        canonical_sha256(value)
        return value, fingerprint(after)
    except Exception:
        raise ProductToolCatalogError("product_tool_catalog_unreadable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def _schema(schema: Any, value: Any, root: dict[str, Any], depth: int = 0) -> None:
    """Validate the bounded subset used by the pinned real tool schemas.

    References are local only. Unsupported validation keywords fail closed;
    schema text never causes network access or controls execution effects.
    """
    if depth > 32 or type(schema) is not dict:
        raise ValueError
    if set(schema) - _SCHEMA_KEYS:
        raise ValueError
    if "$ref" in schema:
        ref = schema["$ref"]
        if type(ref) is not str or not ref.startswith("#/$defs/"):
            raise ValueError
        selected: Any = root
        for token in ref[2:].split("/"):
            selected = selected[token.replace("~1", "/").replace("~0", "~")]
        _schema(selected, value, root, depth + 1)
    for keyword in ("anyOf", "oneOf", "allOf"):
        if keyword in schema:
            results = []
            for branch in schema[keyword]:
                try:
                    _schema(branch, value, root, depth + 1)
                    results.append(True)
                except (ValueError, KeyError, TypeError):
                    results.append(False)
            if (
                not results
                or (keyword == "allOf" and not all(results))
                or (keyword == "anyOf" and not any(results))
                or (keyword == "oneOf" and results.count(True) != 1)
            ):
                raise ValueError
    kind = schema.get("type")
    expected = {
        "string": str,
        "object": dict,
        "array": list,
        "integer": int,
        "boolean": bool,
        "null": type(None),
    }
    if kind == "number":
        if type(value) not in {int, float}:
            raise ValueError
    elif kind is not None and (
        kind not in expected or type(value) is not expected[kind]
    ):
        raise ValueError
    if (
        "minimum" in schema
        and type(value) in {int, float}
        and value < schema["minimum"]
    ):
        raise ValueError
    if "const" in schema and (
        type(value) is not type(schema["const"]) or value != schema["const"]
    ):
        raise ValueError
    if "enum" in schema and not any(
        type(value) is type(item) and value == item for item in schema["enum"]
    ):
        raise ValueError
    if type(value) is dict:
        properties = schema.get("properties", {})
        if set(schema.get("required", [])) - set(value):
            raise ValueError
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            raise ValueError
        for key, item in value.items():
            if key in properties:
                _schema(properties[key], item, root, depth + 1)
            for pattern, child in schema.get("patternProperties", {}).items():
                if re.search(pattern, key) is not None:
                    _schema(child, item, root, depth + 1)
    if type(value) is str:
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get(
            "maxLength", _MAX_BYTES
        ):
            raise ValueError
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValueError
    if type(value) is list:
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get(
            "maxItems", 1024
        ):
            raise ValueError
        for item in value:
            _schema(schema.get("items", {}), item, root, depth + 1)


def _schema_structure(schema: Any, root: dict[str, Any], depth: int = 0) -> None:
    if depth > 32 or type(schema) is not dict or set(schema) - _SCHEMA_KEYS:
        raise ValueError
    if schema.get("type") not in {
        None,
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }:
        raise ValueError
    if "$ref" in schema:
        ref = schema["$ref"]
        if type(ref) is not str or not ref.startswith("#/$defs/"):
            raise ValueError
        selected: Any = root
        for token in ref[2:].split("/"):
            selected = selected[token.replace("~1", "/").replace("~0", "~")]
        _schema_structure(selected, root, depth + 1)
    for key in ("properties", "$defs", "patternProperties"):
        if key in schema:
            if type(schema[key]) is not dict:
                raise ValueError
            for name, value in schema[key].items():
                if key == "patternProperties":
                    re.compile(name)
                _schema_structure(value, root, depth + 1)
    if "required" in schema and (
        type(schema["required"]) is not list
        or any(type(key) is not str for key in schema["required"])
        or len(set(schema["required"])) != len(schema["required"])
    ):
        raise ValueError
    if (
        "additionalProperties" in schema
        and type(schema["additionalProperties"]) is not bool
    ):
        raise ValueError
    if "items" in schema:
        _schema_structure(schema["items"], root, depth + 1)
    for keyword in ("anyOf", "oneOf", "allOf"):
        if keyword in schema:
            if type(schema[keyword]) is not list or not schema[keyword]:
                raise ValueError
            for child in schema[keyword]:
                _schema_structure(child, root, depth + 1)
    for keyword in ("minLength", "maxLength", "minItems", "maxItems"):
        if keyword in schema and (
            type(schema[keyword]) is not int or schema[keyword] < 0
        ):
            raise ValueError
    if "pattern" in schema:
        re.compile(schema["pattern"])


def _validate_shape(name: str, schema: dict[str, Any]) -> None:
    _schema_structure(schema, schema)
    if (
        type(schema) is not dict
        or schema.get("type") != "object"
        or type(schema.get("properties")) is not dict
    ):
        raise ValueError
    for key in _SCALAR_KEYS[name]:
        if schema["properties"].get(key, {}).get("type") != "string":
            raise ValueError
    if name == "edit" and schema["properties"].get("edits", {}).get("type") != "array":
        raise ValueError


class ProductToolCatalog:
    """Only trusted catalog hashes are public; source schemas remain private."""

    def __init__(self, path: str, activation: ProductActivationBundleV1) -> None:
        raw, fingerprint = _read(path)
        self._path = path
        self._fingerprint = fingerprint
        self._content_digest = canonical_sha256(raw)
        self._activation_digest = canonical_sha256(activation.model_dump(mode="json"))
        self._raw_json = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        try:
            self._validate(activation)
        except Exception:
            raise ProductToolCatalogError() from None

    @property
    def content_digest(self) -> str:
        return self._content_digest

    def __repr__(self) -> str:
        return f"ProductToolCatalog(content_digest={self.content_digest!r})"

    def _validate(self, activation: ProductActivationBundleV1) -> None:
        raw = json.loads(self._raw_json)
        if (
            set(raw) != {"schema_version", "semantics_version", "runtimes"}
            or raw["schema_version"] != "1.0"
            or raw["semantics_version"] != PRODUCT_TOOL_SEMANTICS_VERSION
        ):
            raise ValueError
        runtimes = raw["runtimes"]
        if (
            type(runtimes) is not list
            or not 1 <= len(runtimes) <= 2
            or len({item["runtime"] for item in runtimes}) != len(runtimes)
        ):
            raise ValueError
        for item in runtimes:
            if set(item) != {"runtime", "execution", "inventory"}:
                raise ValueError
            entry = activation.runtime_entry(item["runtime"])
            if (
                product_runtime_profile_digest(
                    entry.model_dump(mode="json"), item["execution"]
                )
                != entry.profile_digest
            ):
                raise ValueError
            inventory = item["inventory"]
            tools = inventory["tools"]
            if [tool["tool_id"] for tool in tools] != list(PRODUCT_TOOL_NAMES):
                raise ValueError
            if item["runtime"] == "langgraph":
                if (
                    set(inventory) != {"tools", "model_visible_tools"}
                    or canonical_sha256(tools) != entry.tool_inventory_digest
                    or langgraph_host_inventory_digest(inventory["model_visible_tools"])
                    != entry.host_inventory_digest
                    or inventory["model_visible_tools"]
                    != product_model_visible_tools(tools)
                ):
                    raise ValueError
                expected_binding = canonical_sha256(
                    {
                        "root": item["execution"]["root"],
                        "inbox_url": item["execution"]["inbox_url"],
                        "script_digest": item["execution"]["script_digest"],
                        "source_id": _LG_SOURCE,
                    }
                )
                for tool in tools:
                    if (
                        set(tool)
                        != {
                            "tool_id",
                            "source_id",
                            "description",
                            "input_schema",
                            "execution_schema",
                            "event_type",
                            "category",
                            "kind",
                            "operation",
                            "execution_binding_digest",
                            "fixture_id",
                        }
                        or tuple(
                            tool[key]
                            for key in ("event_type", "category", "kind", "operation")
                        )
                        != _LG_SEMANTICS[tool["tool_id"]]
                        or type(tool["description"]) is not str
                        or not 1 <= len(tool["description"]) <= 32768
                        or tool["source_id"] != _LG_SOURCE
                        or tool["execution_binding_digest"] != expected_binding
                        or tool["fixture_id"]
                        != f"langgraph:{tool['tool_id']}:isolated-v1"
                    ):
                        raise ValueError
                    _validate_shape(tool["tool_id"], tool["input_schema"])
                    _validate_shape(tool["tool_id"], tool["execution_schema"])
            else:
                if set(inventory) != {"tools", "input_schemas", "plugin_order"} or set(
                    inventory["input_schemas"]
                ) != set(PRODUCT_TOOL_NAMES):
                    raise ValueError
                frozen = [OpenClawFrozenToolV1.model_validate(tool) for tool in tools]
                digests = build_openclaw_inventory_digests(
                    tools=frozen, plugin_order=inventory["plugin_order"]
                )
                for key, value in digests.model_dump(
                    exclude={"schema_version"}
                ).items():
                    if getattr(entry, key) != value:
                        raise ValueError
                for tool in frozen:
                    source = (
                        "agentguard-product-runtime-fixture"
                        if tool.tool_id.startswith("agentguard_memory_")
                        else "openclaw-core"
                    )
                    schema = inventory["input_schemas"][tool.tool_id]
                    if (
                        tool.source_plugin_id != source
                        or canonical_sha256(schema) != tool.input_schema_digest
                        or tool.event_type
                        != (
                            "memory_write_proposed"
                            if tool.tool_id == "agentguard_memory_write"
                            else "tool_call_proposed"
                        )
                    ):
                        raise ValueError
                    _validate_shape(tool.tool_id, schema)

    def verify_current(
        self,
        activation: ProductActivationBundleV1,
        activation_ack: ActivationAckV1 | None = None,
    ) -> None:
        try:
            raw, fingerprint = _read(self._path)
            if (
                fingerprint != self._fingerprint
                or canonical_sha256(raw) != self.content_digest
                or canonical_sha256(activation.model_dump(mode="json"))
                != self._activation_digest
            ):
                raise ValueError
            if activation_ack is not None:
                entry = activation.runtime_entry(activation_ack.runtime)
                if (
                    activation_ack.activation_ref_digest
                    != activation.activation_ref_digest
                    or activation_ack.capability_digest
                    != entry.capability_report_digest
                ):
                    raise ValueError
                for name in (
                    "runtime",
                    "runtime_version",
                    "plugin_version",
                    "profile_id",
                    "agent_id",
                    "runtime_binding_id",
                    "host_inventory_digest",
                    "plugin_inventory_digest",
                    "plugin_order_inventory_digest",
                    "tool_inventory_digest",
                ):
                    if getattr(activation_ack, name) != getattr(entry, name):
                        raise ValueError
        except Exception:
            raise ProductToolCatalogError("product_tool_catalog_drift") from None

    def _tool(
        self, runtime: str, tool_name: str
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        raw = json.loads(self._raw_json)
        try:
            item = next(item for item in raw["runtimes"] if item["runtime"] == runtime)
            tool = next(
                tool
                for tool in item["inventory"]["tools"]
                if tool["tool_id"] == tool_name
            )
            schema = (
                tool["input_schema"]
                if runtime == "langgraph"
                else item["inventory"]["input_schemas"][tool_name]
            )
            return tool, schema, item["execution"]
        except Exception:
            raise ProductToolCatalogError("product_tool_catalog_missing_tool") from None

    def describe_tool(
        self,
        runtime: str,
        tool_name: str,
        *,
        activation: ProductActivationBundleV1,
        runtime_binding_id: str,
        activation_ack: ActivationAckV1 | None = None,
    ) -> dict[str, str]:
        self.verify_current(activation, activation_ack)
        try:
            if runtime not in ("langgraph", "openclaw"):
                raise ValueError
            entry = activation.runtime_entry(runtime)
        except Exception:
            raise ProductToolCatalogError(
                "product_tool_catalog_identity_mismatch"
            ) from None
        if (
            entry.runtime_binding_id != runtime_binding_id
            or activation_ack is not None
            and activation_ack.runtime != runtime
        ):
            raise ProductToolCatalogError("product_tool_catalog_identity_mismatch")
        tool, schema, execution = self._tool(runtime, tool_name)
        descriptor_digest = canonical_sha256(tool)
        return {
            "descriptor_digest": descriptor_digest,
            "input_schema_digest": canonical_sha256(schema),
            "inventory_digest": entry.tool_inventory_digest,
            "runtime_binding_id": runtime_binding_id,
            "semantics_digest": canonical_sha256(
                {
                    "version": PRODUCT_TOOL_SEMANTICS_VERSION,
                    "inventory_digest": entry.tool_inventory_digest,
                    "descriptor_digest": descriptor_digest,
                    "execution": execution,
                }
            ),
        }

    def resolve(
        self,
        event: GuardEvent,
        *,
        activation: ProductActivationBundleV1,
        activation_ack: ActivationAckV1 | None = None,
    ) -> VerifiedProductTool | None:
        self.verify_current(activation, activation_ack)
        if event.event_type not in {
            "tool_call_proposed",
            "memory_write_proposed",
            "message_send_proposed",
        }:
            return None
        try:
            runtime = event.runtime
            if runtime not in ("langgraph", "openclaw"):
                raise ValueError
            entry = activation.runtime_entry(runtime)
            if (
                event.security_context.agent_id != entry.agent_id
                or activation_ack is not None
                and activation_ack.runtime != event.runtime
            ):
                raise ValueError
            name, _, arguments = product_tool_arguments(event)
            descriptor, schema, execution = self._tool(event.runtime, name)
            _schema(schema, arguments, schema)
            if "execution_schema" in descriptor:
                _schema(
                    descriptor["execution_schema"],
                    arguments,
                    descriptor["execution_schema"],
                )
            return bind_verified_product_tool(
                event,
                runtime_binding_id=entry.runtime_binding_id,
                inventory_digest=entry.tool_inventory_digest,
                descriptor=descriptor,
                execution=execution,
            )
        except Exception:
            raise ProductToolCatalogError(
                "product_tool_catalog_action_invalid"
            ) from None


def load_product_tool_catalog(
    path: str, *, activation: ProductActivationBundleV1
) -> ProductToolCatalog:
    return ProductToolCatalog(path, activation)
