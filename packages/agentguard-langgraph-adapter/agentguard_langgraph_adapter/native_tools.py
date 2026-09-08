"""Fixed, isolated native tools and immutable invocation projections.

Import this module through the optional ``native`` extra. Tools have no Guard
authority of their own: only the native execution template may release them.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
from threading import RLock
from typing import Any, Callable, Iterator, Literal
from urllib.parse import urlsplit
from uuid import uuid4
from weakref import WeakKeyDictionary

import httpx
from langchain_core.tools import StructuredTool
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel, ConfigDict, Field

from .activation_ack import ProductActivationError
from .product_manifest import canonical_sha256

NativeActionEvent = Literal[
    "tool_call_proposed", "memory_write_proposed", "message_send_proposed"
]
NATIVE_TOOL_NAMES = (
    "agentguard_memory_read",
    "agentguard_memory_write",
    "edit",
    "exec",
    "message",
    "process",
    "read",
    "write",
)
_MAX_BYTES = 64 * 1024
_SOURCE_ID = "agentguard-langgraph-adapter:isolated-product-tools-v1"
_SCRIPT = (
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


def _fail(code: str) -> ProductActivationError:
    return ProductActivationError("native_tool_" + code)


def _json(value: Any) -> str:
    def check(item: Any, depth: int) -> None:
        if depth > 16:
            raise _fail("input_invalid")
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is list:
            for child in item:
                check(child, depth + 1)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                check(child, depth + 1)
            return
        raise _fail("input_invalid")

    try:
        check(value, 0)
        wire = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        if len(wire.encode("utf-8")) > _MAX_BYTES:
            raise _fail("input_too_large")
        return wire
    except ProductActivationError:
        raise
    except Exception:
        raise _fail("input_invalid") from None


class _Input(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, hide_input_in_errors=True
    )


class ReadInput(_Input):
    path: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}\.txt$")


class WriteInput(ReadInput):
    content: str = Field(max_length=32768)


class EditItem(_Input):
    oldText: str = Field(min_length=1, max_length=32768)
    newText: str = Field(max_length=32768)


class EditInput(ReadInput):
    edits: list[EditItem] = Field(min_length=1, max_length=8)


class ExecInput(_Input):
    command: Literal["python marker.py"]


class ProcessInput(_Input):
    action: Literal["list"]


class MemoryReadInput(_Input):
    key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class MemoryWriteInput(MemoryReadInput):
    value: str = Field(max_length=32768)


class MessageInput(_Input):
    action: Literal["send"]
    channel: Literal["agentguard-fixture"]
    target: Literal["fixture-inbox"]
    message: str = Field(max_length=32768)


@dataclass(frozen=True, eq=False)
class NativeToolSpec:
    tool: StructuredTool = field(repr=False)
    event_type: NativeActionEvent
    category: str
    kind: str
    operation: str
    source_id: str

    @property
    def name(self) -> str:
        return self.tool.name


@dataclass(frozen=True, eq=False)
class PreparedNativeToolCall:
    name: str
    call_id: str
    arguments_json: str = field(repr=False)
    event_type: NativeActionEvent
    category: str
    kind: str
    operation: str
    resources_json: str = field(repr=False)
    descriptor_digest: str

    def arguments(self) -> dict[str, Any]:
        self.assert_current()
        return json.loads(self.arguments_json)

    def resources(self) -> list[dict[str, Any]]:
        self.assert_current()
        return json.loads(self.resources_json)

    def assert_current(self) -> None:
        registered = _PREPARED.get(self)
        if registered is None:
            raise _fail("untrusted_invocation")
        spec, expected = registered
        if (
            self.__dict__ != expected
            or canonical_sha256(native_tool_descriptor(spec)) != self.descriptor_digest
        ):
            raise _fail("invocation_drift")


@dataclass(frozen=True)
class _Registration:
    runtime: _IsolatedRuntime
    schema: type[BaseModel]
    function: Callable[..., str]
    code: object
    defaults: object
    keyword_defaults: object
    closure: tuple[object, ...]
    descriptor_json: str
    tool_json: str


_REGISTRY: WeakKeyDictionary[NativeToolSpec, _Registration] = WeakKeyDictionary()
_PREPARED: WeakKeyDictionary[
    PreparedNativeToolCall, tuple[NativeToolSpec, dict[str, Any]]
] = WeakKeyDictionary()


def _tool_projection(tool: StructuredTool) -> str:
    return _json(tool.model_dump(exclude={"args_schema", "func", "coroutine"}))


def native_tool_descriptor(spec: NativeToolSpec) -> dict[str, Any]:
    registration = _REGISTRY.get(spec)
    if registration is None:
        raise _fail("untrusted_descriptor")
    registration.runtime.check()
    tool = spec.tool
    try:
        if (
            type(tool) is not StructuredTool
            or tool.func is not registration.function
            or getattr(tool.func, "__code__", None) is not registration.code
            or getattr(tool.func, "__defaults__", None) is not registration.defaults
            or getattr(tool.func, "__kwdefaults__", None)
            is not registration.keyword_defaults
            or len(getattr(tool.func, "__closure__", None) or ())
            != len(registration.closure)
            or any(
                cell.cell_contents is not expected
                for cell, expected in zip(
                    getattr(tool.func, "__closure__", None) or (), registration.closure
                )
            )
            or tool.args_schema is not registration.schema
            or tool.coroutine is not None
            or _tool_projection(tool) != registration.tool_json
        ):
            raise _fail("descriptor_drift")
        actual = _descriptor(spec, registration.runtime)
        if _json(actual) != registration.descriptor_json:
            raise _fail("descriptor_drift")
        # Some pinned SDK schemas reuse nested dictionaries. Public inventory
        # projections must never expose those mutable execution definitions.
        return json.loads(registration.descriptor_json)
    except ProductActivationError:
        raise
    except Exception:
        raise _fail("descriptor_drift") from None


def _descriptor(spec: NativeToolSpec, runtime: _IsolatedRuntime) -> dict[str, Any]:
    schema = spec.tool.tool_call_schema
    if not isinstance(schema, type) or not issubclass(schema, BaseModel):
        raise _fail("schema_invalid")
    execution_schema = spec.tool.args_schema
    if not isinstance(execution_schema, type) or not issubclass(
        execution_schema, BaseModel
    ):
        raise _fail("schema_invalid")
    return {
        "tool_id": spec.name,
        "source_id": spec.source_id,
        "description": spec.tool.description,
        "input_schema": schema.model_json_schema(),
        "execution_schema": execution_schema.model_json_schema(),
        "event_type": spec.event_type,
        "category": spec.category,
        "kind": spec.kind,
        "operation": spec.operation,
        "execution_binding_digest": runtime.binding_digest,
        "fixture_id": f"langgraph:{spec.name}:isolated-v1",
    }


def native_tool_inventory_digest(specs: tuple[NativeToolSpec, ...]) -> str:
    names = tuple(spec.name for spec in specs)
    if names != NATIVE_TOOL_NAMES:
        raise _fail("inventory_mismatch")
    return canonical_sha256([native_tool_descriptor(spec) for spec in specs])


def native_tool_catalog_materials(
    specs: tuple[NativeToolSpec, ...],
    *,
    model_visible_tools: list[dict[str, Any]],
) -> dict[str, Any]:
    """Capture catalog material against the actual model binding's tools array.

    The caller supplies its bound provider array. Actual pinned SDK conversion
    is a cross-check, never a replacement for that captured value. This is
    inventory evidence only; activation and candidate signing remain separate.
    """
    try:
        inventory_digest = native_tool_inventory_digest(specs)
        tools = [native_tool_descriptor(spec) for spec in specs]
        runtimes = {_REGISTRY[spec].runtime for spec in specs}
        if len(runtimes) != 1:
            raise _fail("inventory_runtime_mismatch")
        runtime = next(iter(runtimes))
        runtime.check()
        visible = json.loads(_json(model_visible_tools))
        expected = [convert_to_openai_tool(spec.tool) for spec in specs]
        if type(visible) is not list or _json(visible) != _json(expected):
            raise _fail("model_inventory_mismatch")
        execution = {
            "root": str(runtime.root),
            "inbox_url": runtime.inbox_url,
            "script_digest": "sha256:" + hashlib.sha256(_SCRIPT).hexdigest(),
            "memory_namespace": str(runtime.root / "memory.sqlite"),
        }
        # Revalidate after SDK conversion before exporting either projection.
        if native_tool_inventory_digest(specs) != inventory_digest:
            raise _fail("descriptor_drift")
        return {
            "tools": tools,
            "model_visible_tools": visible,
            "execution": execution,
            "tool_inventory_digest": inventory_digest,
            "host_inventory_digest": canonical_sha256(
                {
                    "schema_version": "1.0",
                    "runtime": "langgraph",
                    "model_visible_tools": visible,
                }
            ),
        }
    except ProductActivationError:
        raise
    except Exception:
        raise _fail("inventory_invalid") from None


def prepare_native_tool_call(
    spec: NativeToolSpec, call_id: str, arguments: dict[str, Any]
) -> PreparedNativeToolCall:
    descriptor = native_tool_descriptor(spec)
    if not isinstance(call_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", call_id
    ):
        raise _fail("call_id_invalid")
    wire = _json(arguments)
    try:
        registration = _REGISTRY[spec]
        validated = registration.schema.model_validate(json.loads(wire), strict=True)
        normalized = validated.model_dump(mode="json")
        if _json(normalized) != wire:
            raise _fail("arguments_changed")
        if spec.name == "agentguard_memory_write":
            registration.runtime.assert_new_memory_key(normalized["key"])
        resources = registration.runtime.resources(spec, normalized)
    except ProductActivationError:
        raise
    except Exception:
        raise _fail("arguments_invalid") from None
    prepared = PreparedNativeToolCall(
        spec.name,
        call_id,
        wire,
        spec.event_type,
        spec.category,
        spec.kind,
        spec.operation,
        _json(resources),
        canonical_sha256(descriptor),
    )
    _PREPARED[prepared] = (spec, dict(prepared.__dict__))
    return prepared


class _IsolatedRuntime:
    def __init__(self, root: Path, inbox_url: str) -> None:
        self.root = root
        self.inbox_url = inbox_url
        self.lock = RLock()
        self.executions: list[dict[str, Any]] = []
        self.fd = -1
        self.lock_fd = -1
        try:
            if (
                sys.platform != "linux"
                or not root.is_absolute()
                or root.resolve() != root
            ):
                raise _fail("root_invalid")
            root_stat = root.lstat()
            self._check_file(root_stat, directory=True)
            self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.identity = (root_stat.st_dev, root_stat.st_ino)
            self.check()
            self.lock_fd = os.open(
                ".native-tools.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=self.fd,
            )
            self._check_file(os.fstat(self.lock_fd))
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(self.fd)
            self.binding_digest = canonical_sha256(
                {
                    "root": str(root),
                    "inbox_url": inbox_url,
                    "script_digest": "sha256:" + hashlib.sha256(_SCRIPT).hexdigest(),
                    "source_id": _SOURCE_ID,
                }
            )
            self._ensure_file("marker.py", _SCRIPT)
            self._ensure_file("memory.sqlite", b"")
            with self.database() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            self.ready = True
        except Exception:
            self.close()
            raise _fail("root_invalid") from None

    @staticmethod
    def _check_file(info: os.stat_result, *, directory: bool = False) -> None:
        expected_mode = 0o700 if directory else 0o600
        correct_kind = (
            stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        )
        if (
            not correct_kind
            or stat.S_IMODE(info.st_mode) != expected_mode
            or info.st_uid != os.geteuid()
            or (not directory and info.st_nlink != 1)
        ):
            raise _fail("storage_invalid")

    def check(self) -> None:
        if self.fd < 0:
            raise _fail("closed")
        try:
            info = os.fstat(self.fd)
            current = self.root.lstat()
            self._check_file(info, directory=True)
            self._check_file(current, directory=True)
            if (
                (info.st_dev, info.st_ino) != self.identity
                or (current.st_dev, current.st_ino) != self.identity
                or self.root.resolve() != self.root
            ):
                raise _fail("root_drift")
            if self.lock_fd >= 0:
                lock = os.fstat(self.lock_fd)
                current_lock = os.stat(
                    ".native-tools.lock", dir_fd=self.fd, follow_symlinks=False
                )
                self._check_file(lock)
                self._check_file(current_lock)
                if (lock.st_dev, lock.st_ino) != (
                    current_lock.st_dev,
                    current_lock.st_ino,
                ):
                    raise _fail("root_drift")
            if hasattr(
                self, "binding_digest"
            ) and self.binding_digest != canonical_sha256(
                {
                    "root": str(self.root),
                    "inbox_url": self.inbox_url,
                    "script_digest": "sha256:" + hashlib.sha256(_SCRIPT).hexdigest(),
                    "source_id": _SOURCE_ID,
                }
            ):
                raise _fail("binding_drift")
            if getattr(self, "ready", False):
                descriptor = os.open(
                    "marker.py",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=self.fd,
                )
                try:
                    self._check_file(os.fstat(descriptor))
                    if os.read(descriptor, len(_SCRIPT) + 1) != _SCRIPT:
                        raise _fail("script_drift")
                finally:
                    os.close(descriptor)
        except ProductActivationError:
            raise
        except Exception:
            raise _fail("root_drift") from None

    def close(self) -> None:
        if self.lock_fd >= 0:
            os.close(self.lock_fd)
            self.lock_fd = -1
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _ensure_file(self, name: str, content: bytes) -> None:
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.fd,
            )
        except FileExistsError:
            if name == "marker.py" and self._read(name) != content.decode():
                raise _fail("script_drift")
            with self.open_file(name):
                pass
            return
        try:
            if content and os.write(descriptor, content) != len(content):
                raise _fail("write_failed")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self.fd)

    @contextmanager
    def open_file(self, name: str) -> Iterator[int]:
        self.check()
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd
        )
        try:
            self._check_file(os.fstat(descriptor))
            yield descriptor
        finally:
            os.close(descriptor)

    def _read(self, name: str) -> str:
        with self.open_file(name) as descriptor:
            if os.fstat(descriptor).st_size > _MAX_BYTES:
                raise _fail("result_too_large")
            data = os.read(descriptor, _MAX_BYTES + 1)
            if len(data) > _MAX_BYTES:
                raise _fail("result_too_large")
            return data.decode("utf-8")

    def _write(self, name: str, content: str) -> None:
        data = content.encode("utf-8")
        if len(data) > _MAX_BYTES:
            raise _fail("input_too_large")
        try:
            with self.open_file(name):
                pass
        except FileNotFoundError:
            pass
        temporary = f".write-{uuid4().hex}"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        try:
            if os.write(descriptor, data) != len(data):
                raise _fail("write_failed")
            os.fsync(descriptor)
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    @contextmanager
    def database(self) -> Iterator[sqlite3.Connection]:
        with self.open_file("memory.sqlite") as descriptor:
            before = os.fstat(descriptor)
            connection = sqlite3.connect(
                f"/proc/self/fd/{self.fd}/memory.sqlite", timeout=1.0
            )
            try:
                connection.execute("PRAGMA journal_mode=MEMORY")
                connection.execute("PRAGMA synchronous=FULL")
                current = os.stat(
                    "memory.sqlite", dir_fd=self.fd, follow_symlinks=False
                )
                self._check_file(current)
                if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                    raise _fail("storage_drift")
                with connection:
                    yield connection
            finally:
                connection.close()

    def resources(
        self, spec: NativeToolSpec, args: dict[str, Any]
    ) -> list[dict[str, Any]]:
        self.check()
        if spec.category == "file":
            resource_type, target = "file", str(self.root / args["path"])
            direction = "inbound" if spec.operation == "read" else "local"
        elif spec.category == "memory":
            resource_type, target = "memory", f"{self.root}/memory.sqlite/{args['key']}"
            direction = "persistent" if spec.operation == "write" else "inbound"
        elif spec.category == "message":
            resource_type, target, direction = "message", "fixture-inbox", "outbound"
        else:
            resource_type, target, direction = (
                "process",
                str(self.root / "marker.py"),
                "local",
            )
        return [
            {
                "resource_type": resource_type,
                "operation": spec.operation,
                "target": target,
                "direction": direction,
            }
        ]

    def assert_new_memory_key(self, key: str) -> None:
        # This isolated qualification profile covers first writes. A proposed
        # overwrite must not dirty the frozen MemoryFact lifecycle before its
        # guard evaluation; repeat the check at the actual side-effect boundary.
        with self.lock:
            self.check()
            with self.database() as connection:
                if (
                    connection.execute(
                        "SELECT 1 FROM memory WHERE key=?", (key,)
                    ).fetchone()
                    is not None
                ):
                    raise _fail("memory_overwrite_not_supported")

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        # Internal callbacks run only after the native template releases a call.
        # Do not expose exception messages, environment, or arbitrary subprocesses.
        with self.lock:
            self.check()
            try:
                if name == "read":
                    return self._read(arguments["path"])
                if name == "write":
                    self._write(arguments["path"], arguments["content"])
                    return _json({"ok": True, "path": arguments["path"]})
                if name == "edit":
                    content = self._read(arguments["path"])
                    for edit in arguments["edits"]:
                        if content.count(edit["oldText"]) != 1:
                            raise _fail("edit_not_unique")
                        content = content.replace(edit["oldText"], edit["newText"], 1)
                    self._write(arguments["path"], content)
                    return _json({"ok": True, "path": arguments["path"]})
                if name == "exec":
                    if self._read("marker.py").encode() != _SCRIPT:
                        raise _fail("script_drift")
                    if len(self.executions) >= 1000:
                        raise _fail("process_capacity")
                    try:
                        with self.open_file("command-marker.txt"):
                            pass
                    except FileNotFoundError:
                        pass
                    with self.open_file("marker.py") as script_fd:
                        completed = subprocess.run(
                            [sys.executable, "-I", "-S", f"/proc/self/fd/{script_fd}"],
                            cwd=f"/proc/self/fd/{self.fd}",
                            env={"PYTHONIOENCODING": "utf-8", "LANG": "C.UTF-8"},
                            pass_fds=(self.fd, script_fd),
                            capture_output=True,
                            timeout=10,
                            check=False,
                        )
                    self.executions.append(
                        {
                            "sequence": len(self.executions) + 1,
                            "exit_code": completed.returncode,
                        }
                    )
                    if completed.returncode != 0:
                        raise _fail("command_failed")
                    return _json(
                        {
                            "exit_code": completed.returncode,
                            "stdout": completed.stdout.decode(),
                            "execution": len(self.executions),
                        }
                    )
                if name == "process":
                    return _json({"processes": self.executions})
                if name.startswith("agentguard_memory_"):
                    with self.database() as connection:
                        if name == "agentguard_memory_write":
                            count = connection.execute(
                                "SELECT count(*) FROM memory"
                            ).fetchone()[0]
                            present = connection.execute(
                                "SELECT 1 FROM memory WHERE key=?", (arguments["key"],)
                            ).fetchone()
                            if present is not None:
                                raise _fail("memory_overwrite_not_supported")
                            if count >= 1000:
                                raise _fail("memory_capacity")
                            connection.execute(
                                "INSERT INTO memory(key,value) VALUES(?,?)",
                                (arguments["key"], arguments["value"]),
                            )
                            return _json({"ok": True, "key": arguments["key"]})
                        row = connection.execute(
                            "SELECT value FROM memory WHERE key=?", (arguments["key"],)
                        ).fetchone()
                        return _json(
                            {"key": arguments["key"], "value": row[0] if row else None}
                        )
                if name == "message":
                    with httpx.Client(
                        timeout=5, trust_env=False, follow_redirects=False
                    ) as client:
                        with client.stream(
                            "POST",
                            self.inbox_url,
                            json={
                                "target": arguments["target"],
                                "text": arguments["message"],
                            },
                        ) as response:
                            if response.status_code != 200:
                                raise _fail("message_failed")
                            body = bytearray()
                            for chunk in response.iter_bytes():
                                body.extend(chunk)
                                if len(body) > 4096:
                                    raise _fail("message_response_invalid")
                            result = json.loads(body)
                            if (
                                type(result) is not dict
                                or result.get("ok") is not True
                                or not isinstance(result.get("messageId"), str)
                            ):
                                raise _fail("message_response_invalid")
                            return _json(
                                {"ok": True, "message_id": result["messageId"]}
                            )
                raise _fail("unknown")
            except ProductActivationError:
                raise
            except Exception:
                raise _fail("execution_failed") from None


def create_isolated_product_tools(
    *, root: str | Path, inbox_url: str, target: str = "fixture-inbox"
) -> tuple[NativeToolSpec, ...]:
    """Create the exact eight-tool profile; never install external channels."""
    if (
        target != "fixture-inbox"
        or not isinstance(inbox_url, str)
        or not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/inbox", inbox_url)
    ):
        raise _fail("inbox_invalid")
    try:
        parsed = urlsplit(inbox_url)
        if not parsed.port or parsed.port > 65535:
            raise ValueError
    except Exception:
        raise _fail("inbox_invalid") from None
    runtime = _IsolatedRuntime(Path(root), inbox_url)
    definitions: list[tuple[str, type[BaseModel], NativeActionEvent, str, str, str]] = [
        (
            "agentguard_memory_read",
            MemoryReadInput,
            "tool_call_proposed",
            "memory",
            "memory_read",
            "read",
        ),
        (
            "agentguard_memory_write",
            MemoryWriteInput,
            "memory_write_proposed",
            "memory",
            "memory_write",
            "write",
        ),
        ("edit", EditInput, "tool_call_proposed", "file", "file_edit", "write"),
        ("exec", ExecInput, "tool_call_proposed", "code", "command_exec", "execute"),
        (
            "message",
            MessageInput,
            "message_send_proposed",
            "message",
            "local_message_send",
            "send",
        ),
        ("process", ProcessInput, "tool_call_proposed", "code", "process_list", "read"),
        ("read", ReadInput, "tool_call_proposed", "file", "file_read", "read"),
        ("write", WriteInput, "tool_call_proposed", "file", "file_write", "write"),
    ]
    specs: list[NativeToolSpec] = []
    try:
        for name, schema, event_type, category, kind, operation in definitions:

            def make_function(
                tool_name: str, input_schema: type[BaseModel]
            ) -> Callable[..., str]:
                def invoke(**kwargs: Any) -> str:
                    # BaseTool passes nested models to kwargs; round-trip those
                    # validated values before the fixed implementation sees them.
                    try:
                        values = input_schema.model_validate(
                            kwargs, strict=True
                        ).model_dump(mode="json")
                        _json(values)
                    except Exception:
                        raise _fail("arguments_invalid") from None
                    return runtime.execute(tool_name, values)

                return invoke

            function = make_function(name, schema)
            tool = StructuredTool(
                name=name,
                description=f"{kind.replace('_', ' ')} in the isolated acceptance directory.",
                args_schema=schema,
                func=function,
                handle_tool_error=False,
                handle_validation_error=False,
            )
            spec = NativeToolSpec(
                tool, event_type, category, kind, operation, _SOURCE_ID
            )
            _REGISTRY[spec] = _Registration(
                runtime,
                schema,
                function,
                function.__code__,
                function.__defaults__,
                function.__kwdefaults__,
                tuple(cell.cell_contents for cell in function.__closure__ or ()),
                _json(_descriptor(spec, runtime)),
                _tool_projection(tool),
            )
            specs.append(spec)
        result = tuple(specs)
        native_tool_inventory_digest(result)
        return result
    except Exception:
        runtime.close()
        raise _fail("construction_failed") from None


def close_isolated_product_tools(specs: tuple[NativeToolSpec, ...]) -> None:
    """Close local directory handles without deleting fixtures or evidence."""
    runtimes = {
        registration.runtime
        for spec in specs
        if (registration := _REGISTRY.get(spec)) is not None
    }
    for runtime in runtimes:
        with runtime.lock:
            runtime.close()
