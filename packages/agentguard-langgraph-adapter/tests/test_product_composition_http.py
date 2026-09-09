"""Actual StateGraph/ToolNode/Guard HTTP with B09 gates enabled.

Only candidate artifact/version are synthetic. No global execution fuse or permit
validator is patched; the model and automated test operator are explicitly local.
"""

from dataclasses import replace
from importlib.metadata import version
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage
from agentguard_langgraph_adapter import activation_session, product_composition
from agentguard_langgraph_adapter.langgraph_adapter import LangGraphAdapter
from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph
from tests.support.native_product_runtime import (
    HttpFixtureModel,
    native_product_runtime_http,
)
from tests.test_langgraph_native_graph_http import _automated_test_operator

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    "tool,args",
    [
        ("read", {"path": "fixture.txt"}),
        ("write", {"path": "created.txt", "content": "native composition evidence"}),
    ],
)
def test_actual_native_loop_through_owned_composition(
    tmp_path, monkeypatch, tool, args
):
    monkeypatch.setenv("AGENTGUARD_CONTEXT_BUILDER_ENABLED", "true")
    monkeypatch.setenv("AGENTGUARD_CT_FACT_PROJECTION_ENABLED", "true")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    with native_product_runtime_http(tmp_path) as http:

        def assumed(name):
            return (
                "0.1.0rc1" if name == "agentguard-langgraph-adapter" else version(name)
            )

        monkeypatch.setattr(activation_session, "version", assumed)
        monkeypatch.setattr(product_composition, "version", assumed)
        entry = http.fixture.bundle.runtime_entry("langgraph")
        monkeypatch.setattr(
            product_composition,
            "verify_installed_product_artifact",
            lambda *a, **kw: SimpleNamespace(
                digest=entry.adapter_artifact_digest, assert_current=lambda: None
            ),
        )
        adapter = LangGraphAdapter(
            config=replace(
                http.config(),
                product_execution_enabled=True,
                product_adapter_wheel_path=str(tmp_path / "synthetic.whl"),
                product_receipt_directory=str(tmp_path / "queue"),
                product_receipt_key_path=str(tmp_path / "keys" / "queue.key"),
            )
        )
        model = HttpFixtureModel(
            responses=[
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": tool,
                            "args": args,
                            "id": "native_composition_1",
                            "type": "tool_call",
                        }
                    ],
                ),
                AIMessage(content="completed"),
            ]
        )
        graph = build_native_product_graph(
            adapter=adapter,
            model=model,
            tools=http.tools,
            provider="deterministic-local-contract",
            model_name="recording-model-no-provider",
        )
        try:
            graph.start()
            security = dict(http.event()["security_context"], task_id=http.task_id)
            with _automated_test_operator(http) as resolutions:
                result = graph.invoke(
                    sources=[
                        {
                            "role": "user",
                            "content": security["user_task"],
                            "source_id": "native-authenticated-task",
                            "source_type": "user",
                            "source_trust": "trusted",
                        }
                    ],
                    security=security,
                    trace_id=http.trace_id,
                )
            summary = {
                "blocked": result.blocked,
                "models": result.model_calls,
                "tools": result.tool_invocations,
                "error": result.error_code,
            }
            assert summary == {"blocked": False, "models": 2, "tools": 1, "error": None}
            assert len(model._messages) == 2
            status = adapter.product_delivery_status()
            assert status.pending_count == status.unknown_action_count == 0
            assert not status.breaker_open
            if tool == "write":
                assert (http.root / "created.txt").read_text() == args["content"]
                assert len(resolutions) == 1
        finally:
            graph.close()
            adapter.close_product_delivery()


def test_source_only_candidate_installation_matches_imported_sdk(tmp_path):
    """Synthetic RC wheel+installed RECORD, actual isolated Python import.

    This validates the verifier on the complete SDK rather than bypassing its
    loader. The production package version is not changed or overridden.
    """
    import hashlib
    import os
    from pathlib import Path
    import subprocess
    import sys
    from zipfile import ZipFile
    from agentguard_langgraph_adapter import product_artifact

    package = "agentguard_langgraph_adapter"
    root = tmp_path / "installation"
    private = tmp_path / "private"
    root.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    source = Path(product_artifact.__file__).parent
    files = {
        package + "/" + path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    dist = package + "-0.1.0rc1.dist-info"
    files[dist + "/METADATA"] = (
        b"Name: agentguard-langgraph-adapter\nVersion: 0.1.0rc1\n"
    )
    files[dist + "/WHEEL"] = (
        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )
    records = "".join(
        f"{name},{product_artifact._hash(body)},{len(body)}\n"
        for name, body in files.items()
    )
    files[dist + "/RECORD"] = (records + dist + "/RECORD,,\n").encode()
    wheel = private / "synthetic.whl"
    with ZipFile(wheel, "w") as archive:
        for name, body in files.items():
            archive.writestr(name, body)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(0o644)
    wheel.chmod(0o600)
    digest = "sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest()
    script = """import sys
from agentguard_langgraph_adapter import native_langgraph, product_artifact
artifact = product_artifact.verify_installed_product_artifact(sys.argv[1], expected_digest=sys.argv[2])
artifact.assert_current()
print('verified')
"""
    env = {**os.environ, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [sys.executable, "-B", "-c", script, str(wheel), digest],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "verified"
