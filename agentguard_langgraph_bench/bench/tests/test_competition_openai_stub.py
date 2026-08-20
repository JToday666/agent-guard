from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from langchain_openai import ChatOpenAI

from agentguard_langgraph_bench.bench.model_exchange import invoke_with_model_exchange


class _OpenAIStubHandler(BaseHTTPRequestHandler):
    requests: list[dict] = []
    authorization: list[str] = []

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).requests.append(payload)
        type(self).authorization.append(self.headers.get("Authorization", ""))
        response = {
            "id": "chatcmpl-compatible-stub",
            "object": "chat.completion",
            "created": 1,
            "model": "vendor-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call-stub-1",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path":"/docs/public.txt"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("x-request-id", "request-compatible-stub")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:
        return


@contextmanager
def _stub_server() -> Iterator[str]:
    _OpenAIStubHandler.requests = []
    _OpenAIStubHandler.authorization = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OpenAIStubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/v1"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_other_openai_compatible_provider_crosses_real_http_boundary() -> None:
    secret = "compatible-provider-secret"
    tool_schema = {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read one public file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    }
    with _stub_server() as base_url:
        llm = ChatOpenAI(
            model="vendor-model",
            api_key=secret,
            base_url=base_url,
            max_retries=0,
            temperature=0,
        ).bind_tools([tool_schema])
        _, evidence = invoke_with_model_exchange(
            llm,
            model_input=[("system", "fixed protocol"), ("user", "read public file")],
            sources=[
                {
                    "source_id": "protocol",
                    "role": "system",
                    "content": "fixed protocol",
                },
                {"source_id": "task", "role": "user", "content": "read public file"},
            ],
            tool_schemas=[tool_schema],
            authority_binding={"task_id": "task-1"},
            case_id="BN-001",
            arm_id="A0",
            repeat_index=0,
            round_index=1,
            provider_id="other-vendor",
            model="vendor-model",
            base_url=base_url,
            context_mode="off",
        )

    assert len(_OpenAIStubHandler.requests) == 1
    assert _OpenAIStubHandler.requests[0]["model"] == "vendor-model"
    assert _OpenAIStubHandler.requests[0]["tools"][0]["function"]["name"] == "read_file"
    assert _OpenAIStubHandler.authorization == [f"Bearer {secret}"]
    assert evidence.model_invoked is True
    assert evidence.provider_id == "other-vendor"
    assert evidence.tool_names == ("read_file",)
    assert secret not in repr(evidence.public_dump())
