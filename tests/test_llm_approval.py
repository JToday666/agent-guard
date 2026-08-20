"""⑧ LLM 审批解析加固单测：围栏/混合文本/非法 JSON/超时重试。"""

from __future__ import annotations

import json

import httpx
import pytest

from guard_api.llm_approval import HttpLlmApprovalReviewer, _extract_json_object
from guard_api.models import LlmApprovalReviewInput

_REVIEW_REQUEST = LlmApprovalReviewInput(
    runtime="openclaw",
    resource="send_email:viewer@example.com",
    reason="external send requires approval",
    risk_score=60,
    severity="medium",
    evidence={"rule_hits": ["P005_external_send"]},
)


def _reviewer(handler) -> HttpLlmApprovalReviewer:
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    return HttpLlmApprovalReviewer(
        base_url="https://llm.example.invalid/v1",
        api_key="key",
        model="test-model",
        timeout_seconds=5.0,
        client=client,
    )


def _completion(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


def _review_body() -> str:
    return json.dumps(
        {
            "decision": "deny",
            "confidence": 0.9,
            "reason": "external send",
            "evidence_refs": ["P005_external_send"],
        }
    )


def test_parse_fenced_json_block() -> None:
    """```json``` 围栏包裹的响应应被剥离后解析。"""
    reviewer = _reviewer(
        lambda request: httpx.Response(
            200, json=_completion(f"```json\n{_review_body()}\n```")
        )
    )
    review = reviewer.review(_REVIEW_REQUEST)
    assert review.status == "reviewed"
    assert review.decision == "deny"
    assert review.confidence == pytest.approx(0.9)


def test_parse_json_embedded_in_prose() -> None:
    """混合文本（前后带说明文字）应截取首个完整 JSON 对象。"""
    reviewer = _reviewer(
        lambda request: httpx.Response(
            200,
            json=_completion(
                f"Here is my assessment.\n{_review_body()}\nEnd of review."
            ),
        )
    )
    review = reviewer.review(_REVIEW_REQUEST)
    assert review.status == "reviewed"
    assert review.decision == "deny"
    assert review.evidence_refs == ["P005_external_send"]


def test_invalid_json_returns_error_branch() -> None:
    """完全非法 JSON → 明确 error 分支（不抛异常）。"""
    reviewer = _reviewer(
        lambda request: httpx.Response(
            200, json=_completion("I cannot produce a verdict, sorry.")
        )
    )
    review = reviewer.review(_REVIEW_REQUEST)
    assert review.status == "error"
    assert review.decision is None
    assert review.error is not None
    assert "PARSE_FAILED" in review.error


def test_timeout_retries_once_then_error() -> None:
    """超时 → 重试 1 次仍超时 → error 分支（共 2 次请求）。"""
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ReadTimeout("read timed out", request=request)

    reviewer = _reviewer(handler)
    review = reviewer.review(_REVIEW_REQUEST)
    assert calls["count"] == 2
    assert review.status == "error"
    assert review.error is not None
    assert "ReadTimeout" in review.error


def test_timeout_retry_succeeds_on_second_attempt() -> None:
    """首次超时、重试成功 → 正常 review（重试语义闭环）。"""
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.ReadTimeout("read timed out", request=request)
        return httpx.Response(200, json=_completion(_review_body()))

    reviewer = _reviewer(handler)
    review = reviewer.review(_REVIEW_REQUEST)
    assert calls["count"] == 2
    assert review.status == "reviewed"
    assert review.decision == "deny"


def test_extract_json_object_unbalanced_raises() -> None:
    with pytest.raises(ValueError):
        _extract_json_object('{"decision": "deny"')
    with pytest.raises(ValueError):
        _extract_json_object("no braces here")
