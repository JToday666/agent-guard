"""LLM-backed approval reviewer for Guard API ask decisions."""

from __future__ import annotations

import json
from typing import Any, Protocol

import httpx

from guard_api.models import LlmApprovalReview, LlmApprovalReviewInput
from guard_api.settings import GuardApiSettings


class LlmApprovalReviewer(Protocol):
    def review(self, request: LlmApprovalReviewInput) -> LlmApprovalReview | dict[str, Any]:
        ...


class HttpLlmApprovalReviewer:
    provider = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.client = client

    @classmethod
    def from_settings(cls, settings: GuardApiSettings) -> "HttpLlmApprovalReviewer | None":
        if not settings.llm_approval_enabled or not settings.llm_approval_configured():
            return None
        return cls(
            base_url=settings.llm_approval_base_url,
            api_key=settings.llm_approval_api_key or "",
            model=settings.llm_approval_model or "",
            timeout_seconds=settings.llm_approval_timeout_seconds,
        )

    def review(self, request: LlmApprovalReviewInput) -> LlmApprovalReview:
        payload = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an AgentGuard approval reviewer. "
                        "Review only the bounded evidence. Return strict JSON with keys: "
                        "decision, confidence, reason, evidence_refs. "
                        "decision must be allow_once or deny. If unsure, choose deny."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(request.model_dump(mode="json"), ensure_ascii=False, sort_keys=True),
                },
            ],
        }
        response_payload = self._post_chat_completions(payload)
        content = _chat_completion_content(response_payload)
        parsed = json.loads(content)
        review = LlmApprovalReview.model_validate(parsed)
        return review.model_copy(update={"provider": self.provider, "model": self.model})

    def _post_chat_completions(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"
        if self.client is not None:
            response = self.client.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
            response.raise_for_status()
            return response.json()
        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()


def _chat_completion_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("LLM approval response missing choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ValueError("LLM approval response choice is invalid")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ValueError("LLM approval response missing message")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("LLM approval response missing content")
    return content
