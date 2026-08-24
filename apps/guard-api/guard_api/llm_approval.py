"""LLM-backed approval reviewer for Guard API ask decisions."""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

import httpx
from pydantic import ValidationError

from guard_api.models import LlmApprovalReview, LlmApprovalReviewInput
from guard_api.settings import GuardApiSettings

logger = logging.getLogger(__name__)

# ⑧ 容错解析：MaaS json_object 模式长尾严重（实测 18.5s+），改为普通文本
# 生成 + 围栏剥离 + 首个完整 JSON 对象截取；解析失败归一为 error 分支。
_REVIEWER_NAME = "llm-approval"


class LlmApprovalReviewer(Protocol):
    def review(
        self, request: LlmApprovalReviewInput
    ) -> LlmApprovalReview | dict[str, Any]: ...


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
    def from_settings(
        cls, settings: GuardApiSettings
    ) -> "HttpLlmApprovalReviewer | None":
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
            # ⑧ 不再使用 response_format=json_object：该模式在兼容端点
            # 需要完整生成后才返回，长尾延迟不可控；改为普通文本生成 +
            # 容错解析（_extract_json_object）。
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an AgentGuard approval reviewer. "
                        "Review only the bounded evidence. Reply with a single "
                        "JSON object with keys: decision, confidence, reason, "
                        "evidence_refs. decision must be allow_once or deny. "
                        "If unsure, choose deny."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        request.model_dump(mode="json"),
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                },
            ],
        }
        try:
            response_payload = self._post_chat_completions(payload)
            content = _chat_completion_content(response_payload)
            parsed = _extract_json_object(content)
            review = LlmApprovalReview.model_validate(parsed)
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            # 真错误：网络/超时/HTTP 失败 → 明确 error 分支（审批保持
            # pending，由人工放行兜底）。
            return self._error_review(f"{type(exc).__name__}: {exc}")
        except (ValueError, ValidationError, json.JSONDecodeError) as exc:
            # 真错误：响应结构非法或无法解析出 JSON → error 分支。
            return self._error_review(f"PARSE_FAILED: {exc}")
        return review.model_copy(
            update={"provider": self.provider, "model": self.model}
        )

    def warmup(self, *, timeout_seconds: float = 20.0) -> None:
        """④ 启动预热：对 LLM 端点打一次极小合成请求（best-effort）。

        fire-and-forget 语义由调用方保证（独立 task）；此处任何异常只记
        日志不抛出，绝不阻塞启动。
        """
        request = LlmApprovalReviewInput(
            runtime="warmup",
            resource="warmup",
            reason="AgentGuard startup warmup; deny is acceptable.",
            risk_score=0,
            severity="low",
            evidence={},
        )
        payload = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": 16,
            "messages": [
                {
                    "role": "system",
                    "content": "Reply with the single word: ready",
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        request.model_dump(mode="json"),
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                },
            ],
        }
        try:
            self._post_chat_completions(
                payload, timeout_seconds=timeout_seconds, retries=0
            )
            logger.info("llm approval endpoint warmup completed (model=%s)", self.model)
        except Exception as exc:  # noqa: BLE001 - best-effort warmup
            logger.warning("llm approval endpoint warmup failed: %s", exc)

    def _error_review(self, detail: str) -> LlmApprovalReview:
        return LlmApprovalReview(
            reviewer=_REVIEWER_NAME,
            status="error",
            decision=None,
            confidence=None,
            reason=None,
            evidence_refs=[],
            error=detail,
            provider=self.provider,
            model=self.model,
        )

    def _post_chat_completions(
        self,
        payload: dict[str, Any],
        *,
        timeout_seconds: float | None = None,
        retries: int = 1,
    ) -> dict[str, Any]:
        """⑧ 超时类错误重试 1 次（沿用同超时；总时长 = 2 × timeout）。"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"
        timeout = (
            timeout_seconds if timeout_seconds is not None else self.timeout_seconds
        )
        attempts = retries + 1
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                if self.client is not None:
                    response = self.client.post(
                        url, headers=headers, json=payload, timeout=timeout
                    )
                    response.raise_for_status()
                    return response.json()
                with httpx.Client(timeout=timeout) as client:
                    response = client.post(url, headers=headers, json=payload)
                    response.raise_for_status()
                    return response.json()
            except httpx.TimeoutException as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    logger.warning(
                        "llm approval request timed out (attempt %d/%d); retrying",
                        attempt + 1,
                        attempts,
                    )
                    continue
                raise
        raise last_error if last_error else RuntimeError("unreachable")


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


def _extract_json_object(content: str) -> dict[str, Any]:
    """⑧ 容错解析：剥 ```json``` 围栏后截取首个完整 `{…}`。"""
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines:
            lines = lines[1:]
        while lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    start = stripped.find("{")
    if start < 0:
        raise ValueError("LLM approval response contains no JSON object")
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(stripped)):
        char = stripped[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = stripped[start : index + 1]
                parsed = json.loads(candidate)
                if not isinstance(parsed, dict):
                    raise ValueError("LLM approval JSON is not an object")
                return parsed
    raise ValueError("LLM approval response JSON object is unbalanced")
