"""Structured error responses for Guard API."""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Any = Field(default_factory=list)


class ErrorEnvelope(BaseModel):
    error: ErrorBody


_ERROR_MESSAGES = {
    "AUTH_MISSING": "Authentication is required.",
    "TOKEN_INVALID": "Bearer token is invalid.",
    "SCOPE_DENIED": "Bearer token does not include the required scope.",
    "SESSION_INVALID": "Browser session is invalid.",
    "SESSION_EXPIRED": "Browser session has expired.",
    "CSRF_INVALID": "CSRF token is invalid.",
    "LAUNCH_CODE_INVALID": "Launch code is invalid.",
    "LAUNCH_CODE_EXPIRED": "Launch code has expired.",
    "APPROVAL_NONCE_INVALID": "Approval nonce is invalid.",
    "APPROVAL_SUBJECT_MISSING": "Approval subject is required.",
    "APPROVAL_NOT_FOUND": "Approval was not found.",
    "APPROVAL_DECISION_INVALID": "Approval decision is invalid.",
    "APPROVAL_WAIT_DENIED": "Approval wait is not allowed for this principal.",
    "AUDIT_ID_CONFLICT": "The audit_id is already bound to different content.",
    "POLICY_EVALUATION_WRITE_FORBIDDEN": (
        "policy_evaluation records can only be written by POST /v1/guard/evaluate."
    ),
    "CURSOR_EXPIRED": "The audit window cursor has expired or is invalid.",
    "CURSOR_SCOPE_MISMATCH": "Request filters do not match the audit window cursor scope.",
    "COHORT_RANGE_MISSING": "evaluated_from and evaluated_to are required for policy evaluation cohorts.",
    "EVALUATION_CONFLICT": "Evaluation conflicts with an existing result for the same event.",
    "VALIDATION_ERROR": "Request validation failed.",
    "NOT_FOUND": "Resource was not found.",
    "METHOD_NOT_ALLOWED": "HTTP method is not allowed.",
    "INTERNAL_ERROR": "Internal server error.",
}


def error_response(
    code: str,
    *,
    status_code: int,
    message: str | None = None,
    details: Any | None = None,
) -> JSONResponse:
    envelope = ErrorEnvelope(
        error=ErrorBody(
            code=code,
            message=message or _ERROR_MESSAGES.get(code, _default_error_message(code)),
            details=[] if details is None else details,
        )
    )
    return JSONResponse(
        status_code=status_code, content=envelope.model_dump(mode="json")
    )


def validation_error_details(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "loc": list(error.get("loc", [])),
            "msg": str(error.get("msg", "")),
            "type": str(error.get("type", "")),
        }
        for error in errors
    ]


def http_error_code(status_code: int) -> str:
    if status_code == 404:
        return "NOT_FOUND"
    if status_code == 405:
        return "METHOD_NOT_ALLOWED"
    return "HTTP_ERROR"


def _default_error_message(code: str) -> str:
    return code.lower().replace("_", " ").capitalize() + "."
