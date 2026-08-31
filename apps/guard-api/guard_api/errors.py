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
    "CREDENTIAL_IDENTITY_INCOMPLETE": "Credential is missing its runtime identity binding.",
    "EVENT_IDENTITY_INCOMPLETE": "Runtime request is missing its agent identity.",
    "RUNTIME_IDENTITY_MISMATCH": "Runtime request does not match the credential identity.",
    "V21_PRODUCT_ACTIVATION_NOT_CURRENT": (
        "Product V2 activation is not currently valid."
    ),
    "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH": (
        "Runtime request does not match the Product V2 activation identity."
    ),
    "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH": (
        "Runtime observation does not match the Product V2 activation."
    ),
    "V21_PRODUCT_SELECTOR_NOT_WIRED": ("Product V2 authority selector is not wired."),
    "SESSION_INVALID": "Browser session is invalid.",
    "SESSION_EXPIRED": "Browser session has expired.",
    "CSRF_INVALID": "CSRF token is invalid.",
    "LAUNCH_CODE_INVALID": "Launch code is invalid.",
    "LAUNCH_CODE_EXPIRED": "Launch code has expired.",
    "APPROVAL_NOT_FOUND": "Approval was not found.",
    "APPROVAL_DECISION_INVALID": "Approval decision is invalid.",
    "APPROVAL_EXPIRED": "Approval has expired.",
    "APPROVAL_ALREADY_RESOLVED": "Approval has already been resolved.",
    "APPROVAL_WAIT_DENIED": "Approval wait is not allowed for this principal.",
    "APPROVAL_CONSUMPTION_DENIED": (
        "Approval execution lease consumption is not allowed for this principal."
    ),
    "APPROVAL_NOT_CONSUMABLE": "Approval cannot issue an execution lease.",
    "APPROVAL_CONSUMPTION_CONFLICT": (
        "Approval execution lease consumption conflicts with persisted state."
    ),
    "EXECUTION_LEASE_EXPIRED": "Execution lease has expired.",
    "EXECUTION_LEASE_UNAVAILABLE": "Execution lease is temporarily unavailable.",
    "CREDENTIAL_NOT_FOUND": "Credential was not found.",
    "AUDIT_ID_CONFLICT": "The audit_id is already bound to different content.",
    "AUDIT_TIMESTAMP_INVALID": "Audit timestamps must be RFC 3339 values with a timezone.",
    "AUDIT_CANONICALIZATION_INVALID": (
        "Audit evidence must be valid RFC 8785 / I-JSON data."
    ),
    "POLICY_EVALUATION_WRITE_FORBIDDEN": (
        "policy_evaluation records can only be written by POST /v1/guard/evaluate."
    ),
    "CONTEXT_MANIFEST_WRITE_FORBIDDEN": (
        "Context Manifest records can only be written by the Guard API Context Builder."
    ),
    "RUNTIME_OUTCOME_INVALID": "Runtime outcome receipt failed strict validation.",
    "RUNTIME_OUTCOME_PARENT_NOT_FOUND": (
        "Runtime outcome receipt does not reference a policy evaluation."
    ),
    "RUNTIME_OUTCOME_PARENT_MISMATCH": (
        "Runtime outcome receipt conflicts with its policy evaluation."
    ),
    "POLICY_INVALID": "Policy bundle failed semantic validation.",
    "POLICY_PRECONDITION_REQUIRED": "Policy writes require the current revision ETag.",
    "POLICY_REVISION_CONFLICT": "Policy revision is stale or invalid.",
    "PROVENANCE_CONFLICT": "A stable provenance ID conflicts with persisted facts.",
    "CURSOR_EXPIRED": "The audit window cursor has expired or is invalid.",
    "CURSOR_SCOPE_MISMATCH": "Request filters do not match the audit window cursor scope.",
    "COHORT_RANGE_MISSING": "evaluated_from and evaluated_to are required for policy evaluation cohorts.",
    "COHORT_RANGE_INVALID": "The policy evaluation cohort range is invalid.",
    "REQUEST_TOO_LARGE": "Request body exceeds the configured size limit.",
    "EVALUATION_CONFLICT": "Evaluation conflicts with an existing result for the same event.",
    "EVALUATION_RUN_CONFLICT": (
        "Evaluation run ID is already bound to different immutable content."
    ),
    "TASK_REVISION_CONFLICT": (
        "Task revision is stale or conflicts with existing revision content."
    ),
    "TASK_NOT_FOUND": "Task was not found.",
    "TASK_PRINCIPAL_MISMATCH": "Task is bound to a different principal.",
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
