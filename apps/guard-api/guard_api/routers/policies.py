"""Policy management routes."""

from __future__ import annotations

import re
from typing import Any

from agentguard_core import PolicyBundle
from fastapi import Cookie, FastAPI, Header
from fastapi.responses import JSONResponse

from guard_api.auth import ApiAuthError
from guard_api.services.policy import validate_policy_bundle
from guard_api.storage.base import PolicySnapshotRecord

from .common import bounded_limit, verify_browser_or_bearer_read
from .context import ApiContext

_POLICY_ETAG_RE = re.compile(r'^"policy-revision:(\d+)"$')


def policy_snapshot_record_payload(record: PolicySnapshotRecord) -> dict[str, Any]:
    return {
        "revision": record.revision,
        "updated_at": record.updated_at,
        "updated_by": record.updated_by,
        "bundle_id": record.policy_bundle.bundle_id,
        "version": record.policy_bundle.version,
    }


def changed_policy_fields(current: PolicyBundle, candidate: PolicyBundle) -> list[str]:
    current_payload = current.model_dump(mode="json")
    candidate_payload = candidate.model_dump(mode="json")
    return sorted(
        key
        for key in set(current_payload) | set(candidate_payload)
        if current_payload.get(key) != candidate_payload.get(key)
    )


def policy_revision_etag(revision: int) -> str:
    return f'"policy-revision:{revision}"'


def required_policy_revision(if_match: str | None) -> int:
    if if_match is None:
        raise ApiAuthError("POLICY_PRECONDITION_REQUIRED", status_code=428)
    match = _POLICY_ETAG_RE.fullmatch(if_match.strip())
    if match is None:
        raise ApiAuthError("POLICY_REVISION_CONFLICT", status_code=412)
    return int(match.group(1))


def policy_response(policy: PolicyBundle, *, revision: int) -> JSONResponse:
    return JSONResponse(
        policy.model_dump(mode="json"),
        headers={
            "ETag": policy_revision_etag(revision),
            "Cache-Control": "private, no-cache",
            "Vary": "Cookie, Authorization",
        },
    )


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    policy_service = context.policy_service

    @app.get("/v1/policies/current")
    def current_policy(
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> JSONResponse:
        verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        policy, revision = policy_service.current_state()
        return policy_response(policy, revision=revision)

    @app.put("/v1/policies/current")
    def update_current_policy(
        payload: PolicyBundle,
        if_match: str | None = Header(default=None, alias="If-Match"),
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> JSONResponse:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        record = policy_service.save_snapshot(
            payload,
            expected_revision=required_policy_revision(if_match),
            updated_by="dashboard",
        )
        return policy_response(record.policy_bundle, revision=record.revision)

    @app.get("/v1/policies/history")
    def policy_history(
        limit: int = 100,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return [
            policy_snapshot_record_payload(record)
            for record in policy_service.list_history(limit=bounded_limit(limit))
        ]

    @app.post("/v1/policies/validate")
    def validate_policy(
        payload: PolicyBundle,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        issues = validate_policy_bundle(payload)
        return {
            "valid": not issues,
            "bundle_id": payload.bundle_id,
            "version": payload.version,
            "issues": [issue.as_dict() for issue in issues],
        }

    @app.post("/v1/policies/diff")
    def diff_policy(
        payload: PolicyBundle,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        current = policy_service.current_snapshot()
        return {
            "current": current.model_dump(mode="json"),
            "candidate": payload.model_dump(mode="json"),
            "changed_fields": changed_policy_fields(current, payload),
            "issues": [issue.as_dict() for issue in validate_policy_bundle(payload)],
        }

    @app.post("/v1/policies/rollback/{revision}")
    def rollback_policy(
        revision: int,
        if_match: str | None = Header(default=None, alias="If-Match"),
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> JSONResponse:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        expected_revision = required_policy_revision(if_match)
        for record in policy_service.list_history(limit=1000):
            if record.revision == revision:
                saved = policy_service.save_snapshot(
                    record.policy_bundle,
                    expected_revision=expected_revision,
                    updated_by="rollback",
                )
                return policy_response(
                    saved.policy_bundle,
                    revision=saved.revision,
                )
        raise ApiAuthError("POLICY_REVISION_NOT_FOUND", status_code=404)
