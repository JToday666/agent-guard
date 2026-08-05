"""Policy management routes."""

from __future__ import annotations

from typing import Any

from agentguard_core import PolicyBundle
from fastapi import Cookie, FastAPI, Header

from guard_api.auth import ApiAuthError
from guard_api.storage.base import PolicySnapshotRecord

from .common import bounded_limit, verify_browser_or_bearer_read
from .context import ApiContext


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


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    policy_service = context.policy_service

    @app.get("/v1/policies/current")
    def current_policy(
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="policy:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return policy_service.current_snapshot().model_dump(mode="json")

    @app.put("/v1/policies/current")
    def update_current_policy(
        payload: PolicyBundle,
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        return policy_service.save_snapshot(payload, updated_by="dashboard").model_dump(
            mode="json"
        )

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
        return {
            "valid": True,
            "bundle_id": payload.bundle_id,
            "version": payload.version,
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
        }

    @app.post("/v1/policies/rollback/{revision}")
    def rollback_policy(
        revision: int,
        x_agentguard_csrf: str | None = Header(default=None, alias="X-AgentGuard-CSRF"),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        auth.verify_csrf(session, x_agentguard_csrf)
        for record in policy_service.list_history(limit=1000):
            if record.revision == revision:
                return policy_service.save_snapshot(
                    record.policy_bundle, updated_by="rollback"
                ).model_dump(mode="json")
        raise ApiAuthError("POLICY_REVISION_NOT_FOUND", status_code=404)
