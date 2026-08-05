"""Credential lifecycle routes."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header

from guard_api.auth import ApiAuthError
from guard_api.models import CredentialCreateRequest

from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth

    @app.post("/v1/credentials")
    def create_credential(
        payload: CredentialCreateRequest,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "credential:write")
        token, credential = auth.create_credential(payload)
        return {"token": token, "credential": credential.public_dump()}

    @app.get("/v1/credentials")
    def list_credentials(
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, Any]]:
        auth.verify_bearer(authorization, "credential:read")
        return [credential.public_dump() for credential in auth.list_credentials()]

    @app.post("/v1/credentials/{credential_id}/revoke")
    def revoke_credential(
        credential_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "credential:revoke")
        try:
            return auth.revoke_credential(credential_id).public_dump()
        except KeyError:
            raise ApiAuthError("CREDENTIAL_NOT_FOUND", status_code=404)
