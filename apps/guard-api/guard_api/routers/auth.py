"""Browser session routes."""

from __future__ import annotations

from typing import Any

from fastapi import Cookie, FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .context import ApiContext


class LaunchExchangeRequest(BaseModel):
    launch_code: str


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    settings = context.settings

    @app.post("/v1/auth/browser/launch")
    def launch(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth.verify_bearer(authorization, "auth:launch")
        return {
            "launch_code": auth.create_launch_code(),
            "expires_in": settings.launch_code_ttl_seconds,
        }

    @app.post("/v1/auth/browser/exchange")
    def exchange(payload: LaunchExchangeRequest) -> JSONResponse:
        session = auth.exchange_launch_code(payload.launch_code)
        response = JSONResponse(
            {
                "authenticated": True,
                "expires_at": session.expires_at.isoformat(),
                "csrf_token": session.csrf_token,
            }
        )
        response.set_cookie(
            "agentguard_session",
            session.session_id,
            httponly=True,
            secure=settings.browser_cookie_secure,
            samesite="strict",
            path="/",
            max_age=settings.browser_session_ttl_seconds,
        )
        return response

    @app.get("/v1/auth/browser/me")
    def me(agentguard_session: str | None = Cookie(default=None)) -> dict[str, Any]:
        session = auth.verify_browser_session(agentguard_session)
        return {
            "authenticated": True,
            "expires_at": session.expires_at.isoformat(),
            "csrf_token": session.csrf_token,
        }

    @app.post("/v1/auth/browser/logout")
    def logout(agentguard_session: str | None = Cookie(default=None)) -> JSONResponse:
        session = auth.verify_browser_session(agentguard_session)
        auth.logout_browser_session(session.session_id)
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(
            "agentguard_session",
            path="/",
            secure=settings.browser_cookie_secure,
            httponly=True,
            samesite="strict",
        )
        return response
