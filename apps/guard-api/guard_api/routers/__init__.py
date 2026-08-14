"""Guard API route registration."""

from fastapi import FastAPI

from . import (
    approvals,
    audit,
    auth,
    config_audit,
    credentials,
    evaluations,
    guard,
    memory,
    metrics,
    policies,
    system,
    tasks,
)
from .context import ApiContext


def register_routes(app: FastAPI, context: ApiContext) -> None:
    system.register_routes(app, context)
    auth.register_routes(app, context)
    guard.register_routes(app, context)
    policies.register_routes(app, context)
    audit.register_routes(app, context)
    metrics.register_routes(app, context)
    evaluations.register_routes(app, context)
    config_audit.register_routes(app, context)
    credentials.register_routes(app, context)
    memory.register_routes(app, context)
    approvals.register_routes(app, context)
    tasks.register_routes(app, context)


__all__ = ["ApiContext", "register_routes"]
