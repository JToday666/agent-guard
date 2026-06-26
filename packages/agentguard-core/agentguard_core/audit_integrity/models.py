"""Tamper-evident audit integrity domain models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuditIntegrityMetadata(BaseModel):
    sequence: int = Field(ge=1)
    prev_hash: str | None = None
    event_hash: str
    canonicalization: str = "json:v1"
