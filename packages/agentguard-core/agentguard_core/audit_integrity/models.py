"""Tamper-evident audit integrity domain models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AuditIntegrityMetadata(BaseModel):
    sequence: int = Field(ge=1)
    prev_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    canonicalization: Literal["jcs:rfc8785"] = "jcs:rfc8785"
