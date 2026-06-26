"""Provenance graph domain models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..ids import new_id, utc_now_iso


class ProvenanceNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    node_id: str = Field(default_factory=lambda: new_id("node"))
    trace_id: str
    kind: str
    ref_id: str
    label: str
    timestamp: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProvenanceEdge(BaseModel):
    model_config = ConfigDict(extra="allow")

    edge_id: str = Field(default_factory=lambda: new_id("edge"))
    trace_id: str
    source_node_id: str
    target_node_id: str
    relation: str
    timestamp: str = Field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)
