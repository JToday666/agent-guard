"""Tool runtime protocol for sandbox-backed benchmark tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ToolRuntimeProtocol(Protocol):
    sandbox_dir: Path

    def invoke(self, name: str, arguments: dict[str, Any]) -> Any:
        ...

    def list_tools(self) -> dict[str, dict[str, Any]]:
        ...

    def snapshot(self) -> dict[str, tuple[int, int]]:
        ...

    def diff(self, before: dict[str, tuple[int, int]]) -> list[dict[str, Any]]:
        ...

    def close(self) -> None:
        ...
