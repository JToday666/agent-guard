"""Installed distribution version."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("agentguard-api")
except PackageNotFoundError:  # pragma: no cover - source tree without metadata
    __version__ = "0.1.0b1"
