"""Command-line entrypoint for AttackBench."""

from __future__ import annotations

from .runner import build_parser, main

__all__ = ["build_parser", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
