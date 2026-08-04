"""Console entry point for the Guard API."""

from __future__ import annotations

import uvicorn

from guard_api.settings import GuardApiSettings


def main() -> None:
    settings = GuardApiSettings()
    settings.validate_for_startup()
    uvicorn.run(
        "guard_api.main:app",
        host=settings.host,
        port=settings.port,
        factory=False,
    )


if __name__ == "__main__":
    main()
