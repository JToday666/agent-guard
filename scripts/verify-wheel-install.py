"""Install the AgentGuard meta package from a local wheelhouse and verify imports."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheelhouse", type=Path)
    args = parser.parse_args()
    root = args.wheelhouse.resolve()
    find_links: list[str] = []
    for directory in (
        "agentguard-core",
        "agentguard-api",
        "agentguard-cli",
        "agentguard",
    ):
        find_links.extend(["--find-links", str(root / directory)])

    with tempfile.TemporaryDirectory(prefix="agentguard-wheel-install-") as temp_dir:
        environment = Path(temp_dir)
        _run(["uv", "venv", str(environment), "--python", "3.12", "--seed"])
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                *find_links,
                "agentguard[all]==0.1.0b1",
            ]
        )
        _run(
            [
                str(python),
                "-c",
                (
                    "import importlib.util; "
                    "import agentguard_core, guard_api, agentguard_cli; "
                    "assert agentguard_core.__version__ == '0.1.0b1'; "
                    "assert guard_api.__version__ == '0.1.0b1'; "
                    "assert agentguard_cli.__version__ == '0.1.0b1'; "
                    "assert importlib.util.find_spec('agentguard') is None"
                ),
            ]
        )
        command = scripts / (
            "agentguardctl.exe" if os.name == "nt" else "agentguardctl"
        )
        completed = subprocess.run(
            [str(command), "--version"], check=True, capture_output=True, text=True
        )
        if completed.stdout.strip() != "0.1.0b1":
            raise RuntimeError(
                f"unexpected agentguardctl version: {completed.stdout!r}"
            )

    print("isolated wheelhouse install: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
