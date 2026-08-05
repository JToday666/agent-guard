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
        "aegis-agentguard-core",
        "aegis-agentguard-api",
        "aegis-agentguard-cli",
        "aegis-agentguard",
    ):
        find_links.extend(["--find-links", str(root / directory)])

    with tempfile.TemporaryDirectory(prefix="agentguard-wheel-install-") as temp_dir:
        environment = Path(temp_dir)
        _run(["uv", "venv", str(environment), "--python", "3.12"])
        scripts = environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        _run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(python),
                *find_links,
                "aegis-agentguard[all]==0.1.0b1",
            ]
        )
        _run(
            [
                str(python),
                "-c",
                (
                    "import importlib.util; "
                    "import aegis_agentguard, agentguard_core, guard_api, "
                    "agentguard_cli; "
                    "assert aegis_agentguard.__version__ == '0.1.0b1'; "
                    "assert agentguard_core.__version__ == '0.1.0b1'; "
                    "assert guard_api.__version__ == '0.1.0b1'; "
                    "assert agentguard_cli.__version__ == '0.1.0b1'; "
                    "assert aegis_agentguard.GuardEngine is agentguard_core.GuardEngine; "
                    "assert aegis_agentguard.GuardEvent is agentguard_core.GuardEvent; "
                    "assert aegis_agentguard.GuardDecision is agentguard_core.GuardDecision; "
                    "assert aegis_agentguard.PolicyBundle is agentguard_core.PolicyBundle; "
                    "assert aegis_agentguard.evaluate is agentguard_core.evaluate; "
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
        api_command = scripts / (
            "agentguard-api.exe" if os.name == "nt" else "agentguard-api"
        )
        if not api_command.is_file():
            raise RuntimeError(
                f"agentguard-api console script is missing: {api_command}"
            )

    print("isolated wheelhouse install: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
