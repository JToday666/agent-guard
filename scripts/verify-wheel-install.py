"""Install the three AgentGuard Python components and verify their entry points."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

_WHEEL_DIRECTORIES = (
    "aegis-agentguard-core",
    "aegis-agentguard-api",
    "aegis-agentguard-cli",
)


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def _local_wheels(root: Path) -> list[Path]:
    wheels: list[Path] = []
    for directory in _WHEEL_DIRECTORIES:
        wheel_dir = root / directory
        matches = sorted(wheel_dir.glob("*.whl"))
        if len(matches) != 1:
            raise RuntimeError(
                f"expected exactly one wheel in {wheel_dir}, found {len(matches)}"
            )
        wheels.append(matches[0])
    return wheels


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheelhouse", type=Path)
    args = parser.parse_args()
    root = args.wheelhouse.resolve()
    wheels = _local_wheels(root)

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
                *(str(wheel) for wheel in wheels),
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
