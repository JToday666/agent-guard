"""Clean-install four candidate wheels and verify the independent native SDK."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

VERSION = "0.1.0rc1"
_WHEEL_DIRECTORIES = (
    "aegis-agentguard-core",
    "aegis-agentguard-api",
    "aegis-agentguard-cli",
    "agentguard-langgraph-adapter",
)

# This probe executes inside the clean candidate environment with -I -B. It
# never imports a checkout helper or starts a Product session.
_PROBE = r"""
import hashlib, importlib, importlib.metadata as md, importlib.util, json, sys
from pathlib import Path
root = Path(sys.prefix).resolve()
assert Path(sys.executable).is_file() and not Path(sys.executable).is_symlink()
artifacts = json.loads(sys.argv[1])
packages = []
for distribution, module_name in (
    ("aegis-agentguard-core", "agentguard_core"),
    ("aegis-agentguard-api", "guard_api"),
    ("aegis-agentguard-cli", "agentguard_cli"),
    ("agentguard-langgraph-adapter", "agentguard_langgraph_adapter"),
):
    dist = md.distribution(distribution)
    assert dist.version == "0.1.0rc1"
    module = importlib.import_module(module_name)
    module_file = Path(module.__file__).resolve()
    assert module_file.is_relative_to(root)
    if distribution != "agentguard-langgraph-adapter":
        assert module.__version__ == "0.1.0rc1"
    direct = dist.read_text("direct_url.json")
    assert direct is not None and not json.loads(direct).get("dir_info", {}).get("editable", False)
    files = []
    metadata_path = None
    for relative in dist.files or ():
        path = Path(dist.locate_file(relative))
        # Console scripts are installer-generated and verified by execution.
        if ".." in relative.parts:
            continue
        assert not path.is_symlink() and path.stat().st_nlink == 1
        assert path.stat().st_mode & 0o022 == 0, "candidate installed file is writable by another account"
        path = path.resolve()
        assert path.is_relative_to(root) and path.suffix != ".pyc"
        content = path.read_bytes()
        files.append({"path":str(path),"size":len(content),"raw_sha256":"sha256:"+hashlib.sha256(content).hexdigest()})
        if path.name == "METADATA" and path.parent.name.endswith(".dist-info"):
            assert metadata_path is None
            metadata_path = str(path)
    assert files and metadata_path
    packages.append({"distribution":distribution,"version":dist.version,"artifact":artifacts[distribution],"metadata_path":metadata_path,"module_file":str(module_file),"files":sorted(files,key=lambda item:item["path"])})
from agentguard_langgraph_adapter import AgentGuardLangGraphConfig
from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph
assert callable(build_native_product_graph)
assert AgentGuardLangGraphConfig(core_base_url="http://127.0.0.1:1", token="unused", agent_id="candidate-inspection").product_execution_enabled is False
assert importlib.util.find_spec("agentguard") is None
runtime_versions={name:md.version(name) for name in ("langgraph","langgraph-prebuilt","langchain-core")}
assert runtime_versions == {"langgraph":"1.2.7","langgraph-prebuilt":"1.1.0","langchain-core":"1.4.8"}
for name in runtime_versions:
    dist = md.distribution(name)
    metadata = [Path(dist.locate_file(entry)) for entry in dist.files or () if entry.name == "METADATA" and str(entry.parent).endswith(".dist-info")]
    assert len(metadata) == 1
    assert not metadata[0].is_symlink() and metadata[0].stat().st_nlink == 1
    assert metadata[0].stat().st_mode & 0o022 == 0, "native runtime metadata is writable by another account"
print(json.dumps({"environment_root":str(root),"python_executable":str(Path(sys.executable)),"python_version":sys.version.split()[0],"packages":packages,"runtime_versions":runtime_versions}))
"""


def _environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT"):
        environment.pop(name, None)
    environment.update(PYTHONDONTWRITEBYTECODE="1", UV_COMPILE_BYTECODE="0")
    return environment


def _run(command: list[str], *, cwd: Path | None = None, capture: bool = False):
    return subprocess.run(
        command,
        check=True,
        cwd=cwd,
        env=_environment(),
        umask=0o022,
        capture_output=capture,
        text=True,
    )


def _local_wheels(root: Path) -> list[Path]:
    wheels: list[Path] = []
    for directory in _WHEEL_DIRECTORIES:
        wheel_dir = root / directory
        matches = sorted(wheel_dir.glob("*.whl"))
        if len(matches) != 1:
            raise RuntimeError(
                f"expected exactly one wheel in {wheel_dir}, found {len(matches)}"
            )
        wheel = matches[0]
        expected = f"{directory.replace('-', '_')}-{VERSION}-py3-none-any.whl"
        if wheel.name != expected or wheel.is_symlink() or wheel.stat().st_nlink != 1:
            raise RuntimeError(f"candidate wheel identity mismatch: {directory}")
        wheels.append(wheel)
    return wheels


def _create_environment(environment: Path) -> Path:
    if environment.exists():
        raise RuntimeError("candidate environment must not already exist")
    # Retained reports and their environment share a private parent. Create
    # missing ancestors deliberately: Path.mkdir(parents=True) applies its mode
    # only to the leaf and would inherit a caller's permissive umask above it.
    missing: list[Path] = []
    parent = environment.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for path in reversed(missing):
        path.mkdir(mode=0o700)
    if (
        environment.parent.is_symlink()
        or environment.parent.resolve() != environment.parent
    ):
        raise RuntimeError("candidate environment parent must not contain links")
    parent_stat = environment.parent.stat()
    if parent_stat.st_mode & 0o777 != 0o700 or parent_stat.st_uid != os.geteuid():
        raise RuntimeError("candidate environment parent must be private and owned")
    environment.mkdir(mode=0o700)
    _run(
        [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "venv",
            "--copies",
            "--without-pip",
            str(environment),
        ]
    )
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    return scripts / ("python.exe" if os.name == "nt" else "python")


def _install(
    python: Path, wheels: list[Path], dependency_wheelhouse: Path | None
) -> None:
    # A shared, previously unpacked uv cache can retain writable file modes even
    # under umask 022. A qualification install must unpack its own dependencies.
    command = [
        "uv",
        "--no-cache",
        "pip",
        "install",
        "--python",
        str(python),
        "--link-mode",
        "copy",
    ]
    if dependency_wheelhouse is not None:
        command.extend(
            ["--offline", "--no-index", "--find-links", str(dependency_wheelhouse)]
        )
    command.extend(
        str(wheel)
        + ("[native]" if wheel.name.startswith("agentguard_langgraph_adapter-") else "")
        for wheel in wheels
    )
    # Resolve runtime dependencies against the candidate checkout's real lock,
    # while installing the four explicitly supplied wheels, never editable paths.
    lock = tomllib.loads((Path(__file__).resolve().parents[1] / "uv.lock").read_text())
    versions: dict[str, str] = {}
    for package in lock["package"]:
        if "registry" not in package["source"]:
            continue
        name, version = package["name"], package["version"]
        if name in versions and versions[name] != version:
            raise RuntimeError("candidate dependency lock has ambiguous versions")
        versions[name] = version
    with tempfile.TemporaryDirectory(
        prefix="agentguard-candidate-constraints-"
    ) as temporary:
        constraints = Path(temporary) / "constraints.txt"
        constraints.write_text(
            "".join(
                f"{name}=={version}\n" for name, version in sorted(versions.items())
            )
        )
        command.extend(["--constraint", str(constraints)])
        _run(command, cwd=python.parent.parent)


def verify_installation(
    root: Path,
    environment: Path,
    *,
    source_revision: str | None = None,
    dependency_wheelhouse: Path | None = None,
) -> dict:
    wheels = _local_wheels(root)
    artifacts = {
        name: {
            "path": str(wheel),
            "size": wheel.stat().st_size,
            "raw_sha256": "sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest(),
        }
        for name, wheel in zip(_WHEEL_DIRECTORIES, wheels, strict=True)
    }
    python = _create_environment(environment)
    _install(python, wheels, dependency_wheelhouse)
    probe = _run(
        [str(python), "-I", "-B", "-c", _PROBE, json.dumps(artifacts)],
        cwd=environment,
        capture=True,
    )
    observed = json.loads(probe.stdout)
    command = python.parent / (
        "agentguardctl.exe" if os.name == "nt" else "agentguardctl"
    )
    completed = _run([str(command), "--version"], cwd=environment, capture=True)
    if completed.stdout.strip() != VERSION:
        raise RuntimeError("candidate CLI version mismatch")
    api_command = python.parent / (
        "agentguard-api.exe" if os.name == "nt" else "agentguard-api"
    )
    if not api_command.is_file():
        raise RuntimeError("candidate API console entry is missing")
    # A second environment proves native SDK installation does not acquire Core
    # or the benchmark from the other three candidate wheels.
    with tempfile.TemporaryDirectory(
        prefix="agentguard-native-independent-"
    ) as temporary:
        native_environment = Path(temporary) / "environment"
        native_python = _create_environment(native_environment)
        _install(native_python, [wheels[-1]], dependency_wheelhouse)
        _run(
            [
                str(native_python),
                "-I",
                "-B",
                "-c",
                (
                    "import importlib.util; from agentguard_langgraph_adapter.native_langgraph import build_native_product_graph; "
                    "assert callable(build_native_product_graph); "
                    "assert importlib.util.find_spec('agentguard_core') is None; "
                    "assert importlib.util.find_spec('agentguard_langgraph_bench') is None"
                ),
            ],
            cwd=native_environment,
        )
    return {
        "schema_version": "1.0",
        "kind": "python_candidate_installation",
        "source_revision": source_revision,
        **observed,
        "product_active_enabled": False,
        "external_provider_requests": 0,
        "complete": True,
        "exit_code": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheelhouse", type=Path)
    parser.add_argument("--environment-root", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--source-revision")
    parser.add_argument("--dependency-wheelhouse", type=Path)
    args = parser.parse_args()
    if args.report and (
        args.environment_root is None
        or not re.fullmatch(r"[0-9a-f]{40}", args.source_revision or "")
    ):
        parser.error(
            "--report requires --environment-root and a full --source-revision"
        )
    root = args.wheelhouse.resolve()
    if args.report and args.report.exists():
        parser.error("report must not already exist")
    if args.environment_root:
        report = verify_installation(
            root,
            args.environment_root.absolute(),
            source_revision=args.source_revision,
            dependency_wheelhouse=args.dependency_wheelhouse,
        )
    else:
        with tempfile.TemporaryDirectory(
            prefix="agentguard-wheel-install-"
        ) as temporary:
            report = verify_installation(
                root,
                Path(temporary) / "environment",
                dependency_wheelhouse=args.dependency_wheelhouse,
            )
    if args.report:
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    print("isolated four-wheel and independent native SDK install: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
