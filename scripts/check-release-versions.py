"""Validate source candidate versions; this command never publishes a release."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_VERSION = "0.1.0rc1"
PUBLIC_VERSION = "0.1.0-rc.1"
GIT_TAG = f"v{PUBLIC_VERSION}"
NPM_PACKAGE = "@agentguard-ai/openclaw-plugin"
GHCR_IMAGE = "ghcr.io/jtoday666/agentguard-api"
GHCR_TAG = f"{GHCR_IMAGE}:{PUBLIC_VERSION}"

PYTHON_PROJECTS = {
    "aegis-agentguard-core": Path("packages/agentguard-core/pyproject.toml"),
    "aegis-agentguard-api": Path("apps/guard-api/pyproject.toml"),
    "aegis-agentguard-cli": Path("apps/cli/pyproject.toml"),
    "agentguard-langgraph-adapter": Path(
        "packages/agentguard-langgraph-adapter/pyproject.toml"
    ),
}


def _toml(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def validate(tag: str | None = None) -> list[str]:
    errors: list[str] = []
    for expected_name, relative_path in PYTHON_PROJECTS.items():
        path = ROOT / relative_path
        project = _toml(path)["project"]
        actual_name = project["name"]
        actual_version = project["version"]
        if actual_name != expected_name:
            errors.append(f"{path}: name {actual_name!r} != {expected_name!r}")
        if actual_version != PYTHON_VERSION:
            errors.append(f"{path}: version {actual_version!r} != {PYTHON_VERSION!r}")

    api = _toml(ROOT / PYTHON_PROJECTS["aegis-agentguard-api"])["project"]
    if f"aegis-agentguard-core=={PYTHON_VERSION}" not in api["dependencies"]:
        errors.append("API must depend on the exact candidate Core version")
    for path in (
        "packages/agentguard-core/agentguard_core/_version.py",
        "apps/guard-api/guard_api/_version.py",
        "apps/cli/agentguard_cli/_version.py",
    ):
        if f'__version__ = "{PYTHON_VERSION}"' not in (ROOT / path).read_text():
            errors.append(f"{path}: source fallback version mismatch")
    for lock_name, expected_sources in (
        ("uv.lock", {name: str(path.parent) for name, path in PYTHON_PROJECTS.items()}),
        (
            "apps/guard-api/uv.lock",
            {
                "aegis-agentguard-api": ".",
                "aegis-agentguard-core": "../../packages/agentguard-core",
            },
        ),
    ):
        packages = _toml(ROOT / lock_name)["package"]
        for name, source in expected_sources.items():
            matching = [package for package in packages if package["name"] == name]
            if len(matching) != 1 or matching[0].get("version") != PYTHON_VERSION:
                errors.append(f"{lock_name}: {name} candidate version mismatch")
            elif matching[0].get("source") != {"editable": source} or any(
                field in matching[0] for field in ("sdist", "wheels")
            ):
                errors.append(
                    f"{lock_name}: {name} must use the local source candidate"
                )

    package_path = ROOT / "packages/agentguard-openclaw-plugin/package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    if package["name"] != NPM_PACKAGE:
        errors.append(f"{package_path}: name {package['name']!r} != {NPM_PACKAGE!r}")
    if package["version"] != PUBLIC_VERSION:
        errors.append(
            f"{package_path}: version {package['version']!r} != {PUBLIC_VERSION!r}"
        )

    manifest_path = ROOT / "packages/agentguard-openclaw-plugin/openclaw.plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["id"] != "agentguard-security":
        errors.append(f"{manifest_path}: id must remain 'agentguard-security'")
    if manifest["version"] != PUBLIC_VERSION:
        errors.append(
            f"{manifest_path}: version {manifest['version']!r} != {PUBLIC_VERSION!r}"
        )

    source_path = ROOT / "packages/agentguard-openclaw-plugin/src/index.ts"
    source = source_path.read_text(encoding="utf-8")
    match = re.search(r'const PLUGIN_VERSION = "([^"]+)";', source)
    if match is None or match.group(1) != PUBLIC_VERSION:
        actual = match.group(1) if match else "missing"
        errors.append(
            f"{source_path}: heartbeat version {actual!r} != {PUBLIC_VERSION!r}"
        )

    for relative in (
        "packages/agentguard-openclaw-plugin/product-runtime/product/package.json",
        "packages/agentguard-openclaw-plugin/product-runtime/product/openclaw.plugin.json",
    ):
        child = json.loads((ROOT / relative).read_text())
        if child.get("version") != PUBLIC_VERSION:
            errors.append(f"{relative}: Product package version mismatch")
    factory = ROOT / "packages/agentguard-openclaw-plugin/product-runtime/factory.mjs"
    if not re.search(
        r'version:\s*"' + re.escape(PUBLIC_VERSION) + r'"', factory.read_text()
    ):
        errors.append("Product factory self-reported version mismatch")

    expected_fragments = {
        ROOT
        / "apps/guard-api/Dockerfile": [
            f"aegis-agentguard-core=={PYTHON_VERSION}",
            f"aegis-agentguard-api=={PYTHON_VERSION}",
        ],
    }
    for path, fragments in expected_fragments.items():
        content = path.read_text(encoding="utf-8")
        for fragment in fragments:
            if fragment not in content:
                errors.append(f"{path}: missing release mapping {fragment!r}")

    if tag is not None and tag != GIT_TAG:
        errors.append(f"release tag {tag!r} != {GIT_TAG!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tag",
        help="Release tag to validate when running a tag publication",
    )
    args = parser.parse_args()
    errors = validate(args.tag)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "git_tag": GIT_TAG,
                "python": PYTHON_VERSION,
                "npm_openclaw_ghcr": PUBLIC_VERSION,
                "npm_package": NPM_PACKAGE,
                "ghcr_image": GHCR_IMAGE,
                "ghcr_tag": GHCR_TAG,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
