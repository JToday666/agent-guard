"""Validate the version mapping for an AgentGuard beta release."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_VERSION = "0.1.0b1"
PUBLIC_VERSION = "0.1.0-beta.1"
GIT_TAG = f"v{PUBLIC_VERSION}"
NPM_PACKAGE = "@agentguard-ai/openclaw-plugin"
GHCR_IMAGE = "ghcr.io/jtoday666/agentguard-api"

PYTHON_PROJECTS = {
    "agentguard-core": ROOT / "packages/agentguard-core/pyproject.toml",
    "agentguard-api": ROOT / "apps/guard-api/pyproject.toml",
    "agentguard-cli": ROOT / "apps/cli/pyproject.toml",
    "agentguard": ROOT / "packages/agentguard-meta/pyproject.toml",
}


def _toml(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def validate(tag: str | None = None) -> list[str]:
    errors: list[str] = []
    for expected_name, path in PYTHON_PROJECTS.items():
        project = _toml(path)["project"]
        actual_name = project["name"]
        actual_version = project["version"]
        if actual_name != expected_name:
            errors.append(f"{path}: name {actual_name!r} != {expected_name!r}")
        if actual_version != PYTHON_VERSION:
            errors.append(f"{path}: version {actual_version!r} != {PYTHON_VERSION!r}")

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

    expected_fragments = {
        ROOT
        / "apps/guard-api/Dockerfile": [
            f"agentguard-core=={PYTHON_VERSION}",
            f"agentguard-api=={PYTHON_VERSION}",
        ],
        ROOT
        / ".github/workflows/publish-beta.yml": [
            f"{GHCR_IMAGE}:{PUBLIC_VERSION}",
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
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
