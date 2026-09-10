"""Synthetic unit protocol fixtures only; these never qualify a real candidate."""

import base64
import copy
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

from scripts.product_runtime import candidate as c
from scripts.product_runtime.evidence import EvidenceError, EvidenceStore, sha256

pytestmark = pytest.mark.contract


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    path.write_bytes(content)
    path.chmod(0o644)
    return path


def _json(path, value):
    return _write(path, json.dumps(value, indent=2).encode())


def _absolute(path):
    content = path.read_bytes()
    return {"path": str(path), "size": len(content), "raw_sha256": sha256(content)}


def _ref(root, path):
    return {**_absolute(path), "path": path.relative_to(root).as_posix()}


def _archive(path, members, *, wheel=False):
    result = io.BytesIO()
    if wheel:
        with zipfile.ZipFile(result, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
    else:
        with tarfile.open(fileobj=result, mode="w:gz") as archive:
            for name, content in members.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return _write(path, result.getvalue())


def _git(root, *args):
    return (
        subprocess.check_output(
            [
                "git",
                "-c",
                "user.name=Unit Fixture",
                "-c",
                "user.email=unit@agentguard.invalid",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            cwd=root,
            stderr=subprocess.DEVNULL,
        )
        .decode()
        .strip()
    )


@pytest.fixture
def unit_candidate(tmp_path, *, extra_sources=None, extra_python=None, extra_node=None):
    """Minimal archive/install trees, protocol reports, and an actual temporary Git SHA."""
    root = tmp_path / "evidence"
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    root.mkdir()
    members_by_id = {}
    artifacts = []
    for distribution, (project, module) in c.PYTHON_PROJECTS.items():
        content = b'__version__ = "0.1.0rc1"\n'
        sources = {
            module + "/__init__.py": content,
            "pyproject.toml": b"# unit fixture\n",
            "README.md": b"Unit fixture\n",
            "LICENSE": b"MIT\n",
        }
        sources.update((extra_python or {}).get(distribution, {}))
        for name, value in sources.items():
            _write(checkout / project / name, value)
        metadata = f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {c.PYTHON_VERSION}\n"
        if distribution == "aegis-agentguard-api":
            metadata += "Requires-Dist: aegis-agentguard-core==0.1.0rc1\n"
        if distribution == "agentguard-langgraph-adapter":
            metadata += "Provides-Extra: native\n"
            for name, version in c._NATIVE_PINS.items():
                metadata += f'Requires-Dist: {name}=={version}; extra == "native"\n'
        stem = distribution.replace("-", "_") + "-" + c.PYTHON_VERSION
        wheel = {
            module + "/__init__.py": content,
            stem + ".dist-info/METADATA": metadata.encode(),
            stem + ".dist-info/licenses/LICENSE": b"MIT\n",
            stem + ".dist-info/RECORD": b"",
        }
        wheel.update((extra_python or {}).get(distribution, {}))
        sdist = {stem + "/" + name: value for name, value in sources.items()}
        sdist[stem + "/PKG-INFO"] = metadata.encode()
        for kind, members in (("wheel", wheel), ("sdist", sdist)):
            path = (
                root / "artifacts" / distribution / c.archive_name(distribution, kind)
            )
            _archive(path, members, wheel=kind == "wheel")
            members_by_id[distribution, kind] = members
            artifacts.append(
                {"distribution": distribution, "kind": kind, "file": _ref(root, path)}
            )
    npm_local = {
        "package.json": json.dumps(
            {"name": c.NPM_DISTRIBUTION, "version": c.NPM_VERSION}
        ).encode(),
        "openclaw.plugin.json": json.dumps(
            {"id": "agentguard-security", "version": c.NPM_VERSION}
        ).encode(),
        "product-runtime/product/package.json": json.dumps(
            {
                "name": "@agentguard-ai/openclaw-product-runtime",
                "version": c.NPM_VERSION,
            }
        ).encode(),
        "product-runtime/product/openclaw.plugin.json": json.dumps(
            {"id": "agentguard-product-runtime-fixture", "version": c.NPM_VERSION}
        ).encode(),
        "product-runtime/product/index.mjs": b"export default {};\n",
        "dist/index.js": b"export default {};\n",
        "LICENSE": b"MIT\n",
    }
    npm_local.update(extra_node or {})
    for name, value in npm_local.items():
        if not name.startswith("dist/"):
            _write(checkout / "packages/agentguard-openclaw-plugin" / name, value)
    npm_members = {"package/" + name: value for name, value in npm_local.items()}
    npm_path = root / "artifacts/npm" / c.archive_name(c.NPM_DISTRIBUTION, "npm_tgz")
    _archive(npm_path, npm_members)
    members_by_id[c.NPM_DISTRIBUTION, "npm_tgz"] = npm_members
    artifacts.append(
        {
            "distribution": c.NPM_DISTRIBUTION,
            "kind": "npm_tgz",
            "file": _ref(root, npm_path),
        }
    )
    for name, value in (extra_sources or {}).items():
        _write(checkout / name, value)
    _git(checkout, "init", "--quiet")
    _git(checkout, "add", ".")
    _git(checkout, "commit", "--quiet", "-m", "Unit fixture only")
    revision = _git(checkout, "rev-parse", "HEAD")
    source_path = _write(
        root / "source/source.tar", c.source_archive_bytes(checkout, revision)
    )
    log = _write(
        root / "build/log.txt", b"Unit protocol fixture; no real build is claimed.\n"
    )
    commands = [
        ["uv", "build", project, "--out-dir", str(root / "artifacts" / name)]
        for name, (project, _module) in c.PYTHON_PROJECTS.items()
    ]
    commands += [
        ["pnpm", "--filter", c.NPM_DISTRIBUTION, "build"],
        [
            "pnpm",
            "--filter",
            c.NPM_DISTRIBUTION,
            "pack",
            "--pack-destination",
            str(npm_path.parent),
        ],
    ]
    build = {
        "schema_version": "agentguard-product-build/1",
        "source_revision": revision,
        "source_archive_raw_sha256": sha256(source_path.read_bytes()),
        "commands": [
            {
                "argv": cmd,
                "cwd": str(checkout),
                "exit_code": 0,
                "stdout": _ref(root, log),
                "stderr": _ref(root, log),
            }
            for cmd in commands
        ],
        "tool_versions": {
            "python": "Python 3.12.12",
            "uv": "uv 0.12.5",
            "node": "v22.18.0",
            "pnpm": "10.0.0",
        },
        "artifacts": [a["file"] for a in artifacts],
        "complete": True,
        "exit_code": 0,
    }
    build_path = _json(root / "build/report.json", build)
    environment = root / "installed/python"
    executable = environment / "python"
    executable.parent.mkdir(parents=True)
    shutil.copyfile(sys.executable, executable)
    executable.chmod(0o755)
    packages = []
    for distribution, (_project, module) in c.PYTHON_PROJECTS.items():
        wheel = members_by_id[distribution, "wheel"]
        site = environment / "site-packages"
        for name, content in wheel.items():
            _write(site / name, content)
        dist = distribution.replace("-", "_") + "-" + c.PYTHON_VERSION + ".dist-info"
        artifact = next(
            a
            for a in artifacts
            if a["distribution"] == distribution and a["kind"] == "wheel"
        )
        archive_path = root / artifact["file"]["path"]
        origin = {
            "url": archive_path.as_uri(),
            "archive_info": {"hashes": {"sha256": artifact["file"]["raw_sha256"][7:]}},
        }
        _json(site / dist / "direct_url.json", origin)
        _write(site / dist / "INSTALLER", b"uv\n")
        files = sorted(
            [
                p
                for directory in (site / module, site / dist)
                for p in directory.rglob("*")
                if p.is_file()
            ]
        )
        output = io.StringIO()
        writer = csv.writer(output)
        for path in files:
            name = path.relative_to(site).as_posix()
            if name == dist + "/RECORD":
                writer.writerow([name, "", ""])
            else:
                content = path.read_bytes()
                digest = (
                    base64.urlsafe_b64encode(bytes.fromhex(sha256(content)[7:]))
                    .decode()
                    .rstrip("=")
                )
                writer.writerow([name, "sha256=" + digest, str(len(content))])
        _write(site / dist / "RECORD", output.getvalue().encode())
        packages.append(
            {
                "distribution": distribution,
                "version": c.PYTHON_VERSION,
                "artifact": _absolute(archive_path),
                "metadata_path": str(site / dist / "METADATA"),
                "module_file": str(site / module / "__init__.py"),
                "files": [_absolute(p) for p in files],
            }
        )
    for name, version in c._NATIVE_PINS.items():
        _write(
            environment
            / "site-packages"
            / (name.replace("-", "_") + "-" + version + ".dist-info")
            / "METADATA",
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n".encode(),
        )
    flags = {
        "product_active_enabled": False,
        "external_provider_requests": 0,
        "complete": True,
        "exit_code": 0,
    }
    python = {
        "schema_version": "1.0",
        "kind": "python_candidate_installation",
        "source_revision": revision,
        "environment_root": str(environment),
        "python_executable": str(executable),
        "python_version": "3.12.12",
        "packages": packages,
        "runtime_versions": c._NATIVE_PINS,
        **flags,
    }
    python_path = _json(root / "install/python.json", python)
    node_env = root / "installed/node"
    lanes = []
    for lane, runtime_version in (("legacy", "2026.6.6"), ("product", "2026.7.1-2")):
        lane_root = node_env / lane
        plugin = lane_root / "plugin"
        runtime = lane_root / "openclaw"
        for name, content in npm_local.items():
            _write(plugin / name, content)
        _json(
            runtime / "package.json", {"name": "openclaw", "version": runtime_version}
        )
        inspection = (
            {
                "active": False,
                "artifactDigest": sha256(npm_path.read_bytes()),
                "runtimeVersion": runtime_version,
                "packageVersion": c.NPM_VERSION,
            }
            if lane == "product"
            else None
        )
        lane_evidence = _json(lane_root / "evidence.json", {"unit_fixture": True})
        lanes.append(
            {
                "lane": lane,
                "runtime_version": runtime_version,
                "package_version": c.NPM_VERSION,
                "installation_root": str(lane_root),
                "plugin_root": str(plugin),
                "runtime_root": str(runtime),
                "artifact_digest": sha256(npm_path.read_bytes()),
                "files": [_absolute(plugin / name) for name in npm_local],
                "compatibility_import": True,
                "product_inspection": inspection,
                "product_active_enabled": False,
                "evidence_file": _absolute(lane_evidence),
            }
        )
        _json(
            lane_evidence,
            {
                key: value
                for key, value in lanes[-1].items()
                if key not in {"lane", "evidence_file"}
            },
        )
        lanes[-1]["evidence_file"] = _absolute(lane_evidence)
    node = {
        "schema_version": "1.0",
        "kind": "openclaw_candidate_installation",
        "source_revision": revision,
        "artifact": _absolute(npm_path),
        "package_version": c.NPM_VERSION,
        "environment_root": str(node_env),
        "lanes": lanes,
        **flags,
    }
    node_path = _json(root / "install/node.json", node)
    aggregate = {
        "schema_version": "agentguard-product-installation/1",
        "source_revision": revision,
        "python": _ref(root, python_path),
        "openclaw": _ref(root, node_path),
    }
    installation_path = _json(root / "install/aggregate.json", aggregate)
    manifest = {
        "schema_version": c.CANDIDATE_SCHEMA,
        "source_revision": revision,
        "source_archive": _ref(root, source_path),
        "artifacts": artifacts,
        "build_evidence": _ref(root, build_path),
        "installation_evidence": _ref(root, installation_path),
    }
    manifest_path = _json(root / "candidate.json", manifest)
    # The test process may inherit umask 0002. Candidate protection is explicit.
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
    return SimpleNamespace(
        root=root,
        checkout=checkout,
        revision=revision,
        manifest=manifest,
        manifest_path=manifest_path,
        source_path=source_path,
        build=build,
        build_path=build_path,
        python=python,
        python_path=python_path,
        node=node,
        node_path=node_path,
        aggregate=aggregate,
        installation_path=installation_path,
        members=members_by_id,
    )


def _refresh(f):
    for runtime in ("python", "node"):
        _json(getattr(f, runtime + "_path"), getattr(f, runtime))
    f.aggregate["python"] = _ref(f.root, f.python_path)
    f.aggregate["openclaw"] = _ref(f.root, f.node_path)
    _json(f.installation_path, f.aggregate)
    _json(f.build_path, f.build)
    f.manifest["installation_evidence"] = _ref(f.root, f.installation_path)
    f.manifest["build_evidence"] = _ref(f.root, f.build_path)
    _json(f.manifest_path, f.manifest)


def _verify(f):
    return c.verify_candidate(
        _ref(f.root, f.manifest_path), EvidenceStore(f.root), f.checkout, f.revision
    )


def test_all_nine_unit_archives_have_source_raw_hash_and_retained_install_binding(
    unit_candidate,
):
    f = unit_candidate
    verified = _verify(f)
    assert len(verified.artifacts) == 9
    assert verified.manifest == f.manifest
    assert verified.canonical_digest != sha256(f.manifest_path.read_bytes())
    assert set(verified.installation_reports) == {"python", "openclaw"}


@pytest.mark.parametrize(
    "mutation",
    [
        "pnpm_pack_order",
        "changed_value",
        "added_field",
        "duplicate_key",
        "boolean_number",
        "nested_json_format",
        "source_bytes",
    ],
)
def test_pnpm_pack_top_level_metadata_keeps_complete_source_equivalence(
    tmp_path, mutation
):
    metadata = {
        "name": c.NPM_DISTRIBUTION,
        "version": c.NPM_VERSION,
        "private": True,
        "scripts": {"build": "tsc", "test": "node --test"},
        "peerDependencies": {"openclaw": ">=2026.6.6 <2027.0.0"},
    }
    source_bytes = (json.dumps(metadata, indent=2) + "\n").encode()
    fixture = unit_candidate.__wrapped__(
        tmp_path, extra_node={"package.json": source_bytes}
    )
    members = fixture.members[c.NPM_DISTRIBUTION, "npm_tgz"].copy()
    packed = metadata.copy()
    packed["scripts"] = packed.pop("scripts")
    if mutation == "changed_value":
        packed["scripts"] = {"build": "unrelated-command", "test": "node --test"}
    elif mutation == "added_field":
        packed["unrequested"] = "extra-metadata"
    elif mutation == "boolean_number":
        packed["private"] = 1
    packed_bytes = json.dumps(packed, indent=2).encode()
    if mutation == "duplicate_key":
        packed_bytes = packed_bytes[:-1] + b',"version":"0.1.0-rc.1"}'
    members["package/package.json"] = packed_bytes
    if mutation == "nested_json_format":
        nested = "package/product-runtime/product/package.json"
        members[nested] = json.dumps(json.loads(members[nested]), indent=2).encode()
    elif mutation == "source_bytes":
        members["package/LICENSE"] += b"\n"
    item = next(a for a in fixture.manifest["artifacts"] if a["kind"] == "npm_tgz")
    archive = fixture.root / item["file"]["path"]
    _archive(archive, members)
    item["file"] = _ref(fixture.root, archive)
    source = c.safe_archive_members(fixture.source_path.read_bytes(), wheel=False)
    if mutation == "pnpm_pack_order":
        assert source_bytes != packed_bytes
        artifacts = c.verify_artifacts(
            EvidenceStore(fixture.root), fixture.manifest["artifacts"], source
        )
        npm = next(a for a in artifacts if a.kind == "npm_tgz")
        assert len(artifacts) == 9
        assert npm.raw_sha256 == sha256(archive.read_bytes())
        assert npm.members["package/package.json"] == packed_bytes
    else:
        with pytest.raises(EvidenceError):
            c.verify_artifacts(
                EvidenceStore(fixture.root), fixture.manifest["artifacts"], source
            )


@pytest.mark.parametrize(
    "mutation",
    ["missing", "duplicate", "revision", "schema", "conformance", "raw_hash"],
)
def test_candidate_manifest_rejects_incomplete_drift_or_circular_evidence(
    unit_candidate, mutation
):
    f = unit_candidate
    if mutation == "missing":
        f.manifest["artifacts"].pop()
    elif mutation == "duplicate":
        f.manifest["artifacts"][-1] = copy.deepcopy(f.manifest["artifacts"][0])
    elif mutation in {"revision", "schema"}:
        f.manifest[
            "source_revision" if mutation == "revision" else "schema_version"
        ] = "wrong"
    elif mutation == "conformance":
        f.manifest["conformance"] = {"complete": True}
    else:
        f.manifest["artifacts"][0]["file"]["raw_sha256"] = "sha256:" + "0" * 64
    _json(f.manifest_path, f.manifest)
    with pytest.raises(EvidenceError):
        _verify(f)


@pytest.mark.parametrize(
    "mutation", ["dirty", "sha", "source_archive", "checkout_alias"]
)
def test_checkout_and_source_are_actual_immutable_sha_bytes(unit_candidate, mutation):
    f = unit_candidate
    if mutation == "dirty":
        _write(
            f.checkout / "packages/agentguard-core/agentguard_core/__init__.py",
            b"changed\n",
        )
    elif mutation == "sha":
        f.revision = "0" * 40
    elif mutation == "source_archive":
        _archive(f.source_path, {"unrelated": b"x"})
        f.manifest["source_archive"] = _ref(f.root, f.source_path)
        _json(f.manifest_path, f.manifest)
    else:
        alias = f.checkout.parent / "alias"
        alias.symlink_to(f.checkout, target_is_directory=True)
        f.checkout = alias
    with pytest.raises(EvidenceError):
        _verify(f)


@pytest.mark.parametrize("mutation", ["metadata", "source", "pin", "license", "leak"])
def test_actual_archive_metadata_sources_dependencies_and_members_are_checked(
    unit_candidate, mutation
):
    f = unit_candidate
    distribution = (
        "agentguard-langgraph-adapter" if mutation == "pin" else "aegis-agentguard-core"
    )
    item = next(
        a
        for a in f.manifest["artifacts"]
        if a["distribution"] == distribution and a["kind"] == "wheel"
    )
    members = f.members[distribution, "wheel"].copy()
    metadata = next(name for name in members if name.endswith("/METADATA"))
    if mutation == "metadata":
        members[metadata] = members[metadata].replace(b"0.1.0rc1", b"0.1.0b1")
    elif mutation == "pin":
        members[metadata] = members[metadata].replace(
            b"langgraph==1.2.7", b"langgraph==1.0.0"
        )
    elif mutation == "source":
        members[next(name for name in members if name.endswith("/__init__.py"))] = (
            b"changed\n"
        )
    elif mutation == "license":
        del members[next(name for name in members if name.endswith("/LICENSE"))]
    else:
        members[".env/key"] = b"unit fixture"
    path = f.root / item["file"]["path"]
    _archive(path, members, wheel=True)
    item["file"] = _ref(f.root, path)
    _json(f.manifest_path, f.manifest)
    with pytest.raises(EvidenceError):
        _verify(f)


@pytest.mark.parametrize(
    "mutation",
    [
        "build_failure",
        "build_command",
        "build_sha",
        "active",
        "provider",
        "incomplete",
        "runtime",
        "installed_bytes",
        "extra_file",
        "writable_file",
        "writable_dir",
        "node_runtime",
        "node_inspection",
        "node_artifact",
        "native_metadata",
        "native_duplicate",
        "site_writable",
        "node_worker_only",
        "node_report_only",
    ],
)
def test_build_and_install_evidence_cannot_qualify_failed_or_drifted_tree(
    unit_candidate, mutation
):
    f = unit_candidate
    if mutation == "build_failure":
        f.build["commands"][0]["exit_code"] = 1
    elif mutation == "build_command":
        f.build["commands"][0]["argv"] = ["echo", "pretend build"]
    elif mutation == "build_sha":
        f.build["source_revision"] = "0" * 40
    elif mutation == "active":
        f.python["product_active_enabled"] = True
    elif mutation == "provider":
        f.python["external_provider_requests"] = 1
    elif mutation == "incomplete":
        f.python["complete"] = False
    elif mutation == "runtime":
        f.python["runtime_versions"] = {**c._NATIVE_PINS, "langgraph": "1.0.0"}
    elif mutation == "installed_bytes":
        _write(Path(f.python["packages"][0]["module_file"]), b"changed\n")
    elif mutation == "extra_file":
        _write(
            Path(f.python["packages"][0]["module_file"]).parent / "injected.py",
            b"added\n",
        )
    elif mutation == "writable_file":
        Path(f.python["packages"][0]["module_file"]).chmod(0o664)
    elif mutation == "writable_dir":
        Path(f.python["packages"][0]["module_file"]).parent.chmod(0o775)
    elif mutation == "node_runtime":
        _json(
            Path(f.node["lanes"][1]["runtime_root"]) / "package.json",
            {"name": "openclaw", "version": "wrong"},
        )
    elif mutation == "node_inspection":
        f.node["lanes"][1]["product_inspection"]["active"] = True
    elif mutation == "native_metadata":
        site = Path(f.python["packages"][0]["metadata_path"]).parent.parent
        _write(
            site / "langgraph-1.2.7.dist-info/METADATA",
            b"Name: langgraph\nVersion: 1.0.0\n",
        )
    elif mutation == "native_duplicate":
        site = Path(f.python["packages"][0]["metadata_path"]).parent.parent
        _write(
            site / "langgraph-1.0.0.dist-info/METADATA",
            b"Name: langgraph\nVersion: 1.0.0\n",
        )
    elif mutation == "site_writable":
        Path(f.python["packages"][0]["metadata_path"]).parent.parent.chmod(0o775)
    elif mutation == "node_worker_only":
        lane = f.node["lanes"][1]
        path = Path(lane["evidence_file"]["path"])
        worker = json.loads(path.read_bytes())
        worker["compatibility_import"] = False
        _json(path, worker)
        lane["evidence_file"] = _absolute(path)
    elif mutation == "node_report_only":
        f.node["lanes"][1]["product_inspection"]["extra_fabricated_claim"] = True
    else:
        f.node["artifact"]["raw_sha256"] = "sha256:" + "0" * 64
    _refresh(f)
    with pytest.raises(EvidenceError):
        _verify(f)


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../outside", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("a//b", tarfile.REGTYPE),
        ("symlink", tarfile.SYMTYPE),
        ("hardlink", tarfile.LNKTYPE),
        ("pipe", tarfile.FIFOTYPE),
    ],
)
def test_archive_members_reject_unsafe_names_and_types(name, kind):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "target" if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE} else ""
        archive.addfile(member)
    with pytest.raises(EvidenceError):
        c.safe_archive_members(out.getvalue(), wheel=False)


def test_duplicate_archive_and_expansion_limits_are_enforced(monkeypatch):
    out = io.BytesIO()
    with pytest.warns(UserWarning), zipfile.ZipFile(out, "w") as archive:
        archive.writestr("a", b"one")
        archive.writestr("a", b"two")
    with pytest.raises(EvidenceError, match="duplicate"):
        c.safe_archive_members(out.getvalue(), wheel=True)
    monkeypatch.setattr(c, "MEMBER_LIMIT", 2)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("a", b"large")
    with pytest.raises(EvidenceError, match="size_limit"):
        c.safe_archive_members(out.getvalue(), wheel=True)


def test_subprocess_output_and_elapsed_time_are_bounded(tmp_path):
    with pytest.raises(EvidenceError, match="output_limit"):
        c.bounded_command(
            [sys.executable, "-c", "print('x' * 100000)"], cwd=tmp_path, limit=1024
        )
    with pytest.raises(EvidenceError, match="timeout"):
        c.bounded_command(
            [sys.executable, "-c", "import time;time.sleep(10)"],
            cwd=tmp_path,
            timeout=0.1,
        )


def test_build_subprocess_permissions_do_not_inherit_writable_caller_umask(tmp_path):
    previous = os.umask(0o002)
    try:
        status, _stdout, _stderr = c.bounded_command(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('created').write_text('unit'); Path('directory').mkdir()",
            ],
            cwd=tmp_path,
        )
    finally:
        os.umask(previous)
    assert status == 0
    assert (tmp_path / "created").stat().st_mode & 0o777 == 0o644
    assert (tmp_path / "directory").stat().st_mode & 0o777 == 0o755


def test_candidate_cli_verify_keeps_activation_disabled_and_fails_wrong_sha(
    unit_candidate,
):
    f = unit_candidate
    script = Path(__file__).parents[1] / "scripts/product-runtime-candidate.py"
    argv = [
        sys.executable,
        str(script),
        "verify",
        "--evidence-root",
        str(f.root),
        "--checkout",
        str(f.checkout),
        "--expected-source-revision",
        f.revision,
        "--manifest",
        str(f.manifest_path),
    ]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["product_active_enabled"] is False
    argv[argv.index(f.revision)] = "0" * 40
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert json.loads(result.stderr)["verified"] is False


@pytest.mark.parametrize(
    "failure", [None, "bad_build", "linked_output_parent", "linked_artifact_parent"]
)
def test_candidate_cli_only_publishes_verified_complete_manifest(
    unit_candidate, failure
):
    f = unit_candidate
    script = Path(__file__).parents[1] / "scripts/product-runtime-candidate.py"
    output = f.root / "created.json"
    if failure == "bad_build":
        f.build["exit_code"] = 1
        _refresh(f)
    elif failure == "linked_output_parent":
        alias = f.root / "alias"
        alias.symlink_to(f.root, target_is_directory=True)
        output = alias / "created.json"
    elif failure == "linked_artifact_parent":
        alias = f.root / "artifacts/alias"
        alias.symlink_to(f.root / "artifacts/npm", target_is_directory=True)
    argv = [
        sys.executable,
        str(script),
        "create",
        "--evidence-root",
        str(f.root),
        "--checkout",
        str(f.checkout),
        "--expected-source-revision",
        f.revision,
        "--artifacts-root",
        str(f.root / "artifacts"),
        "--source-archive",
        str(f.source_path),
        "--build-evidence",
        str(f.build_path),
        "--installation-evidence",
        str(f.installation_path),
        "--output",
        str(output),
    ]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if failure is None:
        assert result.returncode == 0, result.stderr
        assert json.loads(output.read_bytes()) == f.manifest
        assert output.stat().st_nlink == 1
        original = output.read_bytes()
        repeated = subprocess.run(argv, capture_output=True, text=True, check=False)
        assert repeated.returncode == 1
        assert output.read_bytes() == original
    else:
        assert result.returncode != 0
        assert not output.exists()
    assert not list(f.root.glob("*.unverified"))


@pytest.fixture
def candidate_cli(monkeypatch):
    scripts = Path(__file__).parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location(
        "candidate_unit_cli", scripts / "product-runtime-candidate.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "failure", [None, "command_failed", "report_failed", "unbuilt"]
)
def test_install_aggregate_requires_successful_commands_and_actual_report_readback(
    unit_candidate, candidate_cli, monkeypatch, failure
):
    """Only the subprocess is controlled; all archive/report/filesystem checks are real."""
    f = unit_candidate
    commands = []
    if failure == "unbuilt":
        f.build["exit_code"] = 1
        _refresh(f)

    def runner(argv, **_kwargs):
        commands.append(argv)
        if failure == "command_failed":
            return 1, b"unit failed command", b""
        report = copy.deepcopy(f.python if len(commands) == 1 else f.node)
        if failure == "report_failed":
            report["complete"] = False
        _json(Path(argv[argv.index("--report") + 1]), report)
        return 0, b"unit subprocess response only", b""

    monkeypatch.setattr(candidate_cli, "bounded_command", runner)
    args = SimpleNamespace(
        artifacts_root=f.root / "artifacts",
        source_archive=f.source_path,
        build_evidence=f.build_path,
        expected_source_revision=f.revision,
        dependency_wheelhouse=None,
    )
    if failure is not None:
        with pytest.raises(candidate_cli.EvidenceError):
            candidate_cli._install(
                args, candidate_cli.EvidenceStore(f.root), f.checkout
            )
        assert not (f.root / "installation/installation-evidence.json").exists()
        assert len(commands) == (
            0 if failure == "unbuilt" else 1 if failure == "command_failed" else 2
        )
    else:
        summary = candidate_cli._install(
            args, candidate_cli.EvidenceStore(f.root), f.checkout
        )
        aggregate = json.loads(
            (f.root / summary["installation_evidence"]["path"]).read_bytes()
        )
        assert aggregate["schema_version"] == "agentguard-product-installation/1"
        assert summary["product_active_enabled"] is False
        assert len(commands) == 2
        assert commands[0][1] == str(f.checkout / "scripts/verify-wheel-install.py")
        assert commands[1][:2] == [
            "node",
            str(f.checkout / "scripts/verify-npm-tarball.mjs"),
        ]


@pytest.mark.parametrize("writable", [False, True])
def test_build_refuses_writable_source_before_subprocess(
    unit_candidate, candidate_cli, writable
):
    f = unit_candidate
    f.checkout.chmod(0o755)
    for path in f.checkout.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
    if writable:
        (f.checkout / "packages/agentguard-core/agentguard_core/__init__.py").chmod(
            0o664
        )
        with pytest.raises(candidate_cli.EvidenceError, match="writable"):
            candidate_cli._require_build_source(f.checkout, f.source_path.read_bytes())
    else:
        candidate_cli._require_build_source(f.checkout, f.source_path.read_bytes())


@pytest.mark.parametrize(
    "mutation", [None, "origin_hash", "origin_path", "cache_schema", "unrecorded_cache"]
)
def test_actual_uv_local_origin_and_cache_still_require_all_bytes_and_record_hashes(
    unit_candidate, mutation
):
    f = unit_candidate
    package = f.python["packages"][0]
    metadata = Path(package["metadata_path"])
    directory = metadata.parent
    site = directory.parent
    origin = json.loads((directory / "direct_url.json").read_bytes())
    origin["archive_info"] = {}
    if mutation == "origin_hash":
        origin["archive_info"] = {"hashes": {"sha256": "0" * 64}}
    elif mutation == "origin_path":
        origin["url"] = "file:///unrelated.whl"
    _json(directory / "direct_url.json", origin)
    cache = {
        "timestamp": {"secs_since_epoch": 1, "nanos_since_epoch": 2},
        "commit": None,
        "tags": None,
        "env": {},
        "directories": {},
    }
    if mutation == "cache_schema":
        cache["commit"] = "arbitrary-source"
    _json(directory / "uv_cache.json", cache)
    _write(directory / "INSTALLER", b"uv")
    paths = sorted(
        [Path(item["path"]) for item in package["files"]]
        + [directory / "uv_cache.json"]
    )
    output = io.StringIO()
    writer = csv.writer(output)
    for path in paths:
        local = path.relative_to(site).as_posix()
        if path.name == "RECORD":
            writer.writerow([local, "", ""])
        elif path.name == "uv_cache.json" and mutation == "unrecorded_cache":
            continue
        else:
            content = path.read_bytes()
            digest = (
                base64.urlsafe_b64encode(bytes.fromhex(sha256(content)[7:]))
                .decode()
                .rstrip("=")
            )
            writer.writerow([local, "sha256=" + digest, str(len(content))])
    _write(directory / "RECORD", output.getvalue().encode())
    package["files"] = [_absolute(path) for path in paths]
    _refresh(f)
    if mutation is None:
        _verify(f)
    else:
        with pytest.raises(EvidenceError):
            _verify(f)


@pytest.mark.parametrize(
    "sentinel", ["valid", "wrong_bytes", "wrong_location", "unknown_file"]
)
def test_cli_archive_inventory_only_allows_fixed_uv_sentinel(
    unit_candidate, candidate_cli, sentinel
):
    f = unit_candidate
    artifacts = f.root / "artifacts"
    for distribution in c.PYTHON_PROJECTS:
        _write(artifacts / distribution / ".gitignore", b"*")
    if sentinel == "wrong_bytes":
        _write(artifacts / next(iter(c.PYTHON_PROJECTS)) / ".gitignore", b"*\n")
    elif sentinel == "wrong_location":
        _write(artifacts / "npm/.gitignore", b"*")
    elif sentinel == "unknown_file":
        _write(artifacts / "invented-manifest.json", b"{}")
    if sentinel == "valid":
        assert (
            len(
                candidate_cli._artifact_refs(
                    candidate_cli.EvidenceStore(f.root), artifacts
                )
            )
            == 9
        )
    else:
        with pytest.raises(candidate_cli.EvidenceError, match="unexpected_file"):
            candidate_cli._artifact_refs(candidate_cli.EvidenceStore(f.root), artifacts)
