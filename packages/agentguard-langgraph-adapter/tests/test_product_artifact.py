"""Synthetic clean wheel installations; no production version or path override."""

from dataclasses import replace
import hashlib
import json
import stat
import sys
import types
from zipfile import ZipFile, ZipInfo

import pytest
from agentguard_langgraph_adapter import product_artifact as module
from agentguard_langgraph_adapter.activation_ack import ProductActivationError

pytestmark = pytest.mark.unit


@pytest.fixture
def installation(tmp_path, monkeypatch):
    package = "synthetic_product_artifact"
    monkeypatch.setattr(module, "_PACKAGE", package)
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    root = tmp_path / "installed"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    dist = package + "-0.1.0rc1.dist-info"
    bodies = {
        package + "/__init__.py": b"def run():\n    return 1\n",
        package + "/empty.py": b"",
        dist + "/METADATA": b"Name: agentguard-langgraph-adapter\nVersion: 0.1.0rc1\n",
        dist
        + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = "".join(
        f"{name},{module._hash(body)},{len(body)}\n" for name, body in bodies.items()
    )
    bodies[dist + "/RECORD"] = (record + f"{dist}/RECORD,,\n").encode()
    wheel = private / "adapter.whl"
    with ZipFile(wheel, "w") as archive:
        for name, body in bodies.items():
            archive.writestr(name, body)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(0o644)
    wheel.chmod(0o600)

    class Distribution:
        version = "0.1.0rc1"
        direct = None

        def locate_file(self, name):
            return root / name

        def read_text(self, name):
            return self.direct

    distribution = Distribution()
    monkeypatch.setattr(module.metadata, "distribution", lambda name: distribution)
    monkeypatch.setattr(module.metadata, "version", lambda name: distribution.version)
    imported = types.ModuleType(package)
    imported.__file__ = str(root / package / "__init__.py")
    exec(
        compile(bodies[package + "/__init__.py"], imported.__file__, "exec"),
        imported.__dict__,
    )
    monkeypatch.setitem(sys.modules, package, imported)

    def verify():
        return module.verify_installed_product_artifact(
            str(wheel),
            expected_digest="sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest(),
        )

    return types.SimpleNamespace(
        root=root,
        private=private,
        wheel=wheel,
        package=package,
        distribution=distribution,
        imported=imported,
        verify=verify,
        bodies=bodies,
    )


def test_clean_wheel_empty_file_and_actual_loaded_code(installation):
    result = installation.verify()
    result.assert_current()
    assert installation.imported.run() == 1
    assert str(installation.root) not in repr(result)


@pytest.mark.parametrize(
    "change",
    [
        "beta",
        "editable",
        "source",
        "record",
        "extra",
        "bytecode",
        "import_shadow",
        "loaded_code",
        "writable",
        "symlink",
    ],
)
def test_installation_drift_fails_closed(installation, change):
    item = installation
    result = item.verify()
    source = item.root / item.package / "__init__.py"
    if change == "beta":
        item.distribution.version = "0.1.0"
    elif change == "editable":
        item.distribution.direct = json.dumps({"dir_info": {"editable": True}})
        with pytest.raises(ProductActivationError):
            item.verify()
        return
    elif change == "source":
        source.write_text("def run():\n    return 2\n")
    elif change == "record":
        (item.root / (item.package + "-0.1.0rc1.dist-info/RECORD")).write_text(
            "invalid"
        )
    elif change == "extra":
        (source.parent / "extra.py").write_text("x = 1")
    elif change == "bytecode":
        cached = source.parent / "__pycache__"
        cached.mkdir()
        (cached / "__init__.cpython-312.pyc").write_bytes(b"unverified cache")
    elif change == "import_shadow":
        item.imported.__file__ = str(item.private / "__init__.py")
    elif change == "loaded_code":
        exec(
            compile("def run():\n    return 2\n", str(source), "exec"),
            item.imported.__dict__,
        )
    elif change == "writable":
        source.chmod(0o666)
    elif change == "symlink":
        source.rename(source.with_suffix(".saved"))
        source.symlink_to(source.with_suffix(".saved"))
    with pytest.raises(ProductActivationError, match="installed_artifact_drift"):
        result.assert_current()


def test_unissued_or_mutated_artifact_rejected(installation):
    result = installation.verify()
    # dataclasses.replace is constructible but carries no verifier brand.
    with pytest.raises(ProductActivationError):
        replace(result).assert_current()
    object.__setattr__(result, "_files", ())
    with pytest.raises(ProductActivationError):
        result.assert_current()


@pytest.mark.parametrize("kind", [stat.S_IFIFO, stat.S_IFCHR, stat.S_IFLNK])
def test_special_zip_member_is_never_extracted(installation, kind):
    item = installation
    with ZipFile(item.wheel, "a") as archive:
        entry = ZipInfo(item.package + "/danger")
        entry.external_attr = (kind | 0o600) << 16
        archive.writestr(entry, b"x")
    with pytest.raises(ProductActivationError, match="installed_artifact_invalid"):
        item.verify()


def test_source_only_process_required(installation, monkeypatch):
    monkeypatch.setattr(sys, "dont_write_bytecode", False)
    with pytest.raises(ProductActivationError):
        installation.verify()


def test_candidate_digest_must_match(installation):
    with pytest.raises(ProductActivationError):
        module.verify_installed_product_artifact(
            str(installation.wheel), expected_digest="sha256:" + "0" * 64
        )


def test_ancestor_exchange_during_read_is_rejected(installation, monkeypatch):
    real = module.os.fstat
    observed = 0

    def exchange(descriptor):
        nonlocal observed
        result = real(descriptor)
        if stat.S_ISREG(result.st_mode):
            observed += 1
            if observed == 2:
                original = installation.private
                old = original.with_name("old-private")
                original.rename(old)
                original.mkdir(mode=0o700)
                (original / "adapter.whl").write_bytes(b"different new tree")
                (original / "adapter.whl").chmod(0o600)
        return result

    monkeypatch.setattr(module.os, "fstat", exchange)
    with pytest.raises(ProductActivationError):
        module._read(installation.wheel, private=True)
