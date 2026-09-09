"""Reviewed candidate admission through the existing Core signature functions."""

from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hmac
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import io
import tempfile
from typing import Any

from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.actions.product_tools import (
    PRODUCT_TOOL_NAMES,
    PRODUCT_TOOL_SEMANTICS_VERSION,
    langgraph_host_inventory_digest,
    product_model_visible_tools,
    product_runtime_profile_digest,
)
from agentguard_core.decisions.product import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    PRODUCT_EVENT_TYPES,
    OpenClawFrozenToolV1,
    RuntimeActivationEntryV1,
    build_openclaw_inventory_digests,
    build_product_activation_bundle,
    build_residual_risk_acceptance,
    build_rollout_admission_record,
    verify_product_activation_bundle,
    verify_residual_risk_acceptance,
    verify_rollout_admission_record,
)
from guard_api.services.product_tool_catalog import (
    _LG_SEMANTICS,
    _LG_SOURCE,
    _validate_shape,
)

from .candidate import VerifiedCandidate, bounded_command, verify_candidate
from .conformance import (
    DISTRIBUTIONS,
    PINS,
    VerifiedConformance,
    exact,
    policy_templates,
    require,
    verify_pre_activation,
)
from .evidence import EvidenceStore, VerifiedDocument, object_fields
from .models import AdmissionError, ReviewRecord, SigningRequest, read_model
from .requirements import POLICY_GROUPS, RUNTIMES, requirements_document

CONTRACT_ROOT = "docs/AgentGuard_Core_V2.1_Final_Contract_Freeze/"
CONTRACT_FILES = tuple(
    CONTRACT_ROOT + name
    for name in (
        "contract_freeze.yaml",
        "fusion_matrix.yaml",
        "FREEZE_METADATA.yaml",
        "11_决策记录_V21-08前置.md",
        "12_决策记录_V21-09前置.md",
    )
) + ("packages/agentguard-core/agentguard_core/actions/product_tools.py",)
_VERIFIED = object()


@dataclass(frozen=True)
class VerifiedAdmissionInputs:
    request: SigningRequest
    candidate: VerifiedCandidate = field(repr=False)
    reports: dict[str, VerifiedConformance] = field(repr=False)
    policies: dict[str, PolicyBundle] = field(repr=False)
    materials: dict[str, VerifiedDocument] = field(repr=False)
    entries: tuple[dict[str, Any], ...] = field(repr=False)
    review: ReviewRecord
    store: EvidenceStore = field(repr=False)
    request_reference: Any = field(repr=False)
    checkout: Path
    marker: object = field(repr=False)


def _window(issued: str, expires: str, clock: datetime) -> None:
    try:
        start, end = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            for value in (issued, expires)
        )
        require(all(value.utcoffset() == timedelta(0) for value in (start, end, clock)))
        require(
            start <= clock < end and timedelta(0) < end - start <= timedelta(days=14)
        )
    except (ValueError, TypeError):
        raise AdmissionError("admission_window_invalid") from None


def _inventory(
    inventory: Any, runtime: str, execution: dict[str, Any]
) -> dict[str, Any]:
    tools = inventory["tools"]
    require(
        [row["tool_id"] for row in tools] == list(PRODUCT_TOOL_NAMES),
        "admission_tool_set_invalid",
    )
    if runtime == "openclaw":
        object_fields(
            inventory,
            {"tools", "input_schemas", "plugin_order"},
            "admission_inventory_invalid",
        )
        require(set(inventory["input_schemas"]) == set(PRODUCT_TOOL_NAMES))
        frozen = [OpenClawFrozenToolV1.model_validate(row) for row in tools]
        digests = build_openclaw_inventory_digests(
            tools=frozen, plugin_order=inventory["plugin_order"]
        ).model_dump(exclude={"schema_version"})
        for tool in frozen:
            schema = inventory["input_schemas"][tool.tool_id]
            require(
                tool.source_plugin_id
                == (
                    "agentguard-product-runtime-fixture"
                    if tool.tool_id.startswith("agentguard_memory_")
                    else "openclaw-core"
                )
            )
            require(tool.input_schema_digest == canonical_sha256(schema))
            require(
                tool.event_type
                == {
                    "message": "message_send_proposed",
                    "agentguard_memory_write": "memory_write_proposed",
                }.get(tool.tool_id, "tool_call_proposed")
            )
            _validate_shape(tool.tool_id, schema)
    else:
        object_fields(
            inventory, {"tools", "model_visible_tools"}, "admission_inventory_invalid"
        )
        require(
            exact(inventory["model_visible_tools"], product_model_visible_tools(tools))
        )
        digests = {
            "host_inventory_digest": langgraph_host_inventory_digest(
                inventory["model_visible_tools"]
            ),
            "tool_inventory_digest": canonical_sha256(tools),
            "plugin_inventory_digest": None,
            "plugin_order_inventory_digest": None,
        }
        binding = canonical_sha256(
            {key: execution[key] for key in ("root", "inbox_url", "script_digest")}
            | {"source_id": _LG_SOURCE}
        )
        for tool in tools:
            object_fields(
                tool,
                {
                    "tool_id",
                    "source_id",
                    "description",
                    "input_schema",
                    "execution_schema",
                    "event_type",
                    "category",
                    "kind",
                    "operation",
                    "execution_binding_digest",
                    "fixture_id",
                },
                "admission_tool_invalid",
            )
            require(
                tool["source_id"] == _LG_SOURCE
                and tool["execution_binding_digest"] == binding
            )
            require(tool["fixture_id"] == f"langgraph:{tool['tool_id']}:isolated-v1")
            require(
                tuple(
                    tool[key] for key in ("event_type", "category", "kind", "operation")
                )
                == _LG_SEMANTICS[tool["tool_id"]]
            )
            require(
                type(tool["description"]) is str
                and 0 < len(tool["description"]) <= 32768
            )
            _validate_shape(tool["tool_id"], tool["input_schema"])
            _validate_shape(tool["tool_id"], tool["execution_schema"])
    return digests


def _materials(
    request: SigningRequest,
    candidate: VerifiedCandidate,
    reports: dict[str, VerifiedConformance],
    store: EvidenceStore,
) -> dict[str, VerifiedDocument]:
    names = (
        "capability_matrix",
        "tool_catalog",
        "dataset_manifest",
        "contract_manifest",
        "review_record",
    )
    material = {name: store.read_json(getattr(request, name)) for name in names}
    dataset = object_fields(
        material["dataset_manifest"].data,
        {"schema_version", "source_revision", "requirements", "policies"},
        "admission_dataset_invalid",
    )
    require(
        dataset["schema_version"] == "agentguard-product-dataset/1"
        and dataset["source_revision"] == request.source_revision
    )
    require(
        exact(dataset["requirements"], requirements_document())
        and exact(dataset["policies"], policy_templates())
    )
    contract = object_fields(
        material["contract_manifest"].data,
        {"schema_version", "source_revision", "semantics_version", "files"},
        "admission_contract_invalid",
    )
    require(
        contract["schema_version"] == "agentguard-product-contract/1"
        and contract["source_revision"] == request.source_revision
        and contract["semantics_version"] == PRODUCT_TOOL_SEMANTICS_VERSION
    )
    require([row["source_path"] for row in contract["files"]] == list(CONTRACT_FILES))
    with tarfile.open(
        fileobj=io.BytesIO(candidate.source_archive.content), mode="r:*"
    ) as archive:
        members = {
            member.name.removeprefix("./"): member for member in archive.getmembers()
        }
        for row in contract["files"]:
            object_fields(
                row, {"source_path", "file"}, "admission_contract_file_invalid"
            )
            member = members.get(row["source_path"])
            if member is None or not member.isfile():
                raise AdmissionError("admission_contract_file_invalid")
            stream = archive.extractfile(member)
            if stream is None:
                raise AdmissionError("admission_contract_file_invalid")
            require(store.read_file(row["file"]).content == stream.read())
    matrix = object_fields(
        material["capability_matrix"].data,
        {"schema_version", "source_revision", "candidate_manifest_digest", "runtimes"},
        "admission_matrix_invalid",
    )
    require(
        matrix["schema_version"] == "agentguard-product-capability-matrix/1"
        and matrix["source_revision"] == request.source_revision
        and matrix["candidate_manifest_digest"] == candidate.canonical_digest
    )
    require([row["runtime"] for row in matrix["runtimes"]] == list(RUNTIMES))
    for row in matrix["runtimes"]:
        object_fields(
            row,
            {"runtime", "observed", "activation_target", "cf_13", "evidence"},
            "admission_matrix_runtime_invalid",
        )
        report = reports[row["runtime"]]
        require(
            exact(
                store.read_json(row["observed"]).data["report"],
                report.observed_capability.model_dump(mode="json"),
            )
        )
        require(
            exact(
                store.read_json(row["activation_target"]).data["report"],
                report.activation_target.model_dump(mode="json"),
            )
        )
        require(
            row["cf_13"]
            == ("PASS" if row["runtime"] == "langgraph" else "NOT_SUPPORTED")
        )
        evidence = store.read_json(row["evidence"]).data
        require(
            evidence["runtime"] == row["runtime"]
            and evidence["source_revision"] == request.source_revision
        )
        require(
            evidence["c3_atomic_replace_and_seal"] is (row["runtime"] == "langgraph")
        )
        require(
            evidence["residual_boundaries"]
            == (
                []
                if row["runtime"] == "langgraph"
                else list(OPENCLAW_RESIDUAL_BOUNDARIES)
            )
        )
    return material


def verify_request(
    request_reference: Any,
    store: EvidenceStore,
    checkout: str | Path,
    expected_source_revision: str,
    *,
    clock: datetime | None = None,
) -> VerifiedAdmissionInputs:
    """Keyless verification. It neither reads a key nor creates any output."""
    request = read_model(SigningRequest, store.read_json(request_reference).data)
    require(
        request.source_revision == expected_source_revision,
        "admission_revision_mismatch",
    )
    _window(request.issued_at, request.expires_at, clock or datetime.now(timezone.utc))
    require([item.id for item in request.policy_groups] == list(POLICY_GROUPS))
    require([item.runtime for item in request.runtime_identities] == list(RUNTIMES))
    candidate = verify_candidate(
        request.candidate_manifest, store, checkout, expected_source_revision
    )
    templates = policy_templates()
    policies: dict[str, PolicyBundle] = {}
    for item in request.policy_groups:
        raw = store.read_json(item.policy_bundle).data
        require(exact(raw, templates[item.id]), "admission_policy_outside_scope")
        policies[item.id] = PolicyBundle.model_validate(raw)
    reports = {
        runtime: verify_pre_activation(
            store.read_json(getattr(request, f"{runtime}_conformance")),
            candidate,
            policies,
            store,
        )
        for runtime in RUNTIMES
    }
    require(all(value.report.runtime == runtime for runtime, value in reports.items()))
    material = _materials(request, candidate, reports, store)
    review = read_model(ReviewRecord, material["review_record"].data)
    require(
        review.source_revision == request.source_revision
        and review.candidate_manifest_digest == candidate.canonical_digest
    )
    require(
        review.policy_groups == list(POLICY_GROUPS)
        and review.runtimes == list(RUNTIMES)
    )
    catalog = object_fields(
        material["tool_catalog"].data,
        {"schema_version", "semantics_version", "runtimes"},
        "admission_catalog_invalid",
    )
    require(
        catalog["schema_version"] == "1.0"
        and catalog["semantics_version"] == PRODUCT_TOOL_SEMANTICS_VERSION
    )
    require([row["runtime"] for row in catalog["runtimes"]] == list(RUNTIMES))
    entries = []
    for identity, row in zip(
        request.runtime_identities, catalog["runtimes"], strict=True
    ):
        object_fields(
            row,
            {"runtime", "execution", "inventory"},
            "admission_catalog_runtime_invalid",
        )
        runtime = identity.runtime
        report = reports[runtime]
        require(exact(report.inventory, row["inventory"]))
        require(
            store.read_json(report.report.materials.tool_catalog).canonical_digest
            == material["tool_catalog"].canonical_digest
        )
        capability = report.activation_target
        require(
            (capability.runtime, capability.agent_id, capability.runtime_binding_id)
            == (runtime, identity.agent_id, identity.runtime_binding_id)
        )
        artifact = next(
            item
            for item in candidate.artifacts
            if item.distribution == DISTRIBUTIONS[runtime]
            and item.kind in {"wheel", "npm_tgz"}
        )
        entry = identity.model_dump(mode="json") | {
            "runtime_version": PINS[runtime][0],
            "plugin_version": PINS[runtime][1],
            "profile_id": capability.profile_id,
            "adapter_artifact_digest": artifact.raw_sha256,
            "capability_report_digest": capability.report_digest,
            **_inventory(row["inventory"], runtime, row["execution"]),
            "event_types": list(PRODUCT_EVENT_TYPES),
            "ask_release_mode": (
                "strong_binding" if runtime == "langgraph" else "restricted_allow_once"
            ),
            "residual_boundaries": (
                [] if runtime == "langgraph" else list(OPENCLAW_RESIDUAL_BOUNDARIES)
            ),
            "environment": "internal_rc_canary",
            "expires_at": request.expires_at,
        }
        entry["profile_digest"] = product_runtime_profile_digest(
            entry, row["execution"]
        )
        entries.append(entry)
    require(entries[0]["runtime_binding_id"] != entries[1]["runtime_binding_id"])
    store.recheck_reads()
    return VerifiedAdmissionInputs(
        request,
        candidate,
        reports,
        policies,
        material,
        tuple(entries),
        review,
        store,
        request_reference,
        Path(checkout),
        _VERIFIED,
    )


def _secret_file(path: str | Path) -> bytes:
    """Read the actual raw key from a protected, non-linked file."""
    supplied = Path(path)
    require(
        supplied.is_absolute() and str(supplied) == os.fspath(path),
        "admission_key_unavailable",
    )
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    descriptor = None
    try:
        for component in supplied.parts[1:-1]:
            next_directory = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        descriptor = os.open(
            supplied.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and before.st_size == 32,
            "admission_key_unavailable",
        )
        value = os.read(descriptor, 33)
        after = os.fstat(descriptor)
        visible = os.stat(supplied.name, dir_fd=directory, follow_symlinks=False)

        def identity(info: os.stat_result) -> tuple[int, ...]:
            return (
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        require(
            len(value) == 32
            and identity(before) == identity(after) == identity(visible),
            "admission_key_changed",
        )
        return value
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def api_secret_value(raw: bytes) -> str:
    require(type(raw) is bytes and len(raw) == 32, "admission_key_invalid")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _write(path: Path, value: Any, mode: int = 0o600) -> None:
    content = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode
    )
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require(path.read_bytes() == content, "admission_output_changed")


def _commit_directory(stage: Path, output: Path) -> None:
    """Linux no-replace directory commit; a competing destination is never replaced."""
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    if rename is None:
        raise AdmissionError("admission_atomic_commit_unavailable")
    result = rename(-100, os.fsencode(stage), -100, os.fsencode(output), 1)
    if result != 0:
        raise AdmissionError("admission_output_commit_failed")


def _validate_outputs(
    directory: Path,
    catalog: Path,
    secret: bytes,
    shadow: bytes,
    key_id: str,
    clock: datetime,
    openclaw_reader: Path,
) -> None:
    from agentguard_langgraph_adapter.product_manifest import ProductActivationManifest
    from guard_api.services.product_activation import load_frozen_product_activation
    from guard_api.services.product_tool_catalog import ProductToolCatalog
    from guard_api.settings import GuardApiSettings

    settings = GuardApiSettings(
        v21_mode="active",
        v21_product_activation_path=str(directory / "activation.json"),
        v21_product_activation_server_secret=api_secret_value(secret),
        v21_product_activation_signer_key_id=key_id,
        v21_shadow_server_secret=api_secret_value(shadow),
    )
    require(settings.v21_product_activation_server_secret_bytes() == secret)
    loaded = load_frozen_product_activation(settings, clock=lambda: clock)
    if loaded is None:
        raise AdmissionError("admission_output_loader_rejected")
    ProductToolCatalog(str(catalog), loaded.bundle)
    manifest = ProductActivationManifest.from_file(
        directory / "langgraph-manifest.json"
    )
    require(manifest.activation_ref_digest == loaded.bundle.activation_ref_digest)
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"NODE_OPTIONS", "NODE_PATH"}
    }
    code, stdout, stderr = bounded_command(
        [
            "node",
            "--input-type=module",
            "-e",
            "import {pathToFileURL} from 'node:url'; const {OpenClawProductManifest}=await import(pathToFileURL(process.argv[1]).href); const manifest=await OpenClawProductManifest.fromFile(process.argv[2]); if(manifest.data.activation_ref_digest!==process.argv[3]) process.exit(1);",
            str(openclaw_reader),
            str(directory / "openclaw-manifest.json"),
            loaded.bundle.activation_ref_digest,
        ],
        cwd=directory,
        env=environment,
        timeout=20,
        limit=4096,
    )
    require(
        code == 0 and not stdout and not stderr, "admission_openclaw_reader_rejected"
    )


def sign_verified(
    inputs: VerifiedAdmissionInputs,
    *,
    key_file: str | Path,
    shadow_key_file: str | Path,
    output_dir: str | Path,
    clock: datetime | None = None,
) -> dict[str, Any]:
    require(inputs.marker is _VERIFIED, "admission_unverified_inputs")
    now = clock or datetime.now(timezone.utc)
    # Revalidate nested mutable models and every input immediately before key access.
    fresh = verify_request(
        inputs.request_reference,
        inputs.store,
        inputs.checkout,
        inputs.request.source_revision,
        clock=now,
    )
    secret, shadow = _secret_file(key_file), _secret_file(shadow_key_file)
    require(not hmac.compare_digest(secret, shadow), "admission_shadow_key_reused")
    request = fresh.request
    product_lane = next(
        row
        for row in fresh.candidate.installation_reports["openclaw"].data["lanes"]
        if row["lane"] == "product"
    )
    openclaw_reader = (
        Path(product_lane["plugin_root"]) / "dist/runtime/product-manifest.js"
    )
    values = {
        "issued_at": request.issued_at,
        "expires_at": request.expires_at,
        "signer_key_id": request.signer_key_id,
    }
    oc = dict(fresh.entries[1])
    risk = build_residual_risk_acceptance(
        server_secret=secret,
        **values,
        **{
            key: oc[key]
            for key in (
                "runtime",
                "runtime_version",
                "plugin_version",
                "profile_id",
                "profile_digest",
                "agent_id",
                "runtime_binding_id",
                "host_inventory_digest",
                "plugin_inventory_digest",
                "plugin_order_inventory_digest",
                "tool_inventory_digest",
                "canary_cohort",
                "environment",
                "residual_boundaries",
            )
        },
        reviewer_id=fresh.review.reviewer_id,
        candidate_artifact_digest=fresh.candidate.canonical_digest,
    )
    require(verify_residual_risk_acceptance(risk, server_secret=secret))
    entries = [
        RuntimeActivationEntryV1.model_validate(
            entry
            | {
                "residual_risk_acceptance_digest": (
                    risk.acceptance_ref_digest
                    if entry["runtime"] == "openclaw"
                    else None
                )
            }
        )
        for entry in fresh.entries
    ]
    output = Path(output_dir)
    require(
        output.is_absolute()
        and str(output) == os.fspath(output_dir)
        and not output.exists(),
        "admission_output_exists_or_invalid",
    )
    parent_stat = output.parent.lstat()
    require(
        stat.S_ISDIR(parent_stat.st_mode)
        and stat.S_IMODE(parent_stat.st_mode) == 0o700
        and parent_stat.st_uid == os.geteuid(),
        "admission_output_parent_unprotected",
    )
    # The evidence reader supplies no-follow traversal without reading a signing key.
    output_store = EvidenceStore(output.parent)
    stage = Path(tempfile.mkdtemp(prefix=".product-sign-", dir=output.parent))
    activations: dict[str, str] = {}
    committed = False
    try:
        stage.chmod(0o700)
        _write(stage / "residual-acceptance.json", risk.model_dump(mode="json"))
        _write(stage / "tool-catalog.json", fresh.materials["tool_catalog"].data)
        _write(stage / "review-record.json", fresh.review.model_dump(mode="json"))
        for group in POLICY_GROUPS:
            directory = stage / group
            directory.mkdir(mode=0o700)
            common = {
                "candidate_artifact_manifest_digest": fresh.candidate.canonical_digest,
                "policy_digest": canonical_sha256(
                    fresh.policies[group].model_dump(mode="json")
                ),
                "dataset_digest": fresh.materials["dataset_manifest"].canonical_digest,
                "contract_digest": fresh.materials[
                    "contract_manifest"
                ].canonical_digest,
            }
            admission = build_rollout_admission_record(
                server_secret=secret,
                **values,
                **common,
                source_revision=request.source_revision,
                langgraph_conformance_digest=fresh.reports[
                    "langgraph"
                ].document.canonical_digest,
                openclaw_conformance_digest=fresh.reports[
                    "openclaw"
                ].document.canonical_digest,
                capability_matrix_digest=fresh.materials[
                    "capability_matrix"
                ].canonical_digest,
                tool_inventory_digest=oc["tool_inventory_digest"],
            )
            require(verify_rollout_admission_record(admission, server_secret=secret))
            activation = build_product_activation_bundle(
                server_secret=secret,
                rollout_admission_record=admission,
                residual_risk_acceptance=risk,
                **values,
                **common,
                rollout_admission_digest=admission.admission_ref_digest,
                runtimes=entries,
            )
            require(verify_product_activation_bundle(activation, server_secret=secret))
            _write(directory / "admission.json", admission.model_dump(mode="json"))
            _write(
                directory / "policy.json", fresh.policies[group].model_dump(mode="json")
            )
            _write(
                directory / "activation.json", activation.model_dump(mode="json"), 0o400
            )
            for entry in entries:
                fields = (
                    "runtime",
                    "runtime_version",
                    "plugin_version",
                    "principal_id",
                    "agent_id",
                    "runtime_binding_id",
                    "profile_id",
                    "profile_digest",
                    "adapter_artifact_digest",
                    "capability_report_digest",
                    "host_inventory_digest",
                    "tool_inventory_digest",
                )
                manifest = {
                    "schema_version": "1.0",
                    **{key: getattr(entry, key) for key in fields},
                    "activation_ref_digest": activation.activation_ref_digest,
                }
                if entry.runtime == "openclaw":
                    manifest.update(
                        plugin_inventory_digest=entry.plugin_inventory_digest,
                        plugin_order_inventory_digest=entry.plugin_order_inventory_digest,
                    )
                _write(directory / f"{entry.runtime}-manifest.json", manifest)
            _validate_outputs(
                directory,
                stage / "tool-catalog.json",
                secret,
                shadow,
                request.signer_key_id,
                now,
                openclaw_reader,
            )
            activations[group] = activation.activation_ref_digest
        summary = {
            "schema_version": "agentguard-product-signing-result/1",
            "source_revision": request.source_revision,
            "candidate_manifest_digest": fresh.candidate.canonical_digest,
            "activation_refs": activations,
            "scope": "fixed_isolated_profiles",
            "product_active_run_completed": False,
            "shadow_key_comparison": {
                "source": str(Path(shadow_key_file)),
                "format": "32_raw_bytes",
                "different": True,
            },
        }
        _write(stage / "verification-summary.json", summary)
        _write(
            stage / "input-digests.json",
            {key: doc.canonical_digest for key, doc in fresh.materials.items()}
            | {
                "request": canonical_sha256(request.model_dump(mode="json")),
                "candidate_manifest": fresh.candidate.canonical_digest,
                **{
                    runtime: report.document.canonical_digest
                    for runtime, report in fresh.reports.items()
                },
            },
        )
        fresh.store.recheck_reads()
        output_store.recheck_reads()
        _window(
            request.issued_at,
            request.expires_at,
            clock if clock is not None else datetime.now(timezone.utc),
        )
        for directory in [stage / group for group in POLICY_GROUPS] + [stage]:
            descriptor = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _commit_directory(stage, output)
        committed = True
        parent_descriptor = os.open(
            output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return summary
    except BaseException:
        if committed:
            shutil.rmtree(output)
        raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)
