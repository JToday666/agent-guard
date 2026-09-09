"""Actual Node reader against signed unit files; not candidate qualification."""

from pathlib import Path

import pytest

from scripts.product_runtime import signing
from tests.test_product_runtime_admission import prepare_signing

pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    not (
        Path(__file__).resolve().parents[1]
        / "packages/agentguard-openclaw-plugin/dist/runtime/product-manifest.js"
    ).is_file(),
    reason="actual OpenClaw reader requires the built Node package; not qualification evidence",
)
def test_signed_canonical_outputs_pass_actual_openclaw_reader(tmp_path, monkeypatch):
    inputs, key, shadow, output = prepare_signing(
        tmp_path, monkeypatch, real_openclaw_reader=True
    )
    result = signing.sign_verified(
        inputs, key_file=key, shadow_key_file=shadow, output_dir=output
    )
    assert len(result["activation_refs"]) == 3
