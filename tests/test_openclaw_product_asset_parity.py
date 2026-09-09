"""Installed Product command bytes obey the existing Core tool contract."""

import hashlib
from pathlib import Path

from agentguard_core.actions.product_tools import (
    product_command_script,
    product_command_script_digest,
)


def test_packaged_openclaw_marker_preserves_frozen_core_bytes():
    path = (
        Path(__file__).resolve().parents[1]
        / "packages/agentguard-openclaw-plugin/product-runtime/marker.mjs"
    )
    actual = path.read_bytes()
    assert actual == product_command_script("openclaw")
    assert "sha256:" + hashlib.sha256(actual).hexdigest() == (
        product_command_script_digest("openclaw")
    )
