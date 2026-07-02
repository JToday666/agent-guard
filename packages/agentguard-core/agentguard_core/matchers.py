"""Deterministic text matchers used by Core detectors."""

from __future__ import annotations

import re

from .events import ModelCallPayload
from .credentials import has_credential_command_text as _has_credential_command_text
from .credentials import has_credential_value_text
from .policies import PolicyBundle


def contains_any(text: str, needles: list[str]) -> bool:
    normalized_text = normalize_match_text(text)
    return any(_marker_matches(normalized_text, needle) for needle in needles)


def normalize_match_text(text: str) -> str:
    lowered = text.lower()
    lowered = re.sub(r"[\t\r\n]+", " ", lowered)
    lowered = re.sub(r"\s*([=|;&])\s*", r"\1", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def _marker_matches(normalized_text: str, marker: str) -> bool:
    normalized_marker = normalize_match_text(marker)
    if not normalized_marker:
        return False
    prefix = r"(?<![a-z0-9_])" if normalized_marker[0].isalnum() else ""
    suffix = r"(?![a-z0-9_])" if normalized_marker[-1].isalnum() else ""
    return re.search(f"{prefix}{re.escape(normalized_marker)}{suffix}", normalized_text) is not None


def has_sensitive_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.sensitive_text_markers)


def has_instruction_like_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.prompt_injection_markers)


def has_high_confidence_prompt_injection_text(text: str, policies: PolicyBundle) -> bool:
    return has_instruction_like_text(text, policies) and contains_any(
        text, policies.high_confidence_prompt_injection_markers
    )


def has_jailbreak_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.jailbreak_markers)


def looks_like_sensitive_model_leak(payload: ModelCallPayload, policies: PolicyBundle) -> bool:
    return contains_any(payload.content_preview, policies.model_leak_markers)


def has_credential_exposure_text(text: str, policies: PolicyBundle) -> bool:
    return has_credential_value_text(text) or contains_any(text, policies.credential_exposure_markers)


def has_credential_command_text(command: str, policies: PolicyBundle) -> bool:
    return _has_credential_command_text(command) or contains_any(command, policies.credential_exposure_markers)


def has_dangerous_command_text(command: str, policies: PolicyBundle) -> bool:
    return contains_any(command, policies.dangerous_command_markers)


def has_memory_poisoning_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.memory_poisoning_markers)


def has_high_confidence_memory_poisoning_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.high_confidence_memory_poisoning_markers)
