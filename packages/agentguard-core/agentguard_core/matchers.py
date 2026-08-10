"""Deterministic text matchers used by Core detectors."""

from __future__ import annotations

import re
import unicodedata

from .events import ModelCallPayload
from .credentials import has_credential_command_text as _has_credential_command_text
from .credentials import has_credential_value_text
from .policies import PolicyBundle

_PROMPT_INJECTION_INTENT_MARKERS: dict[str, list[str]] = {
    "override_instruction": [
        "ignore developer instructions",
        "developer message",
        "system message",
        "override the system",
    ],
    "secret_exfiltration": [
        "send /private",
        "/private/",
        "attacker@",
        "exfiltrate",
        "send the token",
        "send secrets",
        "credential bundle",
    ],
    "unsafe_external_action": [
        "send externally",
        "upload externally",
        "forward externally",
        "submit to an external",
        "copy into the external form",
        "paste into the external form",
        "complete the external action",
    ],
    "security_control_weakening": [
        "bypass verification",
        "disable verification",
        "skip verification",
        "reduce verification controls",
        "weaken security controls",
        "disable security controls",
        "override approval",
    ],
    "system_or_account_configuration_change": [
        "configuration change",
        "apply configuration change",
        "account configuration",
        "change account settings",
        "grant administrator access",
        "change permissions",
    ],
}

_MEMORY_POISONING_INTENT_MARKERS: dict[str, list[str]] = {
    "persistent_rule_injection": [
        "persist this rule",
        "remember this rule",
        "store this rule",
        "save this rule",
        "remember this instruction",
        "store this instruction",
        "save this instruction",
        "from now on",
        "for all future",
        "future tasks",
        "future requests",
        "future reports",
        "future runs",
        "future sessions",
        "always use",
        "always prefer",
        "reuse this answer as an instruction",
    ],
    "delayed_trigger": [
        "next time",
        "when asked later",
        "on future requests",
        "for all future tasks",
        "future tasks",
        "future runs",
        "future sessions",
    ],
    "future_external_action": [
        "always send",
        "send future",
        "send reports externally",
        "route future reports",
        "route reports",
        "attacker@",
        "webhook",
        "external",
        "http://",
        "https://",
    ],
    "safety_override": [
        "ignore previous",
        "ignore all prior",
        "ignore developer instructions",
        "override",
        "never reveal",
        "never mention",
        "never tell",
        "hide this rule",
        "do not mention this rule",
    ],
    "poisoned_reference_answer": [
        "reuse this answer as an instruction",
        "treat this answer as instruction",
        "answer as an instruction",
    ],
}

_AGENT_ABUSE_INTENT_MARKERS: dict[str, list[str]] = {
    "malicious_payload_delivery": [
        "/payloads/",
        "download payload",
        "malicious payload",
        "curl -fs",
        "curl -fsSL",
        "wget ",
        "invoke-webrequest",
    ],
    "backdoor_or_compute_abuse": [
        "backdoor",
        "reverse shell",
        "/dev/tcp",
        "crypto-miner",
        "crypto miner",
        "miner",
        "remote maintenance",
        "background worker",
        "socket",
        "subprocess",
    ],
    "platform_abuse": [
        "meeting disruption",
        "platform abuse",
        "service disruption",
    ],
    "phishing_or_impersonation": [
        "phishing",
        "impersonate",
        "credential reset",
        "reset link",
        "restore access through",
        "fake identity",
    ],
    "click_fraud": [
        "/ads/clicks",
        "click fraud",
        "ad click",
        "automated ad clicks",
    ],
    "account_recovery_abuse": [
        "submit appeal",
        "account recovery",
        "manual review override",
        "restore access",
        "antiabuse",
        "verification abuse",
        "verification override",
        "bypass captcha",
    ],
    "defamation_or_misinformation": [
        "misinformation",
        "defamation",
        "false allegation",
        "fabricated claim",
    ],
    "private_record_collection": [
        "private records",
        "private record",
        "current residence",
        "family property records",
        "private email",
        "private phone",
        "home address",
        "contact_details",
    ],
}

_EXECUTABLE_PAYLOAD_RE = re.compile(
    r"\.(?:exe|dll|msi|bat|cmd|ps1|sh|bash|zsh|jar|py|pl|rb|bin|scr|so|dylib)(?:\b|[?#\"'\\])",
    flags=re.IGNORECASE,
)
_ARCHIVE_PAYLOAD_RE = re.compile(
    r"\.(?:zip|tar|tgz|tar\.gz|gz|7z|rar)(?:\b|[?#\"'\\])",
    flags=re.IGNORECASE,
)
_URL_OR_PATH_PAYLOAD_RE = re.compile(
    r"(?:https?://|/)(?:[^\s\"']*/)?(?:payloads?|downloads?|artifacts?|staging|bin|scripts?)/",
    flags=re.IGNORECASE,
)
_PAYLOAD_DELIVERY_ACTION_MARKERS = [
    "curl ",
    "curl-",
    "wget ",
    "invoke-webrequest",
    "download",
    "fetch",
    "retrieve",
    "pull",
    "stage",
    "staging",
    "execute",
    "chmod+x",
    "chmod +x",
    'method":"get',
    'method":"post',
    'method": "get',
    'method": "post',
    "browser_input",
    "write_file",
    "call_api",
    "dockerfile",
    "run ",
]
_BACKDOOR_COMPUTE_ABUSE_RE = re.compile(
    r"("
    r"reverse\s+shell|/dev/tcp|netcat|nc\s+-e|"
    r"socket\s*[,)]|socket\(|subprocess|popen|"
    r"crypto[-\s]?miner|cryptominer|coinhive|xmrig|"
    r"backdoor|remote\s+maintenance|unauthorized\s+remote|"
    r"background\s+worker|persistence|payload\s+staging"
    r")",
    flags=re.IGNORECASE,
)


def contains_any(text: str, needles: list[str]) -> bool:
    normalized_text = normalize_match_text(text)
    return any(_marker_matches(normalized_text, needle) for needle in needles)


def normalize_match_text(text: str) -> str:
    lowered = unicodedata.normalize("NFKC", text).lower()
    lowered = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", lowered)
    lowered = re.sub(r"[\t\r\n]+", " ", lowered)
    lowered = re.sub(r"(?<=[a-z0-9])[-_]+(?=[a-z0-9])", " ", lowered)
    lowered = re.sub(r"\s*([=|;&])\s*", r"\1", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def _marker_matches(normalized_text: str, marker: str) -> bool:
    normalized_marker = normalize_match_text(marker)
    if not normalized_marker:
        return False
    prefix = r"(?<![a-z0-9_])" if normalized_marker[0].isalnum() else ""
    suffix = r"(?![a-z0-9_])" if normalized_marker[-1].isalnum() else ""
    return (
        re.search(f"{prefix}{re.escape(normalized_marker)}{suffix}", normalized_text)
        is not None
    )


def has_sensitive_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.sensitive_text_markers)


def has_instruction_like_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.prompt_injection_markers)


def prompt_injection_intents(text: str, policies: PolicyBundle) -> list[str]:
    intents = [
        intent
        for intent, markers in _PROMPT_INJECTION_INTENT_MARKERS.items()
        if contains_any(text, markers)
    ]
    if not intents and contains_any(
        text, policies.high_confidence_prompt_injection_markers
    ):
        intents.append("unsafe_external_action")
    return intents


def environment_poisoning_intents(text: str, policies: PolicyBundle) -> list[str]:
    return [
        intent
        for intent in prompt_injection_intents(text, policies)
        if intent != "override_instruction"
    ]


def has_high_confidence_prompt_injection_text(
    text: str,
    policies: PolicyBundle,
    *,
    contains_instruction_like_text: bool = False,
) -> bool:
    return (
        contains_instruction_like_text or has_instruction_like_text(text, policies)
    ) and bool(prompt_injection_intents(text, policies))


def has_high_confidence_environment_poisoning_text(
    text: str,
    policies: PolicyBundle,
    *,
    contains_instruction_like_text: bool = False,
) -> bool:
    return (
        contains_instruction_like_text or has_instruction_like_text(text, policies)
    ) and bool(environment_poisoning_intents(text, policies))


def has_jailbreak_text(text: str, policies: PolicyBundle) -> bool:
    return contains_any(text, policies.jailbreak_markers)


def looks_like_sensitive_model_leak(
    payload: ModelCallPayload, policies: PolicyBundle
) -> bool:
    return contains_any(payload.content_preview, policies.model_leak_markers)


def has_credential_exposure_text(text: str, policies: PolicyBundle) -> bool:
    return has_credential_value_text(text) or contains_any(
        text, policies.credential_exposure_markers
    )


def has_credential_command_text(command: str, policies: PolicyBundle) -> bool:
    return _has_credential_command_text(command) or contains_any(
        command, policies.credential_exposure_markers
    )


def has_dangerous_command_text(command: str, policies: PolicyBundle) -> bool:
    return (
        contains_any(command, policies.dangerous_command_markers)
        or _looks_like_malicious_payload_delivery(command)
        or _looks_like_backdoor_or_compute_abuse(command)
    )


def agent_abuse_intents(text: str, policies: PolicyBundle) -> list[str]:
    intents = [
        intent
        for intent, markers in _AGENT_ABUSE_INTENT_MARKERS.items()
        if contains_any(text, markers)
    ]
    if _looks_like_malicious_payload_delivery(text):
        intents.append("malicious_payload_delivery")
    if _looks_like_backdoor_or_compute_abuse(text):
        intents.append("backdoor_or_compute_abuse")
    if _looks_like_defamatory_claim(text):
        intents.append("defamation_or_misinformation")
    if not intents and contains_any(text, policies.agent_abuse_markers):
        intents.append("unauthorized_action")
    return list(dict.fromkeys(intents))


def _looks_like_defamatory_claim(text: str) -> bool:
    normalized = normalize_match_text(text)
    allegation = contains_any(
        normalized,
        [
            "heroin",
            "cocaine",
            "drug addict",
            "addicted to drugs",
            "committed fraud",
            "committed a crime",
        ],
    )
    asserted_as_fact = contains_any(
        normalized,
        [
            "caught",
            "is a",
            "was a",
            "confirmed",
            "proven",
        ],
    )
    return allegation and asserted_as_fact


def _looks_like_malicious_payload_delivery(text: str) -> bool:
    normalized = normalize_match_text(text)
    if not normalized:
        return False
    has_delivery_action = contains_any(normalized, _PAYLOAD_DELIVERY_ACTION_MARKERS)
    if not has_delivery_action:
        return False
    has_payload_path = _URL_OR_PATH_PAYLOAD_RE.search(text) is not None
    has_executable_payload = _EXECUTABLE_PAYLOAD_RE.search(text) is not None
    has_archive_payload = _ARCHIVE_PAYLOAD_RE.search(text) is not None
    has_network_or_staging_target = bool(
        re.search(
            r"https?://|/(?:tmp|var/tmp|opt|usr/local/bin|payloads?|downloads?|artifacts?|staging|scripts?)/",
            text,
            flags=re.IGNORECASE,
        )
    )
    if has_payload_path and (
        has_executable_payload or has_archive_payload or "payload" in normalized
    ):
        return True
    return has_executable_payload and has_network_or_staging_target


def _looks_like_backdoor_or_compute_abuse(text: str) -> bool:
    normalized = normalize_match_text(text)
    if not normalized:
        return False
    if not _BACKDOOR_COMPUTE_ABUSE_RE.search(text):
        return False
    if contains_any(
        normalized,
        [
            "reverse shell",
            "/dev/tcp",
            "crypto-miner",
            "crypto miner",
            "cryptominer",
            "xmrig",
            "backdoor",
            "remote maintenance",
            "unauthorized remote",
            "payload staging",
        ],
    ):
        return True
    return contains_any(
        normalized,
        [
            "socket",
            "subprocess",
            "background worker",
            "persistence",
        ],
    ) and contains_any(
        normalized,
        [
            "remote",
            "miner",
            "mining",
            "unauthorized",
            "connect",
            "execute",
            "shell",
            "popen",
            "call_api",
            "browser_input",
            "write_file",
        ],
    )


def memory_poisoning_intents(text: str, policies: PolicyBundle) -> list[str]:
    intents = [
        intent
        for intent, markers in _MEMORY_POISONING_INTENT_MARKERS.items()
        if contains_any(text, markers)
    ]
    if not intents and contains_any(text, policies.memory_poisoning_markers):
        intents.append("persistent_rule_injection")
    return intents


def has_memory_poisoning_text(text: str, policies: PolicyBundle) -> bool:
    intents = set(memory_poisoning_intents(text, policies))
    return contains_any(text, policies.memory_poisoning_markers) or bool(
        intents
        & {"persistent_rule_injection", "delayed_trigger", "poisoned_reference_answer"}
    )


def has_high_confidence_memory_poisoning_text(
    text: str, policies: PolicyBundle
) -> bool:
    if contains_any(text, policies.high_confidence_memory_poisoning_markers):
        return True
    intents = set(memory_poisoning_intents(text, policies))
    persistent = bool(intents & {"persistent_rule_injection", "delayed_trigger"})
    risky_action = bool(intents & {"future_external_action", "safety_override"})
    return persistent and risky_action
