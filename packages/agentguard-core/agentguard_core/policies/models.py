"""Policy bundle models for stateless Core evaluation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..decisions import RuleOverrideDecision


class RuleOverride(BaseModel):
    decision: RuleOverrideDecision | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    severity: str | None = None


class ToolProfile(BaseModel):
    model_config = ConfigDict(extra="allow")

    categories: list[str]
    kinds: list[str]
    operations: list[str]
    directions: list[str]


def default_tool_profiles() -> dict[str, ToolProfile]:
    return {
        "read_file": ToolProfile(
            categories=["tool", "file"],
            kinds=["read_file", "file_read"],
            operations=["read"],
            directions=["local"],
        ),
        "write_file": ToolProfile(
            categories=["tool", "file"],
            kinds=["write_file", "file_write"],
            operations=["write"],
            directions=["local"],
        ),
        "send_email": ToolProfile(
            categories=["tool", "message", "email"],
            kinds=["send_email", "email_send"],
            operations=["send"],
            directions=["outbound"],
        ),
        "call_api": ToolProfile(
            categories=["tool", "api", "network"],
            kinds=["call_api", "api_call", "http_request"],
            operations=["get", "post", "put", "patch", "delete"],
            directions=["outbound"],
        ),
        "code_exec": ToolProfile(
            categories=["tool", "code", "process"],
            kinds=["code_exec", "shell_exec", "command_exec"],
            operations=["execute"],
            directions=["local"],
        ),
    }


class PolicyBundle(BaseModel):
    model_config = ConfigDict(extra="allow")

    bundle_id: str = "default"
    version: str = "p0"
    disabled_rules: list[str] = Field(default_factory=list)
    rule_overrides: dict[str, RuleOverride] = Field(default_factory=dict)
    sensitive_resource_markers: list[str] = Field(
        default_factory=lambda: [
            ".env",
            "token",
            "secret",
            "private",
            "credential",
            "id_rsa",
            "password",
            "payment_details",
            "tacacs",
            "business_plan",
            "ssh_access",
        ]
    )
    sensitive_text_markers: list[str] = Field(
        default_factory=lambda: ["token=", "secret", "credential", "api key", "password", "private key"]
    )
    prompt_injection_markers: list[str] = Field(
        default_factory=lambda: [
            "ignore previous instructions",
            "ignore all prior instructions",
            "ignore all previous instructions",
            "disregard previous instructions",
            "override the system",
            "send /private",
            "persist this rule",
            "future runs",
        ]
    )
    jailbreak_markers: list[str] = Field(
        default_factory=lambda: [
            "you are now dan",
            "developer mode",
            "jailbreak",
            "ignore all safety",
            "ignore safety policies",
            "reveal hidden instructions",
            "reveal the system prompt",
            "hidden instructions",
        ]
    )
    model_leak_markers: list[str] = Field(
        default_factory=lambda: [
            "system prompt",
            "hidden instruction",
            "token=",
            "secret",
            "credential",
            "api key",
        ]
    )
    dangerous_command_markers: list[str] = Field(
        default_factory=lambda: [
            "curl ",
            "wget ",
            "| sh",
            "| bash",
            "bash -c",
            "rm -rf",
            "sudo ",
            " nc ",
            "netcat",
            "/etc/passwd",
            "printenv",
            "chmod +x",
            "ssh ",
            "scp ",
        ]
    )
    memory_poisoning_markers: list[str] = Field(
        default_factory=lambda: [
            "always send",
            "attacker@",
            "ignore previous",
            "future reports",
            "future runs",
            "persist this rule",
        ]
    )
    allowed_email_domains: list[str] = Field(default_factory=lambda: ["agentguard.local"])
    allowed_api_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allowed_api_paths: list[str] = Field(default_factory=lambda: ["/status"])
    collection_path_markers: list[str] = Field(
        default_factory=lambda: ["/collect/", "upload", "exfil", "webhook"]
    )
    tool_profiles: dict[str, ToolProfile] = Field(default_factory=default_tool_profiles)
    tool_action_aliases: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "read_file": ["read"],
            "write_file": ["write"],
            "send_email": ["email", "send"],
            "call_api": ["api", "call"],
            "memory_write": ["memory", "write"],
            "code_exec": ["execute", "run"],
        }
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
