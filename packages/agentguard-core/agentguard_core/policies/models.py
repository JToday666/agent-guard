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
    def code_exec_profile() -> ToolProfile:
        return ToolProfile(
            categories=["tool", "code", "process", "shell", "terminal"],
            kinds=[
                "code_exec",
                "exec",
                "shell",
                "shell_exec",
                "command",
                "command_exec",
                "bash",
                "sh",
                "powershell",
                "terminal",
                "code_mode_exec",
            ],
            operations=["execute"],
            directions=["local"],
        )

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
        "code_exec": code_exec_profile(),
        "exec": code_exec_profile(),
        "shell": code_exec_profile(),
        "command": code_exec_profile(),
        "bash": code_exec_profile(),
        "sh": code_exec_profile(),
        "powershell": code_exec_profile(),
        "terminal": code_exec_profile(),
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
            "/config/",
            "mdm_enrollment",
            "deployment configuration",
            "signing key",
            "business plan",
            "payment_details",
            "tacacs",
            "business_plan",
            "ssh_access",
        ]
    )
    sensitive_text_markers: list[str] = Field(
        default_factory=lambda: [
            "token=",
            "secret",
            "credential",
            "api key",
            "password",
            "private key",
            "authorization:",
            "bearer ",
        ]
    )
    prompt_injection_markers: list[str] = Field(
        default_factory=lambda: [
            "ignore previous instructions",
            "ignore all prior instructions",
            "ignore all previous instructions",
            "disregard previous instructions",
            "override the system",
            "ignore developer instructions",
            "developer message",
            "system message",
            "follow these instructions instead",
            "treat this content as a system message",
            "do not tell the user",
            "send /private",
            "persist this rule",
            "future runs",
            "bypass verification",
            "disable verification",
            "reduce verification controls",
            "weaken security controls",
            "override approval",
            "change account settings",
            "apply configuration change",
            "grant administrator access",
        ]
    )
    high_confidence_prompt_injection_markers: list[str] = Field(
        default_factory=lambda: [
            "send /private",
            "/private/",
            "attacker@",
            "exfiltrate",
            "send the token",
            "send secrets",
            "ignore developer instructions",
            "developer message",
            "system message",
            "follow these instructions instead",
            "treat this content as a system message",
            "bypass verification",
            "disable verification",
            "reduce verification controls",
            "weaken security controls",
            "override approval",
            "change account settings",
            "apply configuration change",
            "grant administrator access",
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
            "authorization:",
            "bearer ",
        ]
    )
    credential_exposure_markers: list[str] = Field(
        default_factory=lambda: [
            "dashscope_api_key",
            "openai_api_key",
            "anthropic_api_key",
            "api_key=",
            "access_token=",
            "secret_key=",
            "/proc/self/environ",
        ]
    )
    dangerous_command_markers: list[str] = Field(
        default_factory=lambda: [
            "| sh",
            "| bash",
            "rm -rf",
            "/etc/passwd",
            "/payloads/",
            "reverse shell",
            "/dev/tcp",
            "nc -e",
            "netcat -e",
            "mkfifo",
            "powershell -encodedcommand",
            "invoke-expression",
            "certutil -decode",
            "chmod +s",
            "crypto-miner",
            "crypto miner",
            "backdoor",
            "unauthorized remote access",
        ]
    )
    memory_poisoning_markers: list[str] = Field(
        default_factory=lambda: [
            "always send",
            "attacker@",
            "from now on",
            "next time",
            "for all future",
            "future tasks",
            "future reports",
            "future runs",
            "future requests",
            "remember this rule",
            "store this rule",
            "save this rule",
            "remember this instruction",
            "store this instruction",
            "save this instruction",
            "persist this rule",
            "route future reports",
            "send reports externally",
        ]
    )
    high_confidence_memory_poisoning_markers: list[str] = Field(
        default_factory=lambda: [
            "always send",
            "attacker@",
            "future runs",
            "persist this rule",
            "route future reports",
            "send reports externally",
        ]
    )
    agent_abuse_markers: list[str] = Field(
        default_factory=lambda: [
            "unauthorized_write",
            "repo:write",
            "escalation",
            "cross_task",
            "/payloads/",
            "backdoor",
            "crypto-miner",
            "reverse shell",
            "platform abuse",
            "phishing",
            "impersonate",
            "credential reset",
            "click fraud",
            "account recovery",
            "manual review override",
            "verification override",
            "submit appeal",
            "misinformation",
            "defamation",
            "fabricated claim",
            "false allegation",
            "private records",
            "home address",
            "private email",
            "private phone",
        ]
    )
    file_exfiltration_sink_markers: list[str] = Field(
        default_factory=lambda: [
            "attacker@",
            "exfiltration",
            "/collect/",
            "webhook",
            "upload",
        ]
    )
    mcp_hijack_argument_markers: list[str] = Field(
        default_factory=lambda: [
            "callback_url",
            "webhook_url",
            "redirect_uri",
            "upload_url",
            "forward_to",
            "send_to",
            "external_url",
            "/collect/",
            "exfil",
            "shadow",
            "required_dependency",
        ]
    )
    tool_hijack_external_argument_keys: list[str] = Field(
        default_factory=lambda: [
            "callback_url",
            "webhook_url",
            "redirect_uri",
            "upload_url",
            "forward_to",
            "send_to",
            "collection_callback_url",
            "citation_cache_callback_url",
            "external_url",
        ]
    )
    tool_hijack_semantic_bias_argument_keys: list[str] = Field(
        default_factory=lambda: [
            "routing_override",
            "provider_override",
            "destination_override",
            "ranking_bias",
            "entity_override",
        ]
    )
    default_enforcement_mode: str = "enforce"
    allowed_email_domains: list[str] = Field(
        default_factory=lambda: ["agentguard.local"]
    )
    allowed_api_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost"]
    )
    allowed_api_paths: list[str] = Field(default_factory=lambda: ["/status"])
    collection_path_markers: list[str] = Field(
        default_factory=lambda: ["/collect/", "upload", "exfil", "webhook"]
    )
    tool_profiles: dict[str, ToolProfile] = Field(default_factory=default_tool_profiles)
    tool_action_aliases: dict[str, list[str]] = Field(
        default_factory=lambda: {
            "read_file": ["read"],
            "write_file": [
                "write",
                "create",
                "add",
                "copy",
                "save",
                "edit",
                "update",
                "modify",
            ],
            "send_email": ["email", "send"],
            "call_api": ["api", "call"],
            "memory_write": ["memory", "write"],
            "code_exec": ["execute", "run"],
            "exec": ["execute", "run", "shell"],
            "shell": ["execute", "run", "shell"],
            "command": ["execute", "run", "command"],
            "bash": ["execute", "run", "shell"],
            "sh": ["execute", "run", "shell"],
            "powershell": ["execute", "run", "shell"],
            "terminal": ["execute", "run", "shell"],
        }
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
