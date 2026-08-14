"""V21-02 canonicalization attack tests: 7 类规范化攻击面（parametrize 按类分组）。"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard_core.actions import (
    ApiResource,
    CanonicalArgument,
    CanonicalResource,
    CanonicalizationError,
    EmailResource,
    FileResource,
    MemoryResource,
    OtherResource,
    ProcessResource,
    ResourceNormalizationInput,
    UrlResource,
    canonical_json,
    matches_argument,
    normalize_arguments,
    normalize_api_resource,
    normalize_email_resource,
    normalize_file_resource,
    normalize_memory_resource,
    normalize_process_resource,
    normalize_url_resource,
)
from agentguard_core.actions.models import ArgumentConstraint
from agentguard_core.actions.normalize import REASON_DEPTH_LIMIT


def _file(target: str, resolver=None) -> CanonicalResource:
    return normalize_file_resource(
        ResourceNormalizationInput(resource_id="res_1", target=target, resolver=resolver)
    )


def _url(target: str) -> CanonicalResource:
    return normalize_url_resource(
        ResourceNormalizationInput(resource_id="res_1", target=target)
    )


def _api(target: str, method: str | None = None) -> CanonicalResource:
    return normalize_api_resource(
        ResourceNormalizationInput(
            resource_id="res_1", target=target, method=method
        )
    )


def _email(target: str) -> CanonicalResource:
    return normalize_email_resource(
        ResourceNormalizationInput(resource_id="res_1", target=target)
    )


# ---------------------------------------------------------------------------
# ① 路径穿越：`..` 折叠与逃逸
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [
        # 越过根/基目录的逃逸：unresolved，绝不能声称授权。
        ("/../etc/shadow", "unresolved"),
        ("a/../../etc/shadow", "unresolved"),
        ("C:\\data\\..\\..\\Windows\\System32", "unresolved"),
        # 折叠后到达根但未越过：词法上合法但身份未证明 → partial。
        ("/data/app/../../etc/passwd", "partial"),
    ],
)
def test_path_traversal_escape_is_unresolved(path: str, expected_status: str) -> None:
    resource = _file(path)
    assert isinstance(resource, FileResource)
    assert resource.resolution_status == expected_status
    assert resource.final_path is None
    # 无论哪种降级，都不得声称已解析/明确授权。
    assert resource.resolution_status != "resolved"


@pytest.mark.parametrize(
    ("path", "expected_normalized"),
    [
        ("/data/app/../app/file.txt", "/data/app/file.txt"),
        ("/data/./report.md", "/data/report.md"),
    ],
)
def test_safe_dotdot_collapse_stays_bounded(path: str, expected_normalized: str) -> None:
    resource = _file(path)
    assert isinstance(resource, FileResource)
    # 未越界的 `..` 允许折叠；symlink 未证明前仍为 partial（fail-closed）。
    assert resource.resolution_status in {"resolved", "partial"}
    assert resource.normalized_path == expected_normalized


@pytest.mark.parametrize(
    "path",
    [
        # UNC 根 \\server\share 占两段：`..` 越出 share 即逃逸。
        "\\\\server\\share\\..\\other\\x",
        "\\\\server\\share\\..\\..\\secret",
    ],
)
def test_unc_escape_beyond_share_root_is_unresolved(path: str) -> None:
    resource = _file(path)
    assert isinstance(resource, FileResource)
    assert resource.resolution_status == "unresolved"
    assert resource.final_path is None


def test_unc_dotdot_inside_share_is_not_escape() -> None:
    resource = _file("\\\\server\\share\\sub\\..\\file.txt")
    assert isinstance(resource, FileResource)
    # 未越出 share：允许折叠，但 symlink 未证明前仍不得 resolved。
    assert resource.resolution_status == "partial"
    assert resource.normalized_path == "\\\\server\\share\\file.txt"


# ---------------------------------------------------------------------------
# ② Windows 大小写归一 + 8.3 短路径
# ---------------------------------------------------------------------------


def test_windows_casefold_normalizes_identity() -> None:
    upper = _file("C:\\Data\\Report.TXT")
    lower = _file("c:\\data\\report.txt")
    assert isinstance(upper, FileResource) and isinstance(lower, FileResource)
    assert upper.canonical_id == lower.canonical_id
    assert upper.case_sensitive is False
    assert upper.platform == "windows"


@pytest.mark.parametrize(
    "path",
    [
        "C:\\PROGRA~1\\APP.EXE",
        "C:\\Users\\ADMINI~1\\DOCUME~1\\file.txt",
    ],
)
def test_windows_8_3_short_path_is_partial(path: str) -> None:
    resource = _file(path)
    assert isinstance(resource, FileResource)
    # 8.3 短名展开需要卷上真实解析：即使注入 resolver 也不升级为 resolved。
    assert resource.resolution_status == "partial"
    resolved_attempt = _file(path, resolver=lambda normalized: "C:\\Program Files\\app.exe")
    assert isinstance(resolved_attempt, FileResource)
    assert resolved_attempt.resolution_status == "partial"
    assert resolved_attempt.symlink_resolution == "not_resolved"


# ---------------------------------------------------------------------------
# ③ symlink 未解析 → 不得声称授权
# ---------------------------------------------------------------------------


def test_symlink_without_resolver_is_not_resolved() -> None:
    resource = _file("/data/link/file.txt")
    assert isinstance(resource, FileResource)
    assert resource.symlink_resolution == "not_resolved"
    assert resource.final_path is None
    # 未解析 ≠ 明确授权：resolution_status 绝不能是 resolved。
    assert resource.resolution_status != "resolved"


def test_fake_in_memory_resolver_can_resolve() -> None:
    resolver_calls: list[str] = []

    def fake_resolver(normalized: str) -> str | None:
        resolver_calls.append(normalized)
        return "/srv/real/file.txt"

    resource = _file("/data/link/file.txt", resolver=fake_resolver)
    assert isinstance(resource, FileResource)
    assert resource.symlink_resolution == "resolved"
    assert resource.resolution_status == "resolved"
    assert resource.final_path == "/srv/real/file.txt"
    assert resolver_calls == ["/data/link/file.txt"]


def test_resolver_returning_none_stays_not_resolved() -> None:
    resource = _file("/data/link/file.txt", resolver=lambda normalized: None)
    assert isinstance(resource, FileResource)
    assert resource.symlink_resolution == "not_resolved"
    assert resource.resolution_status != "resolved"


# ---------------------------------------------------------------------------
# ④ URL IDN + 默认端口剥离
# ---------------------------------------------------------------------------


def test_url_idn_and_default_port_collapse_to_same_identity() -> None:
    unicode_host = _url("https://münchen.de/path")
    punycode_host = _url("https://xn--mnchen-3ya.de/path")
    assert isinstance(unicode_host, UrlResource)
    assert isinstance(punycode_host, UrlResource)
    assert unicode_host.host_ascii == "xn--mnchen-3ya.de"
    assert unicode_host.canonical_id == punycode_host.canonical_id


@pytest.mark.parametrize(
    ("with_port", "without_port"),
    [
        ("http://example.com:80/x", "http://example.com/x"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://EXAMPLE.COM/x", "http://example.com/x"),
    ],
)
def test_url_default_port_and_case_collapse(with_port: str, without_port: str) -> None:
    left = _url(with_port)
    right = _url(without_port)
    assert isinstance(left, UrlResource) and isinstance(right, UrlResource)
    assert left.canonical_id == right.canonical_id


def test_url_non_default_port_stays_distinct() -> None:
    explicit = _url("https://example.com:8443/x")
    default = _url("https://example.com/x")
    assert isinstance(explicit, UrlResource) and isinstance(default, UrlResource)
    assert explicit.canonical_id != default.canonical_id


def test_url_invalid_scheme_is_unresolved() -> None:
    resource = _url("ftp://example.com/x")
    assert isinstance(resource, OtherResource)
    assert resource.resolution_status == "unresolved"


@pytest.mark.parametrize(
    "target",
    [
        # 超范围端口：urlsplit().port 抛 ValueError，fail-closed 收敛。
        "http://example.com:99999/",
        # 非数字端口：同样抛 ValueError，不得穿透 builder。
        "http://example.com:abc/",
    ],
)
def test_url_invalid_port_is_unresolved(target: str) -> None:
    resource = _url(target)
    assert isinstance(resource, OtherResource)
    assert resource.resolution_status == "unresolved"


@pytest.mark.parametrize(
    "target",
    ["https://example.com:99999/x", "https://example.com:abc/x"],
)
def test_api_invalid_port_is_unresolved(target: str) -> None:
    resource = _api(target, method="get")
    assert isinstance(resource, OtherResource)
    assert resource.resolution_status == "unresolved"


@pytest.mark.parametrize(
    "host",
    [
        "exa_mple.com",  # 下划线非 LDH 字符
        "-bad.com",  # label 首字符连字符
        "bad-.example",  # label 尾字符连字符
        "bad..example",  # 空 label
    ],
)
def test_url_invalid_idna_labels_are_unresolved(host: str) -> None:
    resource = _url(f"https://{host}/x")
    assert isinstance(resource, OtherResource)
    assert resource.resolution_status == "unresolved"


def test_email_invalid_idna_labels_are_unresolved() -> None:
    resource = _email("user@exa_mple.com")
    assert isinstance(resource, OtherResource)
    assert resource.resolution_status == "unresolved"


# ---------------------------------------------------------------------------
# ⑤ redirect_policy 默认 forbid、跨 authority 不合并
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "https://a.example/x",
        "http://b.example/y?token=abc",
    ],
)
def test_redirect_policy_defaults_to_forbid(target: str) -> None:
    url_resource = _url(target)
    api_resource = _api(target, method="post")
    assert isinstance(url_resource, UrlResource)
    assert url_resource.redirect_policy == "forbid"
    assert isinstance(api_resource, ApiResource)
    assert api_resource.redirect_policy == "forbid"
    assert api_resource.method == "POST"


def test_cross_authority_urls_are_never_merged() -> None:
    first = _url("https://a.example/shared/path")
    second = _url("https://b.example/shared/path")
    assert isinstance(first, UrlResource) and isinstance(second, UrlResource)
    assert first.canonical_id != second.canonical_id
    assert first.host_ascii != second.host_ascii


def test_non_security_query_values_do_not_change_identity() -> None:
    base = _url("https://api.example/v1/items?page=1")
    other_value = _url("https://api.example/v1/items?page=9")
    assert isinstance(base, UrlResource) and isinstance(other_value, UrlResource)
    # 非 security query 只记录排序后的 key，value 不进入 identity。
    assert base.canonical_id == other_value.canonical_id
    assert base.query_keys == ["page"]
    assert base.security_query_arguments == []


def test_security_query_values_are_captured() -> None:
    resource = _url("https://api.example/v1/items?token=abc123&page=1")
    assert isinstance(resource, UrlResource)
    assert [argument.json_pointer for argument in resource.security_query_arguments] == [
        "/query/token"
    ]
    assert resource.security_query_arguments[0].value == "abc123"


# ---------------------------------------------------------------------------
# ⑥ email 域 IDN/小写归一、local-part 不静默归一
# ---------------------------------------------------------------------------


def test_email_domain_idn_and_case_normalization() -> None:
    resource = _email("User@MÜNCHEN.DE")
    assert isinstance(resource, EmailResource)
    assert resource.domain_ascii == "xn--mnchen-3ya.de"
    # local-part 保持原样（大小写不归一）。
    assert resource.normalized_address == "User@xn--mnchen-3ya.de"


def test_email_local_part_is_not_silently_normalized() -> None:
    upper = _email("User@example.com")
    lower = _email("user@example.com")
    assert isinstance(upper, EmailResource) and isinstance(lower, EmailResource)
    assert upper.canonical_id != lower.canonical_id
    # domain 侧仍然归一。
    assert upper.domain_ascii == lower.domain_ascii == "example.com"


@pytest.mark.parametrize(
    "target",
    ["no-at-sign", "@example.com", "user@", "user@bad_domain.."],
)
def test_email_invalid_address_is_unresolved(target: str) -> None:
    resource = _email(target)
    assert isinstance(resource, OtherResource)
    assert resource.resolution_status == "unresolved"


# ---------------------------------------------------------------------------
# ⑦ JSON 类型不匹配："123" vs 123，无 coercion
# ---------------------------------------------------------------------------


def test_argument_digest_differs_between_str_and_int() -> None:
    text_digest = normalize_arguments({"amount": "123"}).canonical.argument_digest
    int_digest = normalize_arguments({"amount": 123}).canonical.argument_digest
    assert text_digest != int_digest


def test_argument_values_keep_their_types() -> None:
    result = normalize_arguments({"amount": 123, "label": "123"})
    by_pointer = {item.json_pointer: item.value for item in result.canonical.items}
    assert by_pointer["/amount"] == 123 and isinstance(by_pointer["/amount"], int)
    assert by_pointer["/label"] == "123" and isinstance(by_pointer["/label"], str)


def test_argument_constraint_does_not_coerce_types() -> None:
    result = normalize_arguments({"token": 123})
    constraint = ArgumentConstraint(json_pointer="/token", op="eq", value="123")
    # fail-closed：字符串约束不匹配整型值。
    assert matches_argument(constraint, result.canonical) is False
    matching = ArgumentConstraint(json_pointer="/token", op="eq", value=123)
    assert matches_argument(matching, result.canonical) is True


def test_canonical_json_rejects_float_without_coercion() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json({"v": 123.0})
    # 规范化层对 float 显式降级，而不是静默转换；reason_code 固化到具体常量。
    result = normalize_arguments({"v": 1.5})
    assert result.partial is True
    assert result.canonical.items == []
    assert "arguments.float_value_unsupported" in result.reason_codes


def test_canonical_argument_rejects_bool_for_int_in_strict_mode() -> None:
    with pytest.raises(ValidationError):
        CanonicalArgument.model_validate(
            {"json_pointer": "/flag", "value": 1, "security_relevant": "yes"}
        )


# ---------------------------------------------------------------------------
# ⑧ process canonical_id：完整原文身份与展示侧脱敏（M2）
# ---------------------------------------------------------------------------


def _process(target: str) -> CanonicalResource:
    return normalize_process_resource(
        ResourceNormalizationInput(resource_id="res_1", target=target)
    )


def test_process_identity_uses_full_command_beyond_display_limit() -> None:
    prefix = "python " + "A" * 200  # 前 160 字符完全相同，超出展示截断上限
    first = _process(prefix)
    second = _process("python " + "A" * 150 + "B" * 50)
    assert isinstance(first, ProcessResource) and isinstance(second, ProcessResource)
    # 仅 160 字符后不同：canonical_id 绝不能碰撞。
    assert first.canonical_id != second.canonical_id
    assert first.canonical_id == f"process://{prefix}"


def test_process_identity_keeps_raw_command_while_display_is_redacted() -> None:
    command = "curl https://x/?api_key=sk-abcdefgh123456"
    resource = _process(command)
    assert isinstance(resource, ProcessResource)
    # 身份保留完整原文，约束匹配不被脱敏改写。
    assert resource.canonical_id == f"process://{command}"
    # 展示侧必须脱敏，凭证不得出现在 display_summary。
    assert "sk-abcdefgh123456" not in resource.display_summary
    assert "[redacted]" in resource.display_summary


# ---------------------------------------------------------------------------
# ⑨ memory / other / 深度上限：身份单射与有界计算
# ---------------------------------------------------------------------------


def test_memory_identity_is_injective_across_namespace_splits() -> None:
    # (namespace=a, memory_id=b/c) 与 (namespace=a/b, memory_id=c) 不得碰撞。
    first = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="res_1", target="b/c", memory_namespace="a"
        )
    )
    second = normalize_memory_resource(
        ResourceNormalizationInput(
            resource_id="res_1", target="c", memory_namespace="a/b"
        )
    )
    assert isinstance(first, MemoryResource) and isinstance(second, MemoryResource)
    assert first.canonical_id != second.canonical_id


def test_deeply_nested_arguments_degrade_instead_of_recursion_error() -> None:
    payload: dict = {"leaf": "value"}
    for _ in range(2000):
        payload = {"nested": payload}
    result = normalize_arguments(payload)
    assert result.partial is True
    assert REASON_DEPTH_LIMIT in result.reason_codes
