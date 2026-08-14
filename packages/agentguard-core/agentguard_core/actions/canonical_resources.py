"""Typed resource canonicalization for V21-02 (01 §7.2, L254-342).

为 8 类 CanonicalResource 提供纯词法（lexical-only）normalizer：

- 零文件系统 / 零网络 I/O：所有规范化只基于输入字符串本身；
- symlink 与 Windows 8.3 短路径的真实解析不在词法层进行，只能通过调用方
  注入的可选 ``resolver`` 回调完成；未注入（默认 None）时一律
  ``not_resolved`` / ``partial``，绝不声称已解析；
- 每个变体一个 normalizer 函数，``RESOURCE_NORMALIZERS`` registry dict 分派。

冻结语义（01 §7.2, L337）：``unresolved`` 资源不能用于证明“明确授权”；
授权针对最终 canonical/resolved identity；若最终资源只能 Runtime 解析，
Runtime 必须执行前二次检查或回报最终解析事实。URL/API 的 security-relevant
query value 进入 ``security_query_arguments`` 与授权指纹；其他 query 只记录
排序后的 key 与脱敏审计摘要，不得悄悄影响授权结果。``redirect_policy``
默认 ``forbid``；跨 authority 不做任何合并。
"""

from __future__ import annotations

import ntpath
import posixpath
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ..credentials import redact_credential_text
from .canonical_json import canonical_sha256
from .models import (
    NORMALIZER_VERSION,
    ApiResource,
    CanonicalArgument,
    CanonicalResource,
    EmailResource,
    FileResource,
    MemoryResource,
    OtherResource,
    ProcessResource,
    ToolResource,
    UrlResource,
)

__all__ = [
    "DEFAULT_SECURITY_QUERY_KEYS",
    "RESOURCE_NORMALIZERS",
    "ResourceNormalizationInput",
    "SymlinkResolver",
    "normalize_api_resource",
    "normalize_email_resource",
    "normalize_file_resource",
    "normalize_memory_resource",
    "normalize_other_resource",
    "normalize_process_resource",
    "normalize_tool_resource",
    "normalize_url_resource",
]

# symlink / 8.3 短路径真实解析回调：输入规范化后的路径，返回最终解析路径；
# 无法解析返回 None。纯内存注入，Core 自身不做任何文件系统访问。
SymlinkResolver = Callable[[str], str | None]

# security-relevant query key（casefold 匹配）：其 value 必须进入
# security_query_arguments 与授权指纹（01 §7.2, L341）。
DEFAULT_SECURITY_QUERY_KEYS = frozenset(
    {
        "token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "auth",
        "authorization",
        "password",
        "credential",
        "user",
        "username",
        "account",
        "id",
    }
)

_DISPLAY_SUMMARY_LIMIT = 160
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
# 8.3 短文件名模式：基础名 ≤8 字符 + ``~`` 数字尾缀 + 可选 ≤3 字符扩展名。
_SHORT_SEGMENT_RE = re.compile(r"^[^\\/:*?\"<>|~]{1,8}~\d(\.[^\\/:*?\"<>|~]{1,3})?$")


@dataclass(frozen=True)
class ResourceNormalizationInput:
    """normalizer 统一输入；所有字段均为调用方已持有的词法信息。"""

    resource_id: str
    target: str
    method: str | None = None
    memory_namespace: str | None = None
    tool_name: str | None = None
    resolver: SymlinkResolver | None = None
    security_query_keys: frozenset[str] = DEFAULT_SECURITY_QUERY_KEYS


def _display_summary(target: str) -> str:
    return redact_credential_text(target)[:_DISPLAY_SUMMARY_LIMIT]


def _unresolved_other(inp: ResourceNormalizationInput, *, type_name: str) -> OtherResource:
    """不可规范化输入的 fail-closed 收敛：unresolved 不能证明明确授权。

    ``canonical_id`` 只内嵌 target 的确定性摘要，绝不内嵌 event 级随机量
    （如 builder 以 event_id 派生的 resource_id），否则语义相同动作的
    授权指纹会跨事件漂移。
    """
    target_digest = canonical_sha256(inp.target)
    return OtherResource(
        resource_id=inp.resource_id,
        canonical_id=f"unresolved:{type_name}:{target_digest}",
        display_summary=_display_summary(inp.target),
        resolution_status="unresolved",
        normalizer_version=NORMALIZER_VERSION,
        type_name=type_name,
        stable_identifier=None,
    )


# ---------------------------------------------------------------------------
# file
# ---------------------------------------------------------------------------


def _detect_platform(path: str) -> str:
    if _WINDOWS_DRIVE_RE.match(path) or "\\" in path or path.startswith("//"):
        return "windows"
    if path.startswith("/"):
        return "posix"
    return "unknown"


def _has_escape(path: str, platform: str) -> bool:
    """在折叠前检测 ``..`` 越界段：越过根目录或相对基目录即视为逃逸。"""
    segments = [seg for seg in re.split(r"[\\/]+", path) if seg not in ("", ".")]
    start_index = 0
    if platform == "windows" and (
        path.startswith("//") or path.startswith("\\\\")
    ):
        # UNC 根 ``\\server\share`` 占 server/share 两段，两段都是根：
        # 深度回落到根之下（``..`` 越出 share）即逃逸。
        start_index = 2
    elif platform == "windows" and _WINDOWS_DRIVE_RE.match(path):
        start_index = 1  # 盘符段本身是根，不参与深度计算
    depth = 0
    for segment in segments[start_index:]:
        if segment == "..":
            # 到达或越过根/基目录的 `..` 一律视为逃逸（即使 normpath 会钳制）。
            if depth <= 0:
                return True
            depth -= 1
        else:
            depth += 1
    return False


def _looks_like_8_3(path: str) -> bool:
    segments = [seg for seg in re.split(r"[\\/]+", path) if seg not in ("", ".")]
    return any(
        _SHORT_SEGMENT_RE.match(segment) for segment in segments if segment != ".."
    )


def normalize_file_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    """文件路径规范化：折叠 ``..``、Windows casefold、8.3 识别、symlink 保守。

    - 折叠前检测越界段：逃逸 → ``unresolved``（不得声称授权）；
    - Windows 侧整体 casefold（大小写不敏感卷）并识别 8.3 短路径 → ``partial``；
    - symlink 一律不在词法层解析：resolver 未注入或返回 None 时
      ``symlink_resolution="not_resolved"`` 且 ``final_path=None``。
    """
    path = inp.target.strip()
    if not path:
        return _unresolved_other(inp, type_name="file")

    platform = _detect_platform(path)
    escaped = _has_escape(path, platform)
    if platform == "windows":
        normalized = ntpath.normpath(path).casefold()
    elif platform == "posix":
        normalized = posixpath.normpath(path)
    else:
        normalized = posixpath.normpath(path)

    case_sensitive: bool | None
    if platform == "windows":
        case_sensitive = False
    elif platform == "posix":
        case_sensitive = True
    else:
        case_sensitive = None

    # 8.3 短路径模式识别：短名展开需要卷上真实解析，词法层无法证明最终
    # identity，一律保持 partial（即使注入 resolver 也不升级）。
    has_short_path = platform == "windows" and _looks_like_8_3(path)

    final_path: str | None = None
    symlink_resolution = "not_resolved"
    if escaped:
        # 越界逃逸：不能证明最终 identity，一律 unresolved（不得声称授权）。
        resolution_status = "unresolved"
    else:
        # 词法规范化完成但 symlink/8.3 真实解析未证明 → 至少 partial。
        resolution_status = "partial"
        if inp.resolver is not None and not has_short_path:
            resolved = inp.resolver(normalized)
            if isinstance(resolved, str) and resolved:
                final_path = resolved
                symlink_resolution = "resolved"
                resolution_status = "resolved"

    return FileResource(
        resource_id=inp.resource_id,
        canonical_id=f"file://{normalized}",
        display_summary=_display_summary(path),
        resolution_status=resolution_status,
        normalizer_version=NORMALIZER_VERSION,
        normalized_path=normalized,
        platform=platform,  # type: ignore[arg-type]
        case_sensitive=case_sensitive,
        symlink_resolution=symlink_resolution,
        final_path=final_path,
    )


# ---------------------------------------------------------------------------
# url / api
# ---------------------------------------------------------------------------


def _idna_encode_domain(domain: str) -> str | None:
    """域名 IDNA 编码：先做 label 基本校验，不通过返回 None（unresolved）。

    校验：label 非空、不以连字符开头/结尾、不含下划线/空白；
    ``encode("idna")`` 自身的 UnicodeError 同样收敛为 None。
    """
    lowered = domain.lower()
    for label in lowered.split("."):
        if not label or label.startswith("-") or label.endswith("-"):
            return None
        if "_" in label or any(character.isspace() for character in label):
            return None
    try:
        return lowered.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _normalize_url_like(
    inp: ResourceNormalizationInput, *, kind: str
) -> CanonicalResource:
    parts = urlsplit(inp.target.strip())
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return _unresolved_other(inp, type_name=kind)
    host = parts.hostname
    if not host:
        return _unresolved_other(inp, type_name=kind)
    host_ascii = _idna_encode_domain(host)
    if host_ascii is None:
        return _unresolved_other(inp, type_name=kind)

    default_port = 443 if scheme == "https" else 80
    try:
        # urlsplit().port 对非法端口（超范围/非数字）抛 ValueError，
        # 必须 fail-closed 收敛，绝不能穿透 builder。
        port = parts.port
    except ValueError:
        return _unresolved_other(inp, type_name=kind)
    port = default_port if port is None else port
    # 默认端口剥离：显式写出 80/443 与省略得到同一 canonical identity。
    authority = host_ascii if port == default_port else f"{host_ascii}:{port}"
    normalized_path = parts.path or "/"

    pairs = parse_qsl(parts.query, keep_blank_values=True)
    query_keys = sorted({key for key, _ in pairs})
    security_arguments = [
        CanonicalArgument(
            json_pointer=f"/query/{key}", value=value, security_relevant=True
        )
        for key, value in sorted(pairs)
        if key.casefold() in inp.security_query_keys
    ]

    canonical_id = f"{scheme}://{authority}{normalized_path}"
    if query_keys:
        # 非 security query 只保留排序后的 key，value 不进入 identity。
        canonical_id += "?" + "&".join(query_keys)

    fields: dict[str, Any] = {
        "resource_id": inp.resource_id,
        "canonical_id": canonical_id,
        "display_summary": f"{scheme}://{host_ascii}{normalized_path}",
        "resolution_status": "resolved",
        "normalizer_version": NORMALIZER_VERSION,
        "scheme": scheme,
        "host_ascii": host_ascii,
        "port": port,
        "normalized_path": normalized_path,
        "query_keys": query_keys,
        "security_query_arguments": security_arguments,
        # redirect 默认 forbid；跨 authority 不合并（01 §7.2 冻结）。
        "redirect_policy": "forbid",
    }
    if kind == "api":
        return ApiResource(method=(inp.method or "GET").upper(), **fields)
    return UrlResource(**fields)


def normalize_url_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    """URL 规范化：scheme/host 小写、IDNA→host_ascii、默认端口剥离、query key 排序。"""
    return _normalize_url_like(inp, kind="url")


def normalize_api_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    """API 规范化：同 URL，另携带大写 method（method 不参与 identity 折叠）。"""
    return _normalize_url_like(inp, kind="api")


# ---------------------------------------------------------------------------
# email
# ---------------------------------------------------------------------------


def normalize_email_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    """email 规范化：local-part 保持原样，domain 小写 + IDNA→domain_ascii。

    local-part 不做任何静默归一（大小写、引号、点折叠都保持原样），避免
    在授权 identity 上引入未冻结的语义。
    """
    address = inp.target.strip()
    local, separator, domain = address.rpartition("@")
    if not separator or not local or not domain:
        return _unresolved_other(inp, type_name="email")
    domain_ascii = _idna_encode_domain(domain)
    if domain_ascii is None:
        return _unresolved_other(inp, type_name="email")
    normalized_address = f"{local}@{domain_ascii}"
    return EmailResource(
        resource_id=inp.resource_id,
        canonical_id=f"mailto:{normalized_address}",
        display_summary=normalized_address,
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        normalized_address=normalized_address,
        domain_ascii=domain_ascii,
    )


# ---------------------------------------------------------------------------
# memory / process / tool / other：直接字段映射
# ---------------------------------------------------------------------------


def _escape_memory_segment(segment: str) -> str:
    # 转义 ``\`` 与 ``/``，保证 namespace/memory_id 分段拼接为单射身份：
    # (a, b/c) 与 (a/b, c) 不再碰撞为同一 canonical_id。
    return segment.replace("\\", "\\\\").replace("/", "\\/")


def normalize_memory_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    memory_id = inp.target.strip()
    namespace = inp.memory_namespace
    identity = (
        f"{_escape_memory_segment(namespace)}/{_escape_memory_segment(memory_id)}"
        if namespace
        else _escape_memory_segment(memory_id)
    )
    return MemoryResource(
        resource_id=inp.resource_id,
        canonical_id=f"memory://{identity}",
        display_summary=_display_summary(identity),
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        memory_id=memory_id,
        namespace=namespace,
    )


def normalize_process_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    executable = inp.target.strip()
    # identity 必须用完整原文：脱敏+截断后的展示文本会导致 160 字符后
    # 不同的命令碰撞，且真实命令被改写后约束匹配失败。展示侧仍脱敏截断。
    return ProcessResource(
        resource_id=inp.resource_id,
        canonical_id=f"process://{executable}",
        display_summary=_display_summary(executable),
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        executable=executable,
        interpreter=None,
    )


def normalize_tool_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    tool_name = (inp.tool_name or inp.target).strip()
    return ToolResource(
        resource_id=inp.resource_id,
        canonical_id=f"tool://{tool_name}",
        display_summary=tool_name,
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        tool_name=tool_name,
        tool_schema_digest=None,
        provider_binding_id=None,
    )


def normalize_other_resource(inp: ResourceNormalizationInput) -> CanonicalResource:
    # 身份优先用稳定标识（target）；resource_id 由 builder 以 event_id
    # 派生，绝不能进入 canonical_id，否则授权指纹跨事件不稳定。
    stable = inp.target.strip() or None
    canonical_id = f"other://{stable}" if stable else "other:unspecified"
    return OtherResource(
        resource_id=inp.resource_id,
        canonical_id=canonical_id,
        display_summary=_display_summary(inp.target),
        resolution_status="resolved",
        normalizer_version=NORMALIZER_VERSION,
        type_name="other",
        stable_identifier=stable,
    )


# ---------------------------------------------------------------------------
# registry 分派
# ---------------------------------------------------------------------------

RESOURCE_NORMALIZERS: Mapping[
    str, Callable[[ResourceNormalizationInput], CanonicalResource]
] = {
    "file": normalize_file_resource,
    "url": normalize_url_resource,
    "api": normalize_api_resource,
    "email": normalize_email_resource,
    "memory": normalize_memory_resource,
    "process": normalize_process_resource,
    "tool": normalize_tool_resource,
    "other": normalize_other_resource,
}
