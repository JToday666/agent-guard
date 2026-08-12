"""Guard API endpoint policy for the standalone CLI package."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_ENCODED_LINE_BREAK = re.compile(r"%0[ad]", re.IGNORECASE)


class GuardApiEndpointError(ValueError):
    """Raised before credentials can be sent to an unsafe Guard API target."""


def validate_guard_api_base_url(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GuardApiEndpointError("Guard API URL must be a non-empty absolute URL")
    if (
        _CONTROL_CHARACTER.search(value)
        or _ENCODED_LINE_BREAK.search(value)
        or "\\" in value
    ):
        raise GuardApiEndpointError("Guard API URL contains forbidden characters")
    if "?" in value or "#" in value:
        raise GuardApiEndpointError("Guard API URL cannot contain a query or fragment")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise GuardApiEndpointError("Guard API URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise GuardApiEndpointError("Guard API URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise GuardApiEndpointError("Guard API URL cannot contain user information")
    if parsed.hostname is None or port is not None and not 1 <= port <= 65535:
        raise GuardApiEndpointError("Guard API URL must contain a valid host and port")

    hostname = parsed.hostname.lower()
    if "%" in hostname:
        raise GuardApiEndpointError("Guard API URL cannot contain a scoped host")
    if not _has_canonical_ip_spelling(hostname):
        raise GuardApiEndpointError("Guard API URL must contain a valid host and port")
    if parsed.scheme == "http" and not _is_explicit_loopback(hostname):
        raise GuardApiEndpointError(
            "Guard API HTTP is allowed only for explicit loopback addresses"
        )
    return value.rstrip("/")


def _is_explicit_loopback(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return address.is_loopback


def _has_canonical_ip_spelling(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return re.fullmatch(r"(?:0x[0-9a-f]+|[0-9.]+)", hostname, re.IGNORECASE) is None
    return True
