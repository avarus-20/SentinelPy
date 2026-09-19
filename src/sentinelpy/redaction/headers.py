"""Header name sensitivity checks and evidence allowlisting."""

from __future__ import annotations

import re

EVIDENCE_VALUE_MAX_LENGTH = 512

_SENSITIVE_EXACT = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "set-cookie2",
        "www-authenticate",
        "proxy-authenticate",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "authentication-info",
        "authorization-info",
        "secure-token",
        "x-session-token",
        "x-user-token",
    }
)

_EVIDENCE_ALLOWLIST = frozenset(
    {
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
        "cross-origin-resource-policy",
    }
)

_SENSITIVE_PREFIXES = ("x-auth-", "x-secret-", "x-key-")


def is_sensitive_header_name(name: str) -> bool:
    """Return True if the header must never appear in public evidence."""

    lowered = name.lower()
    if lowered in _SENSITIVE_EXACT:
        return True
    if lowered.startswith(_SENSITIVE_PREFIXES):
        return True
    if "-cookie" in lowered or "-authorization" in lowered:
        return True
    return False


def may_include_header_value_in_evidence(name: str) -> bool:
    """Return True if a truncated value may be copied into finding evidence."""

    return name.lower() in _EVIDENCE_ALLOWLIST


def truncate_evidence_value(value: str) -> str:
    """Truncate and normalize a header value for safe public evidence."""

    cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value).strip()
    if len(cleaned) <= EVIDENCE_VALUE_MAX_LENGTH:
        return cleaned
    return cleaned[:EVIDENCE_VALUE_MAX_LENGTH]
