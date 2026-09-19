"""Redact sensitive parts of URLs for safe reporting."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "access_token",
        "id_token",
        "auth",
        "authorization",
        "session",
        "sessionid",
        "sid",
        "jwt",
        "api_key",
        "apikey",
        "key",
        "secret",
        "password",
        "passwd",
        "code",
        "state",
    }
)


def redact_url(url: str) -> str:
    """
    Return a URL safe to embed in reports.

    Strips fragments, redacts userinfo, and masks sensitive query values.
    """

    parts = urlsplit(url)
    userinfo = ""
    if parts.username is not None:
        userinfo = "[REDACTED]"
        if parts.hostname is not None:
            userinfo = f"{userinfo}@{parts.hostname}"
        netloc = userinfo
        if parts.port is not None:
            netloc = f"{netloc}:{parts.port}"
    else:
        netloc = parts.netloc

    query_pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _SENSITIVE_QUERY_KEYS:
            query_pairs.append((key, "[REDACTED]"))
        else:
            query_pairs.append((key, value))

    query = urlencode(query_pairs)
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
