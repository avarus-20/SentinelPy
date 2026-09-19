"""URL normalization and validation."""

from __future__ import annotations

from urllib.parse import urlparse

from sentinelpy.exceptions import InvalidTargetError

_HTTP_SCHEMES = ("http://", "https://")


def normalize_url(url: str) -> str:
    """
    Normalize a user-provided URL for scanning.

    Uses HTTPS by default when no scheme is provided. Scheme names are
    matched case-insensitively (for example, ``HTTP://`` becomes ``http://``).
    """

    url = url.strip()
    if not url:
        raise InvalidTargetError("Invalid URL")

    lower = url.lower()
    if lower.startswith("http://"):
        url = "http://" + url[7:]
    elif lower.startswith("https://"):
        url = "https://" + url[8:]
    else:
        url = f"https://{url}"

    try:
        parsed = urlparse(url)
    except ValueError as error:
        raise InvalidTargetError("Invalid URL") from error

    if not parsed.netloc or parsed.netloc in {"[", "]"}:
        raise InvalidTargetError("Invalid URL")

    return url


def target_scheme(normalized_url: str) -> str:
    """Return ``http`` or ``https`` for a normalized URL."""

    return urlparse(normalized_url).scheme.lower()
