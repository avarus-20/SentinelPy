#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Legacy SentinelPy API (v0.1 compatibility).

Deprecated scan helpers may expose raw response headers. Do not publish or log
that output. Prefer the scan CLI added in v0.2.0b once available.
"""

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sentinelpy.constants import SECURITY_HEADERS
from sentinelpy.exceptions import InvalidTargetError
from sentinelpy.http.url import normalize_url as _normalize_url


def normalize_url(url: str) -> str:
    """
    Normalize a user-provided URL.

    Raises ValueError with the legacy ``Invalid URL`` message when invalid.
    """

    try:
        return _normalize_url(url)
    except InvalidTargetError as error:
        raise ValueError("Invalid URL") from error


def check_security_headers(headers: dict[str, str]) -> dict[str, bool]:
    """
    Check whether important HTTP security headers are present.
    """

    normalized_headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    return {
        header: header.lower() in normalized_headers
        for header in SECURITY_HEADERS
    }


def fetch_headers(url: str) -> dict[str, str]:
    """
    Send an HTTP request and return the server response headers.

    Legacy API: may include sensitive headers such as Set-Cookie.
    """

    normalized_url = normalize_url(url)

    request = Request(
        normalized_url,
        headers={"User-Agent": "SentinelPy/0.1"},
    )

    try:
        with urlopen(request, timeout=10) as response:
            return dict(response.headers.items())

    except HTTPError as error:
        return dict(error.headers.items())

    except TimeoutError as error:
        raise TimeoutError(
            "Request timed out after 10 seconds"
        ) from error

    except URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise TimeoutError(
                "Request timed out after 10 seconds"
            ) from error

        raise ConnectionError(
            f"Unable to reach target: {error.reason}"
        ) from error


def scan_site(url: str) -> dict[str, object]:
    """
    Scan a website and return a structured security result.

    .. deprecated:: 0.2.0
        Legacy API. Output may contain raw sensitive headers. Use the scan
        command added in v0.2.0b instead.
    """

    normalized_url = normalize_url(url)
    headers = fetch_headers(normalized_url)
    security_headers = check_security_headers(headers)

    return {
        "url": normalized_url,
        "headers": headers,
        "security_headers": security_headers,
    }
