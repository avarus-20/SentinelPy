#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SentinelPy core website security utilities.
"""

from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def normalize_url(url: str) -> str:
    """
    Normalize a user-provided URL.
    """

    url = url.strip()

    # Use HTTPS by default when no scheme is provided.
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)

    # Ensure that the URL contains a network location.
    if not parsed.netloc:
        raise ValueError("Invalid URL")

    return url


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)


def check_security_headers(headers: dict[str, str]) -> dict[str, bool]:
    """
    Check whether important HTTP security headers are present.
    """

    # HTTP header names are case-insensitive.
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
    """

    normalized_url = normalize_url(url)

    # Identify SentinelPy with a custom User-Agent header.
    request = Request(
        normalized_url,
        headers={"User-Agent": "SentinelPy/0.1"},
    )

    try:
        # Return headers from a successful HTTP response.
        with urlopen(request, timeout=10) as response:
            return dict(response.headers.items())

    except HTTPError as error:
        # HTTP error responses can still contain useful headers.
        return dict(error.headers.items())

def scan_site(url: str) -> dict[str, object]:
    """
    Scan a website and return a structured security result.
    """

    normalized_url = normalize_url(url)
    headers = fetch_headers(normalized_url)
    security_headers = check_security_headers(headers)

    return {
        "url": normalized_url,
        "headers": headers,
        "security_headers": security_headers,
    }
