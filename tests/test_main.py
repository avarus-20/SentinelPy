from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from sentinelpy.main import (
    check_security_headers,
    fetch_headers,
    normalize_url,
    scan_site,
)


def test_adds_https_when_scheme_is_missing():
    # Verify that HTTPS is added automatically when no scheme is provided.
    assert normalize_url("example.com") == "https://example.com"


def test_keeps_existing_https():
    # Verify that an existing HTTPS scheme is preserved.
    assert normalize_url("https://example.com") == "https://example.com"


def test_detects_present_security_headers():
    # Verify that existing security headers are detected.
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }

    result = check_security_headers(headers)

    assert result["Strict-Transport-Security"] is True
    assert result["X-Content-Type-Options"] is True


def test_detects_missing_security_header():
    # Verify that a missing security header is reported.
    headers = {}

    result = check_security_headers(headers)

    assert result["Content-Security-Policy"] is False


def test_fetch_headers_returns_response_headers():
    # Replace the real network request with a mocked response.
    fake_response = MagicMock()

    # Define HTTP headers returned by the mocked response.
    fake_response.headers.items.return_value = [
        ("Content-Type", "text/html"),
        ("X-Content-Type-Options", "nosniff"),
    ]

    # Configure context manager behavior for the mocked response.
    fake_context = MagicMock()
    fake_context.__enter__.return_value = fake_response
    fake_context.__exit__.return_value = False

    # Patch urlopen to avoid a real network request.
    with patch("sentinelpy.main.urlopen", return_value=fake_context):
        result = fetch_headers("example.com")

    assert result["Content-Type"] == "text/html"
    assert result["X-Content-Type-Options"] == "nosniff"


def test_fetch_headers_returns_headers_from_http_error():
    # Create a simulated HTTP 404 error that still contains response headers.
    error = HTTPError(
        url="https://example.com",
        code=404,
        msg="Not Found",
        hdrs={"Content-Security-Policy": "default-src 'self'"},
        fp=None,
    )

    # Patch urlopen so that it raises the simulated HTTPError.
    with patch("sentinelpy.main.urlopen", side_effect=error):
        result = fetch_headers("example.com")

    assert result["Content-Security-Policy"] == "default-src 'self'"

def test_scan_site_returns_structured_result():
    # Use a mocked response to avoid a real network request.
    fake_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }

    with patch("sentinelpy.main.fetch_headers", return_value=fake_headers):
        result = scan_site("example.com")

    assert result["url"] == "https://example.com"
    assert result["headers"] == fake_headers
    assert result["security_headers"]["Strict-Transport-Security"] is True
    assert result["security_headers"]["Content-Security-Policy"] is False
