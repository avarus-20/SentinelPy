import ssl
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from sentinelpy.exceptions import NetworkError, RequestTimeoutError, TLSError
from sentinelpy.http.client import FetchOptions, fetch
from sentinelpy.http.snapshot import SecurityHeaderSnapshot
from sentinelpy.models.http_meta import RedirectHop


def _success_response(
    *,
    status: int = 200,
    final_url: str = "https://example.com/",
    headers: list[tuple[str, str]] | None = None,
):
    fake_response = MagicMock()
    fake_response.status = status
    fake_response.geturl.return_value = final_url
    fake_response.headers.items.return_value = headers or [
        ("Content-Type", "text/html"),
    ]
    fake_context = MagicMock()
    fake_context.__enter__.return_value = fake_response
    fake_context.__exit__.return_value = False
    return fake_context


def test_fetch_returns_metadata_for_200():
    with patch("sentinelpy.http.client.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.return_value = _success_response()
        build_opener.return_value = opener

        response = fetch("https://example.com")

    assert response.status == 200
    assert response.final_url == "https://example.com/"


def test_fetch_returns_metadata_for_404():
    error = HTTPError(
        url="https://example.com/missing",
        code=404,
        msg="Not Found",
        hdrs={"X-Content-Type-Options": "nosniff"},
        fp=None,
    )

    with patch("sentinelpy.http.client.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.side_effect = error
        build_opener.return_value = opener

        response = fetch("https://example.com/missing")

    assert response.status == 404
    snapshot = SecurityHeaderSnapshot.from_header_map(response.headers)
    assert snapshot.x_content_type_options == "nosniff"


def test_fetch_returns_metadata_for_500():
    error = HTTPError(
        url="https://example.com/error",
        code=500,
        msg="Server Error",
        hdrs={"Referrer-Policy": "no-referrer"},
        fp=None,
    )

    with patch("sentinelpy.http.client.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.side_effect = error
        build_opener.return_value = opener

        response = fetch("https://example.com/error")

    assert response.status == 500
    snapshot = SecurityHeaderSnapshot.from_header_map(response.headers)
    assert snapshot.referrer_policy == "no-referrer"


def test_fetch_raises_network_error_on_url_error():
    with patch("sentinelpy.http.client.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.side_effect = URLError("Name or service not known")
        build_opener.return_value = opener

        with pytest.raises(NetworkError, match="Unable to reach the target"):
            fetch("https://example.com")


def test_fetch_raises_timeout_error():
    with patch("sentinelpy.http.client.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.side_effect = TimeoutError("timed out")
        build_opener.return_value = opener

        with pytest.raises(RequestTimeoutError):
            fetch("https://example.com")


def test_fetch_raises_tls_error():
    with patch("sentinelpy.http.client.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.side_effect = URLError(ssl.SSLError("certificate verify failed"))
        build_opener.return_value = opener

        with pytest.raises(TLSError):
            fetch("https://example.com")


def test_fetch_exposes_recorded_redirect_hops():
    recording = MagicMock()
    recording.hops = [
        RedirectHop(
            from_url="https://example.com/",
            to_url="https://example.com/final",
            status=302,
        )
    ]

    with patch(
        "sentinelpy.http.client._RecordingRedirectHandler",
        return_value=recording,
    ):
        with patch("sentinelpy.http.client.build_opener") as build_opener:
            opener = MagicMock()
            opener.open.return_value = _success_response(
                final_url="https://example.com/final"
            )
            build_opener.return_value = opener

            response = fetch("https://example.com")

    assert response.redirects[0].status == 302


def test_fetch_without_redirects_keeps_redirect_status():
    error = HTTPError(
        url="https://example.com",
        code=302,
        msg="Found",
        hdrs={"Location": "https://example.com/next"},
        fp=None,
    )

    with patch("sentinelpy.http.client.build_opener") as build_opener:
        opener = MagicMock()
        opener.open.side_effect = error
        build_opener.return_value = opener

        response = fetch(
            "https://example.com",
            options=FetchOptions(follow_redirects=False),
        )

    assert response.status == 302
