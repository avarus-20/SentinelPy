import json
from unittest.mock import patch

import pytest

from sentinelpy.exceptions import NetworkError, RequestTimeoutError, TLSError
from sentinelpy.models.http_meta import HttpResponse, RedirectHop
from sentinelpy.redaction.url import redact_url
from sentinelpy.reports.json import render_json
from sentinelpy.scan.runner import run_scan


def _response(
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    target: str = "https://example.com/",
    final: str = "https://example.com/",
) -> HttpResponse:
    return HttpResponse(
        target_url=target,
        final_url=final,
        status=status,
        headers=headers or {},
        redirects=(),
        elapsed_ms=12.5,
    )


def test_run_scan_completed_has_five_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(headers=headers),
    ):
        report = run_scan("https://example.com")

    assert report.scan_status == "completed"
    assert len(report.findings) == 5
    assert report.summary.status == "passed"


def test_run_scan_https_missing_hsts_fails():
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(headers={"X-Content-Type-Options": "nosniff"}),
    ):
        report = run_scan("https://example.com")

    hsts = next(f for f in report.findings if f.id == "HEADER-HSTS")
    assert hsts.status == "fail"
    assert report.summary.status == "failed"


def test_run_scan_http_missing_hsts_is_warning_not_fail():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(
            target="http://example.com/",
            final="http://example.com/",
            headers=headers,
        ),
    ):
        report = run_scan("http://example.com")

    hsts = next(f for f in report.findings if f.id == "HEADER-HSTS")
    assert hsts.status == "warning"
    assert report.summary.status == "warning"


def test_run_scan_http_with_hsts_header_is_warning():
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(
            target="http://example.com/",
            final="http://example.com/",
            headers={"Strict-Transport-Security": "max-age=1"},
        ),
    ):
        report = run_scan("http://example.com")

    hsts = next(f for f in report.findings if f.id == "HEADER-HSTS")
    assert hsts.status == "warning"
    assert hsts.evidence["observed"] == "present_ignored_over_http"


def test_run_scan_http_500_still_evaluates_findings():
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(status=500, headers={"Referrer-Policy": "no-referrer"}),
    ):
        report = run_scan("https://example.com")

    assert report.http_status == 500
    assert len(report.findings) == 5


def test_run_scan_http_404():
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(status=404, headers={}),
    ):
        report = run_scan("https://example.com")

    assert report.http_status == 404
    assert report.scan_status == "completed"


def test_run_scan_records_redirects():
    response = HttpResponse(
        target_url="https://example.com/",
        final_url="https://example.com/final",
        status=200,
        headers={},
        redirects=(
            RedirectHop(
                from_url="https://example.com/",
                to_url="https://example.com/final",
                status=302,
            ),
        ),
        elapsed_ms=1.0,
    )
    with patch("sentinelpy.scan.runner.fetch", return_value=response):
        report = run_scan("https://example.com")

    assert len(report.redirects) == 1


@pytest.mark.parametrize(
    ("side_effect", "category"),
    [
        (RequestTimeoutError("Request timed out."), "timeout"),
        (NetworkError("Unable to reach the target."), "connection"),
        (TLSError("TLS handshake or certificate verification failed."), "tls"),
    ],
)
def test_run_scan_error_reports(side_effect, category):
    with patch("sentinelpy.scan.runner.fetch", side_effect=side_effect):
        report = run_scan("https://example.com")

    assert report.scan_status == "error"
    assert report.findings == ()
    assert report.error is not None
    assert report.error.category == category
    assert report.final_url is None
    assert report.http_status is None


def test_run_scan_invalid_target_error():
    report = run_scan("")

    assert report.scan_status == "error"
    assert report.error.category == "invalid_target"


def test_json_output_never_leaks_secrets():
    headers = {
        "Set-Cookie": "session=super-secret",
        "Authorization": "Bearer xyz",
        "Strict-Transport-Security": "max-age=31536000",
    }
    raw_url = "https://user:pass@example.com/?token=secret#frag"
    safe_url = redact_url(raw_url)
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(
            target=safe_url,
            final=safe_url,
            headers=headers,
        ),
    ):
        report = run_scan(raw_url)

    payload = render_json(report)
    for secret in ("super-secret", "Bearer xyz", "user:pass", "token=secret", "#frag"):
        assert secret not in payload
    assert "response_headers" not in payload
    parsed = json.loads(payload)
    assert parsed["scan_status"] == "completed"
