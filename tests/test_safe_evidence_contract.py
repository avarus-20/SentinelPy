import json
from unittest.mock import patch

from sentinelpy.exceptions import InvalidTargetError
from sentinelpy.http.url import normalize_url
from sentinelpy.models.http_meta import HttpResponse
from sentinelpy.redaction.evidence import EvidenceBuilder
from sentinelpy.reports.json import render_json
from sentinelpy.scan.runner import run_scan


def test_csp_evidence_never_includes_policy_body():
    sensitive_csp = (
        "default-src 'self'; report-uri https://user:pass@example.com/?token=secret; "
        "script-src 'nonce-abc123secret'"
    )
    evidence = EvidenceBuilder.for_presence(
        "Content-Security-Policy",
        present=True,
        raw_value=sensitive_csp,
    ).to_dict()

    serialized = json.dumps(evidence)
    assert "header_value_excerpt" not in evidence
    assert "secret" not in serialized
    assert "nonce" not in serialized


def test_hsts_uses_final_https_url_after_redirect():
    headers = {"Strict-Transport-Security": "max-age=31536000"}
    response = HttpResponse(
        target_url="http://example.com/",
        final_url="https://example.com/",
        final_scheme="https",
        status=200,
        headers=headers,
        redirects=(),
        elapsed_ms=1.0,
    )
    with patch("sentinelpy.scan.runner.fetch", return_value=response):
        report = run_scan("http://example.com")

    hsts = next(item for item in report.findings if item.id == "HEADER-HSTS")
    assert hsts.status == "pass"
    payload = render_json(report)
    assert "not_applicable_over_http" not in payload


def test_malformed_url_returns_structured_error_report():
    report = run_scan("http://[")

    assert report.scan_status == "error"
    assert report.error is not None
    assert report.error.category == "invalid_target"


def test_normalize_url_rejects_bracket_host():
    import pytest

    with pytest.raises(InvalidTargetError):
        normalize_url("http://[")


def test_run_scan_json_never_includes_csp_secrets():
    sensitive_csp = (
        "default-src 'self'; report-uri https://x.com/?token=secret; "
        "script-src 'nonce-abc123secret'"
    )
    headers = {
        "Content-Security-Policy": sensitive_csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000",
    }
    response = HttpResponse(
        target_url="https://example.com/",
        final_url="https://example.com/",
        final_scheme="https",
        status=200,
        headers=headers,
        redirects=(),
        elapsed_ms=1.0,
    )
    with patch("sentinelpy.scan.runner.fetch", return_value=response):
        report = run_scan("https://example.com")

    payload = render_json(report)
    assert "secret" not in payload
    assert "nonce" not in payload
    assert "report-uri" not in payload


def test_run_scan_rejects_invalid_port():
    report = run_scan("http://user@example.com:bad")

    assert report.scan_status == "error"
    assert report.error is not None
    assert report.error.category == "invalid_target"
