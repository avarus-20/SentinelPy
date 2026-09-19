"""Completed-scan JSON Schema contract tests (deterministic fixtures)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from sentinelpy.http.client import _RecordingRedirectHandler
from sentinelpy.models.http_meta import HttpResponse, RedirectHop
from sentinelpy.redaction.url import redact_url
from sentinelpy.reports.json import render_json
from sentinelpy.scan.runner import run_scan

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report-schema-1.0.0.json"
_FIXED_SCANNED_AT = "2026-09-19T12:00:00Z"
_SECRET_MARKERS = ("super-secret", "user:pass", "token=secret", "nonce-abc")

_ALL_PASS_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@pytest.fixture(scope="module")
def report_validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


@pytest.fixture(autouse=True)
def fixed_scanned_at():
    with patch("sentinelpy.scan.runner._utc_timestamp", return_value=_FIXED_SCANNED_AT):
        yield


def _completed_json(
    response: HttpResponse,
    target: str = "https://example.com",
) -> dict:
    with patch("sentinelpy.scan.runner.fetch", return_value=response):
        report = run_scan(target)
    data = json.loads(render_json(report))
    assert report.scan_status == "completed"
    return data


def _response(
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    target: str = "https://example.com/",
    final: str = "https://example.com/",
    redirects: tuple[RedirectHop, ...] = (),
) -> HttpResponse:
    final_scheme = "http" if final.lower().startswith("http://") else "https"
    return HttpResponse(
        target_url=target,
        final_url=final,
        final_scheme=final_scheme,
        status=status,
        headers=headers or {},
        redirects=redirects,
        elapsed_ms=12.5,
    )


@pytest.mark.parametrize(
    ("headers", "target", "final", "expected_status", "expected_counts"),
    [
        (
            _ALL_PASS_HEADERS,
            "https://example.com/",
            "https://example.com/",
            "passed",
            {"pass": 5, "warning": 0, "fail": 0, "error": 0, "info": 0},
        ),
        (
            {
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            },
            "http://example.com/",
            "http://example.com/",
            "warning",
            {"pass": 4, "warning": 1, "fail": 0, "error": 0, "info": 0},
        ),
        (
            {"Referrer-Policy": "no-referrer"},
            "https://example.com/",
            "https://example.com/",
            "failed",
            {"pass": 1, "warning": 0, "fail": 4, "error": 0, "info": 0},
        ),
    ],
    ids=["passed", "warning", "failed"],
)
def test_completed_summary_status_and_counts(
    report_validator,
    headers,
    target,
    final,
    expected_status,
    expected_counts,
):
    data = _completed_json(_response(headers=headers, target=target, final=final))
    report_validator.validate(data)
    assert data["summary"]["status"] == expected_status
    assert data["summary"]["counts"] == expected_counts
    assert data["scanned_at"] == _FIXED_SCANNED_AT
    assert data["error"] is None


@pytest.mark.parametrize("http_status", [200, 404, 500])
def test_completed_http_status_validates(report_validator, http_status: int):
    data = _completed_json(
        _response(status=http_status, headers={"Referrer-Policy": "no-referrer"})
    )
    report_validator.validate(data)
    assert data["http_status"] == http_status
    assert data["scan_status"] == "completed"


@pytest.mark.parametrize(
    ("redirects", "expected_len"),
    [
        ((), 0),
        (
            (
                RedirectHop(
                    from_url="https://example.com/",
                    to_url="https://example.com/a",
                    status=302,
                ),
            ),
            1,
        ),
        (
            (
                RedirectHop(
                    from_url="https://example.com/",
                    to_url="https://example.com/a",
                    status=301,
                ),
                RedirectHop(
                    from_url="https://example.com/a",
                    to_url="https://example.com/b",
                    status=302,
                ),
            ),
            2,
        ),
    ],
    ids=["no_redirects", "one_redirect", "multi_hop"],
)
def test_completed_redirect_chains_validate(
    report_validator,
    redirects: tuple[RedirectHop, ...],
    expected_len: int,
):
    final = redirects[-1].to_url if redirects else "https://example.com/"
    data = _completed_json(
        _response(
            headers=_ALL_PASS_HEADERS,
            final=final,
            redirects=redirects,
        )
    )
    report_validator.validate(data)
    assert len(data["redirects"]) == expected_len
    for index, hop in enumerate(data["redirects"]):
        assert hop == redirects[index].to_dict()


def test_completed_report_redacts_redirect_urls_in_json(report_validator):
    raw_from = "https://user:pass@example.com/?token=secret"
    raw_to = "https://user:pass@example.com/next?token=secret"
    safe_from = redact_url(raw_from)
    safe_to = redact_url(raw_to)
    data = _completed_json(
        _response(
            target=safe_from,
            final=safe_to,
            headers=_ALL_PASS_HEADERS,
            redirects=(RedirectHop(from_url=safe_from, to_url=safe_to, status=302),),
        ),
        target=raw_from,
    )
    report_validator.validate(data)
    serialized = json.dumps(data)
    for marker in _SECRET_MARKERS:
        assert marker not in serialized
    hop = data["redirects"][0]
    assert hop["from_url"] == safe_from
    assert hop["to_url"] == safe_to


def test_recording_redirect_handler_redacts_hop_urls():
    from urllib.request import Request

    handler = _RecordingRedirectHandler()
    request = Request("https://user:pass@example.com/?token=secret")
    handler.redirect_request(
        request,
        None,
        302,
        "",
        {},
        "https://user:pass@example.com/next?token=secret",
    )
    hop = handler.hops[0]
    serialized = json.dumps(hop.to_dict())
    for marker in _SECRET_MARKERS:
        assert marker not in serialized
    assert hop.from_url == redact_url("https://user:pass@example.com/?token=secret")
    assert hop.to_url == redact_url("https://user:pass@example.com/next?token=secret")
