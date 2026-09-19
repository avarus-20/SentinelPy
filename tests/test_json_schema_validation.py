"""Validate scan reports against docs/report-schema-1.0.0.json."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest
from jsonschema import Draft202012Validator

from sentinelpy.models.http_meta import HttpResponse, RedirectHop
from sentinelpy.reports.json import render_json
from sentinelpy.scan.runner import run_scan

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report-schema-1.0.0.json"
_SECRET_MARKERS = ("super-secret", "nonce-abc", "token=secret", "user:pass")


@pytest.fixture(scope="module")
def report_validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def test_completed_report_validates_against_schema(report_validator):
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    response = HttpResponse(
        target_url="https://example.com/",
        final_url="https://example.com/final",
        final_scheme="https",
        status=200,
        headers=headers,
        redirects=(
            RedirectHop(
                from_url="https://example.com/",
                to_url="https://example.com/final",
                status=302,
            ),
        ),
        elapsed_ms=3.5,
    )
    with patch("sentinelpy.scan.runner.fetch", return_value=response):
        report = run_scan("https://example.com")

    data = json.loads(render_json(report))
    _assert_no_secrets(json.dumps(data))
    report_validator.validate(data)
    assert data["error"] is None
    assert data["scan_status"] == "completed"


def test_error_report_validates_with_null_error_fields(report_validator):
    report = run_scan("http://[")

    data = json.loads(render_json(report))
    report_validator.validate(data)
    assert data["scan_status"] == "error"
    assert data["error"] is not None
    assert data["error"]["category"] == "invalid_target"
    assert data["final_url"] is None
    assert data["http_status"] is None


def test_schema_rejects_additional_top_level_properties(report_validator):
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_minimal_response(),
    ):
        report = run_scan("https://example.com")

    data = json.loads(render_json(report))
    data["response_headers"] = {"Set-Cookie": "session=leak"}

    with pytest.raises(jsonschema.ValidationError):
        report_validator.validate(data)


def test_schema_requires_mandatory_fields(report_validator):
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_minimal_response(),
    ):
        report = run_scan("https://example.com")

    data = json.loads(render_json(report))
    incomplete = deepcopy(data)
    del incomplete["disclaimer"]

    with pytest.raises(jsonschema.ValidationError):
        report_validator.validate(incomplete)


def _minimal_response() -> HttpResponse:
    return HttpResponse(
        target_url="https://example.com/",
        final_url="https://example.com/",
        final_scheme="https",
        status=200,
        headers={},
        redirects=(),
        elapsed_ms=1.0,
    )


def _assert_no_secrets(serialized: str) -> None:
    for marker in _SECRET_MARKERS:
        assert marker not in serialized
