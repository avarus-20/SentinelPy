"""JSON Schema contract tests for every scan error category."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from sentinelpy.exceptions import NetworkError, RequestTimeoutError, TLSError
from sentinelpy.reports.json import render_json
from sentinelpy.scan.runner import run_scan

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report-schema-1.0.0.json"

_FORBIDDEN = (
    "super-secret-cookie",
    "Bearer xyz",
    "session=",
    "user:pass",
    "token=secret",
    "#frag",
    "Traceback (most recent call last)",
    "ValueError:",
    "RuntimeError:",
    "errno",
    "certificate verify failed",
    "Name or service not known",
    "response_headers",
    "Set-Cookie",
    "Authorization",
)

_ERROR_CASES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    (
        "invalid_target",
        "Invalid target URL.",
        {"target": "http://[", "fetch_patch": None},
    ),
    (
        "timeout",
        "Request timed out.",
        {
            "target": "https://user:pass@example.com/?token=secret#frag",
            "fetch_side_effect": RequestTimeoutError(
                "DNS timeout secret.host errno 13 Traceback leaked"
            ),
        },
    ),
    (
        "connection",
        "Unable to reach the target.",
        {
            "target": "https://example.com",
            "fetch_side_effect": NetworkError(
                "Name or service not known: secret.internal errno 111"
            ),
        },
    ),
    (
        "tls",
        "TLS handshake or certificate verification failed.",
        {
            "target": "https://example.com",
            "fetch_side_effect": TLSError(
                "certificate verify failed: self signed certificate"
            ),
        },
    ),
    (
        "internal",
        "An internal error occurred.",
        {
            "target": "https://example.com",
            "fetch_side_effect": RuntimeError(
                "unexpected Set-Cookie leak Bearer xyz traceback"
            ),
        },
    ),
)


@pytest.fixture(scope="module")
def report_validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


@pytest.mark.parametrize(
    ("category", "public_message", "case"),
    _ERROR_CASES,
    ids=[case[0] for case in _ERROR_CASES],
)
def test_error_category_json_schema_contract(
    report_validator: Draft202012Validator,
    category: str,
    public_message: str,
    case: dict[str, Any],
) -> None:
    target = case["target"]
    side_effect = case.get("fetch_side_effect")

    if side_effect is None:
        report = run_scan(target)
    else:
        with patch("sentinelpy.scan.runner.fetch", side_effect=side_effect):
            report = run_scan(target)

    data = json.loads(render_json(report))
    serialized = json.dumps(data)

    report_validator.validate(data)
    assert data["scan_status"] == "error"
    assert data["findings"] == []
    assert data["summary"]["status"] == "error"
    assert data["error"] == {"category": category, "message": public_message}
    assert data["final_url"] is None
    assert data["http_status"] is None

    _assert_forbidden_absent(serialized)


def _assert_forbidden_absent(serialized: str) -> None:
    lowered = serialized.lower()
    for marker in _FORBIDDEN:
        assert marker.lower() not in lowered
