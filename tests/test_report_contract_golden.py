"""Golden JSON fixtures for the public report contract."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from sentinelpy.cli import exit_codes
from sentinelpy.cli.scan_cmd import run_scan_command
from sentinelpy.models.http_meta import HttpResponse, RedirectHop
from sentinelpy.models.report import (
    ScanErrorInfo,
    ScanReport,
    ScanSummary,
    SummaryCounts,
    default_disclaimer,
)
from sentinelpy.models.schema import REPORT_SCHEMA_VERSION
from sentinelpy.reports.json import render_json
from sentinelpy.scan.runner import run_scan

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "report-schema-1.0.0.json"
_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "reports"
_FIXED_SCANNED_AT = "2026-09-19T12:00:00Z"
_DOCS_CI = Path(__file__).resolve().parents[1] / "docs" / "ci-github-actions.md"
_README = Path(__file__).resolve().parents[1] / "README.md"
_GHA_EXAMPLE = (
    Path(__file__).resolve().parents[1] / "examples" / "github-actions-sentinelpy.yml"
)

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


def _http_response(
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    target: str = "https://example.com/",
    final: str | None = None,
    redirects: tuple[RedirectHop, ...] = (),
) -> HttpResponse:
    resolved_final = final if final is not None else target
    scheme = "http" if resolved_final.lower().startswith("http://") else "https"
    return HttpResponse(
        target_url=target,
        final_url=resolved_final,
        final_scheme=scheme,
        status=status,
        headers=headers or {},
        redirects=redirects,
        elapsed_ms=12.5,
    )


def _render_completed(
    response: HttpResponse,
    target: str = "https://example.com",
) -> dict[str, Any]:
    with patch("sentinelpy.scan.runner._utc_timestamp", return_value=_FIXED_SCANNED_AT):
        with patch("sentinelpy.scan.runner.fetch", return_value=response):
            return json.loads(render_json(run_scan(target)))


def _render_error(target: str) -> dict[str, Any]:
    with patch("sentinelpy.scan.runner._utc_timestamp", return_value=_FIXED_SCANNED_AT):
        return json.loads(render_json(run_scan(target)))


def _builders() -> dict[str, Callable[[], dict[str, Any]]]:
    return {
        "completed-passed-200.json": lambda: _render_completed(
            _http_response(headers=_ALL_PASS_HEADERS)
        ),
        "completed-warning-http.json": lambda: _render_completed(
            _http_response(
                target="http://example.com/",
                headers={
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                },
            ),
            target="http://example.com",
        ),
        "completed-failed-https.json": lambda: _render_completed(
            _http_response(headers={"Referrer-Policy": "no-referrer"})
        ),
        "completed-404.json": lambda: _render_completed(
            _http_response(status=404, headers={"Referrer-Policy": "no-referrer"})
        ),
        "completed-multi-redirect.json": lambda: _render_completed(
            _http_response(
                headers=_ALL_PASS_HEADERS,
                final="https://example.com/b",
                redirects=(
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
            )
        ),
        "error-invalid-target.json": lambda: _render_error("http://["),
    }


def _cli_args(target_url: str) -> argparse.Namespace:
    return argparse.Namespace(
        target_url=target_url,
        format="json",
        output=None,
        timeout=10.0,
        user_agent=None,
        no_redirects=False,
        no_color=False,
    )


@pytest.mark.parametrize("fixture_name", sorted(_builders().keys()))
def test_golden_fixture_validates_against_schema(
    report_validator: Draft202012Validator,
    fixture_name: str,
) -> None:
    data = json.loads((_FIXTURES_DIR / fixture_name).read_text(encoding="utf-8"))
    report_validator.validate(data)
    assert data["report_schema_version"] == "1.0.0"
    assert data["tool_name"] == "sentinelpy"


@pytest.mark.parametrize("fixture_name", sorted(_builders().keys()))
def test_golden_fixture_matches_live_renderer(fixture_name: str) -> None:
    expected = json.loads((_FIXTURES_DIR / fixture_name).read_text(encoding="utf-8"))
    actual = _builders()[fixture_name]()
    assert actual == expected


def test_documented_exit_codes_match_cli_constants() -> None:
    combined = _DOCS_CI.read_text(encoding="utf-8") + _README.read_text(
        encoding="utf-8"
    )
    for code in (
        exit_codes.EXIT_OK,
        exit_codes.EXIT_FINDINGS_FAILED,
        exit_codes.EXIT_USAGE,
        exit_codes.EXIT_SCAN_ERROR,
    ):
        assert f"| `{code}`" in combined


def test_github_actions_example_documents_artifacts_and_exit_codes() -> None:
    content = _GHA_EXAMPLE.read_text(encoding="utf-8")
    assert "sentinelpy scan" in content
    assert "--format json" in content
    assert "--format markdown" in content
    assert "upload-artifact" in content
    assert "exit code" in content.lower()


def test_ci_doc_links_schema_and_golden_fixtures() -> None:
    doc = _DOCS_CI.read_text(encoding="utf-8")
    assert "report-schema-1.0.0.json" in doc
    assert "tests/fixtures/reports" in doc
    assert re.search(r"exit code.*`0`", doc, re.IGNORECASE)


def test_ci_doc_snippet_fails_on_exit_codes_two_and_three() -> None:
    doc = _DOCS_CI.read_text(encoding="utf-8")
    assert "exit_code == '2'" in doc
    assert "exit_code == '3'" in doc


def test_cli_exit_code_invalid_target_is_usage() -> None:
    assert run_scan_command(_cli_args("http://[")) == exit_codes.EXIT_USAGE


def test_cli_exit_code_failed_findings() -> None:
    report = ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version="1.3.0",
        scanned_at=_FIXED_SCANNED_AT,
        target_url="https://example.com/",
        scan_status="completed",
        final_url="https://example.com/",
        http_status=200,
        redirects=(),
        elapsed_ms=1.0,
        findings=(),
        summary=ScanSummary(
            status="failed",
            counts=SummaryCounts(fail=1),
        ),
        limitations=("limit",),
        disclaimer=default_disclaimer(),
        error=None,
    )
    with patch("sentinelpy.cli.scan_cmd.run_scan", return_value=report):
        assert run_scan_command(_cli_args("https://example.com")) == (
            exit_codes.EXIT_FINDINGS_FAILED
        )


def test_cli_exit_code_scan_error_non_invalid() -> None:
    report = ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version="1.3.0",
        scanned_at=_FIXED_SCANNED_AT,
        target_url="https://example.com/",
        scan_status="error",
        final_url=None,
        http_status=None,
        redirects=(),
        elapsed_ms=0.0,
        findings=(),
        summary=ScanSummary(status="error", counts=SummaryCounts()),
        limitations=("limit",),
        disclaimer=default_disclaimer(),
        error=ScanErrorInfo(category="timeout", message="Request timed out."),
    )
    with patch("sentinelpy.cli.scan_cmd.run_scan", return_value=report):
        assert run_scan_command(_cli_args("https://example.com")) == (
            exit_codes.EXIT_SCAN_ERROR
        )
