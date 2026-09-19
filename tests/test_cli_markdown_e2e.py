"""End-to-end CLI tests for Markdown report output."""

from __future__ import annotations

from unittest.mock import patch

from sentinelpy.cli.app import main
from sentinelpy.cli.exit_codes import EXIT_OK
from sentinelpy.models.http_meta import HttpResponse

_FORBIDDEN = (
    "super-secret-cookie",
    "Bearer xyz",
    "session=",
    "user:pass",
    "token=secret",
    "#frag",
    "Traceback (most recent call last)",
    "ValueError:",
    "report-uri https://",
    "nonce-abc123secret",
)


def test_cli_markdown_stdout_includes_report_sections(capsys):
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_safe_http_response(),
    ):
        code = main(
            [
                "scan",
                "https://user:pass@example.com/?token=secret#frag",
                "--format",
                "markdown",
            ]
        )

    assert code == EXIT_OK
    text = capsys.readouterr().out
    _assert_markdown_structure(text)
    _assert_no_secrets(text)


def test_cli_markdown_output_file_includes_report_sections(tmp_path):
    output_path = tmp_path / "report.md"
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_safe_http_response(),
    ):
        code = main(
            [
                "scan",
                "https://user:pass@example.com/?token=secret#frag",
                "--format",
                "markdown",
                "--output",
                str(output_path),
            ]
        )

    assert code == EXIT_OK
    text = output_path.read_text(encoding="utf-8")
    _assert_markdown_structure(text)
    _assert_no_secrets(text)


def test_cli_json_unaffected_by_no_color_flag(capsys):
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_safe_http_response(),
    ):
        main(["scan", "https://example.com", "--format", "json"])
        plain = capsys.readouterr().out
        main(
            [
                "scan",
                "https://example.com",
                "--format",
                "json",
                "--no-color",
            ]
        )
        with_flag = capsys.readouterr().out

    assert plain == with_flag


def _safe_http_response() -> HttpResponse:
    return HttpResponse(
        target_url="https://[REDACTED]@example.com/?token=[REDACTED]",
        final_url="https://example.com/",
        final_scheme="https",
        status=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": (
                "default-src 'self'; report-uri https://x.com/?token=secret; "
                "script-src 'nonce-abc123secret'"
            ),
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Set-Cookie": "session=super-secret-cookie",
            "Authorization": "Bearer xyz",
        },
        redirects=(),
        elapsed_ms=2.5,
    )


def _assert_markdown_structure(text: str) -> None:
    assert "# SentinelPy scan report" in text
    assert "## Executive summary" in text
    assert "## Findings" in text
    assert "HEADER-HSTS" in text
    assert "## Scope and limitations" in text
    assert "## Disclaimer" in text


def _assert_no_secrets(text: str) -> None:
    lowered = text.lower()
    for marker in _FORBIDDEN:
        assert marker.lower() not in lowered
