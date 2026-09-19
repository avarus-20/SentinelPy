import subprocess
import sys
from unittest.mock import patch

from sentinelpy.cli.app import main
from sentinelpy.cli.exit_codes import (
    EXIT_FINDINGS_FAILED,
    EXIT_OK,
    EXIT_SCAN_ERROR,
    EXIT_USAGE,
)


def _run_cli(*args: str) -> int:
    return main(list(args))


def test_cli_without_command_exits_usage():
    assert _run_cli() == EXIT_USAGE


def test_cli_version_exits_ok(capsys):
    with patch("sys.argv", ["sentinelpy", "--version"]):
        try:
            main(["--version"])
        except SystemExit as exc:
            assert exc.code == 0


def test_cli_scan_json_stdout_only_json():
    with patch(
        "sentinelpy.cli.scan_cmd.run_scan",
        return_value=_completed_report(failed=False),
    ):
        code = _run_cli("scan", "https://example.com", "--format", "json")

    assert code == EXIT_OK


def test_cli_scan_failed_findings_exit_one():
    with patch(
        "sentinelpy.cli.scan_cmd.run_scan",
        return_value=_completed_report(failed=True),
    ):
        code = _run_cli("scan", "https://example.com")

    assert code == EXIT_FINDINGS_FAILED


def test_cli_invalid_target_exit_usage():
    from sentinelpy.models.report import (
        ScanErrorInfo,
        ScanReport,
        ScanSummary,
        SummaryCounts,
        default_disclaimer,
    )
    from sentinelpy.models.schema import REPORT_SCHEMA_VERSION

    report = ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version="1.2.1",
        scanned_at="2026-09-19T08:00:00Z",
        target_url=None,
        scan_status="error",
        final_url=None,
        http_status=None,
        redirects=(),
        elapsed_ms=0.0,
        findings=(),
        summary=ScanSummary(status="error", counts=SummaryCounts()),
        limitations=("Limited check.",),
        disclaimer=default_disclaimer(),
        error=ScanErrorInfo(category="invalid_target", message="Invalid target URL."),
    )
    with patch("sentinelpy.cli.scan_cmd.run_scan", return_value=report):
        code = _run_cli("scan", "")

    assert code == EXIT_USAGE


def test_cli_scan_error_exit_three():
    from sentinelpy.models.report import (
        ScanErrorInfo,
        ScanReport,
        ScanSummary,
        SummaryCounts,
        default_disclaimer,
    )
    from sentinelpy.models.schema import REPORT_SCHEMA_VERSION

    report = ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version="1.2.1",
        scanned_at="2026-09-19T08:00:00Z",
        target_url="https://example.com/",
        scan_status="error",
        final_url=None,
        http_status=None,
        redirects=(),
        elapsed_ms=0.0,
        findings=(),
        summary=ScanSummary(status="error", counts=SummaryCounts()),
        limitations=("Limited check.",),
        disclaimer=default_disclaimer(),
        error=ScanErrorInfo(category="timeout", message="Request timed out."),
    )
    with patch("sentinelpy.cli.scan_cmd.run_scan", return_value=report):
        code = _run_cli("scan", "https://example.com")

    assert code == EXIT_SCAN_ERROR


def test_cli_scan_output_write_failure_returns_scan_error(tmp_path):
    missing = tmp_path / "missing" / "report.txt"
    with patch(
        "sentinelpy.cli.scan_cmd.run_scan",
        return_value=_completed_report(failed=False),
    ):
        code = _run_cli(
            "scan",
            "https://example.com",
            "--output",
            str(missing),
        )

    assert code == EXIT_SCAN_ERROR


def test_cli_terminal_no_color_disables_ansi_on_tty(capsys):
    with (
        patch(
            "sentinelpy.cli.scan_cmd.run_scan",
            return_value=_completed_report(failed=False),
        ),
        patch("sys.stdout.isatty", return_value=True),
    ):
        code = _run_cli("scan", "https://example.com", "--no-color")

    assert code == EXIT_OK
    assert "\x1b[" not in capsys.readouterr().out


def test_cli_terminal_tty_uses_color_without_no_color(capsys):
    with (
        patch(
            "sentinelpy.cli.scan_cmd.run_scan",
            return_value=_completed_report(failed=False),
        ),
        patch("sys.stdout.isatty", return_value=True),
    ):
        code = _run_cli("scan", "https://example.com")

    assert code == EXIT_OK
    assert "\x1b[" in capsys.readouterr().out


def test_cli_terminal_output_file_has_no_ansi(tmp_path):
    output_file = tmp_path / "report.txt"
    with (
        patch(
            "sentinelpy.cli.scan_cmd.run_scan",
            return_value=_completed_report(failed=False),
        ),
        patch("sys.stdout.isatty", return_value=True),
    ):
        code = _run_cli(
            "scan",
            "https://example.com",
            "--output",
            str(output_file),
        )

    assert code == EXIT_OK
    text = output_file.read_text(encoding="utf-8")
    assert "\x1b[" not in text


def test_module_entrypoint_lists_scan_command():
    result = subprocess.run(
        [sys.executable, "-m", "sentinelpy"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == EXIT_USAGE
    assert "scan" in result.stderr


def _completed_report(*, failed: bool):
    from sentinelpy.models.report import (
        ScanReport,
        ScanSummary,
        SummaryCounts,
        default_disclaimer,
    )
    from sentinelpy.models.schema import REPORT_SCHEMA_VERSION

    status = "failed" if failed else "passed"
    counts = SummaryCounts(fail=1 if failed else 0, pass_count=0 if failed else 1)
    return ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version="1.2.1",
        scanned_at="2026-09-19T08:00:00Z",
        target_url="https://example.com/",
        scan_status="completed",
        final_url="https://example.com/",
        http_status=200,
        redirects=(),
        elapsed_ms=1.0,
        findings=(),
        summary=ScanSummary(status=status, counts=counts),
        limitations=("Limited check.",),
        disclaimer=default_disclaimer(),
        error=None,
    )
