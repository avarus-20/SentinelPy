"""``scan`` subcommand implementation."""

from __future__ import annotations

import argparse
import sys

from sentinelpy.models.report import ScanReport
from sentinelpy.reports.json import render_json
from sentinelpy.reports.markdown import render_markdown
from sentinelpy.reports.terminal import render_terminal
from sentinelpy.scan import ScanOptions, run_scan

_FORMATS = frozenset({"terminal", "json", "markdown"})


def add_scan_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the scan subcommand."""

    parser = subparsers.add_parser(
        "scan",
        help="Scan one URL for selected HTTP security headers.",
    )
    parser.add_argument("target_url", help="Target URL or hostname")
    parser.add_argument(
        "--format",
        choices=sorted(_FORMATS),
        default="terminal",
        help="Report format (default: terminal)",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="output",
        help="Write report to this file instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--user-agent",
        default=None,
        help="Custom User-Agent header",
    )
    parser.add_argument(
        "--no-redirects",
        action="store_true",
        help="Do not follow HTTP redirects",
    )
    parser.set_defaults(handler=run_scan_command)


def run_scan_command(args: argparse.Namespace) -> int:
    """Execute a scan from parsed CLI arguments."""

    from sentinelpy.cli.exit_codes import (
        EXIT_FINDINGS_FAILED,
        EXIT_OK,
        EXIT_SCAN_ERROR,
        EXIT_USAGE,
    )
    from sentinelpy.http.client import DEFAULT_USER_AGENT

    if args.timeout <= 0:
        _stderr("Error: --timeout must be greater than zero.")
        return EXIT_USAGE

    options = ScanOptions(
        timeout=args.timeout,
        user_agent=args.user_agent or DEFAULT_USER_AGENT,
        follow_redirects=not args.no_redirects,
    )

    try:
        report = run_scan(args.target_url, options=options)
    except Exception:
        _stderr("Error: An internal error occurred.")
        return EXIT_SCAN_ERROR

    use_color = args.output is None and sys.stdout.isatty()
    content = _render(report, args.format, use_color=use_color)
    if not _emit(content, args.output):
        return EXIT_SCAN_ERROR

    if report.scan_status == "error":
        if report.error is not None:
            _stderr(f"Error: {report.error.message}")
            if report.error.category == "invalid_target":
                return EXIT_USAGE
        return EXIT_SCAN_ERROR
    if report.summary.status == "failed":
        return EXIT_FINDINGS_FAILED
    return EXIT_OK


def _render(report: ScanReport, fmt: str, *, use_color: bool) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "markdown":
        return render_markdown(report)
    return render_terminal(report, use_color=use_color)


def _emit(content: str, output_path: str | None) -> bool:
    try:
        if output_path:
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(content)
                if not content.endswith("\n"):
                    handle.write("\n")
            return True
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
        return True
    except OSError as error:
        reason = error.strerror or str(error)
        _stderr(f"Error: Could not write report output ({reason}).")
        return False


def _stderr(message: str) -> None:
    sys.stderr.write(message + "\n")
