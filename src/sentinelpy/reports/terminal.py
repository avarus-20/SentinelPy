"""Terminal report rendering."""

from __future__ import annotations

import sys

from sentinelpy.models.report import ScanReport


def render_terminal(report: ScanReport) -> str:
    """Render a concise human-readable report."""

    use_color = sys.stdout.isatty()
    lines = [
        _style("SentinelPy scan report", "bold", use_color),
        f"Target: {report.target_url}",
        f"Status: {report.scan_status} / summary={report.summary.status}",
    ]
    if report.scan_status == "completed":
        lines.append(f"HTTP: {report.http_status}  Final URL: {report.final_url}")
        lines.append(f"Elapsed: {report.elapsed_ms:.1f} ms")
    if report.error is not None:
        lines.append(
            _style(
                f"Error: {report.error.message}",
                "red",
                use_color,
            )
        )
    lines.append("")
    lines.append(_style("Findings:", "bold", use_color))
    for finding in report.findings:
        marker = finding.status.upper()
        lines.append(f"  [{marker}] {finding.id}: {finding.title}")
    lines.append("")
    lines.append(report.disclaimer)
    return "\n".join(lines) + "\n"


def _style(text: str, kind: str, enabled: bool) -> str:
    if not enabled:
        return text
    codes = {
        "bold": "\033[1m",
        "red": "\033[31m",
    }
    reset = "\033[0m"
    return f"{codes.get(kind, '')}{text}{reset}"
