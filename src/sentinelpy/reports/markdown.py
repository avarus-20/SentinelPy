"""Markdown report rendering."""

from __future__ import annotations

from sentinelpy.models.report import ScanReport


def render_markdown(report: ScanReport) -> str:
    """Render a Markdown report suitable for issues and PRs."""

    lines = [
        "# SentinelPy scan report",
        "",
        "## Executive summary",
        "",
        f"- **Summary status:** `{report.summary.status}`",
        f"- **Scan status:** `{report.scan_status}`",
        (
            f"- **Counts:** pass={report.summary.counts.pass_count}, "
            f"warning={report.summary.counts.warning}, "
            f"fail={report.summary.counts.fail}"
        ),
        "",
        "## Target information",
        "",
        f"- **Target URL:** {report.target_url}",
        f"- **Final URL:** {report.final_url}",
        f"- **HTTP status:** {report.http_status}",
        f"- **Elapsed (ms):** {report.elapsed_ms}",
        "",
        "## Findings",
        "",
        "| ID | Status | Severity | Title |",
        "| --- | --- | --- | --- |",
    ]
    for finding in report.findings:
        lines.append(
            f"| {finding.id} | {finding.status} | {finding.severity} | {finding.title} |"
        )
    lines.extend(["", "## Scope and limitations", ""])
    for item in report.limitations:
        lines.append(f"- {item}")
    lines.extend(["", "## Disclaimer", "", report.disclaimer, ""])
    return "\n".join(lines)
