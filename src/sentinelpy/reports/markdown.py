"""Markdown report rendering."""

from __future__ import annotations

from sentinelpy.models.report import ScanReport


def render_markdown(report: ScanReport) -> str:
    """Render a Markdown report suitable for issues and PRs."""

    counts = report.summary.counts
    lines = [
        "# SentinelPy scan report",
        "",
        "> Authorized, read-only header configuration review. "
        "This is not a guarantee that the target is secure.",
        "",
        "## Executive summary",
        "",
        f"- **Summary status:** `{report.summary.status}`",
        f"- **Scan status:** `{report.scan_status}`",
        (
            f"- **Findings:** pass={counts.pass_count}, "
            f"warning={counts.warning}, fail={counts.fail}, error={counts.error}"
        ),
        "",
        "## Target information",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Target URL | {report.target_url} |",
        f"| Final URL | {report.final_url} |",
        f"| HTTP status | {report.http_status} |",
        f"| Elapsed (ms) | {report.elapsed_ms:.1f} |",
        "",
        "## Findings",
        "",
        "| ID | Status | Severity | Title |",
        "| --- | --- | --- | --- |",
    ]
    for finding in report.findings:
        row = (
            f"| {finding.id} | {finding.status} | "
            f"{finding.severity} | {finding.title} |"
        )
        lines.append(row)

    if report.findings:
        lines.extend(["", "## Finding details", ""])
        for finding in report.findings:
            lines.extend(
                [
                    f"### {finding.id} — {finding.title}",
                    "",
                    f"- **Status:** {finding.status}",
                    f"- **Severity:** {finding.severity}",
                    f"- **Explanation:** {finding.explanation}",
                    f"- **Remediation:** {finding.remediation}",
                    f"- **Reference:** {finding.reference}",
                    "",
                ]
            )

    if report.redirects:
        lines.extend(["## Redirects", ""])
        for hop in report.redirects:
            lines.append(f"- `{hop.status}` {hop.from_url} → {hop.to_url}")
        lines.append("")

    lines.extend(["## Scope and limitations", ""])
    for item in report.limitations:
        lines.append(f"- {item}")

    lines.extend(
        [
            "",
            "## Disclaimer",
            "",
            report.disclaimer,
            "",
        ]
    )
    return "\n".join(lines)
