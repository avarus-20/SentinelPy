"""Aggregate finding outcomes into report summaries."""

from __future__ import annotations

from sentinelpy.models.finding import Finding
from sentinelpy.models.report import ScanSummary, SummaryCounts


def summarize_findings(findings: tuple[Finding, ...]) -> ScanSummary:
    """Compute summary status and counts from findings."""

    pass_count = 0
    warning = 0
    fail = 0
    error = 0

    for finding in findings:
        if finding.status == "pass":
            pass_count += 1
        elif finding.status == "warning":
            warning += 1
        elif finding.status == "fail":
            fail += 1
        elif finding.status == "error":
            error += 1

    counts = SummaryCounts(
        pass_count=pass_count,
        warning=warning,
        fail=fail,
        error=error,
        info=0,
    )

    if fail > 0:
        status = "failed"
    elif warning > 0:
        status = "warning"
    elif error > 0:
        status = "error"
    else:
        status = "passed"

    return ScanSummary(status=status, counts=counts)
