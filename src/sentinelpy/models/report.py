"""Scan report model types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sentinelpy.models.finding import Finding
from sentinelpy.models.http_meta import RedirectHop
from sentinelpy.models.schema import REPORT_SCHEMA_VERSION

ScanStatus = Literal["completed", "error"]
SummaryStatus = Literal["passed", "warning", "failed", "error"]
ErrorCategory = Literal[
    "invalid_target",
    "timeout",
    "connection",
    "tls",
    "internal",
]


@dataclass(frozen=True, slots=True)
class ScanErrorInfo:
    """Safe, catalog-based error details."""

    category: ErrorCategory
    message: str

    def to_dict(self) -> dict[str, str]:
        """Serialize the error object."""

        return {
            "category": self.category,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class SummaryCounts:
    """Finding counts grouped by status."""

    pass_count: int = 0
    warning: int = 0
    fail: int = 0
    error: int = 0
    info: int = 0

    def to_dict(self) -> dict[str, int]:
        """Serialize summary counts."""

        return {
            "pass": self.pass_count,
            "warning": self.warning,
            "fail": self.fail,
            "error": self.error,
            "info": self.info,
        }


@dataclass(frozen=True, slots=True)
class ScanSummary:
    """High-level scan outcome."""

    status: SummaryStatus
    counts: SummaryCounts

    def to_dict(self) -> dict[str, object]:
        """Serialize the summary block."""

        return {
            "status": self.status,
            "counts": self.counts.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    """
    Structured scan report.

    Public reports must never include raw response header maps. This type is
    constructed manually in tests during v0.2.0a; orchestration arrives in
    v0.2.0b.
    """

    report_schema_version: str
    tool_name: str
    tool_version: str
    scanned_at: str
    target_url: str | None
    scan_status: ScanStatus
    final_url: str | None
    http_status: int | None
    redirects: tuple[RedirectHop, ...]
    elapsed_ms: float
    findings: tuple[Finding, ...]
    summary: ScanSummary
    limitations: tuple[str, ...]
    disclaimer: str
    error: ScanErrorInfo | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the report using only safe, typed fields."""

        return {
            "report_schema_version": self.report_schema_version,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "scanned_at": self.scanned_at,
            "target_url": self.target_url,
            "scan_status": self.scan_status,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "redirects": [hop.to_dict() for hop in self.redirects],
            "elapsed_ms": self.elapsed_ms,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": self.summary.to_dict(),
            "limitations": list(self.limitations),
            "disclaimer": self.disclaimer,
            "error": None if self.error is None else self.error.to_dict(),
        }


def default_disclaimer() -> str:
    """Return the standard authorized-use disclaimer."""

    return (
        "Authorized, read-only assessment of HTTP response headers. "
        "This report does not guarantee that the target is secure."
    )


def empty_report_template() -> dict[str, object]:
    """Expose the report schema version constant for tests."""

    return {"report_schema_version": REPORT_SCHEMA_VERSION}
