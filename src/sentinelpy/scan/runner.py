"""Public scan orchestration."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelpy._version import __version__
from sentinelpy.checks.presence import evaluate_presence_findings
from sentinelpy.exceptions import (
    InvalidTargetError,
    NetworkError,
    RequestTimeoutError,
    TLSError,
)
from sentinelpy.http.client import FetchOptions, fetch
from sentinelpy.http.snapshot import SecurityHeaderSnapshot
from sentinelpy.http.url import normalize_url, target_scheme
from sentinelpy.models.report import (
    ErrorCategory,
    ScanErrorInfo,
    ScanReport,
    ScanSummary,
    SummaryCounts,
    default_disclaimer,
)
from sentinelpy.models.schema import REPORT_SCHEMA_VERSION
from sentinelpy.redaction.url import redact_url
from sentinelpy.scan.options import ScanOptions
from sentinelpy.scan.summary import summarize_findings

_LIMITATIONS: tuple[str, ...] = (
    "Single HTTP GET to one URL; redirects are recorded but not crawled.",
    "Only five selected response headers are evaluated for presence.",
    "Absence or presence of a header is not a complete security assessment.",
    "Does not inspect HTML, cookies, JavaScript, or server-side logic.",
    "Use only on systems you own or are explicitly authorized to test.",
)


def run_scan(target: str, *, options: ScanOptions | None = None) -> ScanReport:
    """
    Perform an authorized, read-only header scan and return a safe report.

    The report never includes raw response headers or sensitive values.
    """

    opts = options or ScanOptions()
    scanned_at = _utc_timestamp()

    try:
        normalized = normalize_url(target)
    except InvalidTargetError:
        return _error_report(
            scanned_at=scanned_at,
            target_url=None,
            category="invalid_target",
            message="Invalid target URL.",
            elapsed_ms=0.0,
        )

    target_redacted = redact_url(normalized)
    fetch_options = FetchOptions(
        timeout=opts.timeout,
        user_agent=opts.user_agent,
        follow_redirects=opts.follow_redirects,
    )

    try:
        response = fetch(normalized, options=fetch_options)
    except InvalidTargetError:
        return _error_report(
            scanned_at=scanned_at,
            target_url=target_redacted,
            category="invalid_target",
            message="Invalid target URL.",
            elapsed_ms=0.0,
        )
    except RequestTimeoutError:
        return _error_report(
            scanned_at=scanned_at,
            target_url=target_redacted,
            category="timeout",
            message="Request timed out.",
            elapsed_ms=0.0,
        )
    except TLSError:
        return _error_report(
            scanned_at=scanned_at,
            target_url=target_redacted,
            category="tls",
            message="TLS handshake or certificate verification failed.",
            elapsed_ms=0.0,
        )
    except NetworkError:
        return _error_report(
            scanned_at=scanned_at,
            target_url=target_redacted,
            category="connection",
            message="Unable to reach the target.",
            elapsed_ms=0.0,
        )
    except Exception:
        return _error_report(
            scanned_at=scanned_at,
            target_url=target_redacted,
            category="internal",
            message="An internal error occurred.",
            elapsed_ms=0.0,
        )

    snapshot = SecurityHeaderSnapshot.from_header_map(response.headers)
    scheme = target_scheme(normalized)
    findings = evaluate_presence_findings(snapshot, target_scheme=scheme)
    summary = summarize_findings(findings)

    return ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version=__version__,
        scanned_at=scanned_at,
        target_url=response.target_url,
        scan_status="completed",
        final_url=response.final_url,
        http_status=response.status,
        redirects=response.redirects,
        elapsed_ms=response.elapsed_ms,
        findings=findings,
        summary=summary,
        limitations=_LIMITATIONS,
        disclaimer=default_disclaimer(),
        error=None,
    )


def _error_report(
    *,
    scanned_at: str,
    target_url: str | None,
    category: ErrorCategory,
    message: str,
    elapsed_ms: float,
) -> ScanReport:
    return ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version=__version__,
        scanned_at=scanned_at,
        target_url=target_url,
        scan_status="error",
        final_url=None,
        http_status=None,
        redirects=(),
        elapsed_ms=elapsed_ms,
        findings=(),
        summary=ScanSummary(status="error", counts=SummaryCounts()),
        limitations=_LIMITATIONS,
        disclaimer=default_disclaimer(),
        error=ScanErrorInfo(category=category, message=message),
    )


def _utc_timestamp() -> str:
    return (
        datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
