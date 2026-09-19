import json

from sentinelpy.models.finding import Finding
from sentinelpy.models.report import (
    ScanReport,
    ScanSummary,
    SummaryCounts,
    default_disclaimer,
)
from sentinelpy.models.schema import REPORT_SCHEMA_VERSION
from sentinelpy.redaction.evidence import EvidenceBuilder
from sentinelpy.redaction.url import redact_url


def test_evidence_builder_never_serializes_sensitive_values():
    evidence = EvidenceBuilder.for_presence(
        "Set-Cookie",
        present=True,
        raw_value="session=super-secret",
    ).to_dict()

    serialized = json.dumps(evidence)

    assert "super-secret" not in serialized
    assert "session=" not in serialized


def test_manual_report_dict_never_contains_raw_header_map():
    finding = Finding(
        id="HEADER-CSP-PRESENT",
        title="Example",
        severity="info",
        status="pass",
        evidence=EvidenceBuilder.for_presence(
            "Content-Security-Policy",
            present=True,
            raw_value="default-src 'self'",
        ).to_dict(),
        explanation="Example.",
        remediation="Example.",
        reference="https://owasp.org/www-project-secure-headers/",
    )
    report = ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version="0.1.0",
        scanned_at="2026-09-19T08:00:00Z",
        target_url=redact_url("https://example.com/path?token=secret"),
        scan_status="completed",
        final_url=redact_url("https://user:pass@example.com/path?token=secret#frag"),
        http_status=500,
        redirects=(),
        elapsed_ms=10.0,
        findings=(finding,),
        summary=ScanSummary(
            status="failed",
            counts=SummaryCounts(fail=0, pass_count=1),
        ),
        limitations=("Limited single-request check.",),
        disclaimer=default_disclaimer(),
        error=None,
    )

    serialized = json.dumps(report.to_dict())

    assert "response_headers" not in serialized
    assert "super-secret-cookie" not in serialized
    assert "Bearer xyz" not in serialized
    assert "user:pass" not in serialized
    assert "token=secret" not in serialized
    assert "#frag" not in serialized
