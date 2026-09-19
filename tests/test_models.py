import json

from sentinelpy.models.finding import Finding
from sentinelpy.models.report import (
    ScanErrorInfo,
    ScanReport,
    ScanSummary,
    SummaryCounts,
    default_disclaimer,
)
from sentinelpy.models.schema import REPORT_SCHEMA_VERSION


def test_manual_scan_report_serialization_has_no_header_map():
    report = ScanReport(
        report_schema_version=REPORT_SCHEMA_VERSION,
        tool_name="sentinelpy",
        tool_version="0.1.0",
        scanned_at="2026-09-19T08:00:00Z",
        target_url="https://example.com/",
        scan_status="error",
        final_url=None,
        http_status=None,
        redirects=(),
        elapsed_ms=0.0,
        findings=(),
        summary=ScanSummary(
            status="error",
            counts=SummaryCounts(),
        ),
        limitations=("Example limitation.",),
        disclaimer=default_disclaimer(),
        error=ScanErrorInfo(
            category="connection",
            message="Unable to reach the target.",
        ),
    )

    payload = report.to_dict()
    serialized = json.dumps(payload)

    assert "response_headers" not in payload
    assert "headers" not in payload
    assert "Set-Cookie" not in serialized
    assert "Unable to reach target:" not in serialized


def test_finding_evidence_is_copied_safely():
    finding = Finding(
        id="HEADER-CSP-PRESENT",
        title="Content-Security-Policy is present",
        severity="info",
        status="pass",
        evidence={"header_name": "Content-Security-Policy", "observed": "present"},
        explanation="Example.",
        remediation="No change required.",
        reference="https://owasp.org/www-project-secure-headers/",
    )

    finding_dict = finding.to_dict()
    finding_dict["evidence"]["observed"] = "tampered"

    assert finding.to_dict()["evidence"]["observed"] == "present"
