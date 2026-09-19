from sentinelpy.checks.quality import evaluate_security_findings
from sentinelpy.http.snapshot import SecurityHeaderSnapshot


def test_csp_unsafe_inline_is_warning():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
    )
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    csp = next(item for item in findings if item.id == "HEADER-CSP")
    assert csp.status == "warning"


def test_xcto_requires_nosniff():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"X-Content-Type-Options": "invalid"}
    )
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    xcto = next(item for item in findings if item.id == "HEADER-XCTO")
    assert xcto.status == "warning"
