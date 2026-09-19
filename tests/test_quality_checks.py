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


def test_hsts_include_subdomains_only_is_not_pass():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"Strict-Transport-Security": "includeSubDomains"}
    )
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    hsts = next(item for item in findings if item.id == "HEADER-HSTS")
    assert hsts.status == "warning"


def test_hsts_max_age_with_leading_zeros_is_not_disable():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"Strict-Transport-Security": "max-age=0123"}
    )
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    hsts = next(item for item in findings if item.id == "HEADER-HSTS")
    assert hsts.status == "pass"


def test_xfo_invalid_value_is_warning():
    snapshot = SecurityHeaderSnapshot.from_header_map({"X-Frame-Options": "INVALID"})
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    xfo = next(item for item in findings if item.id == "HEADER-XFO")
    assert xfo.status == "warning"


def test_csp_host_named_unsafe_inline_is_pass():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"Content-Security-Policy": "default-src https://unsafe-inline.example"}
    )
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    csp = next(item for item in findings if item.id == "HEADER-CSP")
    assert csp.status == "pass"


def test_referrer_policy_unknown_value_is_warning():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"Referrer-Policy": "not-a-real-policy"}
    )
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    rp = next(item for item in findings if item.id == "HEADER-RP")
    assert rp.status == "warning"


def test_referrer_policy_uses_last_recognized_token():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"Referrer-Policy": "unsafe-url, no-referrer"}
    )
    findings = evaluate_security_findings(snapshot, target_scheme="https")
    rp = next(item for item in findings if item.id == "HEADER-RP")
    assert rp.status == "pass"
