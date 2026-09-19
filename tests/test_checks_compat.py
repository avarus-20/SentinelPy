import warnings

from sentinelpy.checks import evaluate_presence_findings, evaluate_security_findings
from sentinelpy.http.snapshot import SecurityHeaderSnapshot


def test_checks_module_exports_presence_helper_with_deprecation():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"X-Content-Type-Options": "nosniff"}
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        findings = evaluate_presence_findings(snapshot, target_scheme="https")

    assert len(findings) == 5
    assert any(item.id == "HEADER-XCTO-PRESENT" for item in findings)
    assert any(
        issubclass(item.category, DeprecationWarning)
        and "evaluate_presence_findings" in str(item.message)
        for item in caught
    )


def test_checks_module_exports_quality_helper_without_deprecation():
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"X-Content-Type-Options": "nosniff"}
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        findings = evaluate_security_findings(snapshot, target_scheme="https")

    assert len(findings) == 5
    assert any(item.id == "HEADER-XCTO" for item in findings)
    assert not any(issubclass(item.category, DeprecationWarning) for item in caught)
