"""Presence-only checks for the five supported security headers."""

from __future__ import annotations

from sentinelpy.constants import SECURITY_HEADERS
from sentinelpy.http.snapshot import SecurityHeaderSnapshot
from sentinelpy.models.finding import Finding
from sentinelpy.redaction.evidence import EvidenceBuilder

_OSWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"

_HEADER_FIELD = {
    "Strict-Transport-Security": "strict_transport_security",
    "Content-Security-Policy": "content_security_policy",
    "X-Content-Type-Options": "x_content_type_options",
    "X-Frame-Options": "x_frame_options",
    "Referrer-Policy": "referrer_policy",
}

_FINDING_ID = {
    "Strict-Transport-Security": "HEADER-HSTS-PRESENT",
    "Content-Security-Policy": "HEADER-CSP-PRESENT",
    "X-Content-Type-Options": "HEADER-XCTO-PRESENT",
    "X-Frame-Options": "HEADER-XFO-PRESENT",
    "Referrer-Policy": "HEADER-RP-PRESENT",
}


def evaluate_presence_findings(
    snapshot: SecurityHeaderSnapshot,
    *,
    target_scheme: str,
) -> tuple[Finding, ...]:
    """Return exactly five presence findings (honest pass/fail/warning only)."""

    findings: list[Finding] = []
    for header in SECURITY_HEADERS:
        value = getattr(snapshot, _HEADER_FIELD[header])
        present = value is not None
        if header == "Strict-Transport-Security":
            findings.append(_hsts_finding(present, value, target_scheme))
        else:
            findings.append(_standard_presence_finding(header, present, value))
    return tuple(findings)


def _standard_presence_finding(
    header: str,
    present: bool,
    raw_value: str | None,
) -> Finding:
    if present:
        return Finding(
            id=_FINDING_ID[header],
            title=f"{header} header is present",
            severity="info",
            status="pass",
            evidence=EvidenceBuilder.for_presence(
                header,
                present=True,
                raw_value=raw_value,
            ).to_dict(),
            explanation=(
                f"The response included the {header} header. "
                "Presence alone does not confirm optimal configuration."
            ),
            remediation="No change required for presence-only review.",
            reference=_OSWASP_HEADERS,
        )

    return Finding(
        id=_FINDING_ID[header],
        title=f"{header} header is missing",
        severity="medium",
        status="fail",
        evidence=EvidenceBuilder.for_presence(
            header,
            present=False,
            raw_value=None,
        ).to_dict(),
        explanation=(
            f"The response did not include the {header} header. "
            "This is a configuration signal for authorized review."
        ),
        remediation=(
            f"Configure the site or CDN to send {header} on applicable responses."
        ),
        reference=_OSWASP_HEADERS,
    )


def _hsts_finding(
    present: bool,
    raw_value: str | None,
    target_scheme: str,
) -> Finding:
    if target_scheme == "https":
        if present:
            return Finding(
                id="HEADER-HSTS-PRESENT",
                title="Strict-Transport-Security header is present",
                severity="info",
                status="pass",
                evidence=EvidenceBuilder.for_presence(
                    "Strict-Transport-Security",
                    present=True,
                    raw_value=raw_value,
                ).to_dict(),
                explanation=(
                    "The HTTPS response included Strict-Transport-Security (HSTS)."
                ),
                remediation="No change required for presence-only review.",
                reference=_OSWASP_HEADERS,
            )
        return Finding(
            id="HEADER-HSTS-PRESENT",
            title="Strict-Transport-Security header is missing",
            severity="medium",
            status="fail",
            evidence=EvidenceBuilder.for_presence(
                "Strict-Transport-Security",
                present=False,
                raw_value=None,
            ).to_dict(),
            explanation=(
                "The HTTPS response did not include HSTS. "
                "Browsers enforce HSTS only on HTTPS responses."
            ),
            remediation=(
                "Send Strict-Transport-Security with an appropriate max-age "
                "on HTTPS responses."
            ),
            reference=_OSWASP_HEADERS,
        )

    if present:
        evidence = {
            "header_name": "Strict-Transport-Security",
            "observed": "present_ignored_over_http",
        }
        if raw_value is not None:
            excerpt = EvidenceBuilder.for_presence(
                "Strict-Transport-Security",
                present=True,
                raw_value=raw_value,
            ).to_dict()
            if "header_value_excerpt" in excerpt:
                evidence["header_value_excerpt"] = excerpt["header_value_excerpt"]
        explanation = (
            "HSTS was present on an HTTP response, but browsers ignore HSTS "
            "delivered over cleartext HTTP (RFC 6797). Assess HSTS on HTTPS."
        )
    else:
        evidence = {
            "header_name": "Strict-Transport-Security",
            "observed": "not_applicable_over_http",
        }
        explanation = (
            "HSTS is not applicable as a failure on HTTP because browsers "
            "ignore HSTS on cleartext responses. Scan the HTTPS URL to assess HSTS."
        )

    return Finding(
        id="HEADER-HSTS-PRESENT",
        title="Strict-Transport-Security (HTTP target advisory)",
        severity="info",
        status="warning",
        evidence=evidence,
        explanation=explanation,
        remediation="Repeat the scan against the site's HTTPS URL to assess HSTS.",
        reference=_OSWASP_HEADERS,
    )
