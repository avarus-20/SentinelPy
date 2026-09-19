"""Quality-aware checks for five supported security headers."""

from __future__ import annotations

import re

from sentinelpy.constants import SECURITY_HEADERS
from sentinelpy.http.snapshot import SecurityHeaderSnapshot
from sentinelpy.models.finding import Finding
from sentinelpy.redaction.evidence import EvidenceBuilder

_OSWASP = "https://owasp.org/www-project-secure-headers/"
_OWASP_CHEATSHEET = (
    "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
)
_RFC6797 = "https://datatracker.ietf.org/doc/html/rfc6797"


def evaluate_security_findings(
    snapshot: SecurityHeaderSnapshot,
    *,
    target_scheme: str,
) -> tuple[Finding, ...]:
    """Return five findings with conservative presence and quality assessment."""

    return (
        _hsts_finding(snapshot, target_scheme),
        _csp_finding(snapshot),
        _xcto_finding(snapshot),
        _xfo_finding(snapshot),
        _referrer_policy_finding(snapshot),
    )


def _hsts_finding(snapshot: SecurityHeaderSnapshot, target_scheme: str) -> Finding:
    value = snapshot.strict_transport_security
    if target_scheme == "http":
        if value is None:
            evidence = {
                "header_name": "Strict-Transport-Security",
                "observed": "not_applicable_over_http",
            }
            explanation = (
                "HSTS is not treated as a failure on HTTP because browsers "
                "ignore HSTS on cleartext responses (RFC 6797)."
            )
        else:
            evidence = {
                "header_name": "Strict-Transport-Security",
                "observed": "present_ignored_over_http",
            }
            excerpt = EvidenceBuilder.for_presence(
                "Strict-Transport-Security",
                present=True,
                raw_value=value,
            ).to_dict()
            if "header_value_excerpt" in excerpt:
                evidence["header_value_excerpt"] = excerpt["header_value_excerpt"]
            explanation = (
                "HSTS appeared on HTTP but browsers ignore it unless delivered over HTTPS."
            )
        return Finding(
            id="HEADER-HSTS",
            title="Strict-Transport-Security (HTTP advisory)",
            severity="info",
            status="warning",
            evidence=evidence,
            explanation=explanation,
            remediation="Scan the HTTPS URL to assess HSTS configuration.",
            reference=_RFC6797,
        )

    if value is None:
        return Finding(
            id="HEADER-HSTS",
            title="Strict-Transport-Security header is missing",
            severity="medium",
            status="fail",
            evidence=EvidenceBuilder.for_presence(
                "Strict-Transport-Security",
                present=False,
                raw_value=None,
            ).to_dict(),
            explanation="The HTTPS response did not include HSTS.",
            remediation=(
                "Send Strict-Transport-Security with an appropriate max-age on HTTPS responses."
            ),
            reference=_RFC6797,
        )

    lowered = value.lower()
    if "max-age=0" in lowered.replace(" ", ""):
        return Finding(
            id="HEADER-HSTS",
            title="Strict-Transport-Security disables HSTS (max-age=0)",
            severity="medium",
            status="warning",
            evidence=EvidenceBuilder.for_presence(
                "Strict-Transport-Security",
                present=True,
                raw_value=value,
            ).to_dict(),
            explanation="max-age=0 removes HSTS enforcement for the site.",
            remediation="Use a positive max-age if HSTS is intended.",
            reference=_RFC6797,
        )

    return Finding(
        id="HEADER-HSTS",
        title="Strict-Transport-Security header is present",
        severity="info",
        status="pass",
        evidence=EvidenceBuilder.for_presence(
            "Strict-Transport-Security",
            present=True,
            raw_value=value,
        ).to_dict(),
        explanation="HSTS is present on HTTPS. Review max-age and includeSubDomains separately.",
        remediation="No change required for basic presence review.",
        reference=_RFC6797,
    )


def _csp_finding(snapshot: SecurityHeaderSnapshot) -> Finding:
    value = snapshot.content_security_policy
    if value is None:
        return Finding(
            id="HEADER-CSP",
            title="Content-Security-Policy header is missing",
            severity="medium",
            status="fail",
            evidence=EvidenceBuilder.for_presence(
                "Content-Security-Policy",
                present=False,
                raw_value=None,
            ).to_dict(),
            explanation="The response did not include a Content-Security-Policy header.",
            remediation="Define a CSP appropriate for the application.",
            reference=_OWASP_CHEATSHEET,
        )

    lowered = value.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return Finding(
            id="HEADER-CSP",
            title="Content-Security-Policy allows unsafe directives",
            severity="low",
            status="warning",
            evidence=EvidenceBuilder.for_presence(
                "Content-Security-Policy",
                present=True,
                raw_value=value,
            ).to_dict(),
            explanation=(
                "The CSP contains unsafe-inline and/or unsafe-eval. "
                "This may weaken XSS protections depending on context."
            ),
            remediation="Prefer nonces or hashes instead of unsafe directives where feasible.",
            reference=_OWASP_CHEATSHEET,
        )

    return Finding(
        id="HEADER-CSP",
        title="Content-Security-Policy header is present",
        severity="info",
        status="pass",
        evidence=EvidenceBuilder.for_presence(
            "Content-Security-Policy",
            present=True,
            raw_value=value,
        ).to_dict(),
        explanation="A CSP is present. Full policy review is outside this tool's scope.",
        remediation="No change required for basic presence review.",
        reference=_OWASP_CHEATSHEET,
    )


def _xcto_finding(snapshot: SecurityHeaderSnapshot) -> Finding:
    value = snapshot.x_content_type_options
    if value is None:
        return Finding(
            id="HEADER-XCTO",
            title="X-Content-Type-Options header is missing",
            severity="medium",
            status="fail",
            evidence=EvidenceBuilder.for_presence(
                "X-Content-Type-Options",
                present=False,
                raw_value=None,
            ).to_dict(),
            explanation="Missing X-Content-Type-Options may allow MIME sniffing.",
            remediation='Set X-Content-Type-Options: nosniff on applicable responses.',
            reference=_OWASP_CHEATSHEET,
        )
    if value.strip().lower() != "nosniff":
        return Finding(
            id="HEADER-XCTO",
            title="X-Content-Type-Options is not nosniff",
            severity="low",
            status="warning",
            evidence=EvidenceBuilder.for_presence(
                "X-Content-Type-Options",
                present=True,
                raw_value=value,
            ).to_dict(),
            explanation="Only the nosniff value is recommended for this header.",
            remediation='Set X-Content-Type-Options: nosniff.',
            reference=_OWASP_CHEATSHEET,
        )
    return Finding(
        id="HEADER-XCTO",
        title="X-Content-Type-Options is nosniff",
        severity="info",
        status="pass",
        evidence=EvidenceBuilder.for_presence(
            "X-Content-Type-Options",
            present=True,
            raw_value=value,
        ).to_dict(),
        explanation="The header discourages MIME-type sniffing.",
        remediation="No change required.",
        reference=_OWASP_CHEATSHEET,
    )


def _xfo_finding(snapshot: SecurityHeaderSnapshot) -> Finding:
    value = snapshot.x_frame_options
    if value is None:
        return Finding(
            id="HEADER-XFO",
            title="X-Frame-Options header is missing",
            severity="medium",
            status="fail",
            evidence=EvidenceBuilder.for_presence(
                "X-Frame-Options",
                present=False,
                raw_value=None,
            ).to_dict(),
            explanation=(
                "No X-Frame-Options or CSP frame-ancestors evaluation is performed "
                "beyond X-Frame-Options presence here."
            ),
            remediation="Use X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk.",
            reference=_OWASP_CHEATSHEET,
        )
    if re.search(r"allow-from", value, re.IGNORECASE):
        return Finding(
            id="HEADER-XFO",
            title="X-Frame-Options uses deprecated ALLOW-FROM",
            severity="low",
            status="warning",
            evidence=EvidenceBuilder.for_presence(
                "X-Frame-Options",
                present=True,
                raw_value=value,
            ).to_dict(),
            explanation="ALLOW-FROM is deprecated and inconsistently supported.",
            remediation="Prefer CSP frame-ancestors or DENY/SAMEORIGIN.",
            reference=_OWASP_CHEATSHEET,
        )
    return Finding(
        id="HEADER-XFO",
        title="X-Frame-Options header is present",
        severity="info",
        status="pass",
        evidence=EvidenceBuilder.for_presence(
            "X-Frame-Options",
            present=True,
            raw_value=value,
        ).to_dict(),
        explanation="X-Frame-Options is present. CSP frame-ancestors is not evaluated here.",
        remediation="No change required for basic presence review.",
        reference=_OWASP_CHEATSHEET,
    )


def _referrer_policy_finding(snapshot: SecurityHeaderSnapshot) -> Finding:
    value = snapshot.referrer_policy
    if value is None:
        return Finding(
            id="HEADER-RP",
            title="Referrer-Policy header is missing",
            severity="medium",
            status="fail",
            evidence=EvidenceBuilder.for_presence(
                "Referrer-Policy",
                present=False,
                raw_value=None,
            ).to_dict(),
            explanation="Referrer-Policy controls referrer information in requests.",
            remediation="Set an explicit Referrer-Policy suited to your privacy needs.",
            reference=_OWASP_CHEATSHEET,
        )
    lowered = value.lower()
    if "unsafe-url" in lowered or "no-referrer-when-downgrade" in lowered:
        return Finding(
            id="HEADER-RP",
            title="Referrer-Policy uses a permissive value",
            severity="low",
            status="warning",
            evidence=EvidenceBuilder.for_presence(
                "Referrer-Policy",
                present=True,
                raw_value=value,
            ).to_dict(),
            explanation="Some Referrer-Policy values may leak more referrer data.",
            remediation="Consider strict-origin-when-cross-origin or stricter policies.",
            reference=_OWASP_CHEATSHEET,
        )
    return Finding(
        id="HEADER-RP",
        title="Referrer-Policy header is present",
        severity="info",
        status="pass",
        evidence=EvidenceBuilder.for_presence(
            "Referrer-Policy",
            present=True,
            raw_value=value,
        ).to_dict(),
        explanation="Referrer-Policy is present.",
        remediation="No change required for basic presence review.",
        reference=_OSWASP,
    )
