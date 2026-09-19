"""In-memory extraction of security header values for checks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from sentinelpy.constants import SECURITY_HEADERS

_CANONICAL_BY_LOWER = {name.lower(): name for name in SECURITY_HEADERS}


@dataclass(frozen=True, slots=True)
class SecurityHeaderSnapshot:
    """
    Values for the five supported security headers only.

    Full header values are kept in memory for future checks; they must not
    be copied into public reports without redaction.
    """

    strict_transport_security: str | None = None
    content_security_policy: str | None = None
    x_content_type_options: str | None = None
    x_frame_options: str | None = None
    referrer_policy: str | None = None

    @classmethod
    def from_header_map(cls, headers: Mapping[str, str]) -> SecurityHeaderSnapshot:
        """Build a snapshot from a response header mapping."""

        lowered = {key.lower(): value for key, value in headers.items()}
        kwargs: dict[str, str | None] = {}
        for header in SECURITY_HEADERS:
            field = _FIELD_BY_HEADER[header]
            kwargs[field] = lowered.get(header.lower())
        return cls(**kwargs)

    def value_for(self, header_name: str) -> str | None:
        """Return the header value using a canonical or case-insensitive name."""

        canonical = _CANONICAL_BY_LOWER.get(header_name.lower())
        if canonical is None:
            return None
        value = getattr(self, _FIELD_BY_HEADER[canonical])
        return value if isinstance(value, str) else None


_FIELD_BY_HEADER = {
    "Strict-Transport-Security": "strict_transport_security",
    "Content-Security-Policy": "content_security_policy",
    "X-Content-Type-Options": "x_content_type_options",
    "X-Frame-Options": "x_frame_options",
    "Referrer-Policy": "referrer_policy",
}
