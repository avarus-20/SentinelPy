"""Build safe finding evidence from in-memory header values."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelpy.redaction.headers import (
    may_include_header_value_in_evidence,
    truncate_evidence_value,
)


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    """Minimal, non-sensitive evidence attached to a finding."""

    header_name: str | None = None
    header_value_excerpt: str | None = None
    observed: str | None = None
    expected: str | None = None

    def to_dict(self) -> dict[str, str]:
        """Serialize evidence using only populated fields."""

        payload: dict[str, str] = {}
        if self.header_name is not None:
            payload["header_name"] = self.header_name
        if self.header_value_excerpt is not None:
            payload["header_value_excerpt"] = self.header_value_excerpt
        if self.observed is not None:
            payload["observed"] = self.observed
        if self.expected is not None:
            payload["expected"] = self.expected
        return payload


class EvidenceBuilder:
    """Apply allowlisting before evidence leaves the redaction layer."""

    @staticmethod
    def for_presence(
        header_name: str,
        *,
        present: bool,
        raw_value: str | None,
    ) -> FindingEvidence:
        """Build evidence for a simple present/missing header check."""

        if not present:
            return FindingEvidence(
                header_name=header_name,
                observed="absent",
            )

        evidence = FindingEvidence(
            header_name=header_name,
            observed="present",
        )
        if raw_value is not None and may_include_header_value_in_evidence(header_name):
            return FindingEvidence(
                header_name=header_name,
                observed="present",
                header_value_excerpt=truncate_evidence_value(raw_value),
            )
        return evidence
