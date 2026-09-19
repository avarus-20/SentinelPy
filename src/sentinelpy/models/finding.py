"""Finding model types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]
FindingStatus = Literal["pass", "warning", "fail", "error"]


@dataclass(frozen=True, slots=True)
class Finding:
    """One assessed security-header signal."""

    id: str
    title: str
    severity: Severity
    status: FindingStatus
    evidence: dict[str, str]
    explanation: str
    remediation: str
    reference: str

    def to_dict(self) -> dict[str, object]:
        """Serialize the finding for structured output."""

        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "evidence": dict(self.evidence),
            "explanation": self.explanation,
            "remediation": self.remediation,
            "reference": self.reference,
        }
