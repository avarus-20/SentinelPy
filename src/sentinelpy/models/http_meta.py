"""HTTP metadata types used inside the scan pipeline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RedirectHop:
    """One HTTP redirect step."""

    from_url: str
    to_url: str
    status: int

    def to_dict(self) -> dict[str, object]:
        """Serialize a redirect hop."""

        return {
            "from_url": self.from_url,
            "to_url": self.to_url,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """
    Private HTTP response metadata.

    The full header map must not be exposed through public APIs or reports.
    """

    target_url: str
    final_url: str
    status: int
    headers: dict[str, str]
    redirects: tuple[RedirectHop, ...]
    elapsed_ms: float
