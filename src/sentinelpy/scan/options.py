"""Options for ``run_scan``."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelpy.http.client import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """User-configurable scan parameters."""

    timeout: float = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT
    follow_redirects: bool = True
