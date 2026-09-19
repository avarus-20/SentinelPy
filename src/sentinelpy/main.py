#!/usr/bin/env python3

"""
Compatibility entry point for legacy imports.

Prefer ``sentinelpy`` package exports for new code. The scan workflow is added
in v0.2.0b.
"""

from sentinelpy.constants import SECURITY_HEADERS
from sentinelpy.legacy.main import (
    check_security_headers,
    fetch_headers,
    normalize_url,
    scan_site,
)

__all__ = [
    "SECURITY_HEADERS",
    "check_security_headers",
    "fetch_headers",
    "normalize_url",
    "scan_site",
]
