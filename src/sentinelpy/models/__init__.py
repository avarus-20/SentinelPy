"""Typed models for future scan reports."""

from sentinelpy.models.finding import Finding
from sentinelpy.models.http_meta import HttpResponse, RedirectHop
from sentinelpy.models.report import ScanErrorInfo, ScanReport, ScanSummary
from sentinelpy.models.schema import REPORT_SCHEMA_VERSION

__all__ = [
    "Finding",
    "HttpResponse",
    "REPORT_SCHEMA_VERSION",
    "RedirectHop",
    "ScanErrorInfo",
    "ScanReport",
    "ScanSummary",
]
