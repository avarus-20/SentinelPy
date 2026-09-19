"""JSON report rendering."""

from __future__ import annotations

import json

from sentinelpy.models.report import ScanReport


def render_json(report: ScanReport, *, indent: int | None = 2) -> str:
    """Serialize a scan report to a JSON string with stable key order."""

    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)
