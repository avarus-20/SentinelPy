import json
from pathlib import Path
from unittest.mock import patch

from sentinelpy.models.schema import REPORT_SCHEMA_VERSION
from sentinelpy.reports.json import render_json
from sentinelpy.scan.runner import run_scan


def test_render_json_required_fields():
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_minimal_response(),
    ):
        report = run_scan("https://example.com")

    data = json.loads(render_json(report))
    assert data["report_schema_version"] == REPORT_SCHEMA_VERSION
    assert data["tool_name"] == "sentinelpy"
    assert data["scan_status"] == "completed"
    assert "disclaimer" in data
    assert data["error"] is None


def test_schema_file_exists():
    schema_path = Path(__file__).resolve().parents[1] / "docs/report-schema-1.0.0.json"
    assert schema_path.is_file()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["properties"]["report_schema_version"]["pattern"]


def _minimal_response():
    from sentinelpy.models.http_meta import HttpResponse

    return HttpResponse(
        target_url="https://example.com/",
        final_url="https://example.com/",
        final_scheme="https",
        status=200,
        headers={},
        redirects=(),
        elapsed_ms=1.0,
    )
