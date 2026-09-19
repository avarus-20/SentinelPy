from unittest.mock import patch

from sentinelpy.reports.markdown import render_markdown
from sentinelpy.scan.runner import run_scan


def test_render_markdown_includes_summary_and_disclaimer():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    with patch(
        "sentinelpy.scan.runner.fetch",
        return_value=_response(headers),
    ):
        report = run_scan("https://example.com")

    text = render_markdown(report)

    assert "# SentinelPy scan report" in text
    assert "## Findings" in text
    assert "HEADER-HSTS" in text
    assert "## Disclaimer" in text
    assert "default-src" not in text


def _response(headers: dict[str, str]):
    from sentinelpy.models.http_meta import HttpResponse

    return HttpResponse(
        target_url="https://example.com/",
        final_url="https://example.com/",
        final_scheme="https",
        status=200,
        headers=headers,
        redirects=(),
        elapsed_ms=1.0,
    )
