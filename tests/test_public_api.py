import importlib

import sentinelpy


def test_version_matches_package_metadata():
    assert sentinelpy.__version__ == "1.0.1"


def test_public_api_exposes_redaction_and_schema_version():
    assert sentinelpy.REPORT_SCHEMA_VERSION == "1.0.0"
    assert "secret" not in sentinelpy.redact_url("https://example.com/?token=secret")
    assert "REDACTED" in sentinelpy.redact_url("https://example.com/?token=secret")


def test_run_scan_is_public():
    assert callable(sentinelpy.run_scan)


def test_main_legacy_imports_remain_available():
    module = importlib.import_module("sentinelpy.main")

    for name in (
        "normalize_url",
        "fetch_headers",
        "check_security_headers",
        "scan_site",
    ):
        assert hasattr(module, name)


def test_package_all_includes_run_scan():
    assert "run_scan" in sentinelpy.__all__
