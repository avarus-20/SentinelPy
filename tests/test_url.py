import pytest

from sentinelpy.exceptions import InvalidTargetError
from sentinelpy.http.url import normalize_url, target_scheme
from sentinelpy.legacy.main import normalize_url as legacy_normalize_url
from sentinelpy.redaction.url import redact_url


def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_preserves_https():
    assert normalize_url("https://example.com") == "https://example.com"


def test_normalize_url_fixes_uppercase_http_scheme():
    assert normalize_url("HTTP://example.com") == "http://example.com"


def test_legacy_normalize_url_raises_value_error_for_invalid_target():
    with pytest.raises(ValueError, match="Invalid URL"):
        legacy_normalize_url("")


def test_normalize_url_raises_invalid_target_error():
    with pytest.raises(InvalidTargetError):
        normalize_url("")


def test_target_scheme_detects_http():
    assert target_scheme("http://example.com") == "http"


def test_redact_url_masks_sensitive_query():
    redacted = redact_url("https://example.com/path?token=secret&ok=1")
    assert "secret" not in redacted
    assert "REDACTED" in redacted
    assert "ok=1" in redacted


def test_redact_url_removes_userinfo_and_fragment():
    redacted = redact_url("https://user:pass@example.com/a#fragment")
    assert "user" not in redacted
    assert "pass" not in redacted
    assert "fragment" not in redacted
    assert "REDACTED" in redacted
