from sentinelpy.redaction.evidence import EvidenceBuilder
from sentinelpy.redaction.headers import (
    is_sensitive_header_name,
    truncate_evidence_value,
)


def test_sensitive_header_names_are_blocked():
    assert is_sensitive_header_name("Set-Cookie")
    assert is_sensitive_header_name("Authorization")
    assert is_sensitive_header_name("X-Auth-Token")


def test_evidence_allows_hsts_excerpt():
    evidence = EvidenceBuilder.for_presence(
        "Strict-Transport-Security",
        present=True,
        raw_value="max-age=31536000",
    ).to_dict()

    assert evidence["header_value_excerpt"] == "max-age=31536000"


def test_evidence_omits_non_allowlist_values():
    evidence = EvidenceBuilder.for_presence(
        "Server",
        present=True,
        raw_value="nginx",
    ).to_dict()

    assert "header_value_excerpt" not in evidence
    assert evidence["observed"] == "present"


def test_truncate_applies_only_to_evidence_output():
    value = "a" * 600
    excerpt = truncate_evidence_value(value)

    assert len(excerpt) == 512
    assert len(value) == 600
