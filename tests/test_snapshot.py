from sentinelpy.http.snapshot import SecurityHeaderSnapshot


def test_snapshot_extracts_only_security_headers():
    headers = {
        "Set-Cookie": "session=abc",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Type": "text/html",
    }

    snapshot = SecurityHeaderSnapshot.from_header_map(headers)

    assert snapshot.strict_transport_security == "max-age=31536000"
    assert snapshot.content_security_policy is None


def test_snapshot_is_case_insensitive():
    headers = {"x-content-type-options": "nosniff"}

    snapshot = SecurityHeaderSnapshot.from_header_map(headers)

    assert snapshot.x_content_type_options == "nosniff"


def test_snapshot_keeps_full_csp_value():
    long_csp = "default-src 'self'; " + ("script-src 'self' " * 40)
    snapshot = SecurityHeaderSnapshot.from_header_map(
        {"Content-Security-Policy": long_csp}
    )

    assert snapshot.content_security_policy == long_csp
    assert len(snapshot.content_security_policy) > 512
