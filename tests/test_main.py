from sentinelpy.main import check_security_headers, normalize_url


def test_adds_https_when_scheme_is_missing():
    # FI: Tarkistetaan, että HTTPS lisätään automaattisesti.
    # RU: Проверяем, что HTTPS добавляется автоматически.
    assert normalize_url("example.com") == "https://example.com"


def test_keeps_existing_https():
    # FI: Tarkistetaan, ettei olemassa olevaa HTTPS-protokollaa muuteta.
    # RU: Проверяем, что существующий HTTPS не изменяется.
    assert normalize_url("https://example.com") == "https://example.com"
    
def test_detects_present_security_headers():
    # FI: Tarkistetaan, että olemassa oleva turvaotsikko tunnistetaan.
    # RU: Проверяем, что существующий защитный заголовок определяется.
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
    }

    result = check_security_headers(headers)

    assert result["Strict-Transport-Security"] is True
    assert result["X-Content-Type-Options"] is True


def test_detects_missing_security_header():
    # FI: Tarkistetaan, että puuttuva turvaotsikko tunnistetaan.
    # RU: Проверяем, что отсутствующий защитный заголовок определяется.
    headers = {}

    result = check_security_headers(headers)

    assert result["Content-Security-Policy"] is False
    