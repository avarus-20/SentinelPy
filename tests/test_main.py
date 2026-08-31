from sentinelpy.main import normalize_url


def test_adds_https_when_scheme_is_missing():
    # FI: Tarkistetaan, että HTTPS lisätään automaattisesti.
    # RU: Проверяем, что HTTPS добавляется автоматически.
    assert normalize_url("example.com") == "https://example.com"


def test_keeps_existing_https():
    # FI: Tarkistetaan, ettei olemassa olevaa HTTPS-protokollaa muuteta.
    # RU: Проверяем, что существующий HTTPS не изменяется.
    assert normalize_url("https://example.com") == "https://example.com"