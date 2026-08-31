from unittest.mock import MagicMock, patch

from sentinelpy.main import (
    check_security_headers,
    fetch_headers,
    normalize_url,
)
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
    
def test_fetch_headers_returns_response_headers():
    # FI: Korvataan oikea verkkopyyntö testissä keinotekoisella vastauksella.
    # RU: В тесте заменяем настоящий сетевой запрос искусственным ответом.
    fake_response = MagicMock()

    # FI: Määritetään testivastauksen HTTP-otsikot.
    # RU: Задаём HTTP-заголовки тестового ответа.
    fake_response.headers.items.return_value = [
        ("Content-Type", "text/html"),
        ("X-Content-Type-Options", "nosniff"),
    ]

    # FI: Valmistellaan context manager -käyttäytyminen "with"-rakennetta varten.
    # RU: Настраиваем поведение context manager для конструкции "with".
    fake_context = MagicMock()
    fake_context.__enter__.return_value = fake_response
    fake_context.__exit__.return_value = False

    # FI: Korvataan urlopen oikean verkkoyhteyden välttämiseksi.
    # RU: Подменяем urlopen, чтобы не выполнять настоящий сетевой запрос.
    with patch("sentinelpy.main.urlopen", return_value=fake_context):
        result = fetch_headers("example.com")

    assert result["Content-Type"] == "text/html"
    assert result["X-Content-Type-Options"] == "nosniff"
    