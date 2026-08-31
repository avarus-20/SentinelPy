#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 31 17:28:15 2026

@author: omea-ubuntu
"""

from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def normalize_url(url: str) -> str:
    """
    FI: Normalisoi käyttäjän antaman URL-osoitteen.
    RU: Нормализует URL-адрес, введённый пользователем.
    """

    url = url.strip()

    # FI: Jos protokollaa ei ole annettu, käytetään HTTPS:ää oletuksena.
    # RU: Если протокол не указан, по умолчанию используется HTTPS.
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)

    # FI: Varmistetaan, että osoitteessa on verkkotunnus.
    # RU: Проверяем, что URL содержит доменное имя.
    if not parsed.netloc:
        raise ValueError("Invalid URL")

    return url

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)


def check_security_headers(headers: dict[str, str]) -> dict[str, bool]:
    """
    FI: Tarkistaa, löytyvätkö tärkeät HTTP-turvaotsikot vastauksesta.
    RU: Проверяет наличие основных защитных HTTP-заголовков в ответе.
    """

    # FI: HTTP-otsikoiden kirjainkoko ei saa vaikuttaa tarkistukseen.
    # RU: Регистр букв в HTTP-заголовках не должен влиять на проверку.
    normalized_headers = {key.lower(): value for key, value in headers.items()}

    return {
        header: header.lower() in normalized_headers
        for header in SECURITY_HEADERS
    }


def fetch_headers(url: str) -> dict[str, str]:
    """
    FI: Lähettää HTTP-pyynnön ja palauttaa palvelimen vastausotsikot.
    RU: Отправляет HTTP-запрос и возвращает заголовки ответа сервера.
    """

    normalized_url = normalize_url(url)

    # FI: Luodaan HTTP-pyyntö, jossa käytetään omaa User-Agent-arvoa.
    # RU: Создаём HTTP-запрос со своим значением User-Agent.
    request = Request(
        normalized_url,
        headers={"User-Agent": "SentinelPy/0.1"},
    )
    try:
        # FI: Lähetetään HTTP-pyyntö ja palautetaan vastauksen otsikot.
        # RU: Отправляем HTTP-запрос и возвращаем заголовки ответа.
        with urlopen(request, timeout=10) as response:
            return dict(response.headers.items())

    except HTTPError as error:
        # FI: HTTP-virhe sisältää silti palvelimen vastausotsikot.
        # RU: HTTP-ошибка всё равно содержит заголовки ответа сервера.
        return dict(error.headers.items())