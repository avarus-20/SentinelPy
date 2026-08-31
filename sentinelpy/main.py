#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Aug 31 17:28:15 2026

@author: omea-ubuntu
"""

from urllib.parse import urlparse


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