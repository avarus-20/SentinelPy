# SentinelPy

SentinelPy is a small Python tool for checking common website security-related HTTP response headers.
It is a defensive, read-only learning project: it sends a normal HTTP request, reads response headers,
and reports whether selected security headers are present.

## What it checks

SentinelPy currently checks for these headers:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`

A missing header is not a complete security assessment. It is a signal for review.
The tool does not exploit, brute-force, crawl, log in, submit forms, or modify the target website.

## Project status

This repository is a public code sample and learning project. It demonstrates:

- Python project structure
- URL normalization
- HTTP request handling
- security-header checking
- handling headers returned with HTTP error responses
- unit tests with mocked network calls

## Requirements

- Python 3.11 or newer
- pytest for running tests

## Install for local development

```bash
git clone https://github.com/avarus-20/SentinelPy.git
cd SentinelPy
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip pytest
```

On Windows PowerShell:

```powershell
git clone https://github.com/avarus-20/SentinelPy.git
cd SentinelPy
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip pytest
```

## Example use

The current code exposes reusable functions in `sentinelpy/main.py`.
For example, another Python file can import and use them like this:

```python
from sentinelpy.main import fetch_headers, check_security_headers

headers = fetch_headers("example.com")
result = check_security_headers(headers)

for header, present in result.items():
    print(f"{header}: {'present' if present else 'missing'}")
```

FI: Tätä voi käyttää toisesta Python-tiedostosta tuomalla tarvittavat funktiot.
RU: Это можно использовать из другого Python-файла, импортируя нужные функции.

## Run tests

```bash
python -m pytest
```

The tests avoid real network calls where possible by using mocks. They check URL normalization,
security-header detection, normal response headers, and headers returned together with an HTTP error.

## Safety scope

Use this only on websites you own or are explicitly allowed to check. SentinelPy is not a penetration-testing
tool and does not guarantee that a website is secure. It only checks a small set of HTTP response headers.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
