# SentinelPy

SentinelPy is a **local**, **authorized**, **read-only** CLI that checks selected HTTP response security headers for **one URL** and produces professional reports.

## Project status

The project is **feature-complete** at **[v1.2.1](https://github.com/avarus-20/SentinelPy/releases/tag/v1.2.1)** and in **maintenance-only** mode (security, correctness, packaging, and compatibility fixes). See [PROJECT_STATUS.md](PROJECT_STATUS.md).

It is **not** a penetration-testing tool and **does not guarantee** that a website is secure. It performs a limited configuration review of a single HTTP response.

## What it checks

- `Strict-Transport-Security` (with HTTP advisory semantics)
- `Content-Security-Policy` (conservative quality hints)
- `X-Content-Type-Options` (`nosniff`)
- `X-Frame-Options`
- `Referrer-Policy`

## Quick start

Install the **stable** release (**v1.2.1**), not floating `main` (which may carry newer metadata only):

```bash
git clone https://github.com/avarus-20/SentinelPy.git
cd SentinelPy
git checkout v1.2.1
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
sentinelpy scan https://example.com
```

Alternative without a clone: `pip install "git+https://github.com/avarus-20/SentinelPy@v1.2.1"` or install the wheel from [Releases](https://github.com/avarus-20/SentinelPy/releases/tag/v1.2.1).

JSON for CI:

```bash
sentinelpy scan https://example.com --format json --output report.json
echo $?
```

## CLI

```text
sentinelpy scan TARGET_URL [--format terminal|json|markdown] [--output PATH]
                         [--timeout SECONDS] [--user-agent STRING] [--no-redirects]
                         [--no-color]
sentinelpy --version
sentinelpy --help
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; summary `passed` or `warning` |
| `1` | Scan completed; summary `failed` |
| `2` | Usage / invalid target URL |
| `3` | Scan error (timeout, connection, TLS, internal) |

## Python API

```python
from sentinelpy import run_scan, render_json

report = run_scan("https://example.com")
print(render_json(report))
```

Legacy v0.1 helpers remain importable from `sentinelpy.main` but may expose raw headers (deprecated).

## JSON report schema

Machine-readable reports use `report_schema_version` (currently `1.0.0`). See [docs/report-schema-1.0.0.json](docs/report-schema-1.0.0.json). CI validates representative reports against this schema (dev dependency `jsonschema` only).

**Compatibility:** semver for the report schema — patch/minor additive changes only; major bumps may rename or retype required fields.

## Safety scope and limitations

- Use only on systems you **own** or are **explicitly authorized** to test.
- By default the client **follows HTTP redirects** (one additional GET per hop; the final URL may differ). Use `--no-redirects` for a single request. No crawling beyond that redirect chain.
- Public reports **never** include raw cookies, authorization headers, or full header dumps.
- TLS certificate verification is **never** disabled.

## Development

```bash
pip install -e ".[dev]"  # or: pip install -e . --group dev
pytest
ruff check src tests
ruff format --check src tests
mypy
pre-commit run --all-files
```

## Responsible disclosure

See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
