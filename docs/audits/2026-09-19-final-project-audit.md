# Final project audit — SentinelPy

**Date:** 2026-09-19  
**Project decision:** Feature-complete; **maintenance-only** going forward.

## Closure and consistency commits

| Field | Value |
| --- | --- |
| **Initial closure (`main`)** | `1115cd41e88ef06941bbe38f6fa45deb4a24b7ec` ([PR #37](https://github.com/avarus-20/SentinelPy/pull/37)) |
| **Documentation consistency (`main`)** | _Updated after merge of PR #41_ |
| **Current stable release** | **[v1.3.0](https://github.com/avarus-20/SentinelPy/releases/tag/v1.3.0)** (wheel + sdist on GitHub Releases; matches `pyproject.toml`) |

**Note:** [PR #40](https://github.com/avarus-20/SentinelPy/pull/40) pinned docs to v1.2.1 and was superseded by the v1.3.0 consistency correction ([PR #41](https://github.com/avarus-20/SentinelPy/pull/41)). Tags v1.2.1–v1.2.2 remain for history; they are not deleted.

## Verification (2026-09-19, consistency pass)

Environment: Python 3.12.3, Ubuntu, editable dev install + clean venv wheel smoke.

### `ruff check .`

```
All checks passed!
```

### `ruff format --check src tests`

```
56 files already formatted
```

### `mypy src`

```
Success: no issues found in 36 source files
```

### `pytest` (with coverage)

```
128 passed in 0.47s
Total coverage: 88.78% (fail-under 80%)
```

### `python -m build`

```
Successfully built sentinelpy-1.3.0.tar.gz and sentinelpy-1.3.0-py3-none-any.whl
```

### Clean venv wheel install

```
pip install dist/sentinelpy-1.3.0-py3-none-any.whl
sentinelpy --version  →  sentinelpy 1.3.0
sentinelpy scan --help  →  OK
```

### Mocked CLI smoke test

```
pytest tests/test_cli_markdown_e2e.py::test_cli_json_unaffected_by_no_color_flag  →  passed
```

### `git diff --check`

No conflict markers or whitespace errors on consistency changes.

## Security and redaction guarantees

- Public JSON/Markdown/terminal reports **never** include raw response header maps (`response_headers` forbidden by schema and tests).
- URL **userinfo** and **query** redacted in `target_url`, `final_url`, and redirect hops; CSP values are not copied into evidence allowlist.
- Error reports use catalog **categories** and safe messages (no stack traces, errno, or TLS detail leaks).
- TLS certificate verification is **not** disabled.

## Public API and CLI

**CLI:** `sentinelpy scan`, `--format terminal|json|markdown`, `--output`, `--timeout`, `--user-agent`, `--no-redirects`, `--no-color`; exit codes 0–3.

**Python (`sentinelpy.__init__`):** `run_scan`, `ScanOptions`, `ScanReport`, `render_json`, `normalize_target_url`, `redact_url`, `__version__`, `REPORT_SCHEMA_VERSION`, exception types.

**Report contract:** `report_schema_version` **1.0.0** — maintenance fixes only; no planned breaking schema changes.

## Known limitations

- Single URL only; optional redirect following (no crawling).
- Five headers evaluated; presence/quality hints, not full policy audit.
- No PyPI distribution; install from GitHub tag/release or source.
- Warnings (e.g. HTTP without HSTS) yield exit code **0** unless operators parse `summary.status`.

## Defect status

**No open P0 or P1 defects** at project closure. Remaining work is documentation consistency and maintenance-only fixes.

## Maintenance-only decision

- **No** new product features: checks, CLI flags, report formats, or roadmap items.
- **Yes** to confirmed security, correctness, packaging, compatibility, and truthful docs per [PROJECT_STATUS.md](../../PROJECT_STATUS.md).

## References

- [PROJECT_STATUS.md](../../PROJECT_STATUS.md)
- [README.md](../../README.md)
- [SECURITY.md](../../SECURITY.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md)
- [CHANGELOG.md](../../CHANGELOG.md)
- [Releases](https://github.com/avarus-20/SentinelPy/releases)
