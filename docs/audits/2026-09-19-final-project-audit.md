# Final project audit — SentinelPy

**Date:** 2026-09-19  
**Project decision:** Feature-complete at **v1.2.1**; **maintenance-only** going forward.

## Closure commit

| Field | Value |
| --- | --- |
| **Pre-closure `main` baseline** | `c9538af9788057589f740ba479028581721290f8` |
| **Closure commit (`main`)** | `1115cd41e88ef06941bbe38f6fa45deb4a24b7ec` ([PR #37](https://github.com/avarus-20/SentinelPy/pull/37)) |
| **Declared stable release** | **[v1.2.1](https://github.com/avarus-20/SentinelPy/releases/tag/v1.2.1)** |

Historical tags and releases (including v1.2.2, v1.3.0) are retained and not deleted; they do not reopen feature development.

## Verification (2026-09-19, local)

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
126 passed in 0.51s
Total coverage: 88.78% (fail-under 80%)
```

### `python -m build`

```
Successfully built sentinelpy-1.3.0.tar.gz and sentinelpy-1.3.0-py3-none-any.whl
```

(Wheel version reflects `main` metadata at verification time; consumers pinning the **feature-complete** product should use **v1.2.1** release assets.)

### Clean venv wheel install

```
pip install dist/sentinelpy-1.3.0-py3-none-any.whl  # fresh venv
sentinelpy --version  →  sentinelpy 1.3.0
sentinelpy scan --help  →  usage with --format, --output, --no-redirects, --no-color
```

### Mocked CLI smoke test

```
pytest tests/test_cli_markdown_e2e.py::test_cli_json_unaffected_by_no_color_flag  →  passed
```

### `git diff --check`

No conflict markers or whitespace errors on staged closure changes.

## Security and redaction guarantees

- Public JSON/Markdown/terminal reports **never** include raw response header maps (`response_headers` forbidden by schema and tests).
- URL **userinfo** and **query** redacted in `target_url`, `final_url`, and redirect hops; CSP values are not copied into evidence allowlist.
- Error reports use catalog **categories** and safe messages (no stack traces, errno, or TLS detail leaks) — covered by `tests/test_json_schema_error_categories.py`.
- TLS certificate verification is **not** disabled.

## Public API and CLI (v1.2.1 feature scope)

**CLI:** `sentinelpy scan`, `--format terminal|json|markdown`, `--output`, `--timeout`, `--user-agent`, `--no-redirects`, `--no-color`; exit codes 0–3 unchanged since v1.2.1.

**Python (`sentinelpy.__init__`):** `run_scan`, `ScanOptions`, `ScanReport`, `render_json`, `normalize_target_url`, `redact_url`, `__version__`, `REPORT_SCHEMA_VERSION`, exception types.

**Report contract:** `report_schema_version` **1.0.0** — no breaking change planned; maintenance fixes only.

## Known limitations

- Single URL only; optional redirect following (no crawling).
- Five headers evaluated; presence/quality hints, not full policy audit.
- No PyPI distribution; install from GitHub tag/release or source.
- Warnings (e.g. HTTP without HSTS) yield exit code **0** unless operators parse `summary.status`.

## Defect status

**No open P0 or P1 defects** identified at closure. Post–v1.2.1 work on `main` was limited to documentation and contract tests; no mandatory runtime fix required before maintenance mode.

## Maintenance-only decision

- **No** planned features: new checks, CLI flags, report formats, roadmap items from the v1.3 direction audit.
- **Yes** to confirmed security, correctness, packaging, and compatibility fixes per [PROJECT_STATUS.md](../../PROJECT_STATUS.md).

## References

- [PROJECT_STATUS.md](../../PROJECT_STATUS.md)
- [README.md](../../README.md)
- [SECURITY.md](../../SECURITY.md)
- [CONTRIBUTING.md](../../CONTRIBUTING.md)
- [CHANGELOG.md](../../CHANGELOG.md)
- [Releases](https://github.com/avarus-20/SentinelPy/releases)
