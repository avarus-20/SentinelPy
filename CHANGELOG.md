# Changelog

All notable changes to this project are documented here.

## [1.3.0] - 2026-09-19

### Added

- CI trust pack: [docs/ci-github-actions.md](docs/ci-github-actions.md) (exit codes 0–3, JSON/Markdown artifacts, safety notes).
- Copy-paste GitHub Actions example: [examples/github-actions-sentinelpy.yml](examples/github-actions-sentinelpy.yml).
- Golden completed/error JSON fixtures under `tests/fixtures/reports/` with regression tests against the live renderer and JSON Schema.

## [1.2.2] - 2026-09-19

### Added

- Deterministic JSON Schema contract tests for completed scans: summary status and counts (`passed`, `warning`, `failed`), HTTP status codes (200, 404, 500), redirect chains (none, single hop, multi-hop), and redirect URL redaction.

## [1.2.1] - 2026-09-19

### Added

- JSON Schema contract tests for every scan error category (`invalid_target`, `timeout`, `connection`, `tls`, `internal`) with secret-leak guards.

### Fixed

- Stabilize JSON `--no-color` CLI test by fixing `scanned_at` during comparison (Codex PR #29).

### Fixed

- Release workflow clears `dist/` before `python -m build` so stale wheels are never uploaded.

## [1.2.0] - 2026-09-19

### Added

- CLI `--no-color` to disable ANSI styling for terminal format (JSON/Markdown unchanged).
- End-to-end CLI tests for Markdown stdout and `--output` safety.

## [1.1.1] - 2026-09-19

### Fixed

- Restore deprecated `evaluate_presence_findings` export on `sentinelpy.checks` for 1.x import compatibility (removal planned for 2.0).

## [1.1.0] - 2026-09-19

### Added

- JSON Schema validation tests for completed and error reports (`jsonschema` dev-only).
- GitHub Actions pinned to full commit SHAs for supply-chain hardening.

### Notes

- `sentinelpy.checks` exports `evaluate_security_findings` as the supported API; `evaluate_presence_findings` remains deprecated (see 1.1.1).

## [1.0.2] - 2026-09-19

### Fixed

- Warn when Referrer-Policy is present but contains no recognized policy token.

### Added

- Post-release audit (`docs/audits/2026-09-19-post-release-audit.md`).
- End-to-end JSON safety test for CSP bodies; Markdown report smoke tests.

## [1.0.1] - 2026-09-19

### Fixed

- Never embed Content-Security-Policy body text in public finding evidence.
- Evaluate HSTS using the final response URL scheme after redirects.
- Return structured invalid-target error reports for malformed URLs.
- CLI: map `--output` write failures to exit code 3; omit ANSI colors when writing terminal format to a file.
- Quality checks: validate HSTS max-age, X-Frame-Options tokens, CSP unsafe keywords by source token, and effective Referrer-Policy.
- Docs: define `dev` optional extra for `pip install -e ".[dev]"`; clarify redirect follow behavior vs a single GET.
- Build: require setuptools 77+ so SPDX `license = "MIT"` metadata parses on isolated builds.
- Reject malformed host/port during URL normalization so invalid targets never crash redaction.

## [1.0.0] - 2026-09-19

### Added

- Stable CLI (`sentinelpy scan`) with terminal, JSON, and Markdown reports.
- Safe `run_scan()` pipeline with redaction and documented JSON schema `1.0.0`.
- Conservative quality checks for five security headers and HTTP HSTS advisories.
- Engineering quality gates: Ruff, mypy, coverage, CI on Python 3.11/3.12.

### Notes

- Legacy `sentinelpy.main` imports remain for compatibility but may expose raw headers.
- This tool does not guarantee website security; authorized read-only use only.

## [0.5.0] - 2026-09-19

### Added

- Ruff, mypy, coverage, pre-commit, Dependabot, contributor and security docs.

## [0.4.0] - 2026-09-19

### Added

- Conservative quality evaluation for five headers and expanded Markdown reports.

## [0.3.0] - 2026-09-19

### Added

- `sentinelpy scan` CLI with exit codes and terminal/JSON/Markdown output.

## [0.2.0] - 2026-09-19

### Added

- `run_scan()`, safe JSON reports, JSON schema, presence findings with HTTP HSTS advisories.

## [0.1.0] - 2026-08-31

### Added

- Initial library functions and legacy header checks.
