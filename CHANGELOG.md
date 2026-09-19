# Changelog

All notable changes to this project are documented here.

## [1.0.1] - 2026-09-19

### Fixed

- Never embed Content-Security-Policy body text in public finding evidence.
- Evaluate HSTS using the final response URL scheme after redirects.
- Return structured invalid-target error reports for malformed URLs.
- CLI: map `--output` write failures to exit code 3; omit ANSI colors when writing terminal format to a file.
- Quality checks: validate HSTS max-age, X-Frame-Options tokens, CSP unsafe keywords by source token, and effective Referrer-Policy.

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
