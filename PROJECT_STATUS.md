# SentinelPy — project status

**Last updated:** 2026-09-19  
**Status:** **Complete (maintenance only)**

## Current stable release

**[v1.2.1](https://github.com/avarus-20/SentinelPy/releases/tag/v1.2.1)** is the feature-complete stable release for this project.

Later tags (for example v1.2.2, v1.3.0) remain available for historical reference; they do not expand product scope. New feature development is **not** planned.

## Purpose

SentinelPy is a **local**, **authorized**, **read-only** tool that checks selected HTTP response security headers for **one URL** and produces safe JSON, Markdown, or terminal reports.

Use it only on systems you own or are explicitly permitted to test. It is **not** a penetration-testing product and does **not** guarantee that a target is secure.

## Supported capabilities (v1.2.1 scope)

- CLI: `sentinelpy scan TARGET_URL` with `--format terminal|json|markdown`, `--output`, `--timeout`, `--user-agent`, `--no-redirects`, `--no-color`
- Python API: `run_scan`, `ScanOptions`, `render_json`, `ScanReport`, `redact_url`, `normalize_target_url`, `__version__`, `REPORT_SCHEMA_VERSION`
- Five header categories: HSTS (with HTTP advisory semantics), CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- JSON report schema version **1.0.0** ([schema](docs/report-schema-1.0.0.json))
- CLI exit codes **0** (passed/warning completed), **1** (failed findings), **2** (usage/invalid target), **3** (scan error)
- Safe reports: no raw response header maps; URL userinfo/query redaction; redirect hops recorded with redacted URLs

## Non-goals

- PyPI publication
- Crawling, port scanning, or multi-host assessment
- New header categories, SaaS, telemetry, hosted UI, or authentication
- Exploitation, credential testing, or disabling TLS verification
- Planned feature releases or roadmap delivery

## Maintenance policy

The project is **closed to feature development**. Acceptable changes are limited to:

- Confirmed **security** issues
- **Correctness** bugs in scan, reporting, or redaction
- **Packaging** or **compatibility** fixes (Python versions, dependencies, CI)

Each maintenance change should include tests when behavior is affected and a entry in [CHANGELOG.md](CHANGELOG.md). Do not bump version or cut a GitHub Release unless a confirmed defect requires it.

## References

| Resource | Link |
| --- | --- |
| Usage & quick start | [README.md](README.md) |
| Security & disclosure | [SECURITY.md](SECURITY.md) |
| Contributing (maintenance) | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Version history | [CHANGELOG.md](CHANGELOG.md) |
| GitHub releases | [Releases](https://github.com/avarus-20/SentinelPy/releases) |
| v1.3 direction audit (historical planning) | [docs/audits/2026-09-19-v1.3-direction-audit.md](docs/audits/2026-09-19-v1.3-direction-audit.md) |
| Final project audit | [docs/audits/2026-09-19-final-project-audit.md](docs/audits/2026-09-19-final-project-audit.md) |
