# Post-release audit — SentinelPy v1.0.1

**Date:** 2026-09-19  
**Baseline:** `main` after merge of PR #25 and tag `v1.0.1`  
**Auditor:** autonomous engineering pass (local tests + CI + static review)

## Executive summary

SentinelPy v1.0.1 delivers a coherent **authorized, read-only, single-URL** header checker with a **safe public report contract**, stable CLI exit codes, and reproducible CI. No **P0** defects were confirmed. One **P1** finding-accuracy issue and several **P2** maintainability gaps are tracked below with evidence.

## Verified strengths

| Area | Evidence |
| --- | --- |
| Safe report pipeline | `run_scan()` never attaches raw header maps; `tests/test_serialization_safety.py`, `tests/test_safe_evidence_contract.py` |
| CSP non-leakage | CSP removed from evidence allowlist (`redaction/headers.py`); `test_csp_evidence_never_includes_policy_body` |
| HSTS after redirects | `HttpResponse.final_scheme` from raw final URL; `test_hsts_uses_final_https_url_after_redirect` |
| Malformed URLs | `normalize_url()` + `run_scan()` return `invalid_target` without traceback; `test_malformed_url_*`, `test_run_scan_rejects_invalid_port` |
| CLI exit codes | Documented 0–3; tests in `tests/test_cli.py` including output I/O and `-m sentinelpy` |
| Redaction | URL userinfo/query keys; sensitive header names blocked from evidence |
| TLS | urllib/ssl default verification; no bypass hooks |
| Packaging | `pip install -e .` + optional `dev` extra; setuptools ≥77 for SPDX license |
| CI | Matrix 3.11/3.12 (ruff, mypy, pytest ≥80% coverage) + aggregate `test` job |
| Release | Tag `v1.0.1` builds wheel/sdist via `.github/workflows/release.yml` |
| Public API | Stable exports in `sentinelpy.__init__`; legacy `sentinelpy.main` preserved |

## Confirmed defects

### P1 — Unrecognized Referrer-Policy values reported as pass

**Impact:** False confidence when the header is present but contains no recognized policy token (browsers ignore it).

**Reproduction:**

```python
from sentinelpy.checks.quality import evaluate_security_findings
from sentinelpy.http.snapshot import SecurityHeaderSnapshot

snapshot = SecurityHeaderSnapshot.from_header_map({"Referrer-Policy": "not-a-real-policy"})
findings = evaluate_security_findings(snapshot, target_scheme="https")
rp = next(f for f in findings if f.id == "HEADER-RP")
assert rp.status == "pass"  # current (incorrect) behavior
```

**Fix:** Treat “present but no recognized token” as `warning`, not `pass`. (Addressed in post-audit PR.)

### P2 — Legacy `checks/presence.py` unused in pipeline

**Impact:** Maintenance risk; still copies CSP into evidence if ever wired again.

**Evidence:** No imports of `evaluate_presence_findings` under `src/`; runner uses `checks/quality.py` only.

**Recommendation:** Remove or gate behind explicit legacy flag in v1.2; do not re-enable without CSP-safe evidence rules.

### P2 — Markdown renderer lacks automated tests

**Impact:** Regressions in `--format markdown` would not be caught (coverage ~9% on `reports/markdown.py`).

**Evidence:** `pytest --cov` report; no `test_markdown*.py`.

**Recommendation:** Smoke tests for structure and absence of evidence blobs. (Partially addressed post-audit.)

### P2 — End-to-end JSON leak test for CSP body

**Impact:** Unit tests cover `EvidenceBuilder`; full `run_scan` → `render_json` path for CSP secrets was not asserted before audit.

**Recommendation:** Add mocked HTTP response test. (Addressed post-audit.)

### P2 — CONTRIBUTING vs README dev install wording

**Impact:** Contributors following CONTRIBUTING only see `--group dev`; README documents both forms.

**Evidence:** File diff review.

**Recommendation:** Align CONTRIBUTING with README. (Addressed post-audit.)

### P2 — Legacy `sentinelpy.main` may expose raw header values

**Impact:** Documented deprecation; callers using legacy helpers bypass safe report contract.

**Evidence:** `legacy/main.py`, README “Legacy” section.

**Recommendation:** Keep for compatibility; steer integrators to `run_scan()`.

## Non-goals (explicit)

- Network crawling, port scanning, or multi-host assessment
- Exploitation, auth bypass, credential or session testing
- Hosted SaaS, telemetry, accounts, or web UI
- PyPI publishing (unless maintainer opts in)
- Real third-party domains in repository tests
- Claiming “secure site” or CVSS-style scores
- Broad new header categories without safe evidence design

## Roadmap

### v1.1 (quality & trust)

- Fix P1 Referrer-Policy unrecognized tokens
- E2E safe-serialization tests (JSON/Markdown)
- JSON Schema validation test against fixture reports
- Remove or isolate dead `presence.py` module
- Pin GitHub Actions to digest SHAs (supply chain)

### v1.2 (usability)

- Optional `--no-color` for terminal format on stdout
- Richer Markdown (evidence keys without secret values)
- CLI integration tests for `--format markdown`
- Expand URL normalization edge-case table in docs

### v2.0 (if ever)

- Pluggable check registry with mandatory redaction hooks
- Optional config file (still single URL per invocation)
- Report schema 2.0 only with migration guide and semver major

## Post-audit remediation log

| Item | Status | PR / release |
| --- | --- | --- |
| P1 Referrer-Policy unrecognized tokens | fixed in PR | post-audit PR → v1.0.2 |
| P2 E2E CSP JSON safety test | fixed in PR | post-audit PR → v1.0.2 |
| P2 Markdown smoke test | fixed in PR | post-audit PR → v1.0.2 |
| P2 CONTRIBUTING dev install alignment | fixed in PR | post-audit PR → v1.0.2 |
| P2 Remove dead `presence.py` | done | v1.1.0 |
| P2 JSON Schema validation test | done | v1.1.0 |
| P2 Pin Actions to SHA digests | done | v1.1.0 |
