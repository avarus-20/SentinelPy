# Using SentinelPy in GitHub Actions

SentinelPy is designed for **authorized**, **read-only** checks of **one URL** per run. This guide shows a safe CI pattern: install from source or wheel, write JSON and Markdown reports as artifacts, and interpret exit codes without treating warnings as pipeline failures unless you choose to.

## Exit codes (CLI contract)

| Exit code | When it happens | Typical CI handling |
| --- | --- | --- |
| `0` | Scan **completed**; summary is `passed` or `warning` | Job step succeeds; parse JSON if you gate on `summary.status`. |
| `1` | Scan **completed**; summary is `failed` (header findings) | Fail the job if missing headers must block deploy; otherwise upload report and fail only when `summary.status == failed`. |
| `2` | **Usage** (bad flags, e.g. `--timeout 0`) or **invalid target** (`error.category == invalid_target`) | Fail fast — fix workflow inputs. Only **invalid target** runs produce a structured JSON/Markdown report (and with `--output`, that file is written before exit `2`). Other usage failures exit before any report is emitted. |
| `3` | Scan **error** (timeout, connection, TLS, internal) | Fail the job; inspect `error.category` and `error.message` in JSON (no stack traces). |

**Important:** Exit code `0` includes **`warning`** outcomes (for example HTTP without HSTS). If your policy treats warnings like failures, check `summary.status` in `report.json` instead of relying on `$?` alone.

## Report schema and golden fixtures

- Schema: [report-schema-1.0.0.json](report-schema-1.0.0.json) (`report_schema_version`: `1.0.0`).
- Stable examples checked into the repo: [tests/fixtures/reports](../tests/fixtures/reports/). CI in this repository validates them with `jsonschema` (dev dependency only).

## Example workflow

Copy [examples/github-actions-sentinelpy.yml](../examples/github-actions-sentinelpy.yml) into your repository (for example `.github/workflows/security-headers.yml`) and set `TARGET_URL` to a URL you are allowed to test (often a staging site).

### JSON and Markdown artifacts

The example runs two scans (or one scan with two output formats) and uploads:

- `sentinelpy-report.json` — for machines, dashboards, and schema validation.
- `sentinelpy-report.md` — for human review in the Actions UI.

Neither artifact includes raw response header maps or cookies.

### Suggested job logic

```yaml
- name: Scan (JSON)
  id: scan
  run: |
    set +e
    sentinelpy scan "$TARGET_URL" --format json --output report.json
    code=$?
    echo "exit_code=$code" >> "$GITHUB_OUTPUT"
    set -e
    test -f report.json

- name: Enforce policy (failed findings)
  if: steps.scan.outputs.exit_code == '1'
  run: |
    python - <<'PY'
    import json, sys
    data = json.load(open("report.json", encoding="utf-8"))
    if data.get("summary", {}).get("status") == "failed":
        sys.exit(1)
    PY

- name: Fail on usage or scan errors
  if: |
    steps.scan.outputs.exit_code == '2' ||
    steps.scan.outputs.exit_code == '3'
  run: exit 1
```

With `set +e`, the scan step exits **0** whenever `report.json` exists—even when SentinelPy returned **2** (invalid target) or **3**. Capture `exit_code` in outputs and add the step above (same pattern as the full [example workflow](../examples/github-actions-sentinelpy.yml)). Pre-scan usage errors (exit **2** without a report) fail the step at `test -f report.json`, which is usually what you want.

Adjust the enforce step to match your risk tolerance (fail on `warning`, fail only on specific finding IDs, etc.).

## Installing in CI

This project does not publish to PyPI. Pin a **tag** or **commit SHA** and install from GitHub:

```bash
pip install "git+https://github.com/avarus-20/SentinelPy@v1.3.0"
```

For reproducible builds, vendor the wheel from GitHub Releases or build from a pinned SHA in a prior workflow step.

## Safety checklist

- Scan only hosts you own or have written permission to test.
- Do not pass secrets in the target URL; userinfo and query strings are redacted in reports.
- Keep TLS verification enabled (default; not configurable).
- Use `--no-redirects` when you need exactly one HTTP GET.

## Local parity

Developers can run the same contract checks as CI:

```bash
pip install -e ".[dev]"
pytest tests/test_report_contract_golden.py tests/test_json_schema_validation.py
```
