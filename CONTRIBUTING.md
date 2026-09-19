# Contributing to SentinelPy

Thank you for helping improve SentinelPy. This project is a defensive, read-only HTTP header checker.

The project is **feature-complete** (stable release **v1.2.1**) and accepts **maintenance** contributions only — see [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Ground rules

- Use only **authorized** targets in manual testing.
- Do not add exploitation, crawling, credential handling, or features that expose raw sensitive headers in new reports.
- Keep runtime dependencies minimal (stdlib-first).
- Write tests without real network calls.
- Use English for code, docs, commits, and PR descriptions.

## Development setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
# equivalent: pip install -e . --group dev
pre-commit install
pytest
```

## Pull requests

- One focused change per PR.
- Include tests and update docs when behavior changes.
- Report `report_schema_version` changes in CHANGELOG.md.
