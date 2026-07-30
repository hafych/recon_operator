# Contributing

Contributions are welcome when they preserve the project's authorized-use guardrails.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

## Required checks

```bash
ruff format --check .
ruff check .
python -m coverage run -m unittest discover -s tests/unit -t . -v
python -m coverage report
RUN_E2E=1 python -m unittest discover -s tests/e2e -t . -v
bandit -q -ll -r . -x ./.venv,./tests
pip-audit -r requirements.txt
```

Add regression tests for behavior changes. Never include real targets, secrets, scan output,
or exploit payloads in commits or issues.
