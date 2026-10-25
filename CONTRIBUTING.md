# Contributing

Please open an issue describing the input, expected behavior, and actual output.
Use a small synthetic fixture without private data. Do not upload production alerts
or restricted collections. Discuss scope changes before implementation.

Development uses Python 3.11 or later:

```sh
python -m venv .venv
# Activate .venv using your shell's activation command.
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m build
```

Changes to parsing or interpretation need a regression fixture and documentation.
Keep the runtime offline and dependencies minimal. Never silently drop unsupported input.
