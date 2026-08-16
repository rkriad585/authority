# Contributing to authority-auth

Thanks for your interest in contributing! This document covers how to set up a development environment, run checks, and submit changes.

## Development Setup

Requires Python 3.10+.

```bash
# Clone the repository
git clone https://github.com/rkriad585/authority.git
cd authority

# Create and activate a virtual environment (optional but recommended)
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

# Install the package with all extras
pip install -e ".[dev,async]"
```

## Running Tests

```bash
# Full test suite (skips network-dependent HIBP tests)
pytest -m "not network" --ignore=tests/test_fastapi.py

# With coverage
pytest --cov=authority --cov-report=term-missing
```

Network tests are marked with `network` and are deselected by default.

## Linting & Formatting

```bash
# Lint
ruff check src/ tests/

# Check formatting
ruff format --check src/ tests/

# Auto-format
ruff format src/ tests/
```

## Type Checking

```bash
pyright src/authority/
```

## Project Structure

- `src/authority/core.py` — synchronous `AuthManager`
- `src/authority/async_core.py` — asynchronous `AsyncAuthManager`
- `src/authority/storage/` — pluggable storage backends (base interface, SQLite, async SQLite)
- `src/authority/fastapi.py` — optional FastAPI helpers (requires the `fastapi` extra)
- `tests/` — pytest suite; keep sync and async behavior mirrored between `test_core.py` and `test_async_core.py`

## Conventions

- Keep `AuthManager` and `AsyncAuthManager` feature- and behavior-parallel. New public methods must be added to both.
- New storage methods must be added to `StorageInterface` / `AsyncStorageInterface` in `src/authority/storage/base.py` and implemented in both SQLite backends.
- Every public method needs a docstring with `Args:` and `Raises:` sections where applicable.
- New features should come with tests, and the coverage floor (`fail_under = 83`) must be maintained.

## Versioning & Releases

The version is sourced from the `.version` file (`[tool.hatch.version] path = ".version"`). Bump it and add a CHANGELOG.md entry before a release. Publish to PyPI manually:

```bash
pip install build twine
python -m build
twine check dist/*
twine upload dist/*
```

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Implement your change with tests, matching the conventions above.
3. Run the full check suite: `ruff check`, `ruff format --check`, `pyright`, and `pytest`.
4. Open a pull request against `main` describing the change.

## License

By contributing, you agree that your contributions will be licensed under the project's MIT license.
