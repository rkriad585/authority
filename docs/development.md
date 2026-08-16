# Development

Guide for contributing to `authority-auth` itself.

## Setup

```bash
git clone https://github.com/rkriad585/authority.git
cd authority

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -e ".[dev,async]"
pip install uvicorn   # needed by the ASGI example apps
```

## Layout

```
src/authority/          the library
  core.py               AuthManager (sync)
  async_core.py         AsyncAuthManager
  config.py             AuthConfig
  events.py             Event, EventBus
  exceptions.py         exception hierarchy
  utils.py              standalone helpers
  storage/              StorageInterface, SQLiteStorage, AsyncSQLiteStorage
  fastapi.py / flask.py / django.py / starlette.py / asgi.py / wsgi.py
tests/                  pytest suite
examples/apps/          runnable per-framework example applications
tools/                  developer tooling (e.g. screenshots generator)
docs/                   this documentation site
logo/                   logo assets
Screenshots/            generated screenshots used by the docs
```

## Running the checks

```bash
pytest                 # full test suite
ruff check src/ tests/  # lint
ruff format --check src/ tests/  # formatting
pyright src/authority/ # type checking
```

The repository runs all four on CI (`.github/workflows/ci.yml`) against Python
3.10–3.13, plus a build job that runs `python -m build` and `twine check`.

## Test suite notes

- pytest is configured in `pyproject.toml` with `asyncio_mode = "auto"`, so
  async tests do not need explicit markers.
- Tests that make real HTTP requests are marked `network` and are skipped with
  `pytest -m "not network"`.
- Coverage is enforced at 83% via `tool.coverage` (`fail_under = 83`).

## Code style

- Line length 88, target Python 3.10 (see `tool.ruff` in `pyproject.toml`).
- Import sorting: `isort`-style with `known-first-party = ["authority"]`.
- Type hints are expected throughout `src/`; pyright runs in `standard` mode.
- The `webauthn` dependency is optional at type-check time for some test
  blocks — see the existing `# noqa` / `# type: ignore` comments in the tests.

## Regenerating screenshots

The screenshots in `Screenshots/` are generated with `tools/screenshots_gen.py`:

```bash
python tools/screenshots_gen.py
```

The generator renders terminal-style PNGs with Pillow, using monospace fonts
from a platform-specific candidate list.

## Building the documentation

```bash
pip install -e ".[docs]"
mkdocs serve          # local preview at http://127.0.0.1:8000
mkdocs build --strict # production build (fails on warnings)
```

The docs site is deployed to GitHub Pages from the `main` branch by
`.github/workflows/docs.yml`.

## Releasing

`authority-auth` uses hatchling; the version lives in `.version`. Release
roughly means: bump `.version`, update `CHANGELOG.md`, tag, and upload:

```bash
python -m build
twine upload dist/*
```
