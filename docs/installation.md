# Installation

Authority requires **Python 3.10 or newer**. The only hard runtime dependency
is SQLite, which ships with the standard library.

## From PyPI

```bash
pip install authority-auth
```

## Extras

Optional features live behind extras so you only install what you need.

| Extra | Provides |
|---|---|
| `async` | `AsyncSQLiteStorage` (pulls in `aiosqlite`) |
| `fastapi` | `authority.fastapi` integration |
| `flask` | `authority.flask` integration |
| `django` | `authority.django` integration |
| `starlette` | `authority.starlette` integration |
| `quart` | Quart support via the ASGI middleware |
| `dev` | Test and tooling dependencies (pytest, ruff, pyright, framework extras) |
| `docs` | Tooling to build this documentation site (MkDocs + Material) |

Install several extras at once:

```bash
pip install "authority-auth[async,fastapi,flask,django,starlette]"
```

For the example applications you also need `uvicorn` (the ASGI apps run on it):

```bash
pip install "authority-auth[dev]" uvicorn
```

## From source

```bash
git clone https://github.com/rkriad585/authority.git
cd authority

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -e ".[dev]"
```

The editable install keeps the `authority` package importable from `src/` and
registers the `authority-auth` distribution metadata (so `authority.__version__`
resolves correctly).

## Verify the install

```python
import authority

print(authority.__version__)
```

You should see the installed version, e.g. `0.2.0`.
