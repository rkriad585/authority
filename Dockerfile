# Authority demo/example image.
#
# Builds a small image that runs the FastAPI example app from examples/apps/.
# It is intended for local demos and quick experiments, not production use.
#
# Build:
#   docker build -t authority-demo .
#
# Run:
#   docker run --rm -p 8000:8000 -v ${PWD}:/app authority-demo
#
# The volume mount keeps the SQLite database on the host so data persists
# between container restarts.

FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN pip install --no-cache-dir ".[fastapi,async]" uvicorn

FROM python:3.12-slim

WORKDIR /app

# Copy the fully installed site-packages and the source tree from the builder.
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /app /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

CMD ["uvicorn", "examples.apps.fastapi_app.app:app", "--host", "0.0.0.0", "--port", "8000"]
