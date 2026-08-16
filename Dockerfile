# Authority container image.
#
# Runs the FastAPI example app from examples/apps/ (examples.apps.fastapi_app.app).
# This is a demo/example image, not the production runtime of the library.
#
# Build:
#   docker build -t ghcr.io/rkriad585/authority .
#
# Run:
#   docker run --rm -p 8000:8000 -v ${PWD}:/app ghcr.io/rkriad585/authority
#
# The volume mount keeps the SQLite database on the host so data persists
# between container restarts.
#
# Reproducibility: uvicorn is pinned to the version verified in development.
# The `python:3.12-slim` base tag floats; pin a digest for fully reproducible
# builds.

# Metadata overridable at build time (the publish workflow supplies these).
ARG VERSION=0.0.0
ARG SOURCE_COMMIT=unknown
ARG SOURCE_REPOSITORY=https://github.com/rkriad585/authority

# --------------------------------------------------------------------------
# Builder stage: install production dependencies only.
# --------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
COPY examples ./examples

RUN pip install --no-cache-dir --no-compile ".[fastapi,async]" "uvicorn==0.52.3"

# --------------------------------------------------------------------------
# Runtime stage: minimal image with the app and its production deps.
# --------------------------------------------------------------------------
FROM python:3.12-slim

ARG VERSION
ARG SOURCE_COMMIT
ARG SOURCE_REPOSITORY

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Create a non-root user. The example app writes its SQLite database to the
# working directory, so /app must be writable by this user.
RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --create-home appuser

# Copy the fully installed site-packages from the builder, plus the example
# app source tree. The library itself is imported from site-packages.
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /app/examples /app/examples

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

LABEL org.opencontainers.image.title="Authority Example App" \
      org.opencontainers.image.description="Framework-agnostic Python authentication library (JWT, MFA, WebAuthn, RBAC, API keys) running the FastAPI example app" \
      org.opencontainers.image.url="${SOURCE_REPOSITORY}" \
      org.opencontainers.image.source="${SOURCE_REPOSITORY}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${SOURCE_COMMIT}" \
      org.opencontainers.image.vendor="rkriad585" \
      org.opencontainers.image.licenses="MIT"

CMD ["uvicorn", "examples.apps.fastapi_app.app:app", "--host", "0.0.0.0", "--port", "8000"]
