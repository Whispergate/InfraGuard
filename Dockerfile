# syntax=docker/dockerfile:1.7-labs
# InfraGuard - hardened multi-stage build
# Produces a minimal, non-root, read-only rootfs container image.

# ── Stage 1: Build dependencies ─────────────────────────────────────────
FROM python:3.13-slim AS builder

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build tools needed for some Python packages (cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only what we need for dependency resolution
COPY pyproject.toml README.md ./
COPY infraguard/ infraguard/

# Build wheels for all dependencies (avoids build-time tools in final image)
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[all]"


# ── Stage 2: Runtime ───────────────────────────────────────────────────
FROM python:3.13-slim AS runtime

# ── Security: non-root user (UID 1000) ────────────────────────────────
ARG APP_UID=1000
ARG APP_GID=1000
ARG APP_USER=infraguard

# Create non-root user and group before copying files
RUN groupadd --gid "${APP_GID}" "${APP_USER}" \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" \
       --shell /usr/sbin/nologin --no-create-home "${APP_USER}"

# ── Hardened environment ───────────────────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Run as non-root
    APP_UID="${APP_UID}" \
    APP_GID="${APP_GID}" \
    # Writable tmpfs locations (mounted at runtime via tmpfs in compose)
    TMPDIR=/tmp \
    # pip cache in a tmpfs-friendly location
    PIP_CACHE_DIR=/tmp/.pip-cache \
    # Ensure infraguard can find its data directory
    INFRAGUARD_DATA_DIR=/app/data

WORKDIR /app

# ── Runtime OS packages ────────────────────────────────────────────────
# git is required for the config-history audit repo (v0.5). The
# dashboard commits every mutation to INFRAGUARD_CONFIG_HISTORY;
# without git the persist call still succeeds but the audit log is
# skipped.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# ── Install runtime dependencies from pre-built wheels ─────────────────
# Only install runtime deps; build tools (gcc, g++) are not in this stage.
COPY --from=builder /wheels /wheels

RUN pip install --no-cache-dir --no-index --find-links /wheels \
    "infraguard[all]" \
    && rm -rf /wheels

# ── Copy application code ───────────────────────────────────────────────
COPY --chown="${APP_UID}:${APP_GID}" infraguard/ /app/infraguard/
COPY --chown="${APP_UID}:${APP_GID}" examples/ /app/examples/
COPY --chown="${APP_UID}:${APP_GID}" pages/ /app/pages/
# Rules directory ships as read-only signature files; data-driven intel
# in v0.5 reads from here. Mount /app/rules read-only at runtime so
# operators can hot-swap signatures without rebuilding the image.
COPY --chown="${APP_UID}:${APP_GID}" rules/ /app/rules/

# ── Prepare writable directories ────────────────────────────────────────
# These will be backed by tmpfs or named volumes at runtime for read-only rootfs.
# Create with correct ownership so the app can write even before tmpfs mounts.
RUN mkdir -p /app/data /tmp/.pip-cache \
    && chown -R "${APP_UID}:${APP_GID}" /app/data /tmp/.pip-cache

# ── Declare volume mount points (documentation only; compose manages mounts) ─
VOLUME ["/app/data", "/app/config", "/app/certs", "/app/geoip", "/app/rules"]

# ── Security: switch to non-root user ──────────────────────────────────
USER "${APP_UID}:${APP_GID}"

# ── Expose ports (informational) ────────────────────────────────────────
# 443/tcp (HTTP/1.1 + HTTP/2), 443/udp (HTTP/3 QUIC when enabled), 80/tcp
# (ACME challenges + Alt-Svc discovery), 8080/tcp (dashboard API).
EXPOSE 443/tcp 443/udp 80/tcp 8080/tcp

# ── Health check (uses configurable path via env var) ───────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=5 \
    CMD ["python3", "-c", \
         "import urllib.request,ssl,os; \
          p=os.environ.get('INFRAGUARD_HEALTH_PATH','health').strip('/'); \
          port=os.environ.get('INFRAGUARD_HEALTH_PORT','443'); \
          scheme='https' if port=='443' else 'http'; \
          ctx=ssl._create_unverified_context() if scheme=='https' else None; \
          urllib.request.urlopen(f'{scheme}://127.0.0.1:{port}/{p}', context=ctx)"]

# ── Entrypoint ─────────────────────────────────────────────────────────
ENTRYPOINT ["infraguard"]
CMD ["run", "-c", "/app/config/config.yaml"]
