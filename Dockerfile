FROM python:3.13-slim AS base

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ── Dependencies ──────────────────────────────────────────────────────
COPY pyproject.toml README.md ./
COPY infraguard/ infraguard/
COPY examples/ examples/
COPY pages/ pages/

RUN pip install --no-cache-dir ".[all]"

# ── Runtime ───────────────────────────────────────────────────────────
# Config, profiles, and .env are mounted at runtime
VOLUME ["/app/config", "/app/examples", "/app/data"]

EXPOSE 443 80 8080

ENTRYPOINT ["infraguard"]
CMD ["run", "-c", "/app/config/config.yaml"]
