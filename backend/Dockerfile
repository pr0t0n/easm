# Backend image - pure Python FastAPI + Celery.
# No analysis/offensive tooling is installed here. Workers dispatch tools to
# the kali_runner sidecar via HTTP.
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      gcc \
      libpq-dev \
      python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Runtime-only packages. Offensive scanners and analysis CLIs live exclusively
# in the Kali runner image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      libpq5 \
      tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY . .

# Non-root runtime user
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1000 appuser && \
    chown -R appuser:appgroup /app
ENV HOME=/tmp
USER appuser

CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
