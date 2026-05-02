# Backend image — pure Python FastAPI + Celery.
# After the Kali runner refactor, ZERO offensive tooling ships here.
# Workers dispatch every tool to the kali_runner sidecar via HTTP.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Minimal runtime: ssl/curl for outbound HTTP, postgres client, dnsutils for
# scope validation pre-flight only. NO offensive tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget jq \
      libpq-dev gcc python3-dev \
      dnsutils \
      tzdata \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Non-root runtime user
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1000 appuser && \
    chown -R appuser:appgroup /app
ENV HOME=/tmp
USER appuser

CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
