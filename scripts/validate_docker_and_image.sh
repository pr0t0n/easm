#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

IMAGE_NAME="${1:-easm-backend:cyber-autoagent}"

echo "[1/4] Checking docker daemon"
docker info >/dev/null

echo "[2/4] Validating compose file"
docker compose config >/dev/null

echo "[3/4] Building backend image: $IMAGE_NAME"
docker build -f backend/Dockerfile -t "$IMAGE_NAME" backend

echo "[4/4] Running smoke command inside image"
docker run --rm \
	-e DATABASE_URL="postgresql://easm:easm@localhost:5432/easm" \
	-e REDIS_URL="redis://localhost:6379/0" \
	-e CELERY_BROKER_URL="redis://localhost:6379/0" \
	-e CELERY_RESULT_BACKEND="redis://localhost:6379/1" \
	"$IMAGE_NAME" \
	python -c "import app.main; print('backend_import_ok')"

echo "Docker and image validation completed successfully: $IMAGE_NAME"
