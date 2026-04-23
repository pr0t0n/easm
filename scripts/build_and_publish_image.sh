#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

REGISTRY="${REGISTRY:-}"
IMAGE_REPO="${IMAGE_REPO:-easm/backend}"
IMAGE_TAG="${IMAGE_TAG:-cyber-autoagent-$(date +%Y%m%d-%H%M)}"
LOCAL_IMAGE="${LOCAL_IMAGE:-easm-backend:cyber-autoagent}"

if [[ -z "$REGISTRY" ]]; then
  echo "REGISTRY is required. Example: REGISTRY=ghcr.io/pr0t0n"
  exit 1
fi

REMOTE_IMAGE="${REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"

"$ROOT_DIR/scripts/validate_docker_and_image.sh" "$LOCAL_IMAGE"

docker tag "$LOCAL_IMAGE" "$REMOTE_IMAGE"
echo "Pushing image: $REMOTE_IMAGE"
docker push "$REMOTE_IMAGE"

echo "Published image: $REMOTE_IMAGE"
