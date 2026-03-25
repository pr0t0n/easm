#!/bin/sh
set -eu

ROLE="${1:-recon}"
HOSTNAME_SUFFIX="${2:-worker}"

if command -v nproc >/dev/null 2>&1; then
  CPU_CORES="$(nproc)"
elif command -v getconf >/dev/null 2>&1; then
  CPU_CORES="$(getconf _NPROCESSORS_ONLN)"
else
  CPU_CORES=4
fi

if [ -z "${CPU_CORES}" ] || [ "${CPU_CORES}" -lt 1 ] 2>/dev/null; then
  CPU_CORES=4
fi

PREFETCH_MULTIPLIER="${CELERY_PREFETCH_MULTIPLIER:-1}"
MAX_TASKS_PER_CHILD="${CELERY_MAX_TASKS_PER_CHILD:-200}"
AUTOSCALE_CAP="${CELERY_AUTOSCALE_CAP:-64}"

calc_scale() {
  role="$1"
  cores="$2"
  case "$role" in
    recon)
      max=$((cores * 2))
      min=$((cores / 2))
      [ "$min" -lt 2 ] && min=2
      queues="scan.unit,scan.scheduled,worker.unit.reconhecimento,worker.scheduled.reconhecimento"
      ;;
    vuln)
      max=$((cores * 4))
      min=$cores
      [ "$min" -lt 4 ] && min=4
      queues="worker.unit.analise_vulnerabilidade,worker.scheduled.analise_vulnerabilidade"
      ;;
    osint)
      max=$((cores * 3))
      min=$((cores / 2))
      [ "$min" -lt 2 ] && min=2
      queues="worker.unit.osint,worker.scheduled.osint"
      ;;
    *)
      echo "Role invalido: $role (use recon|vuln|osint)" >&2
      exit 1
      ;;
  esac

  if [ "$max" -gt "$AUTOSCALE_CAP" ]; then
    max="$AUTOSCALE_CAP"
  fi
  if [ "$min" -gt "$max" ]; then
    min="$max"
  fi

  echo "$max,$min,$queues"
}

SCALE_DATA="$(calc_scale "$ROLE" "$CPU_CORES")"
AUTOSCALE_MAX="${SCALE_DATA%%,*}"
REST="${SCALE_DATA#*,}"
AUTOSCALE_MIN="${REST%%,*}"
QUEUES="${REST#*,}"

if [ -n "${CELERY_AUTOSCALE_MAX:-}" ]; then
  AUTOSCALE_MAX="${CELERY_AUTOSCALE_MAX}"
fi
if [ -n "${CELERY_AUTOSCALE_MIN:-}" ]; then
  AUTOSCALE_MIN="${CELERY_AUTOSCALE_MIN}"
fi
if [ "$AUTOSCALE_MIN" -gt "$AUTOSCALE_MAX" ]; then
  AUTOSCALE_MIN="$AUTOSCALE_MAX"
fi

echo "[worker-bootstrap] role=${ROLE} cpu=${CPU_CORES} autoscale=${AUTOSCALE_MAX},${AUTOSCALE_MIN} queues=${QUEUES}"

exec celery -A app.workers.celery_app.celery worker \
  --loglevel=INFO \
  --autoscale="${AUTOSCALE_MAX},${AUTOSCALE_MIN}" \
  --prefetch-multiplier="${PREFETCH_MULTIPLIER}" \
  --max-tasks-per-child="${MAX_TASKS_PER_CHILD}" \
  --queues="${QUEUES}" \
  --hostname="${HOSTNAME_SUFFIX}@%h"
