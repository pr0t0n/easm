import os

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings
from app.workers.worker_groups import (
    SCAN_SCHEDULED_QUEUE,
    SCAN_UNIT_QUEUE,
    SCAN_PARALLEL_QUEUE,
    all_queues,
)

# Heartbeat em leque: um agendamento por fila de worker, para que TODOS os
# workers se registrem vivos a cada 30s (não só o que pega a fila default).
try:
    _HEARTBEAT_QUEUES = sorted(set(all_queues("unit")) | {SCAN_UNIT_QUEUE, SCAN_PARALLEL_QUEUE})
except Exception:
    _HEARTBEAT_QUEUES = [SCAN_UNIT_QUEUE]
_HEARTBEAT_SCHEDULE = {
    f"worker-heartbeat-{_q}": {
        "task": "worker.heartbeat",
        "schedule": 30.0,
        "options": {"queue": _q},
    }
    for _q in _HEARTBEAT_QUEUES
}


celery = Celery(
    "easm_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "app.workers.tasks",
    ],
)

celery.conf.update(
    task_track_started=True,
    worker_prefetch_multiplier=max(1, int(os.getenv("CELERY_PREFETCH_MULTIPLIER", "1"))),
    worker_max_tasks_per_child=max(50, int(os.getenv("CELERY_MAX_TASKS_PER_CHILD", "200"))),
    task_soft_time_limit=max(60, int(os.getenv("CELERY_TASK_SOFT_TIME_LIMIT", "21600"))),
    task_time_limit=max(90, int(os.getenv("CELERY_TASK_TIME_LIMIT", "22200"))),
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_disable_rate_limits=True,
    # Tier 1-D: Results expire after 1h — subtask results are never consumed by
    # the caller (fire-and-forget), so without this they accumulate in Redis forever.
    result_expires=int(os.getenv("CELERY_RESULT_EXPIRES", "3600")),
    # Tier 4-D: Compress task payloads with zlib — scan state dicts can be 10-50KB;
    # compression reduces Redis memory and broker I/O by ~70%.
    task_compression="zlib",
    result_compression="zlib",
    # Tier 4-D: Limit broker connection pool to avoid Redis socket exhaustion
    # under high worker concurrency (9 workers × 16 threads = 144 potential conns).
    broker_pool_limit=int(os.getenv("CELERY_BROKER_POOL_LIMIT", "20")),
    broker_transport_options={
        # Must be >= task_time_limit otherwise long-running scans get redelivered
        # and re-executed from P01 (orphan retry storm).
        "visibility_timeout": max(300, int(os.getenv("CELERY_VISIBILITY_TIMEOUT", "25200"))),
    },
    beat_schedule={
        # Dispara a cada minuto para verificar schedules devidos
        "scheduler-tick": {
            "task": "scheduler.tick",
            "schedule": crontab(minute="*"),
            "options": {"queue": SCAN_SCHEDULED_QUEUE},
        },
        # Watchdog: prevê/auto-recupera 'Up mas travado' (kali wedge, stall de scan).
        "watchdog-tick": {
            "task": "watchdog.tick",
            "schedule": crontab(minute="*"),
            "options": {"queue": SCAN_SCHEDULED_QUEUE},
        },
        # Ingestao semanal do aprendizado HackerOne/GitHub (antes so rodava sob demanda).
        "hackerone-learning-tick": {
            "task": "hackerone_learning.tick",
            "schedule": crontab(minute="0", hour="3", day_of_week="1"),
            "options": {"queue": "worker.unit.reporting"},
        },
        # Mantém tool_health_snapshots fresco p/ ENFORCE_TOOL_HEALTH_PRECHECK
        # nunca operar fail-open por falta de snapshot (ver create_scan).
        "tool-health-refresh": {
            "task": "tool_health.refresh",
            "schedule": crontab(minute="*/20"),
            "options": {"queue": SCAN_SCHEDULED_QUEUE},
        },
        **_HEARTBEAT_SCHEDULE,
    },
    timezone="America/Sao_Paulo",
)
