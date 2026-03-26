import os

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings
from app.workers.worker_groups import SCAN_SCHEDULED_QUEUE


celery = Celery(
    "easm_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery.conf.update(
    task_track_started=True,
    worker_prefetch_multiplier=max(1, int(os.getenv("CELERY_PREFETCH_MULTIPLIER", "1"))),
    worker_max_tasks_per_child=max(50, int(os.getenv("CELERY_MAX_TASKS_PER_CHILD", "200"))),
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_disable_rate_limits=True,
    beat_schedule={
        # Dispara a cada minuto para verificar schedules devidos
        "scheduler-tick": {
            "task": "scheduler.tick",
            "schedule": crontab(minute="*"),
            "options": {"queue": SCAN_SCHEDULED_QUEUE},
        },
    },
    timezone="America/Sao_Paulo",
)
