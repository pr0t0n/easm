from celery import Celery
from celery.schedules import crontab

from app.core.config import settings


celery = Celery(
    "easm_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery.conf.update(
    task_track_started=True,
    beat_schedule={
        # Dispara a cada minuto para verificar schedules devidos
        "scheduler-tick": {
            "task": "scheduler.tick",
            "schedule": crontab(minute="*"),
        },
    },
    timezone="America/Sao_Paulo",
)
