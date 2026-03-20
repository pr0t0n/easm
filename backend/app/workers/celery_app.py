from celery import Celery

from app.core.config import settings


celery = Celery(
    "easm_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery.conf.update(task_track_started=True)

# garante registro de tasks
import app.workers.tasks  # noqa: E402,F401
