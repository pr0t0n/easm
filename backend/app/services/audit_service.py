from sqlalchemy.orm import Session

from app.models.models import AuditEvent


def log_audit(
    db: Session,
    event_type: str,
    message: str,
    *,
    actor_user_id: int | None = None,
    scan_job_id: int | None = None,
    level: str = "INFO",
    metadata: dict | None = None,
):
    db.add(
        AuditEvent(
            actor_user_id=actor_user_id,
            scan_job_id=scan_job_id,
            event_type=event_type,
            level=level,
            message=message,
            event_metadata=metadata or {},
        )
    )
