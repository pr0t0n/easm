import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import SessionLocal
from app.models.models import ScanJob, ScanLog, User


router = APIRouter(tags=["ws"])


@router.websocket("/ws/scans/{scan_id}/logs")
async def ws_scan_logs(websocket: WebSocket, scan_id: int):
    token = websocket.query_params.get("token", "")
    subject = decode_access_token(token)
    if not subject:
        await websocket.close(code=4401)
        return

    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(subject)).first()
        if not user:
            await websocket.close(code=4401)
            return

        query = db.query(ScanJob).filter(ScanJob.id == scan_id)
        if not user.is_admin:
            allowed_ids = [g.id for g in user.groups]
            query = query.filter((ScanJob.owner_id == user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
        job = query.first()
        if not job:
            await websocket.close(code=4403)
            return

        await websocket.accept()
        last_id = 0

        while True:
            logs = (
                db.query(ScanLog)
                .filter(ScanLog.scan_job_id == scan_id, ScanLog.id > last_id)
                .order_by(ScanLog.id.asc())
                .limit(200)
                .all()
            )
            if logs:
                payload = [
                    {
                        "id": row.id,
                        "source": row.source,
                        "level": row.level,
                        "message": row.message,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in logs
                ]
                last_id = logs[-1].id
                await websocket.send_json({"type": "logs", "items": payload})

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return
    finally:
        db.close()
