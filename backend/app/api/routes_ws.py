import asyncio

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.api.deps import apply_company_scope
from app.core.security import decode_access_token
from app.db.session import SessionLocal
from app.models.models import AgentTraceEvent, ScanJob, ScanLog, SkillScore, User
from app.services import credential_capture_service


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
        query = apply_company_scope(query, user, ScanJob)
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


def _auth_scan(db: Session, scan_id: int, token: str):
    """Returns (user, job) or (None, None) if auth fails."""
    subject = decode_access_token(token)
    if not subject:
        return None, None
    user = db.query(User).filter(User.id == int(subject)).first()
    if not user:
        return None, None
    q = db.query(ScanJob).filter(ScanJob.id == scan_id)
    q = apply_company_scope(q, user, ScanJob)
    return user, q.first()


@router.websocket("/ws/scans/{scan_id}/identities/capture/{capture_session_id}")
async def ws_credential_capture(websocket: WebSocket, scan_id: int, capture_session_id: str):
    """Bidirectional: streams CDP screencast frames of a live, operator-driven
    Playwright session (started via the REST /identities/capture/start route)
    to the client, and forwards the client's mouse/keyboard events back into
    that session via CDP. See credential_capture_service.py for the capture
    lifecycle and the in-scope-only header/cookie filtering."""
    token = websocket.query_params.get("token", "")
    db: Session = SessionLocal()
    try:
        user, job = _auth_scan(db, scan_id, token)
        if not user or not job:
            await websocket.close(code=4401)
            return

        capture = credential_capture_service.get_capture(capture_session_id, scan_id)
        if capture is None:
            await websocket.close(code=4404)
            return

        await websocket.accept()
        send_lock = asyncio.Lock()

        async def _on_frame(params: dict) -> None:
            try:
                async with send_lock:
                    await websocket.send_json(
                        {"type": "frame", "data": params.get("data"), "sessionId": params.get("sessionId")}
                    )
                await capture.cdp.send("Page.screencastFrameAck", {"sessionId": params.get("sessionId")})
            except Exception:
                pass  # a dropped/failed frame shouldn't kill the CDP session

        capture.cdp.on("Page.screencastFrame", _on_frame)
        # Started here, not in start_capture — CDP sends an immediate frame of
        # the CURRENT page state the moment startScreencast is called, which is
        # exactly what an operator connecting to an already-loaded, already-
        # settled page needs. Starting it earlier (before any listener exists)
        # means that immediate frame — and any repaint before this connects —
        # fires into nothing, and a static page never repaints again on its
        # own, leaving the canvas black with no frame ever arriving.
        try:
            await capture.cdp.send(
                "Page.startScreencast",
                {"format": "jpeg", "quality": 70, "maxWidth": 1280, "maxHeight": 800, "everyNthFrame": 1},
            )
        except Exception:
            pass

        try:
            while True:
                msg = await websocket.receive_json()
                await credential_capture_service.apply_input_event(capture, msg)
        except WebSocketDisconnect:
            # Operator may reconnect mid-flow (e.g. flaky wifi during MFA) —
            # the capture (browser/context) stays alive; only this socket's
            # frame listener needs to go, or screencastFrame keeps firing into
            # a dead callback on every reconnect.
            pass
        finally:
            try:
                await capture.cdp.send("Page.stopScreencast")
            except Exception:
                pass
            try:
                capture.cdp.remove_listener("Page.screencastFrame", _on_frame)
            except Exception:
                pass
    finally:
        db.close()


@router.websocket("/ws/scans/{scan_id}/trace")
async def ws_scan_trace(websocket: WebSocket, scan_id: int):
    """Stream agent trace events in real-time for the visual flow page."""
    token = websocket.query_params.get("token", "")
    db: Session = SessionLocal()
    try:
        user, job = _auth_scan(db, scan_id, token)
        if not user or not job:
            await websocket.close(code=4401)
            return

        await websocket.accept()
        last_id = 0

        while True:
            events = (
                db.query(AgentTraceEvent)
                .filter(AgentTraceEvent.scan_id == scan_id, AgentTraceEvent.id > last_id)
                .order_by(AgentTraceEvent.id.asc())
                .limit(50)
                .all()
            )
            if events:
                payload = [
                    {
                        "id": row.id,
                        "iteration": row.iteration,
                        "event_type": row.event_type,
                        "from_node": row.from_node,
                        "to_node": row.to_node,
                        "skill_id": row.skill_id,
                        "tool_name": row.tool_name,
                        "capability": row.capability,
                        "status": row.status,
                        "duration_ms": row.duration_ms,
                        "payload": row.payload,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in events
                ]
                last_id = events[-1].id
                await websocket.send_json({"type": "trace", "items": payload})

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return
    finally:
        db.close()


@router.get("/api/scans/{scan_id}/trace")
async def get_scan_trace(scan_id: int, token: str = "", limit: int = 200):
    """REST endpoint: returns recent trace events + skill scores for a scan."""
    db: Session = SessionLocal()
    try:
        user, job = _auth_scan(db, scan_id, token)
        if not user or not job:
            raise HTTPException(status_code=403, detail="Forbidden")

        events = (
            db.query(AgentTraceEvent)
            .filter(AgentTraceEvent.scan_id == scan_id)
            .order_by(AgentTraceEvent.id.desc())
            .limit(limit)
            .all()
        )
        scores = (
            db.query(SkillScore)
            .filter(SkillScore.scan_id == scan_id)
            .order_by(SkillScore.id.asc())
            .all()
        )
        return {
            "trace": [
                {
                    "id": row.id,
                    "iteration": row.iteration,
                    "event_type": row.event_type,
                    "from_node": row.from_node,
                    "to_node": row.to_node,
                    "skill_id": row.skill_id,
                    "tool_name": row.tool_name,
                    "capability": row.capability,
                    "status": row.status,
                    "duration_ms": row.duration_ms,
                    "payload": row.payload,
                    "created_at": row.created_at.isoformat(),
                }
                for row in reversed(events)
            ],
            "scores": [
                {
                    "id": row.id,
                    "iteration": row.iteration,
                    "skill_id": row.skill_id,
                    "capability": row.capability,
                    "library_hits": row.library_hits,
                    "tool_attempts": row.tool_attempts,
                    "tool_successes": row.tool_successes,
                    "tool_failures": row.tool_failures,
                    "findings_raw": row.findings_raw,
                    "findings_promoted": row.findings_promoted,
                    "efficiency_score": row.efficiency_score,
                    "productivity_score": row.productivity_score,
                    "created_at": row.created_at.isoformat(),
                }
                for row in scores
            ],
            # Hypothesis trail + kill-chain stage + tech-stack persisted by
            # the workflow's _sync_step_to_db.
            "hypotheses": list((job.state_data or {}).get("pentest_hypotheses") or [])[:30],
            "kill_chain_stage": str((job.state_data or {}).get("kill_chain_stage") or ""),
            "detected_tech_stack": list((job.state_data or {}).get("detected_tech_stack") or []),
        }
    finally:
        db.close()
