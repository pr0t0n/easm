"""Captura dinâmica de SPA/browser para alimentar o inventário."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import ScanJob
from app.services.crawler_result_normalizer import normalize_crawler_result
from app.services.hypothesis_rules import generate_hypotheses_for_scan


def run_browser_capture_for_scan(db: Session, scan: ScanJob, *, target: str, identity_key: str = "") -> dict[str, Any]:
    if not settings.enable_browser_capture:
        return {"skipped": "browser_capture_disabled"}
    result = _run_chromium_capture(target, scan.id, identity_key)
    summary = normalize_crawler_result(
        db,
        scan,
        target=target,
        tool_name="chromium-capture",
        result=result,
        auth_context=identity_key or "anonymous",
    )
    hyp = generate_hypotheses_for_scan(db, scan)
    db.flush()
    return {"target": target, "capture": result.get("status", "unknown"), "inventory": summary, "hypotheses": hyp}


def _run_chromium_capture(target: str, scan_id: int, identity_key: str = "") -> dict[str, Any]:
    try:
        from app.services.kali_executor import execute_via_kali

        extra = {"identity_key": identity_key, "capture_har": settings.browser_capture_har, "screenshots": settings.browser_capture_screenshots}
        return execute_via_kali("chromium-capture", target, scan_id=scan_id, max_wait=settings.browser_max_duration_seconds, extra_args=extra)
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "error": type(exc).__name__,
            "stderr": str(exc)[:500],
            "stdout": "",
            "parsed_result": {"urls": [target]},
        }
