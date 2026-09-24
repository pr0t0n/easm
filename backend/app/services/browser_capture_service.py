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
    result = _run_chromium_capture(db, scan, target, identity_key)
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


# Generic single-page-app section names common to any account/e-commerce style
# app (login, checkout, support, ...) -- not derived from any specific target's
# challenge list. cdp_capture.py's own single home-page load only ever sees the
# handful of XHRs that fire automatically on "/"; a SPA's real REST surface
# (search, basket, profile, ...) only appears once something actually
# navigates to those client-side routes. This is the same idea as a generic
# ffuf wordlist for directory brute-forcing, applied to hash-routed SPA nav.
_GENERIC_SPA_ROUTES = [
    "#/login", "#/register", "#/search", "#/contact", "#/about",
    "#/profile", "#/basket", "#/order-history", "#/privacy-security",
    "#/complain", "#/faq", "#/photo-wall",
]


def _run_chromium_capture(db: Session, scan: ScanJob, target: str, identity_key: str = "") -> dict[str, Any]:
    try:
        from app.services.auth_session_manager import AuthSessionManager
        from app.services.kali_executor import execute_via_kali

        # cdp_capture.py's argv contract is positional: [target, wait, TOKEN,
        # USER, PASS, ROUTES] -- extra_args must be a plain list of strings in
        # that order, never a dict (execute_via_kali iterates it as CLI argv,
        # so a dict silently degenerated into its bare key names with every
        # real value dropped). TOKEN comes from the scan's own captured
        # session for this identity, never invented.
        #
        # Previously extra_args was just [token], which silently dropped USER/
        # PASS/ROUTES (argv[4:6]) -- cdp_capture.py's route-navigation feature
        # (built specifically to expand a SPA's captured surface beyond the
        # single home-page load) has never actually been exercised by any
        # caller. Confirmed live on scan #41 (Juice Shop): chromium-capture
        # only ever saw the 6 XHRs that fire on "/" and never discovered the
        # app's real REST surface (basket, profile, search, ...) because
        # nothing ever told it to navigate anywhere else.
        token = ""
        if identity_key:
            material = AuthSessionManager(db, scan).get_material(identity_key)
            if material and material.valid:
                auth_header = material.headers.get("Authorization") or material.headers.get("authorization") or ""
                token = auth_header.removeprefix("Bearer ").strip()
        routes_csv = ",".join(_GENERIC_SPA_ROUTES)
        # "-" (not "") for the unused USER/PASS slots: execute_via_kali (like
        # mcp_server's own extra_args guardrail) drops any arg where
        # str(arg).strip() is falsy, silently shifting ROUTES one slot left
        # into the USER position. cdp_capture.py treats "-" as "no value".
        return execute_via_kali(
            "chromium-capture", target, scan_id=scan.id,
            max_wait=settings.browser_max_duration_seconds,
            extra_args=[token or "-", "-", "-", routes_csv],
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "failed",
            "error": type(exc).__name__,
            "stderr": str(exc)[:500],
            "stdout": "",
            "parsed_result": {"urls": [target]},
        }
