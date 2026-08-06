"""Interactive, operator-driven authenticated-session capture.

An operator drives a server-side Playwright browser (hosted in the
`browser_runner` container) through a live CDP screencast streamed into the
platform's own UI, to manually complete a login — including MFA/SSO redirects
to a third-party identity provider — entirely inside the platform, with zero
external programs and zero certificate-trust setup (Playwright *is* the
browser; there is no MITM proxy in this path).

Captured Authorization headers and cookies are filtered to ONLY the scan's
authorized target hosts as traffic is observed — anything from a third-party
IdP (e.g. login.microsoftonline.com) is discarded immediately, never buffered,
never logged. Confirming a capture persists it via
AuthSessionManager.upsert_captured_material, encrypted at rest.

Lifecycle: start_capture -> (operator drives the page via the WS endpoint,
apply_input_event) -> confirm_capture (persists + closes) or cancel_capture
(closes, no DB write). Sessions live in an in-process dict — see the plan's
note on backend worker-process affinity for this MVP.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import Browser, BrowserContext, CDPSession, Page, Playwright, async_playwright
from sqlalchemy.orm import Session

from app.models.models import ScanJob
from app.services.auth_session_manager import AuthMaterial, AuthSessionManager
from app.services.scan_scope import authorized_scope_for_scan, host_from_scope_reference, is_host_in_scope

BROWSER_RUNNER_WS_URL = "ws://browser_runner:9222/playwright"
IDLE_TIMEOUT_SECONDS = 15 * 60
# Headers worth retaining verbatim once we've confirmed the request's host is
# in-scope — Authorization plus common tenant/org-scoping headers seen on real
# multi-tenant targets (X-Organization-Id and friends), not an exhaustive list.
_CAPTURED_HEADER_NAMES = {"authorization", "x-organization-id", "x-project-id", "x-tenant-id"}


@dataclass
class CaptureSession:
    capture_session_id: str
    scan_id: int
    identity_key: str
    role: str
    username_ref: str
    authorized_scope: list[str]
    playwright: Playwright
    browser: Browser
    context: BrowserContext
    page: Page
    cdp: CDPSession
    status: str = "active"
    captured_headers: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.monotonic)
    last_activity_at: float = field(default_factory=time.monotonic)


_ACTIVE_CAPTURES: dict[str, CaptureSession] = {}


def _filter_headers_to_scope(url: str, headers: dict[str, str], authorized_scope: list[str]) -> dict[str, str]:
    """Pure function (no I/O) — kept separate from the live-browser plumbing so
    it's directly unit-testable with fixture data, including a third-party IdP
    fixture to prove exclusion."""
    host = urlparse(url).hostname or ""
    if not host or not is_host_in_scope(host, authorized_scope):
        return {}
    out: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _CAPTURED_HEADER_NAMES:
            out[name] = value
    return out


def _filter_cookies_to_scope(cookies: list[dict[str, Any]], authorized_scope: list[str]) -> list[dict[str, Any]]:
    kept = []
    for cookie in cookies:
        domain = host_from_scope_reference(str(cookie.get("domain") or "").lstrip("."))
        if domain and is_host_in_scope(domain, authorized_scope):
            kept.append(cookie)
    return kept


async def start_capture(
    db: Session, scan: ScanJob, identity_key: str, role: str = "", username_ref: str = ""
) -> CaptureSession:
    authorized_scope = authorized_scope_for_scan(db, scan.id)
    playwright = await async_playwright().start()
    try:
        browser = await playwright.chromium.connect(BROWSER_RUNNER_WS_URL)
        context = await browser.new_context()
        page = await context.new_page()
        cdp = await context.new_cdp_session(page)
    except Exception:
        await playwright.stop()
        raise

    capture_session_id = uuid.uuid4().hex
    capture = CaptureSession(
        capture_session_id=capture_session_id,
        scan_id=scan.id,
        identity_key=identity_key,
        role=role,
        username_ref=username_ref,
        authorized_scope=authorized_scope,
        playwright=playwright,
        browser=browser,
        context=context,
        page=page,
        cdp=cdp,
    )

    def _on_response(response: Any) -> None:
        try:
            in_scope = _filter_headers_to_scope(response.url, response.request.headers, capture.authorized_scope)
        except Exception:
            return
        if in_scope:
            capture.captured_headers.update(in_scope)
            capture.last_activity_at = time.monotonic()

    page.on("response", _on_response)

    # Page.startScreencast is deliberately NOT called here. CDP only pushes a
    # NEW frame on repaint — starting the screencast now, before any WS client
    # is listening, means the page's initial load/settle repaints fire into a
    # void, and an operator who connects moments later (the normal case: REST
    # start -> WS connect takes a beat) sees a black canvas with nothing ever
    # arriving, since a static settled page stops repainting. Screencast is
    # started in routes_ws.py instead, exactly when a client connects — CDP
    # sends an immediate frame of the CURRENT state the moment
    # Page.startScreencast is called, regardless of repaints.
    target_url = _normalize_target_url(scan.target_query)
    if target_url:
        try:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=30_000)
        except Exception:
            pass  # operator can still navigate manually from a blank/failed page

    _ACTIVE_CAPTURES[capture_session_id] = capture
    return capture


def _normalize_target_url(target_query: str) -> str:
    first = str(target_query or "").replace(",", "\n").replace(";", "\n").splitlines()
    host = first[0].strip() if first else ""
    if not host:
        return ""
    return host if host.startswith("http") else f"https://{host}"


def get_capture(capture_session_id: str, scan_id: int) -> CaptureSession | None:
    capture = _ACTIVE_CAPTURES.get(capture_session_id)
    if capture is None or capture.scan_id != scan_id:
        return None
    return capture


def get_capture_status(capture_session_id: str, scan_id: int) -> dict[str, Any] | None:
    capture = get_capture(capture_session_id, scan_id)
    if capture is None:
        return None
    return {
        "status": capture.status,
        "current_url": capture.page.url,
        "in_scope_headers_count": len(capture.captured_headers),
        "idle_seconds": round(time.monotonic() - capture.last_activity_at, 1),
    }


async def apply_input_event(capture: CaptureSession, event: dict[str, Any]) -> None:
    capture.last_activity_at = time.monotonic()
    event_type = str(event.get("type") or "")
    try:
        if event_type == "mouse":
            await capture.cdp.send(
                "Input.dispatchMouseEvent",
                {
                    "type": event.get("eventType"),
                    "x": event.get("x"),
                    "y": event.get("y"),
                    "button": event.get("button", "left"),
                    "clickCount": event.get("clickCount", 1),
                },
            )
        elif event_type == "wheel":
            await capture.cdp.send(
                "Input.dispatchMouseEvent",
                {
                    "type": "mouseWheel",
                    "x": event.get("x"),
                    "y": event.get("y"),
                    "deltaX": event.get("deltaX", 0),
                    "deltaY": event.get("deltaY", 0),
                },
            )
        elif event_type == "key":
            await capture.cdp.send(
                "Input.dispatchKeyEvent",
                {
                    "type": event.get("eventType"),
                    "key": event.get("key"),
                    "code": event.get("code"),
                    "text": event.get("text"),
                },
            )
    except Exception:
        pass  # a dropped input event shouldn't tear down the whole capture


async def _teardown(capture: CaptureSession) -> None:
    try:
        await capture.context.close()
    except Exception:
        pass
    try:
        await capture.browser.close()
    except Exception:
        pass
    try:
        await capture.playwright.stop()
    except Exception:
        pass
    _ACTIVE_CAPTURES.pop(capture.capture_session_id, None)


async def cancel_capture(capture_session_id: str, scan_id: int) -> bool:
    capture = get_capture(capture_session_id, scan_id)
    if capture is None:
        return False
    await _teardown(capture)
    return True


async def confirm_capture(db: Session, scan: ScanJob, capture_session_id: str) -> dict[str, Any]:
    capture = get_capture(capture_session_id, scan.id)
    if capture is None:
        raise ValueError("capture_session_not_found")

    raw_cookies = await capture.context.cookies()
    in_scope_cookies = _filter_cookies_to_scope(raw_cookies, capture.authorized_scope)
    cookies = {str(c["name"]): str(c["value"]) for c in in_scope_cookies}
    headers = dict(capture.captured_headers)

    material = AuthMaterial(
        identity_key=capture.identity_key,
        role=capture.role,
        auth_type="session_capture",
        headers=headers,
        cookies=cookies,
        valid=bool(headers or cookies),
        status="valid" if (headers or cookies) else "failed",
        error="" if (headers or cookies) else "no_in_scope_session_material_captured",
    )

    manager = AuthSessionManager(db, scan)
    identity, session = manager.upsert_captured_material(
        capture.identity_key, capture.role, capture.username_ref, material
    )
    db.commit()

    await _teardown(capture)

    return {
        "scan_identity_id": identity.id,
        "scan_auth_session_id": session.id,
        "identity_key": capture.identity_key,
        "status": session.status,
        "headers_captured": len(headers),
        "cookies_captured": len(cookies),
    }
