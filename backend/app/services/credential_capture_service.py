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
import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
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


async def reap_idle_captures() -> int:
    """Close any capture whose browser session has been idle (no operator
    input, no new in-scope header observed) for longer than
    IDLE_TIMEOUT_SECONDS. That constant was declared but never enforced
    anywhere before this — an abandoned capture (operator closed the tab or
    walked away mid-login) kept its Playwright browser/context alive in the
    browser_runner container indefinitely."""
    now = time.monotonic()
    stale = [
        capture
        for capture in list(_ACTIVE_CAPTURES.values())
        if now - capture.last_activity_at > IDLE_TIMEOUT_SECONDS
    ]
    for capture in stale:
        capture.status = "idle_timeout"
        await _teardown(capture)
    return len(stale)


async def run_idle_capture_reaper_loop(interval_seconds: int = 60) -> None:
    """Background loop started once at FastAPI startup (see main.py). Must
    run in-process with start_capture()'s Playwright objects, since
    _ACTIVE_CAPTURES is a plain in-process dict with no cross-process
    visibility — a Celery beat task running in a separate worker process
    cannot see or reap entries in it."""
    import asyncio
    import logging

    logger = logging.getLogger(__name__)
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            reaped = await reap_idle_captures()
            if reaped:
                logger.info("credential_capture_service: reaped %d idle capture(s)", reaped)
        except Exception:
            logger.exception("credential_capture_service: idle capture reaper tick failed")


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
    validation = await _validate_captured_login(capture, headers, cookies)

    material = AuthMaterial(
        identity_key=capture.identity_key,
        role=capture.role,
        auth_type="session_capture",
        headers=headers,
        cookies=cookies,
        valid=bool(validation.get("valid")),
        status="valid" if validation.get("valid") else "failed",
        error="" if validation.get("valid") else str(validation.get("reason") or "captured_login_not_validated"),
    )

    manager = AuthSessionManager(db, scan)
    identity, session = manager.upsert_captured_material(
        capture.identity_key, capture.role, capture.username_ref, material
    )
    session.validation_result = {
        **dict(session.validation_result or {}),
        **validation,
        "identity_key": capture.identity_key,
        "role": capture.role,
    }
    db.add(session)
    db.commit()

    if validation.get("valid"):
        capture.status = "confirmed"
        await _teardown(capture)
    else:
        # Keep the live browser open on validation failure. SPAs often render the
        # same app shell for anonymous/authenticated GET /, while the useful
        # proof only appears after the operator navigates to an authenticated
        # area (profile/account/dashboard). Closing here turned a recoverable
        # false-negative into a 404 on the next confirm attempt.
        capture.status = "validation_failed"
        capture.last_activity_at = time.monotonic()

    return {
        "scan_identity_id": identity.id,
        "scan_auth_session_id": session.id,
        "identity_key": capture.identity_key,
        "status": session.status,
        "headers_captured": len(headers),
        "cookies_captured": len(cookies),
        "validation": validation,
    }


async def _validate_captured_login(
    capture: CaptureSession,
    headers: dict[str, str],
    cookies: dict[str, str],
) -> dict[str, Any]:
    """Prove that captured material changes access relative to anonymous G0.

    A cookie's mere existence is not authentication: consent, CSRF and load
    balancer cookies are common before login.  The current in-scope page is
    requested both anonymously and with captured material and the differential
    is persisted as the admission evidence for G1.
    """
    probe_url = str(capture.page.url or "")
    host = urlparse(probe_url).hostname or ""
    if not probe_url.startswith(("http://", "https://")) or not is_host_in_scope(host, capture.authorized_scope):
        return {"valid": False, "reason": "capture_not_on_in_scope_page", "probe_url": probe_url}
    if not headers and not cookies:
        return {"valid": False, "reason": "no_in_scope_session_material_captured", "probe_url": probe_url}

    def fingerprint(response: httpx.Response) -> dict[str, Any]:
        body = bytes(response.content or b"")[:100_000]
        return {
            "status_code": response.status_code,
            "location": str(response.headers.get("location") or "")[:500],
            "content_type": str(response.headers.get("content-type") or "")[:160],
            "body_length": len(response.content or b""),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }

    try:
        timeout = httpx.Timeout(15.0, connect=8.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
            authenticated = await client.get(probe_url, headers=headers, cookies=cookies)
            anonymous = await client.get(probe_url)
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"session_validation_transport_error:{type(exc).__name__}",
            "probe_url": probe_url,
        }

    auth_fp = fingerprint(authenticated)
    anon_fp = fingerprint(anonymous)
    login_markers = ("/login", "/signin", "/sign-in", "/auth")
    auth_location = str(auth_fp["location"]).lower()
    auth_denied = authenticated.status_code in {401, 403} or (
        authenticated.status_code in {301, 302, 303, 307, 308}
        and any(marker in auth_location for marker in login_markers)
    )
    current_login_page = any(marker in urlparse(probe_url).path.lower() for marker in login_markers)
    materially_different = (
        auth_fp["status_code"] != anon_fp["status_code"]
        or auth_fp["location"] != anon_fp["location"]
        or auth_fp["body_sha256"] != anon_fp["body_sha256"]
    )
    has_authorization = any(str(name).lower() == "authorization" and str(value) for name, value in headers.items())
    valid = bool(not auth_denied and not current_login_page and materially_different)
    # Token-based APIs can return identical public landing pages while the
    # Authorization header itself is strong material; liveness still must pass.
    if has_authorization and not auth_denied and not current_login_page:
        valid = True
    browser_state = await _browser_authenticated_state(capture)
    if not valid and not auth_denied and not current_login_page and browser_state.get("observed"):
        valid = True
    reason = "authenticated_behavior_observed" if valid else (
        "authenticated_probe_denied" if auth_denied else
        "capture_still_on_login_page" if current_login_page else
        "no_authenticated_behavior_observed"
    )
    if valid and not materially_different and not has_authorization and browser_state.get("observed"):
        reason = "browser_authenticated_state_observed"
    return {
        "valid": valid,
        "reason": reason,
        "probe_url": probe_url,
        "anonymous": anon_fp,
        "authenticated": auth_fp,
        "materially_different": materially_different,
        "browser_state": browser_state,
    }


async def _browser_authenticated_state(capture: CaptureSession) -> dict[str, Any]:
    """Look for login-state evidence in the live browser without storing DOM.

    This is intentionally conservative. It exists for SPA/app-shell targets
    where the HTTP probe sees identical HTML for anonymous and authenticated
    users, but the operator-driven browser visibly shows an authenticated
    session after login.
    """
    try:
        body_text = await capture.page.locator("body").inner_text(timeout=3_000)
    except Exception:
        return {"observed": False, "markers": []}

    text = " ".join(str(body_text or "").lower().split())
    if not text:
        return {"observed": False, "markers": []}

    marker_candidates: list[tuple[str, str]] = []
    for label, value in (
        ("identity_key", capture.identity_key),
        ("username_ref", capture.username_ref),
    ):
        normalized = str(value or "").strip().lower()
        if len(normalized) >= 3:
            marker_candidates.append((label, normalized))

    marker_candidates.extend(
        [
            ("logout", "logout"),
            ("sign_out", "sign out"),
            ("sair", "sair"),
            ("desconectar", "desconectar"),
            ("profile", "profile"),
            ("perfil", "perfil"),
            ("my_account", "my account"),
            ("minha_conta", "minha conta"),
            ("account_menu", "account"),
            ("user_menu", "usuário"),
            ("user_menu_ascii", "usuario"),
        ]
    )

    observed = sorted({label for label, marker in marker_candidates if marker and marker in text})
    return {"observed": bool(observed), "markers": observed[:10]}
