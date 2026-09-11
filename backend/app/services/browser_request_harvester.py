"""Browser Request Harvester (Épico 3 of
docs/JUICE_SHOP_STATEFUL_APP_PENTEST_CAPABILITY_PLAN.md, passive_browser mode).

Captures real HTTP request/response traffic (method, url, headers, real
body, response status/content-type/excerpt) produced by an actual browser
loading a target, using the already-running `browser_runner` Playwright
server -- the same infra credential_capture_service.py uses for
human-in-the-loop session capture, but here driven autonomously and without
any form submission or navigation beyond the initial page load.

This exists because nothing else in the codebase preserves a real captured
request body end-to-end: kali-runner's cdp_capture.py grabs a possibly-
truncated postData, but the one consumer that persists it
(offensive_operator_runner.py's _safe_body_template) replaces every real
value with a synthetic placeholder before storing it. That's fine for pure
injection fuzzing (the payload overwrites the value anyway) but breaks
anything that needs the real captured value -- P13 IDOR/BOLA in particular,
which needs the real object id an identity actually saw.

Uses Playwright's SYNC API deliberately: this runs inside the offensive
operator pipeline, which executes on a plain (non-async) Celery worker with
no event loop, unlike credential_capture_service's async client driven from
a FastAPI/websocket handler.
"""
from __future__ import annotations

import hashlib
import json
import logging
import ssl
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse
from urllib.request import HTTPSHandler, Request, build_opener

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import ObservedRequest, ScanJob
from app.services.credential_capture_service import BROWSER_RUNNER_WS_URL
from app.services.offensive_inventory_service import OffensiveInventoryService

logger = logging.getLogger(__name__)

_MAX_BODY_CHARS = 20_000
_CAPTURABLE_RESPONSE_CONTENT_TYPE_MARKERS = ("json", "text", "html", "javascript", "xml")
_CAPTURABLE_RESOURCE_TYPES = {"xhr", "fetch", "document"}
_REDACT_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


def _redact_headers_for_log(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: ("<redacted>" if key.lower() in _REDACT_HEADER_NAMES else value)
        for key, value in headers.items()
    }


def _is_capturable_response_content_type(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return any(marker in lowered for marker in _CAPTURABLE_RESPONSE_CONTENT_TYPE_MARKERS)


def _extract_body_param_names(body: str, content_type: str) -> list[str]:
    lowered_ct = (content_type or "").lower()
    if not body:
        return []
    try:
        if "json" in lowered_ct:
            data = json.loads(body)
            return [str(key) for key in data.keys()] if isinstance(data, dict) else []
        return [key for key, _ in parse_qsl(body, keep_blank_values=True)]
    except Exception:
        return []


def _header_value(headers: dict[str, str], name: str) -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return ""


def _record_request(captured: list[dict[str, Any]], request: Any) -> None:
    try:
        url = request.url
        method = request.method
        resource_type = request.resource_type
    except Exception:
        return
    if resource_type not in _CAPTURABLE_RESOURCE_TYPES:
        return
    if not (url.startswith("http://") or url.startswith("https://")):
        return

    try:
        request_headers = dict(request.headers or {})
    except Exception:
        request_headers = {}
    try:
        raw_body = request.post_data() or ""
    except Exception:
        raw_body = ""

    entry: dict[str, Any] = {
        "method": method,
        "url": url,
        "request_headers": request_headers,
        "request_body_full": raw_body,
        "request_content_type": _header_value(request_headers, "content-type"),
        "status_code": None,
        "response_content_type": "",
        "response_excerpt": "",
    }

    try:
        response = request.response()
    except Exception:
        response = None
    if response is not None:
        try:
            entry["status_code"] = response.status
            resp_headers = dict(response.headers or {})
            resp_ct = _header_value(resp_headers, "content-type")
            entry["response_content_type"] = resp_ct
            if _is_capturable_response_content_type(resp_ct):
                entry["response_excerpt"] = (response.text() or "")[:_MAX_BODY_CHARS]
        except Exception:
            pass

    captured.append(entry)


def _persist_observed_request(
    db: Session,
    scan: ScanJob,
    inv: OffensiveInventoryService,
    entry: dict[str, Any],
    identity_key: str,
) -> None:
    url = str(entry.get("url") or "")
    method = str(entry.get("method") or "GET").upper()
    is_mutating = method not in {"GET", "HEAD", "OPTIONS"}
    full_body = str(entry.get("request_body_full") or "")
    body_sha256 = hashlib.sha256(full_body.encode("utf-8")).hexdigest() if full_body else None
    content_type = str(entry.get("request_content_type") or "")

    tags = ["browser-captured", "real-body"] if full_body else ["browser-captured"]
    if is_mutating:
        # _has_mutating_body_surface (scan_quality.py) already infers this
        # from the endpoint's plain `method`, but it also checks this exact
        # tag set -- cheap, explicit reinforcement for that and any future
        # consumer that reads tags rather than re-deriving from method.
        tags.append("state-changing")
    endpoint = inv.upsert_endpoint(
        url,
        method=method,
        source_tool="browser-harvester",
        status_code=entry.get("status_code"),
        content_type=str(entry.get("response_content_type") or ""),
        tags=tags,
    )
    if is_mutating and full_body:
        for name in _extract_body_param_names(full_body, content_type):
            try:
                inv.upsert_parameter(
                    endpoint, name, location="body",
                    sample_value=full_body[:200], source_tool="browser-harvester",
                )
            except Exception:
                continue

    db.add(ObservedRequest(
        scan_job_id=scan.id,
        endpoint_id=endpoint.id,
        identity_key=identity_key or "",
        source="browser_harvester",
        method=method,
        url=url,
        normalized_url=endpoint.normalized_url,
        request_headers=dict(entry.get("request_headers") or {}),
        request_body={"body": full_body[:_MAX_BODY_CHARS]} if full_body else {},
        body_sha256=body_sha256,
        request_content_type=content_type or None,
        status_code=entry.get("status_code"),
        response_content_type=str(entry.get("response_content_type") or "") or None,
        response_excerpt=str(entry.get("response_excerpt") or "") or None,
        is_mutating=is_mutating,
    ))


def _resolve_identity_headers(db: Session, scan: ScanJob, identity_key: str) -> dict[str, str]:
    if not identity_key:
        return {}
    try:
        from app.services.auth_session_manager import AuthSessionManager

        material = AuthSessionManager(db, scan).get_material(identity_key)
    except Exception:
        return {}
    if not material or not material.valid:
        return {}
    headers = dict(material.headers or {})
    if material.cookies:
        cookie_header = "; ".join(f"{name}={value}" for name, value in material.cookies.items())
        if cookie_header and not _header_value(headers, "cookie"):
            headers["Cookie"] = cookie_header
    return headers


def _field_value(field_name: str, input_type: str) -> str:
    name = (field_name or "").lower()
    if input_type == "password" or any(token in name for token in ("pass", "senha", "pwd")):
        return "PentestInvalid!9z"
    if any(token in name for token in ("user", "login", "email", "mail", "usuario")):
        return "pentest.invalid@example.invalid"
    return "pentest-probe"


def _submit_public_forms(page: Any, target: str) -> int:
    submitted = 0
    try:
        forms = page.locator("form")
        count = min(forms.count(), 10)
    except Exception:
        return 0
    for index in range(count):
        try:
            form = forms.nth(index)
            password_count = form.locator('input[type="password"]').count()
            if password_count < 1:
                continue
            action = str(form.get_attribute("action") or target)
            if action.startswith("/"):
                action = urljoin(target, action)
            if not action.startswith(("http://", "https://")):
                continue
            if urlparse(action).hostname != urlparse(target).hostname:
                continue
            inputs = form.locator("input,textarea")
            for field_index in range(min(inputs.count(), 30)):
                field = inputs.nth(field_index)
                input_type = str(field.get_attribute("type") or "text").lower()
                if input_type in {"hidden", "submit", "button", "checkbox", "radio", "file"}:
                    continue
                name = str(field.get_attribute("name") or field.get_attribute("id") or "")
                if not name:
                    continue
                field.fill(_field_value(name, input_type))
            form.locator('input[type="submit"],button[type="submit"],button').first.click(timeout=5000)
            submitted += 1
        except Exception:
            continue
    return submitted


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action = ""
        self.method = "GET"
        self.fields: list[tuple[str, str, str]] = []
        self.in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form" and not self.in_form:
            self.in_form = True
            self.action = values.get("action", "")
            self.method = values.get("method", "GET").upper()
        elif self.in_form and tag.lower() in {"input", "textarea"}:
            name = values.get("name") or values.get("id")
            if name:
                self.fields.append((name, values.get("value", ""), values.get("type", "text").lower()))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.in_form:
            self.in_form = False


def _fallback_form_capture(target: str) -> list[dict[str, Any]]:
    context = ssl._create_unverified_context()
    opener = build_opener(HTTPSHandler(context=context))
    request = Request(target, headers={"User-Agent": "ScriptKidd.o browser-request-harvester"})
    with opener.open(request, timeout=30) as response:
        html = response.read(200_000).decode("utf-8", "replace")
        headers = {str(key): str(value) for key, value in response.headers.items()}
        status = int(response.status)
    parser = _FormParser()
    parser.feed(html)
    if not any(input_type == "password" for _, _, input_type in parser.fields):
        return []
    action = urljoin(target, parser.action or target)
    if urlparse(action).hostname != urlparse(target).hostname:
        return []
    values = []
    for name, value, input_type in parser.fields:
        values.append((name, _field_value(name, input_type) if input_type != "hidden" else value))
    body = urlencode(values).encode("utf-8")
    post = Request(action, data=body, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "ScriptKidd.o browser-request-harvester"})
    with opener.open(post, timeout=30) as response:
        response_headers = {str(key): str(value) for key, value in response.headers.items()}
        response_body = response.read(20_000).decode("utf-8", "replace")
        post_status = int(response.status)
    return [
        {"method": "GET", "url": target, "request_headers": {}, "request_body_full": "", "request_content_type": "", "status_code": status, "response_content_type": headers.get("Content-Type", ""), "response_excerpt": html[:_MAX_BODY_CHARS]},
        {"method": "POST", "url": action, "request_headers": {"Content-Type": "application/x-www-form-urlencoded"}, "request_body_full": body.decode("utf-8"), "request_content_type": "application/x-www-form-urlencoded", "status_code": post_status, "response_content_type": response_headers.get("Content-Type", ""), "response_excerpt": response_body[:_MAX_BODY_CHARS]},
    ]


def harvest_target(
    db: Session,
    scan: ScanJob,
    target: str,
    *,
    identity_key: str = "",
    max_wait_seconds: int = 30,
) -> dict[str, Any]:
    """Passive-mode capture: loads `target` once, records XHR/fetch/document
    traffic that fires on initial load. Never submits a form, never clicks,
    never navigates beyond the one target URL."""
    if not settings.enable_browser_request_harvester:
        return {"status": "skipped", "reason": "browser_request_harvester_disabled"}

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "reason": f"playwright_unavailable: {exc}"}

    extra_headers = _resolve_identity_headers(db, scan, identity_key)
    captured: list[dict[str, Any]] = []
    storage_snapshot: dict[str, Any] = {}
    forms_submitted = 0

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.connect(BROWSER_RUNNER_WS_URL)
            except Exception as exc:  # noqa: BLE001
                return {"status": "error", "reason": f"browser_runner_unreachable: {exc}"}
            try:
                context = browser.new_context(extra_http_headers=extra_headers or None)
                page = context.new_page()
                page.on("requestfinished", lambda request: _record_request(captured, request))
                try:
                    page.goto(target, wait_until="networkidle", timeout=max_wait_seconds * 1000)
                except Exception:
                    pass  # partial capture from whatever fired before the timeout is still useful
                forms_submitted = _submit_public_forms(page, target)
                if forms_submitted:
                    try:
                        page.wait_for_load_state("networkidle", timeout=min(max_wait_seconds * 1000, 15000))
                    except Exception:
                        pass

                try:
                    cookies = context.cookies()
                    local_storage_raw = page.evaluate("() => JSON.stringify(window.localStorage)")
                    session_storage_raw = page.evaluate("() => JSON.stringify(window.sessionStorage)")
                    storage_snapshot = {
                        "cookie_names": sorted({str(c.get("name")) for c in cookies if c.get("name")}),
                        "local_storage_keys": sorted(json.loads(local_storage_raw or "{}").keys()),
                        "session_storage_keys": sorted(json.loads(session_storage_raw or "{}").keys()),
                    }
                except Exception:
                    pass
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("browser_request_harvester failed target=%s error=%s", target, exc)
        return {"status": "error", "reason": f"harvest_failed: {exc}"}

    if not forms_submitted and not any(str(entry.get("method")) == "POST" for entry in captured):
        try:
            captured.extend(_fallback_form_capture(target))
        except Exception as exc:
            logger.info("browser_request_harvester fallback_failed target=%s error=%s", target, exc)

    inv = OffensiveInventoryService(db, scan)
    persisted = 0
    for entry in captured:
        try:
            _persist_observed_request(db, scan, inv, entry, identity_key)
            persisted += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "browser_request_harvester persist failed url=%s error=%s",
                entry.get("url"), exc,
            )
    db.flush()

    logger.info(
        "browser_request_harvester target=%s identity=%s captured=%d persisted=%d headers=%s",
        target, identity_key or "anonymous", len(captured), persisted,
        _redact_headers_for_log(extra_headers),
    )
    return {
        "status": "success",
        "target": target,
        "requests_captured": len(captured),
        "requests_persisted": persisted,
        "forms_submitted": forms_submitted,
        "storage": storage_snapshot,
    }
