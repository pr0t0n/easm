"""Login Flow Automation.

When the scan needs authenticated coverage of the target, the operator
provides a login_flow recipe and this module:
  1. Optionally GETs the login page to capture CSRF tokens / cookies
  2. POSTs credentials
  3. Verifies success (status code + body marker)
  4. Returns the resulting Cookie + any extracted auth header

The runner then propagates the captured headers to every downstream tool
via the existing _CURRENT_AUTH_HEADERS pipeline.

auth_config example:
  {
    "type": "login_flow",
    "login_flow": {
      "url": "https://target/login",
      "method": "POST",
      "fields": {"username": "alice", "password": "..."},
      "csrf_field": "_csrf",       # optional — auto-extracted from GET
      "success_marker": "Logout",  # body must contain this on success
      "success_status": 200,       # or 302
    }
  }
"""
from __future__ import annotations

import re
from typing import Any

import requests
from requests.cookies import RequestsCookieJar


_CSRF_PATTERNS = [
    re.compile(r'<input[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']', re.I),
    re.compile(r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']([^"\']*csrf[^"\']*)["\']', re.I),
    re.compile(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', re.I),
]


def execute_login_flow(login_flow: dict[str, Any], user_agent: str | None = None,
                       timeout: int = 30) -> dict[str, Any]:
    """Execute the login flow and return captured session data.

    Returns:
      ok:           bool
      cookies:      str  (Cookie header value for downstream tools)
      headers:      dict (Authorization etc. if the server set any)
      diagnostics:  what happened (status codes, markers, etc.)
    """
    url = str(login_flow.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "login_flow.url is required", "cookies": "", "headers": {}}
    method = str(login_flow.get("method") or "POST").upper()
    fields = dict(login_flow.get("fields") or {})
    success_marker = str(login_flow.get("success_marker") or "").lower()
    success_status = login_flow.get("success_status")
    csrf_field = str(login_flow.get("csrf_field") or "").strip()

    session = requests.Session()
    headers = {"User-Agent": user_agent or "Mozilla/5.0 (compatible; ScriptKidd.o-Pentest)"}
    diag: dict[str, Any] = {"steps": []}

    # Step 1 — optional GET to grab CSRF / set initial cookies
    try:
        pre = session.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        diag["steps"].append({"action": "GET", "status": pre.status_code, "url": pre.url})
        # Auto-detect CSRF if not specified, OR extract the value for the named field
        if csrf_field or "csrf" in pre.text.lower():
            for pat in _CSRF_PATTERNS:
                m = pat.search(pre.text)
                if m:
                    groups = m.groups()
                    if len(groups) == 1:
                        # meta tag — store as a header
                        headers["X-CSRF-Token"] = groups[0]
                        diag["csrf_header_set"] = True
                    else:
                        # input pair (name, value) in either order
                        name_idx = 0 if "csrf" in groups[0].lower() else 1
                        val_idx = 1 - name_idx
                        if csrf_field:
                            fields[csrf_field] = groups[val_idx]
                        else:
                            fields[groups[name_idx]] = groups[val_idx]
                        diag["csrf_field_set"] = groups[name_idx]
                    break
    except Exception as exc:  # noqa: BLE001
        diag["pre_get_error"] = str(exc)

    # Step 2 — submit credentials
    try:
        if method == "GET":
            resp = session.get(url, params=fields, headers=headers, timeout=timeout,
                               allow_redirects=True, verify=False)
        else:
            resp = session.post(url, data=fields, headers=headers, timeout=timeout,
                                allow_redirects=True, verify=False)
        diag["steps"].append({
            "action": method, "status": resp.status_code, "final_url": resp.url,
            "body_len": len(resp.text),
        })
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"login submit failed: {exc}",
                "cookies": "", "headers": {}, "diagnostics": diag}

    # Step 3 — verify success
    ok = True
    if success_status is not None:
        ok = ok and resp.status_code == int(success_status)
        diag["status_match"] = ok
    if success_marker:
        marker_ok = success_marker in resp.text.lower()
        diag["marker_match"] = marker_ok
        ok = ok and marker_ok
    if success_status is None and not success_marker:
        # No verification given — accept any 2xx/3xx that produced cookies
        ok = 200 <= resp.status_code < 400 and len(session.cookies) > 0
        diag["fallback_check"] = ok

    if not ok:
        return {"ok": False, "error": "login verification failed",
                "cookies": "", "headers": {}, "diagnostics": diag}

    # Step 4 — build the cookie header for downstream tools
    cookie_pairs = []
    for c in session.cookies:
        cookie_pairs.append(f"{c.name}={c.value}")
    cookie_header = "; ".join(cookie_pairs)

    # Extract any persistent auth header the server returned (rare but useful)
    out_headers: dict[str, str] = {}
    if cookie_header:
        out_headers["Cookie"] = cookie_header
    bearer = resp.headers.get("Authorization") or ""
    if bearer.lower().startswith("bearer "):
        out_headers["Authorization"] = bearer
    if "X-CSRF-Token" in headers:
        out_headers["X-CSRF-Token"] = headers["X-CSRF-Token"]

    diag["cookies_captured"] = len(cookie_pairs)
    return {"ok": True, "cookies": cookie_header, "headers": out_headers, "diagnostics": diag}
