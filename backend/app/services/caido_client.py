"""Caido traffic/replay transport.

The API module routes its probes THROUGH a headless Caido instance via Caido's
GraphQL Replay API, so every request/response is captured in a Caido project the
DevOps/pentest team can open and re-run. This keeps the Python test logic (flow
graph, attack-path, skills) while making Caido the request engine of record.

Design:
- ``send()`` returns the SAME dict shape as ``api_skill_top20_runner._request``
  (ok/response_status/response_headers/response_body/curl/request_body/fingerprint
  + a ``response`` shim exposing ``.status_code``/``.headers``/``.text``), so the
  runner can route through Caido with no change to the skill branches.
- Everything is soft-failing: any error returns ``ok=False`` so the caller falls
  back to direct ``requests``. Caido is an enhancement, never a hard dependency.
- The GraphQL schema "stability is not guaranteed between releases" (Caido docs),
  so mutation/field names live in one place and failures degrade gracefully. The
  Fase-0 feasibility probe (``health``) validates the free-instance + PAT path
  before the runner trusts it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any
from urllib.parse import urlparse

import requests

_EVIDENCE_BODY_MAX = 4000
_DEFAULT_TIMEOUT = 15


class _CaidoResponse:
    """Minimal stand-in for requests.Response consumed by the skill branches
    (``.status_code``, ``.headers`` dict-like, ``.text``)."""

    def __init__(self, status_code: int, headers: dict[str, str], text: str):
        self.status_code = int(status_code)
        self.headers = _HeadersCI(headers or {})
        self.text = text or ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


class _HeadersCI(dict):
    """Case-insensitive header access, like requests' CaseInsensitiveDict."""

    def __init__(self, data: dict[str, str]):
        super().__init__()
        self._lower: dict[str, str] = {}
        for k, v in (data or {}).items():
            self[str(k)] = str(v)
            self._lower[str(k).lower()] = str(v)

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        if key in self:
            return self[key]
        return self._lower.get(str(key).lower(), default)


class CaidoClient:
    """Thin GraphQL client for Caido Replay. One instance per scan."""

    def __init__(self, base_url: str | None = None, token: str | None = None, *, timeout: int = _DEFAULT_TIMEOUT):
        self.base_url = (base_url or os.getenv("CAIDO_INSTANCE_URL") or "").rstrip("/")
        self.token = token or os.getenv("CAIDO_PAT") or os.getenv("CAIDO_ACCESS_TOKEN") or ""
        self.timeout = timeout
        self._graphql = f"{self.base_url}/graphql" if self.base_url else ""
        self._session = requests.Session()
        self._replay_sessions: dict[str, str] = {}   # host:port:tls -> sessionId
        self._enabled: bool | None = None
        self._last_error = ""

    # ------------------------------------------------------------------ #
    @property
    def configured(self) -> bool:
        return bool(self._graphql and self.token)

    def _gql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._session.post(
            self._graphql,
            json={"query": query, "variables": variables or {}},
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            timeout=self.timeout,
            verify=False,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("errors"):
            raise RuntimeError(f"graphql_errors: {json.dumps(payload['errors'])[:300]}")
        return payload.get("data") or {}

    def health(self) -> dict[str, Any]:
        """Fase-0 feasibility probe: confirm the free instance + token can drive
        GraphQL. Returns {ok, detail}. Caches the enabled flag."""
        if not self.configured:
            self._enabled = False
            return {"ok": False, "detail": "caido_not_configured (CAIDO_INSTANCE_URL/CAIDO_PAT ausentes)"}
        try:
            data = self._gql("query{ viewer { id } }")
            self._enabled = bool(data)
            return {"ok": True, "detail": "viewer_ok", "viewer": data.get("viewer")}
        except Exception as exc:  # noqa: BLE001
            # Some releases expose __typename only; try a schema ping.
            try:
                self._gql("query{ __typename }")
                self._enabled = True
                return {"ok": True, "detail": "schema_ping_ok"}
            except Exception as exc2:  # noqa: BLE001
                self._enabled = False
                self._last_error = f"{type(exc2).__name__}: {exc2}"
                return {"ok": False, "detail": f"health_failed: {type(exc).__name__}: {str(exc)[:200]}"}

    @property
    def enabled(self) -> bool:
        if self._enabled is None:
            self.health()
        return bool(self._enabled)

    # ------------------------------------------------------------------ #
    def _ensure_session(self, host: str, port: int, tls: bool) -> str | None:
        key = f"{host}:{port}:{int(tls)}"
        if key in self._replay_sessions:
            return self._replay_sessions[key]
        mutation = """
        mutation($in: CreateReplaySessionInput) {
          createReplaySession(input: $in) { session { id } }
        }
        """
        try:
            data = self._gql(mutation, {"in": {"requestSource": {"raw": {
                "connectionInfo": {"host": host, "port": port, "isTLS": tls},
                "raw": "",
            }}}})
            sid = (((data.get("createReplaySession") or {}).get("session") or {}).get("id"))
            if not sid:
                # fall back to a session with no source (created empty)
                data = self._gql("mutation{ createReplaySession(input:{}) { session { id } } }")
                sid = (((data.get("createReplaySession") or {}).get("session") or {}).get("id"))
            if sid:
                self._replay_sessions[key] = str(sid)
            return str(sid) if sid else None
        except Exception as exc:  # noqa: BLE001
            self._last_error = f"create_session: {type(exc).__name__}: {exc}"
            return None

    def send(self, method: str, url: str, identity_headers: dict[str, str] | None = None,
             cookies: dict[str, str] | None = None, json_body: Any = None,
             *, curl: str = "", timeout: int | None = None) -> dict[str, Any]:
        """Replay one request through Caido. Returns the _request-compatible dict
        (ok=False on any failure so the caller falls back to direct requests)."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        tls = parsed.scheme == "https"
        port = parsed.port or (443 if tls else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        headers = {"User-Agent": "ValidCyber-API-SkillTop20/1.0", "Accept": "application/json, text/plain, */*"}
        headers.update(identity_headers or {})
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        body = json.dumps(json_body, ensure_ascii=False) if json_body is not None else ""
        if json_body is not None:
            headers.setdefault("Content-Type", "application/json")
        raw = self._build_raw(method, path, host, headers, body)
        request_body = body[:_EVIDENCE_BODY_MAX]

        if not self.enabled:
            return {"ok": False, "error": "caido_disabled", "detail": self._last_error, "curl": curl, "request_body": request_body}
        sid = self._ensure_session(host, port, tls)
        if not sid:
            return {"ok": False, "error": "caido_no_session", "detail": self._last_error, "curl": curl, "request_body": request_body}
        try:
            entry_id = self._start_task(sid, raw, host, port, tls)
            status, hdrs, text = self._poll_entry(entry_id, timeout or self.timeout)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": "caido_replay_failed", "detail": f"{type(exc).__name__}: {str(exc)[:200]}",
                    "curl": curl, "request_body": request_body}
        shim = _CaidoResponse(status, hdrs, text)
        body_text = text or ""
        return {
            "ok": True,
            "response": shim,
            "via": "caido",
            "fingerprint": {"status_code": status, "length": len(body_text),
                            "sha1": hashlib.sha1(body_text.encode("utf-8", "ignore")).hexdigest()[:16]},
            "curl": curl,
            "request_body": request_body,
            "response_status": int(status),
            "response_headers": dict(list(hdrs.items())[:25]),
            "response_body": body_text[:_EVIDENCE_BODY_MAX],
            "response_truncated": len(body_text) > _EVIDENCE_BODY_MAX,
        }

    def _start_task(self, session_id: str, raw: str, host: str, port: int, tls: bool) -> str:
        mutation = """
        mutation($id: ID!, $in: StartReplayTaskInput!) {
          startReplayTask(id: $id, input: $in) { task { id replayEntry { id } } }
        }
        """
        data = self._gql(mutation, {"id": session_id, "in": {
            "replaySessionId": session_id,
            "request": {"raw": base64.b64encode(raw.encode("utf-8", "ignore")).decode(),
                        "connectionInfo": {"host": host, "port": port, "isTLS": tls}},
            "settings": {"placeholders": [], "updateContentLength": True},
            "connectionInfo": {"host": host, "port": port, "isTLS": tls},
            "updateContentLength": True,
        }})
        task = (data.get("startReplayTask") or {}).get("task") or {}
        eid = (task.get("replayEntry") or {}).get("id") or task.get("id")
        if not eid:
            raise RuntimeError("no_replay_entry_id")
        return str(eid)

    def _poll_entry(self, entry_id: str, timeout: int) -> tuple[int, dict[str, str], str]:
        query = """
        query($id: ID!) {
          replayEntry(id: $id) {
            id error
            request { response { statusCode raw } }
          }
        }
        """
        deadline = time.time() + max(3, timeout)
        last = None
        while time.time() < deadline:
            data = self._gql(query, {"id": entry_id})
            entry = data.get("replayEntry") or {}
            if entry.get("error"):
                raise RuntimeError(f"replay_error: {str(entry.get('error'))[:160]}")
            resp = ((entry.get("request") or {}).get("response")) or {}
            raw_b64 = resp.get("raw")
            if raw_b64:
                status, hdrs, text = self._parse_raw_response(raw_b64)
                if resp.get("statusCode"):
                    status = int(resp["statusCode"])
                return status, hdrs, text
            last = resp
            time.sleep(0.4)
        if last and last.get("statusCode"):
            return int(last["statusCode"]), {}, ""
        raise RuntimeError("replay_timeout")

    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_raw(method: str, path: str, host: str, headers: dict[str, str], body: str) -> str:
        lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}"]
        for k, v in headers.items():
            if k.lower() == "host":
                continue
            lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
        return "\r\n".join(lines) + "\r\n\r\n" + (body or "")

    @staticmethod
    def _parse_raw_response(raw_b64: str) -> tuple[int, dict[str, str], str]:
        try:
            raw = base64.b64decode(raw_b64).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            raw = raw_b64
        head, _, body = raw.partition("\r\n\r\n")
        if not head:
            head, _, body = raw.partition("\n\n")
        head_lines = head.splitlines()
        status = 0
        if head_lines:
            parts = head_lines[0].split(" ")
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        headers: dict[str, str] = {}
        for line in head_lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        return status, headers, body


def get_caido_client_for_config(api_config: dict[str, Any]) -> CaidoClient | None:
    """Build a CaidoClient when the scan opted in (``use_caido``) and the runtime
    is configured/reachable; otherwise None so the runner uses direct requests."""
    if not bool(api_config.get("use_caido", True)):
        return None
    client = CaidoClient()
    if not client.configured:
        return None
    if not client.enabled:
        return None
    return client
