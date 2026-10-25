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
        # Caido rejects requests whose Host is not in its allow-list ("Domain X
        # not allowed"), so when we reach it by a compose service name we must
        # present an allowed Host (localhost/127.0.0.1). Override via env if needed.
        self._host_header = os.getenv("CAIDO_HOST_HEADER", "localhost")
        # Effective Bearer used on calls. A raw Cloud PAT is NOT a valid instance
        # token; a local --allow-guests instance mints a working accessToken via
        # loginAsGuest(). We start with any provided token and fall back to guest.
        self._bearer = self.token

    # ------------------------------------------------------------------ #
    @property
    def configured(self) -> bool:
        # Token is optional: a --allow-guests instance serves GraphQL without one.
        return bool(self._graphql)

    def _gql(self, query: str, variables: dict[str, Any] | None = None, *, _retry: bool = True) -> dict[str, Any]:
        headers = {"Content-Type": "application/json", "Host": self._host_header}
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"
        resp = self._session.post(
            self._graphql,
            json={"query": query, "variables": variables or {}},
            headers=headers,
            timeout=self.timeout,
            verify=False,
        )
        resp.raise_for_status()
        payload = resp.json()
        errors = payload.get("errors")
        if errors:
            blob = json.dumps(errors)
            # An expired/invalid token on a mutation -> mint a fresh guest token
            # and retry once (the local instance allows guests).
            if _retry and "INVALID_TOKEN" in blob:
                self._bearer = ""
                if self._login_guest():
                    return self._gql(query, variables, _retry=False)
            raise RuntimeError(f"graphql_errors: {blob[:300]}")
        return payload.get("data") or {}

    def _login_guest(self) -> bool:
        """Obtain a valid instance accessToken from a --allow-guests instance."""
        try:
            prev, self._bearer = self._bearer, ""  # unauthenticated call
            data = self._gql("mutation{ loginAsGuest { token { accessToken } } }", _retry=False)
            token = (((data.get("loginAsGuest") or {}).get("token") or {}).get("accessToken"))
            self._bearer = str(token) if token else prev
            return bool(token)
        except Exception as exc:  # noqa: BLE001
            self._last_error = f"login_guest: {type(exc).__name__}: {exc}"
            return False

    def health(self) -> dict[str, Any]:
        """Fase-0 feasibility probe: confirm the instance is reachable and we can
        obtain a usable token (provided or guest). Caches the enabled flag."""
        if not self.configured:
            self._enabled = False
            return {"ok": False, "detail": "caido_not_configured (CAIDO_INSTANCE_URL ausente)"}
        try:
            self._gql("query{ __typename }", _retry=False)  # reachability (guest-ok)
        except Exception as exc:  # noqa: BLE001
            self._enabled = False
            self._last_error = f"{type(exc).__name__}: {exc}"
            return {"ok": False, "detail": f"unreachable: {type(exc).__name__}: {str(exc)[:160]}"}
        # Ensure a token that authorizes mutations (createReplaySession, ...).
        if not self._bearer or not self._login_ok():
            if not self._login_guest():
                self._enabled = False
                return {"ok": False, "detail": "no_usable_token (loginAsGuest falhou; instância sem --allow-guests?)"}
        self._enabled = True
        return {"ok": True, "detail": "guest_token" if self._bearer.endswith(".guest") else "provided_token"}

    def _login_ok(self) -> bool:
        """Cheap check that the current bearer authorizes a viewer query."""
        try:
            self._gql("query{ viewer { id } }", _retry=False)
            return True
        except Exception:
            return False

    @property
    def enabled(self) -> bool:
        if self._enabled is None:
            self.health()
        return bool(self._enabled)

    # ------------------------------------------------------------------ #
    # Caido Replay GraphQL (schema v0.58): createReplaySession(requestSource.raw)
    # -> startReplayTask(sessionId) -> replayEntry(id, sessionKind: HTTP).
    _CREATE_SESSION = (
        "mutation($in: CreateReplaySessionInput!) {"
        " createReplaySession(input: $in) { session { id } error { __typename } } }"
    )
    _START_TASK = (
        "mutation($id: ID!) { startReplayTask(sessionId: $id) {"
        " task { id replayEntry { id } } error { __typename } } }"
    )
    _READ_ENTRY = (
        "query($id: ID!) { replayEntry(id: $id, sessionKind: HTTP) { error"
        " ... on ReplayEntryHttp { request { response { statusCode raw } } } } }"
    )

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
        host_hdr = host if port in (80, 443) else f"{host}:{port}"
        raw = self._build_raw(method, path, host_hdr, headers, body)
        request_body = body[:_EVIDENCE_BODY_MAX]

        if not self.enabled:
            return {"ok": False, "error": "caido_disabled", "detail": self._last_error, "curl": curl, "request_body": request_body}
        try:
            b64 = base64.b64encode(raw.encode("utf-8", "ignore")).decode()
            d1 = self._gql(self._CREATE_SESSION, {"in": {
                "kind": "HTTP",
                "requestSource": {"raw": {"connectionInfo": {"host": host, "port": int(port), "isTLS": tls}, "raw": b64}},
            }})
            sid = (((d1.get("createReplaySession") or {}).get("session") or {}).get("id"))
            if not sid:
                return {"ok": False, "error": "caido_no_session", "detail": str((d1.get("createReplaySession") or {}).get("error")), "curl": curl, "request_body": request_body}
            d2 = self._gql(self._START_TASK, {"id": sid})
            task = (d2.get("startReplayTask") or {}).get("task") or {}
            eid = (task.get("replayEntry") or {}).get("id") or task.get("id")
            if not eid:
                return {"ok": False, "error": "caido_no_entry", "detail": str((d2.get("startReplayTask") or {}).get("error")), "curl": curl, "request_body": request_body}
            status, hdrs, text = self._poll_entry(str(eid), timeout or self.timeout)
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

    def _poll_entry(self, entry_id: str, timeout: int) -> tuple[int, dict[str, str], str]:
        deadline = time.time() + max(3, timeout)
        while time.time() < deadline:
            data = self._gql(self._READ_ENTRY, {"id": entry_id})
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
            time.sleep(0.4)
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
