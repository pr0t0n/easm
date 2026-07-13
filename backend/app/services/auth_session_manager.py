"""Authenticated pentest session manager.

The manager turns ScanJob.state_data["auth_config"] into persisted identities
and reusable auth material. It deliberately stores only operational headers,
cookies and metadata; raw passwords stay in the transient auth_config payload.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import requests
from sqlalchemy.orm import Session

from app.models.models import ScanAuthSession, ScanIdentity, ScanJob
from app.services.pentest_contracts import AuthContract, normalize_auth_config


@dataclass(slots=True)
class AuthMaterial:
    identity_key: str
    role: str
    auth_type: str
    headers: dict[str, str]
    cookies: dict[str, str]
    valid: bool
    status: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_key": self.identity_key,
            "role": self.role,
            "auth_type": self.auth_type,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "valid": self.valid,
            "status": self.status,
            "error": self.error,
        }


class AuthSessionManager:
    def __init__(self, db: Session, scan: ScanJob):
        self.db = db
        self.scan = scan
        state = dict(scan.state_data or {})
        self.contract = normalize_auth_config(state.get("auth_config"))

    def ensure_sessions(self) -> dict[str, Any]:
        """Persist identities and create/validate auth sessions."""
        if self.contract.auth_type in {"", "none"} and not self.contract.headers and not self.contract.cookies:
            return {
                "required": False,
                "auth_type": "none",
                "identities": [],
                "sessions": [],
                "ready": True,
            }

        identities = self.contract.identities or []
        if not identities:
            identities = [
                normalize_auth_config(
                    {
                        "type": self.contract.auth_type,
                        "identities": [{"id": "default", "role": "default", "auth_type": self.contract.auth_type}],
                    }
                ).identities[0]
            ]

        sessions: list[AuthMaterial] = []
        for identity_contract in identities:
            identity = self._upsert_identity(identity_contract)
            material = self._build_material(identity_contract.identity_key, identity_contract.role, self.contract)
            if self.contract.auth_type == "form_login":
                material = self._attempt_form_login(identity_contract.identity_key, identity_contract.role, self.contract)
            identity.status = material.status
            identity.session_valid = material.valid
            identity.last_error = material.error or None
            identity.session_metadata = {
                "role": identity_contract.role,
                "auth_type": identity_contract.auth_type or self.contract.auth_type,
                "validated_at": datetime.now().isoformat(),
            }
            self.db.add(identity)
            self.db.flush()
            session = self._upsert_session(identity, material)
            sessions.append(material)
            self.db.add(session)

        self._persist_scan_auth_summary(sessions)
        self.db.flush()
        return {
            "required": self.contract.required,
            "auth_type": self.contract.auth_type,
            "ready": all(item.valid for item in sessions) if self.contract.required else any(item.valid for item in sessions),
            "identities": [item.identity_key for item in identities],
            "sessions": [item.to_dict() for item in sessions],
        }

    def get_material(self, identity_key: str | None = None) -> AuthMaterial | None:
        """Return persisted auth material for a specific identity or first valid session."""
        query = (
            self.db.query(ScanAuthSession, ScanIdentity)
            .outerjoin(ScanIdentity, ScanAuthSession.scan_identity_id == ScanIdentity.id)
            .filter(ScanAuthSession.scan_job_id == self.scan.id)
            .order_by(ScanAuthSession.id.asc())
        )
        if identity_key:
            query = query.filter(ScanIdentity.identity_key == identity_key)
        for session, identity in query.all():
            status = str(session.status or "")
            if status not in {"valid", "static"}:
                continue
            return AuthMaterial(
                identity_key=str(identity.identity_key if identity else identity_key or "default"),
                role=str(identity.role if identity else ""),
                auth_type=str(session.auth_type or "none"),
                headers={str(k): str(v) for k, v in dict(session.headers or {}).items()},
                cookies={str(k): str(v) for k, v in dict(session.cookies or {}).items()},
                valid=True,
                status=status,
            )
        return None

    def _upsert_identity(self, identity_contract) -> ScanIdentity:
        identity = (
            self.db.query(ScanIdentity)
            .filter(
                ScanIdentity.scan_job_id == self.scan.id,
                ScanIdentity.identity_key == identity_contract.identity_key,
            )
            .first()
        )
        if identity is None:
            identity = ScanIdentity(
                scan_job_id=self.scan.id,
                identity_key=identity_contract.identity_key,
            )
        identity.role = identity_contract.role
        identity.username_ref = identity_contract.username_ref or None
        identity.auth_type = identity_contract.auth_type or self.contract.auth_type
        identity.updated_at = datetime.now()
        return identity

    def _upsert_session(self, identity: ScanIdentity, material: AuthMaterial) -> ScanAuthSession:
        session = (
            self.db.query(ScanAuthSession)
            .filter(
                ScanAuthSession.scan_identity_id == identity.id,
                ScanAuthSession.session_key == "default",
            )
            .first()
            if identity.id
            else None
        )
        if session is None:
            session = ScanAuthSession(
                scan_job_id=self.scan.id,
                scan_identity_id=identity.id,
                session_key="default",
            )
        session.auth_type = material.auth_type
        session.status = material.status
        session.headers = material.headers
        session.cookies = material.cookies
        session.validation_result = {
            "valid": material.valid,
            "identity_key": material.identity_key,
            "role": material.role,
            "error": material.error,
        }
        session.last_validated_at = datetime.now()
        session.last_error = material.error or None
        session.updated_at = datetime.now()
        return session

    def _build_material(self, identity_key: str, role: str, contract: AuthContract) -> AuthMaterial:
        headers = dict(contract.headers)
        cookies = dict(contract.cookies)
        identity_raw = self._raw_identity(identity_key)
        headers.update({str(k): str(v) for k, v in dict(identity_raw.get("headers") or {}).items()})
        cookies.update({str(k): str(v) for k, v in dict(identity_raw.get("cookies") or {}).items()})
        bearer = str(identity_raw.get("bearer_token") or identity_raw.get("token") or "").strip()
        if bearer and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {bearer}"
        basic = identity_raw.get("basic")
        if isinstance(basic, dict) and basic.get("username") and basic.get("password") and "Authorization" not in headers:
            import base64

            raw = f"{basic.get('username')}:{basic.get('password')}".encode()
            headers["Authorization"] = f"Basic {base64.b64encode(raw).decode()}"
        status = "static" if headers or cookies else "pending"
        return AuthMaterial(
            identity_key=identity_key,
            role=role,
            auth_type=contract.auth_type,
            headers=headers,
            cookies=cookies,
            valid=bool(headers or cookies),
            status=status,
        )

    def _attempt_form_login(self, identity_key: str, role: str, contract: AuthContract) -> AuthMaterial:
        identity_raw = self._raw_identity(identity_key)
        username = str(identity_raw.get("username") or "")
        password = str(identity_raw.get("password") or "")
        if not contract.login_url or not username or not password:
            return AuthMaterial(
                identity_key=identity_key,
                role=role,
                auth_type=contract.auth_type,
                headers=dict(contract.headers),
                cookies=dict(contract.cookies),
                valid=False,
                status="failed",
                error="missing login_url, username or password",
            )

        username_field = str(identity_raw.get("username_field") or contract.metadata.get("username_field") or "username")
        password_field = str(identity_raw.get("password_field") or contract.metadata.get("password_field") or "password")
        extra_fields = dict(identity_raw.get("fields") or contract.metadata.get("fields") or {})
        request_headers = dict(contract.headers)
        request_headers.update({str(k): str(v) for k, v in dict(identity_raw.get("headers") or {}).items()})
        payload = {**extra_fields, username_field: username, password_field: password}
        try:
            with requests.Session() as session:
                csrf_field = self._fetch_csrf_field(session, contract.login_url, request_headers)
                if csrf_field and csrf_field[0] not in payload:
                    payload[csrf_field[0]] = csrf_field[1]
                response = session.post(contract.login_url, data=payload, headers=request_headers, timeout=20)
                valid, reason = self._validate_response(response, contract.success_check, contract.login_url)
                response_headers = dict(request_headers)
                if valid and "Authorization" not in response_headers:
                    token = self._extract_bearer_token(response)
                    if token:
                        response_headers["Authorization"] = f"Bearer {token}"
                return AuthMaterial(
                    identity_key=identity_key,
                    role=role,
                    auth_type=contract.auth_type,
                    headers=response_headers,
                    cookies={str(k): str(v) for k, v in session.cookies.get_dict().items()},
                    valid=valid,
                    status="valid" if valid else "failed",
                    error="" if valid else reason,
                )
        except Exception as exc:  # noqa: BLE001
            return AuthMaterial(
                identity_key=identity_key,
                role=role,
                auth_type=contract.auth_type,
                headers=dict(contract.headers),
                cookies=dict(contract.cookies),
                valid=False,
                status="failed",
                error=str(exc),
            )

    def _validate_response(
        self, response: requests.Response, success_check: dict[str, Any], login_url: str = ""
    ) -> tuple[bool, str]:
        if response.status_code >= 400:
            return False, f"login_http_{response.status_code}"
        check_type = str(success_check.get("type") or "").strip().lower()
        value = str(success_check.get("value") or "")
        body = response.text or ""
        if check_type == "text_present" and value:
            return (value in body, "success_text_absent")
        if check_type == "text_absent" and value:
            return (value not in body, "failure_text_present")
        if check_type == "status_code":
            expected = int(success_check.get("value") or 200)
            return (response.status_code == expected, f"unexpected_status_{response.status_code}")
        if login_url and response.history and str(response.url) == login_url:
            # No explicit success_check: a login POST that actually redirected
            # (response.history non-empty) and landed back on the login page
            # itself is the common signature of rejected credentials or a
            # missing CSRF token. Do NOT apply this when there was no redirect
            # at all (e.g. a JSON API that replies 200 in place) — that's the
            # normal successful shape for most REST login endpoints.
            return False, "redirected_back_to_login_url"
        return True, ""

    _CSRF_FIELD_NAMES = ("user_token", "csrf_token", "_token", "authenticity_token", "csrfmiddlewaretoken", "csrf")

    def _fetch_csrf_field(self, session: requests.Session, login_url: str, headers: dict[str, str]) -> tuple[str, str] | None:
        """Some login forms (e.g. DVWA) reject the POST without a hidden CSRF
        token minted by a prior GET of the login page."""
        try:
            resp = session.get(login_url, headers=headers, timeout=15)
        except Exception:
            return None
        html = resp.text or ""
        for name in self._CSRF_FIELD_NAMES:
            match = re.search(rf'name=["\']{name}["\'][^>]*value=["\']([^"\']*)["\']', html, re.I)
            if not match:
                match = re.search(rf'value=["\']([^"\']*)["\'][^>]*name=["\']{name}["\']', html, re.I)
            if match:
                return name, match.group(1)
        return None

    def _extract_bearer_token(self, response: requests.Response) -> str:
        """Most REST login endpoints return a JSON access token, not a cookie."""
        try:
            body = response.json()
        except ValueError:
            return ""
        if not isinstance(body, dict):
            return ""
        for key in ("access_token", "token", "accessToken", "jwt"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
        return ""

    def _raw_identity(self, identity_key: str) -> dict[str, Any]:
        state = dict(self.scan.state_data or {})
        auth_config = dict(state.get("auth_config") or {})
        for item in list(auth_config.get("identities") or []):
            if not isinstance(item, dict):
                continue
            if str(item.get("id") or item.get("identity_key") or "") == identity_key:
                return dict(item)
        return dict(auth_config)

    def _persist_scan_auth_summary(self, sessions: list[AuthMaterial]) -> None:
        state = dict(self.scan.state_data or {})
        state["auth_summary"] = {
            "auth_type": self.contract.auth_type,
            "required": self.contract.required,
            "ready": all(item.valid for item in sessions) if self.contract.required else any(item.valid for item in sessions),
            "identities": [
                {
                    "identity_key": item.identity_key,
                    "role": item.role,
                    "valid": item.valid,
                    "status": item.status,
                    "error": item.error,
                }
                for item in sessions
            ],
            "updated_at": datetime.now().isoformat(),
        }
        self.scan.state_data = state
