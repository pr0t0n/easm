"""Encryption-at-rest for JSONB columns holding captured session material.

ScanAuthSession.headers/.cookies carry real Authorization headers and session
cookies once credential capture is wired up — today's plaintext JSONB storage
means anyone with DB access reads live sessions in the clear. EncryptedJSON
keeps the column type as JSONB (no schema migration needed) but encrypts the
serialized payload with Fernet before it ever reaches the database, and
decrypts on read. Values written before this type was applied cannot be read
back through it (Fernet raises InvalidToken) — see the plan's note on
truncating pre-existing scan_auth_sessions rows rather than migrating them.
"""
from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from app.core.config import settings


def _fernet() -> Fernet:
    return Fernet(settings.credential_encryption_key.encode())


class EncryptedJSON(TypeDecorator):
    """JSONB column whose value is Fernet-encrypted before storage."""

    impl = JSONB
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> Any:
        if value is None:
            return None
        plaintext = json.dumps(value, default=str).encode("utf-8")
        token = _fernet().encrypt(plaintext).decode("ascii")
        return {"__enc__": token}

    def process_result_value(self, value: Any, dialect) -> Any:
        if value is None:
            return None
        if isinstance(value, dict) and "__enc__" in value:
            plaintext = _fernet().decrypt(value["__enc__"].encode("ascii"))
            return json.loads(plaintext)
        # Pre-existing plaintext row written before this type was applied —
        # surface it as-is rather than crashing the whole request; callers
        # that need a valid session will fail their own validity check on
        # this stale data anyway (see the plan's truncate-vs-migrate note).
        return value


class StateDataJSON(TypeDecorator):
    """ScanJob.state_data JSONB, with credential-bearing subtrees encrypted at rest.

    state_data is a large, heterogeneous blob written and read by nearly every
    service in the pentest pipeline as a plain dict (`state.get("auth_config")`,
    `job.state_data = state`, ...). Splitting the credential-bearing keys into
    a dedicated column would mean touching every one of those call sites, so
    instead this transparently Fernet-encrypts just the `auth_config` and
    `llm_risk` subtrees on write and decrypts them on read — every existing
    caller keeps working unchanged, while a direct read of the `scan_jobs` row
    (or `state_data->'auth_config'` in raw SQL) sees only an opaque token
    instead of the raw password/bearer_token/cookie material (SEC-003).
    """

    impl = JSONB
    cache_ok = True

    _SENSITIVE_KEYS = ("auth_config", "llm_risk")

    def process_bind_param(self, value: Any, dialect) -> Any:
        if value is None or not isinstance(value, dict):
            return value
        out = dict(value)
        for key in self._SENSITIVE_KEYS:
            sub = out.get(key)
            if sub is None:
                continue
            if isinstance(sub, dict) and "__enc__" in sub:
                continue  # already encrypted (e.g. re-saving a loaded row unchanged)
            plaintext = json.dumps(sub, default=str).encode("utf-8")
            out[key] = {"__enc__": _fernet().encrypt(plaintext).decode("ascii")}
        return out

    def process_result_value(self, value: Any, dialect) -> Any:
        if value is None or not isinstance(value, dict):
            return value
        out = dict(value)
        for key in self._SENSITIVE_KEYS:
            sub = out.get(key)
            if isinstance(sub, dict) and "__enc__" in sub:
                plaintext = _fernet().decrypt(sub["__enc__"].encode("ascii"))
                out[key] = json.loads(plaintext)
        return out


__all__ = ["EncryptedJSON", "StateDataJSON"]
