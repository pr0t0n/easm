"""interactsh_callback.py — L2: Out-of-band callback infrastructure.

Provides Interactsh-based OOB detection for blind SSRF, XSS, SQLi (DNS/HTTP callbacks).

Interactsh is a tool that generates unique subdomains and HTTP/DNS listeners.
When a payload like `http://xyz.oast.fun` is injected into a target and it
makes an outbound request, Interactsh records the callback.

This service:
  1. Registers a session with an Interactsh server (public or self-hosted)
  2. Generates unique correlation IDs per finding/test
  3. Polls the Interactsh server for callbacks
  4. Promotes candidate findings to "confirmed" when a callback arrives

Config:
  settings.interactsh_server — URL of the Interactsh server (default: oast.fun)
  settings.interactsh_token  — API token (optional, for private servers)
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import time
import uuid
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.core.config import settings

logger = logging.getLogger(__name__)

# Public Interactsh servers (use any, fall back on rate limit)
DEFAULT_INTERACTSH_SERVERS = [
    "https://oast.fun",
    "https://oast.pro",
    "https://oast.live",
    "https://oast.site",
    "https://oast.online",
]

_session_id: str | None = None
_correlation_id: str | None = None
_secret_key: str | None = None
_server_url: str | None = None
_rsa_private_key: rsa.RSAPrivateKey | None = None


def _get_server() -> str:
    """Return configured or first available public server."""
    return str(getattr(settings, "interactsh_server", "") or DEFAULT_INTERACTSH_SERVERS[0])


def register_session() -> dict[str, Any]:
    """Register a new Interactsh session. Returns {server, correlation_id, secret_key}.

    The real Interactsh protocol requires "public-key" to be an actual RSA
    public key (SubjectPublicKeyInfo, PEM, base64-encoded) — the server uses
    it to RSA-OAEP-encrypt the AES key used for future interaction payloads.
    The previous implementation sent a random hex token instead of a key,
    which the server always rejected with 400 ("failed to parse PEM block
    containing the key") — registration, and therefore every OOB
    confirmation downstream, has never succeeded. Verified live against the
    real oast.fun server: a proper RSA keypair registers successfully.
    """
    global _session_id, _correlation_id, _secret_key, _server_url, _rsa_private_key

    server = _get_server()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_b64 = base64.b64encode(public_pem).decode()
    secret = str(uuid.uuid4())
    correlation_id = secrets.token_hex(10)

    try:
        resp = requests.post(
            f"{server}/register",
            json={
                "public-key": public_key_b64,
                "secret-key": secret,
                "correlation-id": correlation_id,
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        _server_url = server
        _correlation_id = correlation_id
        _secret_key = secret
        _rsa_private_key = private_key
        logger.info("interactsh session registered: server=%s correlation_id=%s", server, correlation_id)
        return {"server": server, "correlation_id": correlation_id, "domain": data.get("domain", f"{correlation_id}.{server.replace('https://', '')}")}
    except Exception as e:
        logger.debug("interactsh register failed: %s", e)
        return {"error": str(e)}


def generate_oob_payload(
    finding_id: int | None = None,
    test_type: str = "ssrf",
) -> str:
    """Generate a unique OOB callback URL for a specific finding/test.

    The subdomain encodes the finding_id and test_type so callbacks can be
    correlated back to specific findings.

    Returns a URL like: http://f123-ssrf-abc123.oast.fun
    """
    global _correlation_id, _server_url

    if not _correlation_id:
        result = register_session()
        if "error" in result:
            # Fallback: generate a mock URL that won't actually work
            return f"http://easm-oob-{secrets.token_hex(8)}.example.invalid"

    unique_id = secrets.token_hex(6)
    slug = f"f{finding_id or 0}-{test_type[:8]}-{unique_id}"
    server_host = (_server_url or DEFAULT_INTERACTSH_SERVERS[0]).replace("https://", "").replace("http://", "")
    return f"http://{slug}.{_correlation_id}.{server_host}"


def _decrypt_event(encrypted_aes_key: str, encoded_event: str) -> dict[str, Any] | None:
    """Decrypt one Interactsh interaction record.

    Protocol (matches the real interactsh-client): the server RSA-OAEP(SHA256)
    encrypts a per-session AES-256 key with our public key; each interaction
    is AES-CFB encrypted with that key, IV = first 16 bytes of the ciphertext.
    This has been verified to register and RSA-decrypt correctly against the
    live public oast.fun server; the AES-CFB layer matches the known
    interactsh-client source but has NOT been confirmed end-to-end against a
    real captured interaction (the live test session never received one
    within the polling window, plausibly public-server propagation delay) —
    treat decrypt failures here as "unconfirmed protocol detail", not proof
    no callback occurred.
    """
    if not _rsa_private_key:
        return None
    try:
        aes_key_iv = _rsa_private_key.decrypt(
            base64.b64decode(encrypted_aes_key),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        raw = base64.b64decode(encoded_event)
        iv, ciphertext = raw[:16], raw[16:]
        decryptor = Cipher(algorithms.AES(aes_key_iv[:32]), modes.CFB(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(plaintext)
    except Exception as exc:
        logger.debug("interactsh event decrypt failed (unconfirmed protocol detail): %s", exc)
        return None


def poll_callbacks(timeout_seconds: int = 30) -> list[dict[str, Any]]:
    """Poll the Interactsh server for any callbacks since last poll.

    Returns list of callback events: [{unique_id, protocol, raw_request, timestamp}]
    """
    global _correlation_id, _secret_key, _server_url

    if not _correlation_id or not _server_url:
        return []

    try:
        resp = requests.get(
            f"{_server_url}/poll",
            params={"id": _correlation_id, "secret": _secret_key},
            timeout=max(10, timeout_seconds),
        )
        if resp.status_code == 401:
            logger.debug("interactsh poll: invalid session")
            return []
        resp.raise_for_status()
        data = resp.json()
        raw_events = data.get("data") or []
        aes_key = data.get("aes_key")
        if not raw_events or not aes_key:
            return []
        events = [e for e in (_decrypt_event(aes_key, raw) for raw in raw_events) if e]
        logger.debug("interactsh poll: %d/%d callbacks decrypted", len(events), len(raw_events))
        return [
            {
                "unique_id": e.get("unique-id"),
                "protocol": e.get("protocol"),
                "raw_request": e.get("raw-request"),
                "remote_address": e.get("remote-address"),
                "timestamp": e.get("timestamp"),
            }
            for e in events
        ]
    except Exception as e:
        logger.debug("interactsh poll failed: %s", e)
        return []


def check_and_confirm_oob_findings(db, scan_id: int) -> int:
    """Poll Interactsh and promote candidate findings that triggered callbacks.

    Returns count of findings confirmed via OOB callback.
    """
    from app.models.models import Finding

    callbacks = poll_callbacks(timeout_seconds=10)
    if not callbacks:
        return 0

    confirmed = 0

    for cb in callbacks:
        uid = str(cb.get("unique_id") or "")
        # Parse finding_id from slug: f{id}-{type}-{hex}
        if uid.startswith("f") and "-" in uid:
            parts = uid[1:].split("-")
            try:
                finding_id = int(parts[0])
            except (ValueError, IndexError):
                continue

            finding = db.query(Finding).filter(
                Finding.id == finding_id,
                Finding.scan_job_id == scan_id,
            ).first()

            if finding and finding.verification_status in ("candidate", "hypothesis"):
                finding.verification_status = "confirmed"
                d = dict(finding.details or {})
                d["verification_status"] = "confirmed"
                d["oob_callback"] = {
                    "protocol": cb.get("protocol"),
                    "remote_address": cb.get("remote_address"),
                    "timestamp": cb.get("timestamp"),
                }
                d["needs_verification"] = False
                finding.details = d
                confirmed += 1

    if confirmed:
        from datetime import datetime
        from app.models.models import ScanLog
        db.add(ScanLog(
            scan_job_id=scan_id,
            source="interactsh-oob",
            level="INFO",
            message=f"oob_callback_confirmed scan={scan_id} findings_confirmed={confirmed}",
        ))
        db.commit()

    return confirmed


def deregister_session() -> None:
    """Clean up the Interactsh session when scan completes."""
    global _correlation_id, _secret_key, _server_url

    if not _correlation_id or not _server_url:
        return
    try:
        requests.post(
            f"{_server_url}/deregister",
            json={"correlation-id": _correlation_id, "secret-key": _secret_key},
            timeout=5,
        )
        logger.info("interactsh session deregistered")
    except Exception:
        pass
    finally:
        _correlation_id = None
        _secret_key = None
        _server_url = None
