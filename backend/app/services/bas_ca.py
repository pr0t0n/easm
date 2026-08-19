"""BAS internal PKI: a self-signed root CA the platform uses to authenticate
BAS agents via mutual TLS.

Enrollment (username/password/token) stays on the existing plain HTTP port --
it's the one-time bootstrap step (same pattern as ACME/SPIFFE bootstrapping):
the agent has no certificate yet, so there is nothing for it to present. If
the enroll request includes a CSR (see routes_bas.py's AgentEnrollRequest),
this module signs it with the BAS root CA and the response hands the agent a
client certificate bound to its specific agent_id.

Every call after that (heartbeat, and any future agent-facing route) goes
over a SEPARATE mTLS-required uvicorn listener (see docker-compose.yml's
backend "command" and bas_mtls_port in config.py) whose SSL context requires
and verifies the client certificate against this CA at the TRANSPORT layer,
before any FastAPI route ever runs -- a connection presenting no cert, or one
this CA didn't sign, never completes the TLS handshake at all.

CA private key never leaves this module / the bas_ca_dir volume.
"""
from __future__ import annotations

import datetime
import os
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.config import settings

_LOCK = threading.Lock()

_CA_KEY_FILE = "ca.key"
_CA_CERT_FILE = "ca.crt"
_SERVER_KEY_FILE = "server.key"
_SERVER_CERT_FILE = "server.crt"


def _ca_dir() -> str:
    path = settings.bas_ca_dir
    os.makedirs(path, exist_ok=True)
    return path


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)


def ensure_ca() -> None:
    """Idempotent: generates the root CA + the mTLS listener's server
    certificate if they don't already exist on the persistent bas_ca volume.
    Safe to call from every process that needs them (backend API process,
    the mTLS uvicorn process, tests) -- a lock avoids a torn write if two
    processes race on first boot."""
    with _LOCK:
        d = _ca_dir()
        ca_key_path = os.path.join(d, _CA_KEY_FILE)
        ca_cert_path = os.path.join(d, _CA_CERT_FILE)
        server_key_path = os.path.join(d, _SERVER_KEY_FILE)
        server_cert_path = os.path.join(d, _SERVER_CERT_FILE)

        if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
            if not (os.path.exists(server_key_path) and os.path.exists(server_cert_path)):
                _generate_server_cert(ca_key_path, ca_cert_path, server_key_path, server_cert_path)
            return

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ScriptKidd.o BAS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ScriptKidd.o BAS Root CA"),
        ])
        now = datetime.datetime.utcnow()
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        _write(ca_key_path, ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        _write(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))

        _generate_server_cert(ca_key_path, ca_cert_path, server_key_path, server_cert_path)


def _generate_server_cert(ca_key_path: str, ca_cert_path: str, server_key_path: str, server_cert_path: str) -> None:
    with open(ca_key_path, "rb") as fh:
        ca_key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(ca_cert_path, "rb") as fh:
        ca_cert = x509.load_pem_x509_certificate(fh.read())

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bas-mtls.backend.local")])
    now = datetime.datetime.utcnow()
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("backend"), x509.DNSName("localhost")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _write(server_key_path, server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    _write(server_cert_path, server_cert.public_bytes(serialization.Encoding.PEM))


def ca_cert_pem() -> str:
    ensure_ca()
    with open(os.path.join(_ca_dir(), _CA_CERT_FILE)) as fh:
        return fh.read()


def server_cert_paths() -> tuple[str, str, str]:
    """Returns (server_cert_path, server_key_path, ca_cert_path) -- feeds
    uvicorn's ssl_certfile/ssl_keyfile/ssl_ca_certs for the mTLS listener."""
    ensure_ca()
    d = _ca_dir()
    return (
        os.path.join(d, _SERVER_CERT_FILE),
        os.path.join(d, _SERVER_KEY_FILE),
        os.path.join(d, _CA_CERT_FILE),
    )


def sign_agent_csr(csr_pem: str, *, agent_id: int, valid_days: int | None = None) -> str:
    """Signs an agent-submitted CSR with the BAS root CA. The issued
    certificate's CN is stamped as bas-agent-{agent_id} server-side --
    never taken from the CSR's own subject -- so a cert can never be reused
    to impersonate a different agent."""
    ensure_ca()
    d = _ca_dir()
    with open(os.path.join(d, _CA_KEY_FILE), "rb") as fh:
        ca_key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(os.path.join(d, _CA_CERT_FILE), "rb") as fh:
        ca_cert = x509.load_pem_x509_certificate(fh.read())

    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    if not csr.is_signature_valid:
        raise ValueError("invalid_csr_signature")

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"bas-agent-{agent_id}")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days or settings.bas_agent_cert_valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
