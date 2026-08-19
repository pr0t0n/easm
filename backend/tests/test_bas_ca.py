"""bas_ca.py: the BAS agent mTLS root CA. Enrollment stays on the plain
port (bootstrap, no cert yet); every call after that (heartbeat) must
present a certificate this CA signed -- these tests verify the CA/signing
logic in isolation from the actual mTLS listener."""
from __future__ import annotations

import importlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@pytest.fixture
def bas_ca(tmp_path, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "bas_ca_dir", str(tmp_path / "bas_ca"))
    from app.services import bas_ca as module
    importlib.reload(module)
    return module


def _make_csr(cn: str = "irrelevant-client-supplied-cn"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"), key


def test_ensure_ca_creates_all_four_files(bas_ca, tmp_path):
    bas_ca.ensure_ca()
    d = tmp_path / "bas_ca"
    assert (d / "ca.key").exists()
    assert (d / "ca.crt").exists()
    assert (d / "server.crt").exists()
    assert (d / "server.key").exists()


def test_ensure_ca_is_idempotent_does_not_regenerate(bas_ca, tmp_path):
    bas_ca.ensure_ca()
    first = (tmp_path / "bas_ca" / "ca.crt").read_bytes()
    bas_ca.ensure_ca()
    second = (tmp_path / "bas_ca" / "ca.crt").read_bytes()
    assert first == second


def test_ca_cert_pem_returns_a_valid_self_signed_root(bas_ca):
    pem = bas_ca.ca_cert_pem()
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    assert cert.issuer == cert.subject  # self-signed root
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is True


def test_sign_agent_csr_binds_cn_to_agent_id_not_the_csrs_own_subject(bas_ca):
    """The CSR's own CN must be ignored -- otherwise an agent could request
    a cert claiming to be a different agent_id."""
    csr_pem, _key = _make_csr(cn="pretend-to-be-someone-else")
    cert_pem = bas_ca.sign_agent_csr(csr_pem, agent_id=42)
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "bas-agent-42"
    assert "pretend-to-be-someone-else" not in cert.subject.rfc4514_string()


def test_sign_agent_csr_chains_to_the_ca(bas_ca):
    csr_pem, _key = _make_csr()
    cert_pem = bas_ca.sign_agent_csr(csr_pem, agent_id=7)
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    ca_cert = x509.load_pem_x509_certificate(bas_ca.ca_cert_pem().encode("utf-8"))
    assert cert.issuer == ca_cert.subject


def test_sign_agent_csr_rejects_invalid_signature(bas_ca):
    # Hand-craft a CSR whose signature won't validate by tampering with a
    # legitimately-generated one's signature bytes.
    csr_pem, _key = _make_csr()
    tampered = csr_pem.replace("A", "B", 1)
    with pytest.raises(Exception):
        bas_ca.sign_agent_csr(tampered, agent_id=1)


def test_server_cert_paths_point_to_existing_files(bas_ca, tmp_path):
    cert_path, key_path, ca_path = bas_ca.server_cert_paths()
    assert cert_path.endswith("server.crt")
    assert key_path.endswith("server.key")
    assert ca_path.endswith("ca.crt")
    import os
    assert os.path.isfile(cert_path)
    assert os.path.isfile(key_path)
    assert os.path.isfile(ca_path)


def test_server_cert_is_signed_by_the_ca_and_not_a_ca_itself(bas_ca):
    cert_path, _key_path, ca_path = bas_ca.server_cert_paths()
    with open(cert_path, "rb") as fh:
        server_cert = x509.load_pem_x509_certificate(fh.read())
    with open(ca_path, "rb") as fh:
        ca_cert = x509.load_pem_x509_certificate(fh.read())
    assert server_cert.issuer == ca_cert.subject
    basic_constraints = server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is False
