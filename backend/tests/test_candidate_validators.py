"""Testes das Fases 1-4 do plano de validação de candidates."""
from __future__ import annotations

from types import SimpleNamespace

from app.services.candidate_validators import (
    classify_candidate_family,
    extract_passive_signal,
    is_passive_observation,
    signals_match,
    FAMILY_VALIDATORS,
)


# ─────────────────────────────────────────────────────────────
# LA-2 — classificação passiva (fronteira dura com achados ativos)
# ─────────────────────────────────────────────────────────────

def test_port_finding_is_passive_exposed_service():
    fam = classify_candidate_family("Portas abertas detectadas: www.example.com (1 porta)", "nmap")
    assert fam == "exposed_service"
    assert is_passive_observation("Portas abertas detectadas: www.example.com (1 porta)", "nmap")


def test_header_finding_is_passive_security_headers():
    fam = classify_candidate_family(
        "Header de seguranca ausente: strict-transport-security", "curl-headers",
        {"header_name": "strict-transport-security"},
    )
    assert fam == "security_headers"


def test_active_sqli_is_not_passive():
    assert not is_passive_observation("SQL injection in login parameter", "nuclei-sqli")
    assert classify_candidate_family("SQL injection in login parameter", "nuclei-sqli") is None


def test_active_rce_title_is_not_passive():
    # "RCE" real no título: tool ativa, título ativo — nunca passivo
    assert not is_passive_observation("Remote code execution via upload", "nuclei")


def test_osint_finding_classified():
    fam = classify_candidate_family("Portas expostas (Shodan): www.example.com — 2 portas", "shodan-cli")
    assert fam == "osint_exposure"


def test_every_catalog_family_has_expected_signals():
    for family, spec in FAMILY_VALIDATORS.items():
        assert spec.get("expected_signals", {}).get("positive"), family
        assert spec.get("validator"), family


# ─────────────────────────────────────────────────────────────
# Sinal essencial e comparação de re-probe
# ─────────────────────────────────────────────────────────────

def test_extract_port_signal():
    sig = extract_passive_signal("Versão de serviço exposta: tcpwrapped 8080/tcp open tcpwrapped", "nmap")
    assert sig["family"] == "exposed_service"
    assert sig.get("port") == 8080


def test_port_signal_match():
    sig = {"family": "exposed_service", "port": 443}
    ok, reason = signals_match(sig, "443/tcp open  https\n80/tcp open http")
    assert ok and "443" in reason
    ok, reason = signals_match(sig, "443/tcp closed  https")
    assert not ok


def test_header_signal_match():
    sig = {"family": "security_headers", "header_name": "strict-transport-security"}
    ok, _ = signals_match(sig, "HTTP/1.1 200 OK\nserver: cloudflare\n")
    assert ok  # header ausente na stdout → ainda ausente
    ok, _ = signals_match(sig, "strict-transport-security: max-age=31536000\n")
    assert not ok  # agora presente → refutado/corrigido


def test_fingerprint_signal_match():
    sig = {"family": "tech_fingerprint", "fingerprint_terms": ["cloudflare", "nginx"]}
    ok, _ = signals_match(sig, "Server: cloudflare\nx-powered-by: nginx")
    assert ok
    ok, _ = signals_match(sig, "Server: apache")
    assert not ok


def test_unknown_family_no_match():
    ok, reason = signals_match({"family": ""}, "anything")
    assert not ok and reason == "unknown family"


# ─────────────────────────────────────────────────────────────
# nc_probe — teste mínimo para tcpwrapped/inconclusivo
# ─────────────────────────────────────────────────────────────

def test_needs_nc_probe_for_tcpwrapped():
    from app.services.candidate_validators import needs_nc_probe
    assert needs_nc_probe("Versão de serviço exposta: tcpwrapped 8080/tcp open", {"evidence": "8080/tcp open tcpwrapped"})
    assert not needs_nc_probe("Portas abertas detectadas: www.example.com (1 porta)", {"evidence": "80/tcp open http"})


def test_nc_probe_open_refutes_tcpwrapped():
    sig = {"family": "exposed_service", "port": 8080}
    ok, reason = signals_match(sig, "Connection to www.example.com (104.20.23.154) 8080 [tcp/http] succeeded!")
    assert ok and "nc connect succeeded" in reason


def test_nc_probe_refused():
    sig = {"family": "exposed_service", "port": 8080}
    ok, reason = signals_match(sig, "nc: connect to www.example.com port 8080 (tcp) failed: Connection refused")
    assert not ok and "refused" in reason


def test_nc_probe_timeout_is_not_negative_proof():
    # timeout não é refutação — fica como não-observado (candidate)
    sig = {"family": "exposed_service", "port": 8080}
    ok, reason = signals_match(sig, "nc: connect to www.example.com port 8080 (tcp) timed out")
    assert not ok and "not observed" in reason


def test_nc_probe_markers():
    sig = {"family": "exposed_service", "port": 8080}
    ok, reason = signals_match(sig, "EASM_TCP_OPEN")
    assert ok and "tcp connect succeeded" in reason
    ok, reason = signals_match(sig, "EASM_TCP_REFUSED")
    assert not ok and "refused" in reason
    ok, reason = signals_match(sig, "EASM_TCP_TIMEOUT")
    assert not ok and "not negative proof" in reason


# ─────────────────────────────────────────────────────────────
# Guardrail humano — needs_human_review apenas para categorias bloqueadas
# ─────────────────────────────────────────────────────────────

def test_guardrail_category_dos():
    from app.services.candidate_validators import guardrail_category
    assert guardrail_category("Potential denial of service via expensive query") == "dos"
    assert guardrail_category("DDoS amplification vector detected") == "ddos"


def test_guardrail_category_defacement_and_lfi():
    from app.services.candidate_validators import guardrail_category
    assert guardrail_category("Defacement possible via content injection") == "defacement"
    assert guardrail_category("Local file inclusion in download parameter") in {"lfi", "lfri"}
    assert guardrail_category("Arquivo /etc/passwd exposto via LFI") in {"lfi", "lfri"}


def test_non_guardrail_finding_returns_none():
    from app.services.candidate_validators import guardrail_category
    assert guardrail_category("Header de seguranca ausente: hsts") is None
    assert guardrail_category("SQL injection in login parameter") is None
    assert guardrail_category("Portas abertas detectadas: host (1 porta)") is None


def test_human_test_command_includes_url_and_policy():
    from app.services.candidate_validators import build_human_test_command
    cmd = build_human_test_command("Defacement possible", "zap-baseline", {"url": "https://x.example.com/admin"})
    assert "GUARDRAIL" in cmd and "https://x.example.com/admin" in cmd and "curl -sk" in cmd
