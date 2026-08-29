from __future__ import annotations

from types import SimpleNamespace

from app.api.routes_scans import (
    _finding_kind,
    _finding_kind_label,
    _finding_observation_summary,
    _finding_source_label,
    _finding_source_module,
)


def _finding(**overrides):
    base = {
        "tool": "nmap",
        "severity": "medium",
        "verification_status": "candidate",
        "is_false_positive": False,
        "title": "Open service",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_findings_contract_classifies_bas_info_as_observation():
    finding = _finding(tool="bas-agent", severity="info", verification_status="confirmed")
    details = {
        "source_module": "bas",
        "key_findings": [
            "Resumo nmap: 16 IP(s) varrido(s), 16 host(s) tratados como ativos pelo -Pn, duração 1.07s.",
            "Portas TCP testadas: 22,80,443",
            "Nenhuma das portas TCP BAS foi observada aberta no alvo.",
        ],
    }

    assert _finding_source_module(finding, details) == "bas"
    assert _finding_source_label("bas") == "BAS"
    assert _finding_kind(finding, details, "open") == "bas_observation"
    assert _finding_kind_label("bas_observation") == "Observação BAS"
    assert _finding_observation_summary(finding, details) == (
        "Resumo nmap: 16 IP(s) varrido(s), 16 host(s) tratados como ativos pelo -Pn, duração 1.07s. | "
        "Portas TCP testadas: 22,80,443 | "
        "Nenhuma das portas TCP BAS foi observada aberta no alvo."
    )


def test_findings_contract_classifies_confirmed_non_info_as_validated_risk():
    finding = _finding(tool="nikto", severity="medium", verification_status="confirmed")

    assert _finding_source_module(finding, {}) == "pentest"
    assert _finding_kind(finding, {}, "open") == "validated_risk"
    assert _finding_kind_label("validated_risk") == "Risco validado"


def test_findings_contract_keeps_false_positive_as_own_kind():
    finding = _finding(tool="nuclei", severity="high", verification_status="confirmed", is_false_positive=True)

    assert _finding_kind(finding, {}, "false_positive") == "false_positive"
