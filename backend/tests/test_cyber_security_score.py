"""Testes do Cyber Security Score — valida o modelo determinístico da espec."""
from __future__ import annotations

from app.services.cyber_security_score import (
    CapsContext,
    classify,
    compute_cyber_security_score,
    finding_penalty,
    factor_score,
)


def test_pesos_dos_fatores_somam_um():
    from app.services.cyber_security_score import FACTOR_WEIGHTS
    assert round(sum(FACTOR_WEIGHTS.values()), 6) == 1.0


def test_ambiente_limpo_e_nota_A():
    r = compute_cyber_security_score([])
    assert r["overall_score"] == 100.0
    assert r["final_score"] == 100.0
    assert r["grade"] == "A"


def test_penalty_de_um_critico_pior_caso_componentes():
    # critical(20) × conf high(1.0) × expl high(1.3) × biz high(1.3)
    # × exposed(1.2) × recurrent(1.2) × affected>20(1.5) × age>180(1.5)
    f = {
        "severity": "critical", "confidence": "high", "exploitability": "high",
        "business_impact": "high", "internet_exposed": True, "recurrent": True,
        "affected_count": 25, "age_days": 200,
    }
    expected = 20 * 1.0 * 1.3 * 1.3 * 1.2 * 1.2 * 1.5 * 1.5
    assert round(finding_penalty(f), 4) == round(expected, 4)


def test_penalty_low_recente_baixa_confianca():
    f = {"severity": "low", "confidence": "low", "exploitability": "low",
         "business_impact": "low", "internet_exposed": False, "recurrent": False,
         "affected_count": 1, "age_days": 3}
    expected = 2 * 0.4 * 0.7 * 0.7 * 0.8 * 1.0 * 1.0 * 0.8
    assert round(finding_penalty(f), 4) == round(expected, 4)


def test_severidade_desconhecida_nao_penaliza():
    assert finding_penalty({"severity": "nope"}) == 0.0
    assert finding_penalty({"severity": "informational"}) >= 0.0


def test_factor_score_nunca_negativo():
    assert factor_score([60, 60]) == 0.0   # 100 - 120 → floor 0
    assert factor_score([30]) == 70.0


def test_overall_e_media_ponderada():
    # um único critico em application_security derruba só esse fator (15%)
    f = {"factor": "application_security", "severity": "critical", "confidence": "high",
         "exploitability": "medium", "business_impact": "medium",
         "internet_exposed": False, "recurrent": False, "affected_count": 1, "age_days": 10}
    r = compute_cyber_security_score([f])
    pen = finding_penalty(f)
    expected_appsec = max(0, 100 - pen)
    # overall = appsec*0.15 + 100*(0.85)
    expected_overall = expected_appsec * 0.15 + 100 * 0.85
    assert round(r["factor_scores"]["application_security"], 2) == round(expected_appsec, 2)
    assert round(r["overall_score"], 2) == round(expected_overall, 2)


def test_cap_credenciais_privilegiadas():
    # ambiente perfeito (100), mas credencial privilegiada vazada → teto 70
    r = compute_cyber_security_score([], CapsContext(privileged_credentials_leaked=True))
    assert r["final_score"] == 70.0
    assert r["grade"] == "C"
    assert any(c["ceiling"] == 70.0 for c in r["applied_caps"])


def test_cap_comprometimento_ativo_e_o_menor_teto():
    ctx = CapsContext(leaked_credentials=True, active_compromise_evidence=True, criticals_count=5)
    r = compute_cyber_security_score([], ctx)
    assert r["final_score"] == 60.0  # min(80, 75, 60)
    assert r["grade"] == "D"


def test_classificacao_faixas():
    assert classify(95) == "A"
    assert classify(90) == "A"
    assert classify(89.9) == "B"
    assert classify(80) == "B"
    assert classify(70) == "C"
    assert classify(60) == "D"
    assert classify(59.9) == "F"


def test_factor_desconhecido_e_reportado():
    r = compute_cyber_security_score([{"factor": "quantum", "severity": "high"}])
    assert "quantum" in r["unknown_factor_findings"]
