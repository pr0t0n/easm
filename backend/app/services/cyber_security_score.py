"""Cyber Security Score — score de exposição do ambiente (0–100, nota A–F).

Modelo determinístico e auditável (estilo SecurityScorecard/BitSight): cada
finding gera uma penalização multiplicativa; as penalizações somam por FATOR;
o score do fator é ``100 - soma``; o overall é a média ponderada dos fatores;
travas (caps) impõem teto à nota final.

Puro (sem I/O, sem dependências) → testável e explicável. As entradas são
findings JÁ normalizados; a origem de cada campo na plataforma está documentada
em ``finding_penalty``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# ── Tabelas do modelo (espec. do usuário) ──────────────────────────────────
SEVERITY_BASE = {
    "critical": 20.0, "high": 12.0, "medium": 6.0, "low": 2.0, "informational": 0.5,
}
CONFIDENCE_MULT = {"high": 1.0, "medium": 0.7, "low": 0.4}
EXPLOITABILITY_MULT = {"high": 1.3, "medium": 1.0, "low": 0.7}
BUSINESS_IMPACT_MULT = {"high": 1.3, "medium": 1.0, "low": 0.7}

# Pesos dos fatores (somam 1.0).
FACTOR_WEIGHTS = {
    "network_security":   0.15,
    "application_security": 0.15,
    "patching_cadence":   0.15,
    "dns_health":         0.10,
    "ip_reputation":      0.10,
    "information_leak":   0.10,
    "endpoint_security":  0.08,
    "cubit_score":        0.07,
    "hacker_chatter":     0.05,
    "social_engineering": 0.05,
}

GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def _affected_count_mult(n: int) -> float:
    if n <= 1:
        return 1.0
    if n <= 5:
        return 1.1
    if n <= 20:
        return 1.25
    return 1.5


def _age_mult(days: int) -> float:
    if days <= 7:
        return 0.8
    if days <= 30:
        return 1.0
    if days <= 90:
        return 1.15
    if days <= 180:
        return 1.3
    return 1.5


def finding_penalty(f: dict[str, Any]) -> float:
    """Penalização de UM finding. Campos esperados (origem na plataforma):

    - severity            → Finding.severity
    - confidence          → Finding.confidence_score (alto/médio/baixo)
    - exploitability      → EPSS / exploit disponível (epss_service)
    - business_impact     → criticidade do Asset
    - internet_exposed    → Asset exposto (porta/serviço público)
    - recurrent           → finding reincidente (histórico)
    - affected_count      → nº de ativos afetados
    - age_days            → now - Finding.created_at

    Defaults conservadores quando um campo falta (documentados inline).
    """
    sev = str(f.get("severity", "")).lower()
    base = SEVERITY_BASE.get(sev, 0.0)
    if base == 0.0:
        return 0.0  # severidade desconhecida/informational-zero → sem peso

    conf = CONFIDENCE_MULT.get(str(f.get("confidence", "medium")).lower(), 0.7)
    expl = EXPLOITABILITY_MULT.get(str(f.get("exploitability", "medium")).lower(), 1.0)
    biz = BUSINESS_IMPACT_MULT.get(str(f.get("business_impact", "medium")).lower(), 1.0)
    exposed = 1.2 if f.get("internet_exposed") else 0.8
    recurrent = 1.2 if f.get("recurrent") else 1.0
    affected = _affected_count_mult(int(f.get("affected_count", 1) or 1))
    age = _age_mult(int(f.get("age_days", 30) or 30))

    return base * conf * expl * biz * exposed * recurrent * affected * age


def factor_score(penalties: Iterable[float]) -> float:
    """Score de um fator: max(0, 100 - soma das penalizações)."""
    return max(0.0, 100.0 - sum(penalties))


@dataclass
class CapsContext:
    """Sinais que disparam teto na nota final."""
    critical_exploitable_exposed: bool = False
    criticals_count: int = 0
    leaked_credentials: bool = False
    privileged_credentials_leaked: bool = False
    critical_cve_exploitable_over_90d: bool = False
    sensitive_service_exposed_unprotected: bool = False
    active_compromise_evidence: bool = False


def _applicable_caps(ctx: CapsContext) -> list[tuple[str, float]]:
    caps: list[tuple[str, float]] = []
    if ctx.critical_exploitable_exposed:
        caps.append(("critical_exploravel_e_exposto", 85.0))
    if ctx.criticals_count > 3:
        caps.append(("mais_de_3_criticals", 75.0))
    if ctx.leaked_credentials:
        caps.append(("credenciais_vazadas", 80.0))
    if ctx.privileged_credentials_leaked:
        caps.append(("credenciais_privilegiadas_vazadas", 70.0))
    if ctx.critical_cve_exploitable_over_90d:
        caps.append(("cve_critica_exploravel_90d", 75.0))
    if ctx.sensitive_service_exposed_unprotected:
        caps.append(("servico_sensivel_exposto", 70.0))
    if ctx.active_compromise_evidence:
        caps.append(("comprometimento_ativo", 60.0))
    return caps


def classify(score: float) -> str:
    for floor, grade in GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


def compute_cyber_security_score(
    findings: Iterable[dict[str, Any]],
    caps_context: CapsContext | None = None,
) -> dict[str, Any]:
    """Calcula o Cyber Security Score do ambiente.

    Cada finding deve trazer ``factor`` (uma das chaves de FACTOR_WEIGHTS).
    Fatores sem findings ficam com score 100 (sem penalização) — ver nota de
    implementação no README/PR: isso torna a nota otimista para fatores que a
    plataforma ainda não avalia ativamente (hacker_chatter, social_engineering…).
    """
    ctx = caps_context or CapsContext()
    by_factor: dict[str, list[float]] = {k: [] for k in FACTOR_WEIGHTS}
    unknown_factor: list[str] = []

    for f in findings:
        factor = str(f.get("factor", "")).lower()
        if factor not in by_factor:
            unknown_factor.append(factor or "(vazio)")
            continue
        by_factor[factor].append(finding_penalty(f))

    factor_scores = {k: round(factor_score(v), 2) for k, v in by_factor.items()}
    overall = sum(factor_scores[k] * w for k, w in FACTOR_WEIGHTS.items())

    caps = _applicable_caps(ctx)
    cap_value = min((c[1] for c in caps), default=100.0)
    final = min(overall, cap_value)

    return {
        "overall_score": round(overall, 2),
        "final_score": round(final, 2),
        "grade": classify(final),
        "factor_scores": factor_scores,
        "applied_caps": [{"reason": r, "ceiling": v} for r, v in caps],
        "cap_ceiling": cap_value,
        "unknown_factor_findings": unknown_factor,
    }
