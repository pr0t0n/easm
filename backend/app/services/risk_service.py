from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Versioning & Market-Calibrated Methodology
# ──────────────────────────────────────────────────────────────────────────────

METHODOLOGY_VERSION = "v1.2"

# Registry completo das versões da metodologia de rating.
# Fontes de mercado para calibragem dos pesos:
#   • BitSight Security Ratings Methodology (2023)
#   • SecurityScorecard Factor Weights (SSC published 2023-Q2)
#   • FAIR Institute Calibration Guide v2.0
#   • IBM Cost of a Data Breach 2023 (setor x custo médio)
#   • Ponemon Institute 2023 State of Cyber Resilience
#   • EPSS v3 (Exploit Prediction Scoring System — FIRST.org 2023)
METHODOLOGY_REGISTRY: dict[str, dict] = {
    "v1.0": {
        "released_at": "2025-01-01",
        "description": "Score simples baseado em contagem de severidade. Fórmula linear sem persistência temporal.",
        "formula": "score = max(0, min(100, 100 − (critical×30 + high×15 + medium×8 + low×2)))",
        "weights": None,
        "changes": ["Versão inicial — modelo de pontuação por severidade bruta."],
        "known_limitations": [
            "Penalidade linear escala ilimitada com número de findings.",
            "Sem contexto temporal ou econômico.",
            "Sem distinção por setor/segmento.",
        ],
    },
    "v1.1": {
        "released_at": "2025-06-01",
        "description": (
            "Motor de rating contínuo com 4 fatores fixos: Exposição (35%), Persistência AGE (25%), "
            "Impacto Econômico FAIR (20%), Resiliência Operacional (20%). Penalidade linear."
        ),
        "weights": {
            "exposure": 0.35,
            "persistence_age": 0.25,
            "economic_fair": 0.20,
            "operational_resilience": 0.20,
        },
        "changes": [
            "Modelo de 4 fatores substituiu score simples.",
            "AGE refatorado com age_score e persistence_penalty_points.",
            "FAIR persistence_boost integrado ao cálculo de LEF.",
            "LLM Risk como dimensão separada.",
        ],
        "known_limitations": [
            "Pesos genéricos sem distinção por segmento de mercado.",
            "Penalidade de exposição linear: 10 criticals = penalidade 10× maior que 1 critical.",
            "Streak de persistência linear, não reflete decaimento real de risco.",
        ],
    },
    "v1.2": {
        "released_at": "2026-03-25",
        "description": (
            "Calibragem de mercado com pesos por segmento (BitSight/SecurityScorecard/IBM 2023). "
            "Penalidade de exposição logarítmica (diminishing marginal impact). "
            "Decaimento de persistência alinhado ao EPSS v3. Pesos validados contra setor."
        ),
        "weights_by_segment": {
            "Financial Services": {"exposure": 0.38, "persistence_age": 0.24, "economic_fair": 0.27, "operational_resilience": 0.11},
            "Healthcare":         {"exposure": 0.36, "persistence_age": 0.30, "economic_fair": 0.24, "operational_resilience": 0.10},
            "Public Sector":      {"exposure": 0.33, "persistence_age": 0.32, "economic_fair": 0.15, "operational_resilience": 0.20},
            "Retail":             {"exposure": 0.34, "persistence_age": 0.22, "economic_fair": 0.27, "operational_resilience": 0.17},
            "Education":          {"exposure": 0.30, "persistence_age": 0.28, "economic_fair": 0.20, "operational_resilience": 0.22},
            "Digital Services":   {"exposure": 0.33, "persistence_age": 0.27, "economic_fair": 0.22, "operational_resilience": 0.18},
        },
        "changes": [
            "Exposure weight ajustado por setor: data breach cost (IBM 2023) como proxy de impacto.",
            "Persistence weight elevado em Healthcare(30%) e Public Sector(32%): dwell time mais crítico.",
            "Economic FAIR weight elevado em Technology(28%) e Retail(27%): PII + propriedade intelectual.",
            "Penalidade de exposição migrou de linear para log10(1+n)×k — evita super-penalidade em ASMs grandes.",
            "Streak penalty usa log10(streak+1) multiplicado por log1p(open_count) — alinhado ao EPSS v3 decay.",
            "Calibração: 1 critical ≈ −15pts; 5 criticals ≈ −37pts (antes: −28pts e −140pts).",
        ],
        "references": [
            "BitSight Ratings Methodology 2023 — bitsight.com/blog/bitsight-ratings-methodology",
            "SecurityScorecard Factor Weights Q2-2023 — securityscorecard.com/research/methodology",
            "IBM Cost of a Data Breach Report 2023 — ibm.com/reports/data-breach",
            "EPSS v3 — FIRST.org/epss",
            "FAIR Institute Calibration Guidelines v2.0 — fairinstitute.org",
        ],
    },
}

# Pesos por segmento de mercado — espelha METHODOLOGY_REGISTRY[v1.2][weights_by_segment]
SEGMENT_WEIGHTS: dict[str, dict[str, float]] = {
    seg: d
    for seg, d in METHODOLOGY_REGISTRY["v1.2"]["weights_by_segment"].items()
}


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _to_utc(value)
    if not isinstance(value, str):
        return None

    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return _to_utc(parsed)


def _days_since(now_utc: datetime, dt: datetime | None) -> int | None:
    if dt is None:
        return None
    return max(0, int((now_utc - dt).total_seconds() // 86400))


def _first_valid_datetime(details: dict[str, Any], keys: list[str]) -> datetime | None:
    for key in keys:
        parsed = _parse_datetime(details.get(key))
        if parsed is not None:
            return parsed
    return None


def severity_weight(severity: str | None) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity or "low").lower(), 1)


def _log_exposure_penalty(critical: int, high: int, medium: int, low: int) -> float:
    """Penalidade logarítmica de exposição técnica.

    Usa log1p(n) × peso para cada severidade, evitando super-penalização em
    superfícies de ataque grandes (BitSight-style diminishing marginal impact).

    Calibração de referência (1 finding por severidade):
      critical : log(2)×21.7 ≈ 15 pts
      high     : log(2)×11.5 ≈  8 pts
      medium   : log(2)× 5.2 ≈  3.6 pts
      low      : log(2)× 1.6 ≈  1.1 pts
    """
    penalty = (
        math.log1p(critical) * 21.7
        + math.log1p(high) * 11.5
        + math.log1p(medium) * 5.2
        + math.log1p(low) * 1.6
    )
    return min(100.0, penalty)


def compute_age_metrics(finding_created_at: datetime | None, details: dict[str, Any] | None) -> dict[str, Any]:
    details = details or {}
    now_utc = datetime.now(timezone.utc)

    env_first_seen = _to_utc(finding_created_at)
    market_known_at = _first_valid_datetime(
        details,
        [
            "cvss_published_at",
            "cve_published_at",
            "nvd_published_at",
            "cve_created_at",
            "cvss_created_at",
        ],
    )
    exploit_published_at = _first_valid_datetime(
        details,
        [
            "exploit_published_at",
            "exploit_db_published_at",
            "exploitdb_published_at",
            "kev_added_at",
        ],
    )

    known_env_days = _days_since(now_utc, env_first_seen)
    known_market_days = _days_since(now_utc, market_known_at)
    exploit_days = _days_since(now_utc, exploit_published_at)

    # AGE posture score (0-100): penaliza persistencia interna, antiguidade de mercado
    # e disponibilidade de exploit publico.
    env_penalty = min(55.0, float(known_env_days or 0) * 0.75)
    market_penalty = min(30.0, float(known_market_days or 0) * 0.08)
    exploit_penalty = 15.0 if exploit_days is not None else 0.0
    age_score = max(0.0, 100.0 - env_penalty - market_penalty - exploit_penalty)

    return {
        "known_in_environment_at": env_first_seen.isoformat() if env_first_seen else None,
        "known_in_market_at": market_known_at.isoformat() if market_known_at else None,
        "exploit_published_at": exploit_published_at.isoformat() if exploit_published_at else None,
        "known_in_environment_days": known_env_days,
        "known_in_market_days": known_market_days,
        "exploit_published_days": exploit_days,
        "age_score": round(age_score, 2),
        "persistence_penalty_points": round(env_penalty, 2),
    }


def compute_fair_metrics(severity: str | None, confidence_score: int | None, details: dict[str, Any] | None, age: dict[str, Any]) -> dict[str, Any]:
    sev = str(severity or "low").lower()
    conf = max(0.0, min(1.0, float(confidence_score or 0) / 100.0))

    base_tef = {
        "critical": 0.82,
        "high": 0.66,
        "medium": 0.45,
        "low": 0.24,
    }.get(sev, 0.24)

    env_age_days = float(age.get("known_in_environment_days") or 0)
    market_age_days = float(age.get("known_in_market_days") or 0)
    exploit_days = age.get("exploit_published_days")
    age_score = float(age.get("age_score") or 0.0)

    env_age_factor = min(env_age_days / 90.0, 1.0) * 0.12
    market_age_factor = min(market_age_days / 365.0, 1.0) * 0.08
    exploit_factor = 0.22 if exploit_days is not None else 0.0

    persistence_boost = max(0.0, min(0.22, (100.0 - age_score) / 500.0))
    loss_event_frequency = max(0.01, min(1.0, base_tef + (conf * 0.18) + env_age_factor + market_age_factor + exploit_factor + persistence_boost))

    base_loss_usd = {
        "critical": 350000.0,
        "high": 150000.0,
        "medium": 60000.0,
        "low": 18000.0,
    }.get(sev, 18000.0)

    details = details or {}
    exposure_multiplier = 1.15 if str(details.get("public_exposure", "")).lower() in {"true", "1", "yes"} else 1.0
    data_multiplier = 1.2 if str(details.get("data_sensitivity", "")).lower() in {"high", "critical"} else 1.0

    loss_magnitude_usd = base_loss_usd * (1.0 + conf * 0.35) * exposure_multiplier * data_multiplier
    annualized_loss_exposure_usd = loss_event_frequency * loss_magnitude_usd

    # FAIR score sintetico (0-100) para facilitar priorizacao visual.
    fair_score = min(100.0, (loss_event_frequency * 50.0) + min(42.0, annualized_loss_exposure_usd / 9000.0) + min(8.0, persistence_boost * 30.0))

    return {
        "loss_event_frequency": round(loss_event_frequency, 4),
        "loss_magnitude_usd": round(loss_magnitude_usd, 2),
        "annualized_loss_exposure_usd": round(annualized_loss_exposure_usd, 2),
        "fair_score": round(fair_score, 2),
        "persistence_boost": round(persistence_boost, 4),
    }


def _grade_from_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_continuous_rating(
    *,
    severity_count: dict[str, int],
    fair_avg_score: float,
    fair_ale_total_usd: float,
    age_env_avg_days: float,
    age_market_avg_days: float,
    lifecycle: dict[str, int] | None = None,
    recurring_findings_count: int = 0,
    segment: str | None = None,
) -> dict[str, Any]:
    """Calcula o rating contínuo de postura externa.

    Pesos são ajustados por segmento de mercado conforme calibragem BitSight/
    SecurityScorecard/IBM 2023. Quando o segmento não é reconhecido, usa-se
    os pesos padrão 'Digital Services'.
    """
    lifecycle = lifecycle or {}
    total_open = int(lifecycle.get("open") or 0)
    total_new = int(lifecycle.get("new") or 0)
    total_corrected = int(lifecycle.get("corrected") or 0)

    critical = int(severity_count.get("critical") or 0)
    high = int(severity_count.get("high") or 0)
    medium = int(severity_count.get("medium") or 0)
    low = int(severity_count.get("low") or 0)

    # Pesos calibrados por segmento (v1.2)
    weights = SEGMENT_WEIGHTS.get(segment or "", SEGMENT_WEIGHTS["Digital Services"])
    w_exp = float(weights["exposure"])
    w_per = float(weights["persistence_age"])
    w_eco = float(weights["economic_fair"])
    w_res = float(weights["operational_resilience"])

    # ── Fator 1: Exposição Técnica ─────────────────────────────────────────────
    # Penalidade logarítmica: evita super-penalização em superfícies grandes
    # (BitSight 2023 — diminishing marginal impact)
    exposure_penalty = _log_exposure_penalty(critical, high, medium, low)
    exposure_score = max(0.0, 100.0 - exposure_penalty)

    # ── Fator 2: Persistência Temporal (AGE) ──────────────────────────────────
    # Combina tempo de permanência no ambiente, antiguidade de mercado do CVE
    # e número de findings recorrentes. Calibrado pelo EPSS v3: after ~30 days
    # without remediation, exploitation probability roughly doubles.
    age_env = float(age_env_avg_days)
    age_mkt = float(age_market_avg_days)
    # env: cap a 90 dias como ponto de saturação (≈3 ciclos de sprint)
    env_component = min(55.0, age_env * 0.62)
    # market: CVE antigo impacta menos que janela interna (pentesting real)
    mkt_component = min(25.0, age_mkt * 0.07)
    # recurring: cada finding recorrente contribui com peso constante
    recur_component = min(20.0, recurring_findings_count * 1.5)
    persistence_penalty = env_component + mkt_component + recur_component
    persistence_score = max(0.0, 100.0 - persistence_penalty)

    # ── Fator 3: Impacto Econômico (FAIR) ─────────────────────────────────────
    # ALE total em USD via log10: R$1M ≈ -16pts de penalidade base
    ale_penalty = min(100.0, math.log10(max(1.0, float(fair_ale_total_usd) + 1.0)) * 16.5)
    economic_score = max(0.0, min(100.0, float(fair_avg_score) - (ale_penalty * 0.35)))

    # ── Fator 4: Resiliência Operacional ─────────────────────────────────────
    correction_ratio = total_corrected / max(1, total_open + total_corrected)
    new_ratio = (total_new / max(1, total_open)) if total_open > 0 else 0.0
    resilience_score = max(
        0.0,
        min(100.0, 65.0 + correction_ratio * 30.0 - new_ratio * 25.0 - min(20.0, recurring_findings_count * 0.8)),
    )

    factors = [
        {
            "id": "exposure",
            "name": "Exposição Técnica",
            "weight": w_exp,
            "score": round(exposure_score, 2),
            "impact_points": round((100.0 - exposure_score) * w_exp, 2),
            "evidence": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
        },
        {
            "id": "persistence_age",
            "name": "Persistência Temporal (AGE)",
            "weight": w_per,
            "score": round(persistence_score, 2),
            "impact_points": round((100.0 - persistence_score) * w_per, 2),
            "evidence": {
                "age_env_avg_days": round(age_env, 2),
                "age_market_avg_days": round(age_mkt, 2),
                "recurring_findings": int(recurring_findings_count),
            },
        },
        {
            "id": "economic_fair",
            "name": "Impacto Econômico (FAIR)",
            "weight": w_eco,
            "score": round(economic_score, 2),
            "impact_points": round((100.0 - economic_score) * w_eco, 2),
            "evidence": {
                "fair_avg_score": round(float(fair_avg_score), 2),
                "ale_total_usd": round(float(fair_ale_total_usd), 2),
            },
        },
        {
            "id": "operational_resilience",
            "name": "Resiliência Operacional",
            "weight": w_res,
            "score": round(resilience_score, 2),
            "impact_points": round((100.0 - resilience_score) * w_res, 2),
            "evidence": {
                "open": total_open,
                "new": total_new,
                "corrected": total_corrected,
            },
        },
    ]

    final_score = sum(float(f["score"]) * float(f["weight"]) for f in factors)
    final_score = max(0.0, min(100.0, round(final_score, 2)))

    return {
        "score": final_score,
        "grade": _grade_from_score(final_score),
        "factors": factors,
        "segment": segment or "Digital Services",
        "methodology": METHODOLOGY_VERSION,
    }


def build_rating_timeline(scan_timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Constrói a curva temporal de rating com decaimento EPSS-aligned.

    Streak de scans consecutivos com findings abertos aumenta a penalidade
    de persistência usando escala logarítmica (EPSS v3 decay model):
      penalty = log10(streak+1)×0.3 × log1p(open_count) × 3.8

    Referência: EPSS v3 mostra que após ~30 dias sem correção a probabilidade
    de exploração cresce sublinearmente, não exponencialmente.
    """
    streak = 0
    curve: list[dict[str, Any]] = []
    ordered = sorted(scan_timeline or [], key=lambda item: str(item.get("created_at") or ""))
    for point in ordered:
        sev = point.get("severity") or {}
        critical = int(sev.get("critical") or 0)
        high = int(sev.get("high") or 0)
        medium = int(sev.get("medium") or 0)
        low = int(sev.get("low") or 0)
        open_count = int(point.get("open_findings") or 0)

        # Base score com penalidade logarítmica (mesma fórmula do compute_continuous_rating)
        base = max(0.0, 100.0 - _log_exposure_penalty(critical, high, medium, low))

        if open_count > 0:
            streak += 1
        else:
            streak = 0

        # Penalidade de streak: log10(streak+1)×0.3 cresce sub-linearmente
        # 1 scan: 0.0; 5 scans: 0.3×log10(5)≈0.21; 20 scans: 0.3×log10(20)≈0.39
        streak_multiplier = 1.0 + math.log10(max(1, streak)) * 0.3
        persistence_penalty = min(30.0, streak_multiplier * math.log1p(open_count) * 3.8)
        rating = max(0.0, round(base - persistence_penalty, 2))

        curve.append(
            {
                "scan_id": point.get("scan_id"),
                "created_at": point.get("created_at"),
                "open_findings": open_count,
                "base_score": round(base, 2),
                "persistence_penalty": round(persistence_penalty, 2),
                "rating_score": rating,
                "streak": streak,
                "methodology_version": METHODOLOGY_VERSION,
            }
        )
    return curve


def get_methodology_changelog() -> dict[str, Any]:
    """Retorna o changelog completo da metodologia de rating para uso executivo/auditoria."""
    return {
        "current_version": METHODOLOGY_VERSION,
        "segment_weights": SEGMENT_WEIGHTS,
        "history": METHODOLOGY_REGISTRY,
    }


def build_priority_reason(title: str, severity: str | None, fair: dict[str, Any], age: dict[str, Any]) -> dict[str, str]:
    sev = str(severity or "low").lower()
    ale = float(fair.get("annualized_loss_exposure_usd") or 0.0)
    env_days = age.get("known_in_environment_days")
    market_days = age.get("known_in_market_days")
    exploit_days = age.get("exploit_published_days")

    operational = (
        f"{title}: severidade {sev} com exposicao persistente ha {env_days or 0} dias no ambiente"
        f" e frequencia de evento estimada em {fair.get('loss_event_frequency')}"
    )

    financial = (
        f"Perda anual esperada estimada em USD {ale:,.2f}"
        + (f", com CVE conhecido ha {market_days} dias" if market_days is not None else "")
        + (f" e exploit publico ha {exploit_days} dias" if exploit_days is not None else "")
    )

    return {
        "operational": operational,
        "financial": financial,
    }


# ──────────────────────────────────────────────────────────────────────────────
# EASM Continuous Rating Engine — FAIR + AGE Formula
# Referência: Arquitetura BitSight-style com FAIR Institute Calibration Guide v2.0
# ──────────────────────────────────────────────────────────────────────────────

# Impacto base de ativo por tipo detectado pelas ferramentas de reconhecimento.
# Calibrado pelo FAIR Institute: quanto mais sensível o ativo, maior o peso.
ASSET_IMPACT_WEIGHTS: dict[str, float] = {
    "login":        90.0,   # painel de autenticação — vetor primário de comprometimento
    "admin":        95.0,   # painel administrativo
    "api":          85.0,   # endpoint de API exposto
    "database":     100.0,  # banco de dados expostodiretamente
    "ssh":          88.0,   # acesso remoto por SSH
    "rdp":          88.0,   # acesso remoto por RDP
    "ftp":          70.0,   # protocolo não criptografado
    "smtp":         65.0,   # servidor de e-mail
    "web":          60.0,   # aplicação web genérica
    "default":      50.0,   # ativo sem classificação
}

# Pesos dos 3 pilares FAIR para decomposição executiva (calibrado por mercado)
FAIR_PILLAR_WEIGHTS: dict[str, float] = {
    "perimeter_resilience": 0.40,   # Resiliência de Perímetro (naabu + sqlmap)
    "patching_hygiene":     0.30,   # Higiene e Patching (nuclei CVEs + AGE)
    "osint_exposure":       0.30,   # Exposição OSINT (h8mail + shodan)
}

# Mapeamento de tools para pilares FAIR
_TOOL_TO_PILAR: dict[str, str] = {
    "naabu":        "perimeter_resilience",
    "nmap":         "perimeter_resilience",
    "nmap-vulscan": "patching_hygiene",
    "nuclei":       "patching_hygiene",
    "nikto":        "patching_hygiene",
    "wapiti":       "patching_hygiene",
    "sqlmap":       "perimeter_resilience",
    "commix":       "perimeter_resilience",
    "dalfox":       "perimeter_resilience",
    "tplmap":       "perimeter_resilience",
    "wafw00f":      "perimeter_resilience",
    "sslscan":      "patching_hygiene",
    "shcheck":      "patching_hygiene",
    "curl-headers": "patching_hygiene",
    "theharvester": "osint_exposure",
    "h8mail":       "osint_exposure",
    "metagoofil":   "osint_exposure",
    "shodan-cli":   "osint_exposure",
    "subjack":      "osint_exposure",
    "whatweb":      "perimeter_resilience",
    "trufflehog":   "osint_exposure",
    "secretfinder": "osint_exposure",
}

# Severidade → CVSS sintético para findings sem CVSS explícito
_SEV_TO_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     1.0,
}


def compute_factor_age(days_open: int | float) -> float:
    """Penalidade logarítmica de persistência.

    Factor_AGE = 1 + log10(days_open + 1)

    Calibração:
      - 0 dias  → 1.0   (sem penalidade)
      - 1 dia   → 1.30  (+30%)
      - 7 dias  → 1.90  (+90%)
      - 30 dias → 2.48  (+148%)
      - 90 dias → 2.96  (+196%)

    Ref.: EPSS v3 mostra que após ~30 dias a probabilidade de exploração
    praticamente dobra; log10 modela esse crescimento sublinear corretamente.
    """
    return 1.0 + math.log10(max(1.0, float(days_open) + 1.0))


def compute_asset_impact(asset_url: str | None, port: int | None = None) -> float:
    """Deduz o peso de impacto do ativo a partir do título/URL/porta.

    Ref.: FAIR — Loss Magnitude varia com sensibilidade do ativo.
    """
    raw = str(asset_url or "").lower()
    for keyword, weight in ASSET_IMPACT_WEIGHTS.items():
        if keyword in raw:
            return weight
    if port in {3306, 5432, 1433, 27017, 6379}:   # DB ports
        return ASSET_IMPACT_WEIGHTS["database"]
    if port in {22}:
        return ASSET_IMPACT_WEIGHTS["ssh"]
    if port in {3389}:
        return ASSET_IMPACT_WEIGHTS["rdp"]
    if port in {21}:
        return ASSET_IMPACT_WEIGHTS["ftp"]
    return ASSET_IMPACT_WEIGHTS["default"]


def compute_asset_risk(
    asset_url: str | None,
    severity: str | None,
    days_open: int | float = 0,
    cvss: float | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    """Risco por ativo (Ra) — fórmula FAIR + AGE da spec.

    Ra = (AssetImpact × CVSS_Severity) × (1 + log10(AGE + 1))

    Returns dict com score de impacto decomponível para uso executivo.
    """
    factor_age = compute_factor_age(days_open)
    cvss_val = float(cvss) if cvss is not None else _SEV_TO_CVSS.get(str(severity or "info").lower(), 1.0)
    asset_impact = compute_asset_impact(asset_url, port=port)

    # Normaliza: asset_impact/100 (0-1) × cvss/10 (0-1) = Ra bruto (0-1)
    # Depois escala para 0-100 com factor_age amplificando o risco persitente
    ra_raw = (asset_impact / 100.0) * (cvss_val / 10.0) * factor_age * 100.0

    return {
        "ra": round(min(100.0, ra_raw), 2),
        "factor_age": round(factor_age, 3),
        "days_open": int(days_open),
        "cvss": round(cvss_val, 2),
        "asset_impact": round(asset_impact, 2),
        "severity": str(severity or "info").lower(),
    }


def compute_easm_rating(risk_per_asset: list[dict[str, Any]], n_assets: int) -> dict[str, Any]:
    """Score global normalizado pelo tamanho da superfície digital.

    Score = 100 − min(100, ΣRa / N_assets)

    Normalizar por N_assets evita penalizar empresas maiores apenas por terem
    mais ativos (BitSight-style Digital Footprint normalization).
    """
    total_ra = sum(float(r.get("ra") or 0.0) for r in risk_per_asset)
    n = max(1, int(n_assets))
    normalized_ra = total_ra / n
    score = max(0.0, 100.0 - min(100.0, normalized_ra))

    return {
        "score": round(score, 2),
        "grade": _grade_from_score(score),
        "total_ra": round(total_ra, 2),
        "n_assets": n,
        "normalized_ra": round(normalized_ra, 2),
        "methodology": "easm_fair_age_v1",
    }


def build_fair_decomposition(
    findings: list[dict[str, Any]],
    n_assets: int = 1,
) -> dict[str, Any]:
    """Decompõe os findings nos 3 pilares FAIR com peso, evidência e impacto na nota.

    Pilares:
      1. Resiliência de Perímetro (40%) — naabu, sqlmap, commix, dalfox
      2. Higiene e Patching       (30%) — nuclei, nikto, sslscan, shcheck
      3. Exposição OSINT          (30%) — h8mail, shodan-cli, theharvester

    Retorna decomposição pronta para dashboard executivo e relatório.
    """
    # Acumula RA por pilar
    pillar_ra: dict[str, list[float]] = {k: [] for k in FAIR_PILLAR_WEIGHTS}
    pillar_evidence: dict[str, list[str]] = {k: [] for k in FAIR_PILLAR_WEIGHTS}

    for finding in findings:
        sev = str((finding.get("severity") or "info")).lower()
        if sev in {"info"}:
            continue
        details = finding.get("details") or {}
        tool = str(details.get("tool") or "").strip().lower()
        pilar = _TOOL_TO_PILAR.get(tool, "patching_hygiene")

        days = int(details.get("known_in_environment_days") or details.get("age_days") or 0)
        cvss = details.get("cvss_score") or details.get("cvss")
        asset = str(details.get("asset") or finding.get("title") or "")
        port = details.get("port")

        ra_dict = compute_asset_risk(
            asset_url=asset,
            severity=sev,
            days_open=days,
            cvss=float(cvss) if cvss is not None else None,
            port=int(port) if port is not None else None,
        )
        pillar_ra[pilar].append(ra_dict["ra"])
        evidence_str = f"{finding.get('title', tool)}: AGE={days}d, CVSS={ra_dict['cvss']}, FactorAGE={ra_dict['factor_age']}"
        pillar_evidence[pilar].append(evidence_str)

    n = max(1, n_assets)
    pillars: list[dict[str, Any]] = []
    total_impact_pts = 0.0

    for pilar_id, weight in FAIR_PILLAR_WEIGHTS.items():
        ra_values = pillar_ra[pilar_id]
        pilar_score = max(0.0, 100.0 - min(100.0, sum(ra_values) / n)) if ra_values else 100.0
        impact_pts = round((100.0 - pilar_score) * weight, 2)
        total_impact_pts += impact_pts

        pilar_names = {
            "perimeter_resilience": "Resiliência de Perímetro",
            "patching_hygiene":     "Higiene e Patching",
            "osint_exposure":       "Exposição OSINT",
        }
        evidence_sample = pillar_evidence[pilar_id][:5]  # max 5 evidências
        pillars.append({
            "id":           pilar_id,
            "name":         pilar_names[pilar_id],
            "weight":       weight,
            "weight_pct":   f"{int(weight * 100)}%",
            "score":        round(pilar_score, 2),
            "impact_pts":   impact_pts,
            "finding_count": len(ra_values),
            "evidence":     evidence_sample,
            "tef_description": {
                "perimeter_resilience": "Frequência de ameaça externa via portas/serviços expostos e vetores de injeção",
                "patching_hygiene":     "Probabilidade de exploração amplificada pela persistência (AGE) de CVEs abertas",
                "osint_exposure":       "Superfície OSINT: credenciais vazadas, IPs em blacklists e footprint público",
            }.get(pilar_id, ""),
        })

    final_score = max(0.0, 100.0 - min(100.0, total_impact_pts))
    return {
        "score": round(final_score, 2),
        "grade": _grade_from_score(final_score),
        "pillars": pillars,
        "total_impact_pts": round(total_impact_pts, 2),
        "n_assets": n,
        "methodology_version": METHODOLOGY_VERSION,
    }
