from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any


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
) -> dict[str, Any]:
    lifecycle = lifecycle or {}
    total_open = int(lifecycle.get("open") or 0)
    total_new = int(lifecycle.get("new") or 0)
    total_corrected = int(lifecycle.get("corrected") or 0)

    critical = int(severity_count.get("critical") or 0)
    high = int(severity_count.get("high") or 0)
    medium = int(severity_count.get("medium") or 0)
    low = int(severity_count.get("low") or 0)

    # Fator 1: Exposição técnica
    exposure_penalty = min(100.0, critical * 28 + high * 14 + medium * 6 + low * 2)
    exposure_score = max(0.0, 100.0 - exposure_penalty)

    # Fator 2: Persistência temporal (AGE)
    persistence_penalty = min(100.0, age_env_avg_days * 0.85 + age_market_avg_days * 0.25 + recurring_findings_count * 1.8)
    persistence_score = max(0.0, 100.0 - persistence_penalty)

    # Fator 3: Impacto econômico (FAIR)
    ale_penalty = min(100.0, math.log10(max(1.0, float(fair_ale_total_usd) + 1.0)) * 16.5)
    economic_score = max(0.0, min(100.0, float(fair_avg_score) - (ale_penalty * 0.35)))

    # Fator 4: Resiliência operacional (nova/corrigida/persistente)
    correction_ratio = (total_corrected / max(1, total_open + total_corrected))
    new_ratio = (total_new / max(1, total_open)) if total_open > 0 else 0.0
    resilience_score = max(0.0, min(100.0, 65.0 + correction_ratio * 30.0 - new_ratio * 25.0 - min(20.0, recurring_findings_count * 0.8)))

    factors = [
        {
            "id": "exposure",
            "name": "Exposição Técnica",
            "weight": 0.35,
            "score": round(exposure_score, 2),
            "impact_points": round((100.0 - exposure_score) * 0.35, 2),
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
            "weight": 0.25,
            "score": round(persistence_score, 2),
            "impact_points": round((100.0 - persistence_score) * 0.25, 2),
            "evidence": {
                "age_env_avg_days": round(float(age_env_avg_days), 2),
                "age_market_avg_days": round(float(age_market_avg_days), 2),
                "recurring_findings": int(recurring_findings_count),
            },
        },
        {
            "id": "economic_fair",
            "name": "Impacto Econômico (FAIR)",
            "weight": 0.20,
            "score": round(economic_score, 2),
            "impact_points": round((100.0 - economic_score) * 0.20, 2),
            "evidence": {
                "fair_avg_score": round(float(fair_avg_score), 2),
                "ale_total_usd": round(float(fair_ale_total_usd), 2),
            },
        },
        {
            "id": "operational_resilience",
            "name": "Resiliência Operacional",
            "weight": 0.20,
            "score": round(resilience_score, 2),
            "impact_points": round((100.0 - resilience_score) * 0.20, 2),
            "evidence": {
                "open": total_open,
                "new": total_new,
                "corrected": total_corrected,
            },
        },
    ]

    final_score = sum(float(f.get("score") or 0.0) * float(f.get("weight") or 0.0) for f in factors)
    final_score = max(0.0, min(100.0, round(final_score, 2)))

    return {
        "score": final_score,
        "grade": _grade_from_score(final_score),
        "factors": factors,
        "methodology": "continuous_external_posture_v1",
    }


def build_rating_timeline(scan_timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

        base = max(0.0, 100.0 - min(100.0, critical * 30 + high * 15 + medium * 7 + low * 2))
        if open_count > 0:
            streak += 1
        else:
            streak = 0

        persistence_penalty = min(28.0, streak * 1.6 + open_count * 0.15)
        rating = max(0.0, round(base - persistence_penalty, 2))

        curve.append(
            {
                "scan_id": point.get("scan_id"),
                "created_at": point.get("created_at"),
                "open_findings": open_count,
                "base_score": round(base, 2),
                "persistence_penalty": round(persistence_penalty, 2),
                "rating_score": rating,
            }
        )
    return curve


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
