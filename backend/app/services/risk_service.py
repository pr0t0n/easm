from __future__ import annotations

from datetime import datetime, timezone
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

    return {
        "known_in_environment_at": env_first_seen.isoformat() if env_first_seen else None,
        "known_in_market_at": market_known_at.isoformat() if market_known_at else None,
        "exploit_published_at": exploit_published_at.isoformat() if exploit_published_at else None,
        "known_in_environment_days": _days_since(now_utc, env_first_seen),
        "known_in_market_days": _days_since(now_utc, market_known_at),
        "exploit_published_days": _days_since(now_utc, exploit_published_at),
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

    env_age_factor = min(env_age_days / 90.0, 1.0) * 0.12
    market_age_factor = min(market_age_days / 365.0, 1.0) * 0.08
    exploit_factor = 0.22 if exploit_days is not None else 0.0

    loss_event_frequency = max(0.01, min(1.0, base_tef + (conf * 0.18) + env_age_factor + market_age_factor + exploit_factor))

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
    fair_score = min(100.0, (loss_event_frequency * 55.0) + min(45.0, annualized_loss_exposure_usd / 9000.0))

    return {
        "loss_event_frequency": round(loss_event_frequency, 4),
        "loss_magnitude_usd": round(loss_magnitude_usd, 2),
        "annualized_loss_exposure_usd": round(annualized_loss_exposure_usd, 2),
        "fair_score": round(fair_score, 2),
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
