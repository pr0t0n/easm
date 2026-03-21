from datetime import datetime, timedelta, timezone

from app.services.risk_service import build_priority_reason, compute_age_metrics, compute_fair_metrics


def test_compute_age_metrics_with_market_and_exploit_dates():
    created_at = datetime.now(timezone.utc) - timedelta(days=15)
    details = {
        "cve_published_at": (datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
        "exploit_published_at": (datetime.now(timezone.utc) - timedelta(days=20)).isoformat(),
    }

    age = compute_age_metrics(created_at, details)

    assert age["known_in_environment_days"] >= 15
    assert age["known_in_market_days"] >= 120
    assert age["exploit_published_days"] >= 20


def test_compute_fair_metrics_increases_with_exploit_presence():
    created_at = datetime.now(timezone.utc) - timedelta(days=40)
    base_age = compute_age_metrics(created_at, {"cve_published_at": (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()})
    exploit_age = compute_age_metrics(
        created_at,
        {
            "cve_published_at": (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
            "exploit_published_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
        },
    )

    fair_without_exploit = compute_fair_metrics("high", 70, {}, base_age)
    fair_with_exploit = compute_fair_metrics("high", 70, {}, exploit_age)

    assert fair_with_exploit["annualized_loss_exposure_usd"] > fair_without_exploit["annualized_loss_exposure_usd"]
    assert fair_with_exploit["fair_score"] > fair_without_exploit["fair_score"]


def test_priority_reason_contains_operational_and_financial_explanation():
    fair = {
        "loss_event_frequency": 0.73,
        "annualized_loss_exposure_usd": 250000.0,
        "fair_score": 84.0,
    }
    age = {
        "known_in_environment_days": 33,
        "known_in_market_days": 410,
        "exploit_published_days": 11,
    }

    reasons = build_priority_reason("SQL Injection", "critical", fair, age)

    assert "SQL Injection" in reasons["operational"]
    assert "USD" in reasons["financial"]
    assert "exploit" in reasons["financial"].lower()
