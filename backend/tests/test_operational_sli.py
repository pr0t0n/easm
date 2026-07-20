from app.services.operational_sli import evaluate_scan_slis


def test_operational_sli_reports_all_threshold_failures():
    result = evaluate_scan_slis({
        "score": 48,
        "execution_metrics": {"queue_wait_p95_seconds": 7200, "success_pct": 58.7},
    })
    assert result["status"] == "degraded"
    assert {check["id"] for check in result["failed"]} == {
        "queue_wait_p95",
        "execution_success",
        "quality_score",
    }


def test_operational_sli_accepts_healthy_scan():
    result = evaluate_scan_slis({
        "score": 86,
        "execution_metrics": {"queue_wait_p95_seconds": 120, "success_pct": 91},
    })
    assert result["status"] == "healthy"
    assert result["failed"] == []
