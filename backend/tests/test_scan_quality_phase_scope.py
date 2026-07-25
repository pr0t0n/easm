from types import SimpleNamespace


def test_quality_gate_does_not_score_report_phase_before_report_exists():
    from app.services.scan_quality import _quality_scored_phase_ids

    job = SimpleNamespace(state_data={"scan_level": "full"})
    phase_ids = _quality_scored_phase_ids(job)

    assert "P21" in phase_ids
    assert "P22" not in phase_ids
