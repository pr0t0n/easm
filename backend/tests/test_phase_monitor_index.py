from app.services.phase_monitor import _resolve_pentest_phase_index


def test_derives_index_from_current_phase_when_stored_index_is_stale() -> None:
    # The exact bug this guards: live offensive_operator scans never
    # increment pentest_phase_index (only the bypassed LangGraph path does),
    # so it reports 0 forever even at P13 — misleading the phase-monitor UI
    # into showing whatever phase sits at index 0 (P01).
    assert _resolve_pentest_phase_index(0, "P13") == 13


def test_prefers_stored_index_when_it_is_actually_set() -> None:
    assert _resolve_pentest_phase_index(5, "P13") == 5


def test_falls_back_to_stored_index_when_no_current_phase() -> None:
    assert _resolve_pentest_phase_index(0, "") == 0


def test_falls_back_to_stored_index_on_unparseable_phase_id() -> None:
    assert _resolve_pentest_phase_index(0, "not-a-phase") == 0


def test_handles_lowercase_phase_id() -> None:
    assert _resolve_pentest_phase_index(0, "p07") == 7
