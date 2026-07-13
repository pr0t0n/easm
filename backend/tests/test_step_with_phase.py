from app.workers.tasks import _step_with_phase


def test_prefixes_message_with_current_phase() -> None:
    state = {"current_pentest_phase_id": "P13"}
    assert _step_with_phase(state, "Recuperacao automatica: retomando fila persistida") == (
        "P13 · Recuperacao automatica: retomando fila persistida"
    )


def test_falls_back_to_bare_message_without_phase() -> None:
    assert _step_with_phase({}, "Aguardando worker") == "Aguardando worker"
    assert _step_with_phase(None, "Aguardando worker") == "Aguardando worker"
