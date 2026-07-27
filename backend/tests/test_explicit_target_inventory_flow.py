from app.services.offensive_operator_runner import (
    _is_explicit_target_inventory,
    _next_pending_phase_target,
)


def test_multi_target_scan_is_explicit_target_inventory() -> None:
    targets = [
        "adp.services-valid.com.br",
        "agendamento.services-valid.com.br",
    ]

    assert _is_explicit_target_inventory({}, targets) is True


def test_explicit_target_inventory_routes_to_p02_not_p01() -> None:
    targets = [
        "adp.services-valid.com.br",
        "agendamento.services-valid.com.br",
    ]
    completed = {
        "P01:adp.services-valid.com.br",
        "P01:agendamento.services-valid.com.br",
    }

    assert _next_pending_phase_target(
        targets,
        completed,
        input_target_count=len(targets),
        allowed_phases=None,
        skip_p01_for_input_targets=True,
    ) == ("P02", "adp.services-valid.com.br")


def test_explicit_target_inventory_completes_p02_for_all_targets_before_p06() -> None:
    targets = [
        "adp.services-valid.com.br",
        "agendamento.services-valid.com.br",
    ]
    completed = {
        "P01:adp.services-valid.com.br",
        "P01:agendamento.services-valid.com.br",
        "P02:adp.services-valid.com.br",
    }

    assert _next_pending_phase_target(
        targets,
        completed,
        input_target_count=len(targets),
        allowed_phases=None,
        skip_p01_for_input_targets=True,
    ) == ("P02", "agendamento.services-valid.com.br")


def test_explicit_target_inventory_runs_p06_for_all_targets_before_deep_phases() -> None:
    targets = [
        "adp.services-valid.com.br",
        "agendamento.services-valid.com.br",
    ]
    completed = {
        "P01:adp.services-valid.com.br",
        "P01:agendamento.services-valid.com.br",
        "P02:adp.services-valid.com.br",
        "P02:agendamento.services-valid.com.br",
        "P06:adp.services-valid.com.br",
    }

    assert _next_pending_phase_target(
        targets,
        completed,
        input_target_count=len(targets),
        allowed_phases=None,
        skip_p01_for_input_targets=True,
    ) == ("P06", "agendamento.services-valid.com.br")


def test_explicit_target_inventory_deepens_only_after_p02_and_p06_cover_all_targets() -> None:
    targets = [
        "adp.services-valid.com.br",
        "agendamento.services-valid.com.br",
    ]
    completed = {
        "P01:adp.services-valid.com.br",
        "P01:agendamento.services-valid.com.br",
        "P02:adp.services-valid.com.br",
        "P02:agendamento.services-valid.com.br",
        "P06:adp.services-valid.com.br",
        "P06:agendamento.services-valid.com.br",
    }

    assert _next_pending_phase_target(
        targets,
        completed,
        input_target_count=len(targets),
        allowed_phases=None,
        skip_p01_for_input_targets=True,
    ) == ("P03", "adp.services-valid.com.br")


def test_single_discovery_seed_still_routes_to_p01() -> None:
    assert _is_explicit_target_inventory({}, ["valid.com"]) is False
    assert _next_pending_phase_target(
        ["valid.com"],
        set(),
        input_target_count=1,
        allowed_phases=None,
    ) == ("P01", "valid.com")
