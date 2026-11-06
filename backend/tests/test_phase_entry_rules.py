"""Fase 1 (LANGGRAPH_BRAIN_PLAN): montagem dinâmica de fases — a fase entra
quando o sinal de evidência a justifica (decisão do sponsor: plano montado
como um pentest humano, com justificativa registrada).
"""
from __future__ import annotations

from app.graph.mission import PHASE_ENTRY_RULES, phase_entry_applicable


def _state(**over):
    state = {
        "target": "http://juice_shop:3000",
        "target_type": "site",
        "lista_ativos": [],
        "discovered_ports": [],
        "executed_tool_runs": [],
    }
    state.update(over)
    return state


def test_core_phases_always_applicable():
    for ph in ("P02", "P03", "P05", "P11", "P20", "P21", "P22"):
        ok, reason = phase_entry_applicable(ph, _state())
        assert ok, f"{ph} deveria ser núcleo: {reason}"


def test_domain_phases_skip_for_hostname_target():
    state = _state()  # target_type=site, sem domínio
    for ph in ("P01", "P07", "P08", "P10"):
        ok, reason = phase_entry_applicable(ph, state)
        assert not ok, f"{ph} não deveria aplicar a hostname"
        assert reason


def test_domain_phases_apply_for_domain_target():
    state = _state(target="https://example.com", target_type="dominio")
    for ph in ("P01", "P07", "P08", "P10"):
        ok, _ = phase_entry_applicable(ph, state)
        assert ok, f"{ph} deveria aplicar a domínio"


def test_web_phases_wait_for_web_signal():
    state = _state()
    for ph in ("P06", "P12", "P15", "P17"):
        ok, _ = phase_entry_applicable(ph, state)
        assert not ok, f"{ph} não deveria aplicar sem serviço web"
    state["discovered_ports"] = [3000]
    for ph in ("P06", "P12", "P15", "P17"):
        ok, reason = phase_entry_applicable(ph, state)
        assert ok, f"{ph} deveria aplicar com porta descoberta: {reason}"


def test_tls_phase_only_with_https():
    state = _state(discovered_ports=[3000])
    ok, _ = phase_entry_applicable("P18", state)
    assert not ok
    ok, _ = phase_entry_applicable("P18", _state(discovered_ports=[443]))
    assert ok
    ok, _ = phase_entry_applicable("P18", _state(target="https://app.alvo.com"))
    assert ok


def test_takeover_needs_multiple_assets():
    ok, _ = phase_entry_applicable("P09", _state(lista_ativos=["juice_shop"]))
    assert not ok
    ok, _ = phase_entry_applicable("P09", _state(lista_ativos=["a.com", "b.a.com"]))
    assert ok


def test_every_rule_resolves_to_a_signal():
    from app.graph.mission import _ENTRY_SIGNALS
    for ph, rule in PHASE_ENTRY_RULES.items():
        assert rule in _ENTRY_SIGNALS, f"{ph}: regra {rule} sem sinal registrado"
