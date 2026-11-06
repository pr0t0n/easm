"""Fase 0 (LANGGRAPH_BRAIN_PLAN): definition-of-done por fase.

A normalização mission.PHASE_CONTRACTS deve (a) preservar os campos ricos de
exit_criteria do offensive_operator_core e (b) subir os mínimos de tools de
1/1 para ceil(0.75*|required|) attempted / ceil(0.5*|required|) succeeded.
"""
from __future__ import annotations

import math

from app.graph.mission import PHASE_CONTRACTS


def test_contracts_cover_all_22_phases():
    assert set(PHASE_CONTRACTS) >= {f"P{i:02d}" for i in range(1, 23)}


def test_exit_criteria_minimums_scale_with_required_tools():
    for phase_id, contract in PHASE_CONTRACTS.items():
        required = list(contract.get("required_tools") or [])
        n = len(required)
        exit_c = contract["exit_criteria"]
        assert exit_c["min_required_tools_attempted"] == max(1, math.ceil(0.75 * n)), phase_id
        assert exit_c["min_required_tools_succeeded"] == max(1, math.ceil(0.5 * n)), phase_id


def test_exit_criteria_preserve_core_fields():
    """Campos do core (allow_partial, minimum_evidence_strength...) não podem
    ser descartados pela normalização — eram sobrescritos com min=1/1 antes."""
    for phase_id, contract in PHASE_CONTRACTS.items():
        exit_c = contract["exit_criteria"]
        assert "allow_partial" in exit_c, phase_id
        assert "minimum_evidence_strength" in exit_c, phase_id
        assert exit_c["evidence_persisted"] is True, phase_id
        assert exit_c["parser_result_registered"] is False, phase_id


def test_final_phases_do_not_allow_partial():
    """P20-P22 (correlação/adjudicação/relatório) não aceitam partial no core."""
    for phase_id in ("P20", "P21", "P22"):
        assert PHASE_CONTRACTS[phase_id]["exit_criteria"]["allow_partial"] is False
