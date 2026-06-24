"""Trava de regressão: o dispatcher é GATE-AWARE.

Causa raiz do "scan de vuln em vez de pentest" (scan #4): a fase-gate P09
(prioridade 50) era estarvada pela fase não-gate P16 (prioridade 45) na mesma
capacidade medium → P09 nunca drenava → o gate waiting_for:P09 nunca abria →
toda a exploração ativa (sqlmap/wapiti/dalfox/nuclei-ataque) ficava bloqueada.

O fix torna o claim gate-aware: fases-gate são reivindicadas ANTES das não-gate.
Este teste garante que o conjunto de fases-gate é derivado corretamente do
PHASE_GATE (e não regride para incluir/excluir a fase errada).
"""
from __future__ import annotations

from app.services.scan_work_queue import _GATE_TARGET_PHASES, PHASE_GATE


def test_gate_target_phases_sao_os_valores_do_phase_gate():
    esperado = {g for g in PHASE_GATE.values() if g}
    assert _GATE_TARGET_PHASES == esperado


def test_p09_e_gate_p16_nao_e():
    # P09 destrava toda a exploração → tem que estar no conjunto priorizado.
    assert "P09" in _GATE_TARGET_PHASES
    # P16 não bloqueia ninguém → não pode "roubar" prioridade de gate.
    assert "P16" not in _GATE_TARGET_PHASES


def test_gates_conhecidos_presentes():
    # P02 (port scan) e P06 (fingerprint) também são gates de várias fases.
    assert {"P02", "P06", "P09"} <= _GATE_TARGET_PHASES
