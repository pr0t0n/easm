"""Testes dos estágios 2, 3 e 6 (recuperação, seleção JEV, interpretação)."""
from __future__ import annotations

from app.services import decision_port
from app.services.jev_interpretation import merge_interpretation, _OPTIONS
from app.services.jev_hypothesis_selection import jev_select_next_skill


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeCtx:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, json=None):
        return _FakeResp(self._payload)


def _patch_jev(monkeypatch, value, probability, kind="choice"):
    import httpx
    payload = {"answers": [{"id": "q", "kind": kind, "value": value, "probability": probability, "source": "jev"}]}
    monkeypatch.setattr(decision_port, "_backend", lambda: "jev")
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeCtx(payload))


# ─────────────────────────────────────────────────────────────
# Estágio 3 — seleção de skill
# ─────────────────────────────────────────────────────────────

def test_jev_select_skill_above_threshold(monkeypatch):
    _patch_jev(monkeypatch, "skill.vuln.sqli", 0.9)
    sids = ["skill.recon.crawl", "skill.vuln.sqli", "skill.vuln.xss"]
    chosen = jev_select_next_skill(sids, phase_id="P10", offensive_state={"technologies": ["php", "mysql"]})
    assert chosen == "skill.vuln.sqli"


def test_jev_select_skill_below_threshold_keeps_order(monkeypatch):
    _patch_jev(monkeypatch, "skill.vuln.sqli", 0.4)
    sids = ["skill.recon.crawl", "skill.vuln.sqli"]
    assert jev_select_next_skill(sids, phase_id="P10", offensive_state={}) is None


def test_jev_select_skill_choice_outside_options_rejected(monkeypatch):
    _patch_jev(monkeypatch, "skill.evil.privesc", 0.95)
    sids = ["skill.recon.crawl", "skill.vuln.sqli"]
    assert jev_select_next_skill(sids, phase_id="P10", offensive_state={}) is None


def test_jev_select_skill_single_option_noop():
    assert jev_select_next_skill(["skill.only"], phase_id="P10", offensive_state={}) is None


# ─────────────────────────────────────────────────────────────
# Estágio 6 — interpretação ternária (merge fail-closed)
# ─────────────────────────────────────────────────────────────

def _dossier(contradictions=None):
    return {
        "finding": {"title": "Header ausente", "severity_claimed": "low"},
        "quality": {"missing_artifacts": ["positive_reproduction"], "contradictions": contradictions or []},
        "evidence": [{"artifact_id": 1}],
    }


def test_merge_encerrar_with_contradictions_applies():
    proposal = {"proposal": "encerrar", "probability": 0.9}
    decision = {"verdict": "inconclusive", "reason_code": "contradictory_evidence"}
    out = merge_interpretation(proposal, decision, _dossier(contradictions=["header presente e ausente"]))
    assert out["applied"] is True and out["final_verdict"] == "not_applicable"


def test_merge_encerrar_without_contradictions_preserved():
    proposal = {"proposal": "encerrar", "probability": 0.9}
    decision = {"verdict": "inconclusive", "reason_code": "missing_positive_reproduction"}
    out = merge_interpretation(proposal, decision, _dossier())
    assert out["applied"] is False and out["interpretation"] == "encerrar"


def test_merge_concluir_only_when_gate_confirmed():
    proposal = {"proposal": "concluir", "probability": 0.95}
    confirmed = merge_interpretation(proposal, {"verdict": "confirmed", "reason_code": "x"}, _dossier())
    inconcl = merge_interpretation(proposal, {"verdict": "inconclusive", "reason_code": "x"}, _dossier())
    assert confirmed["applied"] is False
    assert inconcl["applied"] is False


def test_merge_investigar_preserves_path():
    out = merge_interpretation({"proposal": "investigar", "probability": 0.9}, {"verdict": "inconclusive"}, _dossier())
    assert out["applied"] is False and out["interpretation"] == "investigar"


def test_interpretation_options_declared():
    assert set(_OPTIONS) == {"concluir", "investigar", "encerrar"}


def test_wire_tool_repeat_original_probe():
    from types import SimpleNamespace
    from app.services.finding_adjudication import _wire_tool

    f = SimpleNamespace(
        title="Alerta do Nikto",
        tool="nikto",
        details={},
    )
    tool, profile = _wire_tool("repeat_original_probe", f)
    assert tool == "nikto" and profile

    osint = SimpleNamespace(title="Portas Shodan", tool="shodan-cli", details={})
    tool, _ = _wire_tool("repeat_original_probe", osint)
    assert tool is None  # OSINT não re-executa
