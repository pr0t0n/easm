"""Testes do decision_port (Fase 3) — sem JEV real (backend rule/fallback)."""
from __future__ import annotations

import json

import pytest

from app.services import decision_port
from app.services.decision_port import _rule_answer, _call_jev, decide


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeClientCtx:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, json=None):
        return _FakeResp(self._payload)


def test_rule_fallback_noul():
    ans = _rule_answer("noul", "q?", None, None, 5)
    assert ans["value"] is False and ans["probability"] == 0.5


def test_rule_fallback_choice_uniform():
    ans = _rule_answer("choice", "q?", None, ["a", "b", "c", "d"], 5)
    assert ans["value"] == "a" and ans["probability"] == pytest.approx(0.25)


def test_unknown_kind_raises():
    with pytest.raises(ValueError):
        decide(question_id="q", kind="likert", question="a?")


def test_call_jev_invalid_choice_rejected():
    payload = {"answers": [{"id": "q", "kind": "choice", "value": "HACK", "probability": 0.9}]}
    import httpx
    orig = httpx.Client
    httpx.Client = lambda *a, **k: _FakeClientCtx(payload)
    try:
        assert _call_jev(question_id="q", kind="choice", question="x", state={}, options=["a", "b"], scale_max=5) is None
    finally:
        httpx.Client = orig


def test_call_jev_noul_out_of_contract_bool():
    payload = {"answers": [{"id": "q", "kind": "noul", "value": "yes", "probability": 0.9}]}
    import httpx
    orig = httpx.Client
    httpx.Client = lambda *a, **k: _FakeClientCtx(payload)
    try:
        assert _call_jev(question_id="q", kind="noul", question="x", state={}, options=None, scale_max=5) is None
    finally:
        httpx.Client = orig


def test_decide_rule_backend_persists(monkeypatch):
    monkeypatch.setattr(decision_port, "_backend", lambda: "rule")
    r = decide(question_id="t_rule", kind="noul", question="is this a test?", scan_id=None)
    assert r["source"] == "rule" and r["value"] is False

    from app.db.session import SessionLocal
    from app.models.models import JevDecision
    db = SessionLocal()
    try:
        row = db.query(JevDecision).filter(JevDecision.question_id == "t_rule").first()
        assert row is not None and row.source == "rule"
        db.query(JevDecision).filter(JevDecision.question_id == "t_rule").delete()
        db.commit()
    finally:
        db.close()


def test_decide_jev_backend_above_threshold(monkeypatch):
    monkeypatch.setattr(decision_port, "_backend", lambda: "jev")
    payload = {"answers": [{"id": "wire_validation_priority", "kind": "score", "value": 9, "probability": 0.85, "source": "jev"}]}
    import httpx
    orig = httpx.Client
    httpx.Client = lambda *a, **k: _FakeClientCtx(payload)
    try:
        r = decide(question_id="wire_validation_priority", kind="score", question="urgency?", scale_max=10)
        assert r["source"] == "jev" and r["value"] == 9 and not r["below_threshold"]
    finally:
        httpx.Client = orig

    from app.db.session import SessionLocal
    from app.models.models import JevDecision
    db = SessionLocal()
    try:
        row = db.query(JevDecision).filter(JevDecision.question_id == "wire_validation_priority").first()
        assert row is not None and row.source == "jev"
        db.query(JevDecision).filter(JevDecision.question_id == "wire_validation_priority").delete()
        db.commit()
    finally:
        db.close()


def test_decide_jev_below_threshold_falls_back_to_rule(monkeypatch):
    monkeypatch.setattr(decision_port, "_backend", lambda: "jev")
    payload = {"answers": [{"id": "q", "kind": "noul", "value": True, "probability": 0.3, "source": "jev"}]}
    import httpx
    orig = httpx.Client
    httpx.Client = lambda *a, **k: _FakeClientCtx(payload)
    try:
        r = decide(question_id="q", kind="noul", question="x?", threshold=0.6)
        assert r["source"] == "rule" and r["below_threshold"] is True
    finally:
        httpx.Client = orig

    from app.db.session import SessionLocal
    from app.models.models import JevDecision
    db = SessionLocal()
    try:
        db.query(JevDecision).filter(JevDecision.question_id == "q").delete()
        db.commit()
    finally:
        db.close()


def test_decide_jev_unavailable_falls_back(monkeypatch):
    monkeypatch.setattr(decision_port, "_backend", lambda: "jev")
    import httpx
    orig = httpx.Client

    class _BoomCtx:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None):
            raise ConnectionError("jev down")

    httpx.Client = lambda *a, **k: _BoomCtx()
    try:
        r = decide(question_id="q_down", kind="score", question="x?", scale_max=5)
        assert r["source"] == "rule"
    finally:
        httpx.Client = orig

    from app.db.session import SessionLocal
    from app.models.models import JevDecision
    db = SessionLocal()
    try:
        db.query(JevDecision).filter(JevDecision.question_id == "q_down").delete()
        db.commit()
    finally:
        db.close()
