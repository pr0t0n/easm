"""Fase 3 (LANGGRAPH_BRAIN_PLAN): retrieval semântico no laço.

build_runtime_learning_playbook deve consultar o índice vetorial com o contexto
(fase/ferramentas/stack), incluir SOMENTE learnings aceitos (o índice não
filtra status) e cair para o pool por recência quando o índice falha.
"""
from __future__ import annotations

from types import SimpleNamespace

import app.services.vulnerability_learning_service as vls


class _FakeDB:
    def __init__(self, rows_by_id):
        self._rows_by_id = rows_by_id

    def query(self, *args, **kwargs):
        rows = list(self._rows_by_id.values())
        return _FakeQuery(rows)

    def close(self):
        pass


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, n):
        return self

    def all(self):
        return list(self._rows)


def _row(row_id, status):
    return SimpleNamespace(
        id=row_id, status=status, title=f"learning {row_id}",
        summary="s", learned_mission="m", learned_prompt="p",
        steps_to_reproduce="st", impact="i", remediation="r",
        vulnerability_type="xss", source_urls=[], source_kind="test",
        affected_phases=["P12"], affected_skills=[], recommended_tools=[],
        raw_extraction={}, learned_techniques=[],
    )


def test_semantic_path_filters_non_accepted(monkeypatch):
    accepted = _row(1, "accepted")
    pending = _row(2, "pending_review")
    rows_by_id = {1: accepted, 2: pending}
    monkeypatch.setattr(vls, "SessionLocal", lambda: _FakeDB(rows_by_id))
    monkeypatch.setattr(
        "app.services.learning_semantic_index.semantic_search_learnings",
        lambda db, q, top_k: [{"id": 2, "similarity": 0.9}, {"id": 1, "similarity": 0.8}],
    )

    playbook = vls.build_runtime_learning_playbook(
        candidate_tools=["dalfox"], phase="P12", tech_stack=["angular"], limit=12
    )
    assert playbook is not None
    ids = [t["source_learning_id"] for t in playbook["techniques"]]
    assert 1 in ids, "accepted deveria vir do índice"
    assert 2 not in ids, "pending_review NUNCA pode entrar no playbook"


def test_fallback_to_recency_when_semantic_empty(monkeypatch):
    accepted = _row(1, "accepted")
    monkeypatch.setattr(vls, "SessionLocal", lambda: _FakeDB({1: accepted}))
    monkeypatch.setattr(
        "app.services.learning_semantic_index.semantic_search_learnings",
        lambda db, q, top_k: [],
    )

    playbook = vls.build_runtime_learning_playbook(
        candidate_tools=["dalfox"], phase="P12", limit=12
    )
    assert playbook is not None
    ids = [s["id"] for s in playbook["sources"]]
    assert 1 in ids
