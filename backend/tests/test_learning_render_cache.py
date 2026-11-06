"""Fase 4 (LANGGRAPH_BRAIN_PLAN): cache curto do render de learnings.

O prompt do supervisor é montado por iteração e relê o mesmo conteúdo aceito
do Postgres — o cache TTL corta essas transações de apoio repetidas.
"""
from __future__ import annotations

import app.services.vulnerability_learning_service as vls


def test_render_cache_serves_second_call_without_db(monkeypatch):
    calls = {"n": 0}

    def fake_producer():
        calls["n"] += 1
        return "rendered"

    monkeypatch.delitem(vls._learning_render_cache, "k", raising=False)
    vls._learning_render_cache.clear()
    first = vls._learning_render_cached(("k", 1), fake_producer)
    second = vls._learning_render_cached(("k", 1), fake_producer)
    assert first == second == "rendered"
    assert calls["n"] == 1, "segunda chamada deveria vir do cache"


def test_render_cache_expires_after_ttl(monkeypatch):
    calls = {"n": 0}

    def fake_producer():
        calls["n"] += 1
        return f"v{calls['n']}"

    vls._learning_render_cache.clear()
    key = ("k", 2)
    vls._learning_render_cached(key, fake_producer)
    # força expiração
    ts, _ = vls._learning_render_cache[key]
    vls._learning_render_cache[key] = (ts - vls._LEARNING_RENDER_TTL_SECONDS - 1, "stale")
    value = vls._learning_render_cached(key, fake_producer)
    assert value == "v2", "TTL expirado deve reexecutar o producer"


def test_render_accepted_learning_for_prompt_uses_cache(monkeypatch):
    monkeypatch.setattr(vls, "_render_accepted_learning_uncached", lambda limit=8: "cached-render")
    vls._learning_render_cache.clear()
    assert vls.render_accepted_learning_for_prompt(8) == "cached-render"
    assert vls.render_accepted_learning_for_prompt(8) == "cached-render"
