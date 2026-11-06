"""Fase 0 (LANGGRAPH_BRAIN_PLAN): engine única de decisão do scan.

Precedência: state_data["scan_engine"] > settings.scan_engine > flag legada
offensive_operator_enabled. O motor escolhido é registrado em log/auditoria no
início de todo scan (_execute_scan).
"""
from __future__ import annotations

from types import SimpleNamespace

from app.core.config import settings
from app.workers.tasks import _resolve_scan_engine


def test_state_data_override_wins(monkeypatch):
    monkeypatch.setattr(settings, "scan_engine", "operator")
    job = SimpleNamespace(state_data={"scan_engine": "langgraph"})
    assert _resolve_scan_engine(job) == "langgraph"


def test_settings_engine_used_when_no_override(monkeypatch):
    monkeypatch.setattr(settings, "scan_engine", "langgraph")
    job = SimpleNamespace(state_data={})
    assert _resolve_scan_engine(job) == "langgraph"


def test_legacy_flag_fallback_when_engine_unset(monkeypatch):
    monkeypatch.setattr(settings, "scan_engine", "")
    monkeypatch.setattr(settings, "offensive_operator_enabled", True)
    assert _resolve_scan_engine(SimpleNamespace(state_data={})) == "operator"
    monkeypatch.setattr(settings, "offensive_operator_enabled", False)
    assert _resolve_scan_engine(SimpleNamespace(state_data={})) == "langgraph"


def test_invalid_override_ignored(monkeypatch):
    monkeypatch.setattr(settings, "scan_engine", "operator")
    job = SimpleNamespace(state_data={"scan_engine": "bogus"})
    assert _resolve_scan_engine(job) == "operator"


def test_missing_state_data_is_safe(monkeypatch):
    monkeypatch.setattr(settings, "scan_engine", "operator")
    assert _resolve_scan_engine(SimpleNamespace(state_data=None)) == "operator"
