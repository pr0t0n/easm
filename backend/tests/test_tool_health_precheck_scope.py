"""Fase 0 (LANGGRAPH_BRAIN_PLAN): precheck de tool health consciente de escopo.

Ferramentas SAST/SCA (bandit/retire/trivy/semgrep) só são exigíveis quando o
scan traz artefato de código-fonte (source_config). Sem artefato, quebradas
voltam em `excluded` e não bloqueiam o scan — antes, 3 binários ausentes no
Kali bloqueavam todo scan full da plataforma (2026-11).
"""
from __future__ import annotations

from app.services.tool_health_service import (
    SOURCE_ARTIFACT_ONLY_TOOLS,
    partition_broken_required_tools,
)


def test_source_only_tools_excluded_without_source_artifact():
    tools = [
        {"tool_name": "bandit", "status": "missing_binary", "detail": {"requiredness": "required"}},
        {"tool_name": "retire", "status": "missing_binary", "detail": {"requiredness": "required"}},
        {"tool_name": "trivy", "status": "missing_binary", "detail": {"requiredness": "required"}},
    ]
    applicable, excluded = partition_broken_required_tools(tools, has_source_artifact=False)
    assert applicable == []
    assert set(excluded) == {"bandit", "retire", "trivy"}


def test_all_broken_required_apply_with_source_artifact():
    tools = [
        {"tool_name": "bandit", "status": "missing_binary", "detail": {"requiredness": "required"}},
        {"tool_name": "naabu", "status": "missing_binary", "detail": {"requiredness": "required"}},
    ]
    applicable, excluded = partition_broken_required_tools(tools, has_source_artifact=True)
    assert set(applicable) == {"bandit", "naabu"}
    assert excluded == []


def test_non_required_broken_tools_never_block():
    tools = [
        {"tool_name": "amass", "status": "missing_binary", "detail": {"requiredness": "optional"}},
    ]
    applicable, excluded = partition_broken_required_tools(tools, has_source_artifact=True)
    assert applicable == []
    assert excluded == []


def test_ready_tools_not_listed():
    tools = [
        {"tool_name": "nuclei", "status": "ready", "detail": {"requiredness": "required"}},
    ]
    applicable, excluded = partition_broken_required_tools(tools, has_source_artifact=False)
    assert applicable == [] and excluded == []


def test_mixed_web_and_source_tools_without_artifact():
    tools = [
        {"tool_name": "bandit", "status": "missing_binary", "detail": {"requiredness": "required"}},
        {"tool_name": "naabu", "status": "missing_binary", "detail": {"requiredness": "required"}},
    ]
    applicable, excluded = partition_broken_required_tools(tools, has_source_artifact=False)
    assert applicable == ["naabu"]
    assert excluded == ["bandit"]


def test_source_artifact_set_is_explicit():
    assert {"bandit", "retire", "trivy", "semgrep"} <= SOURCE_ARTIFACT_ONLY_TOOLS
