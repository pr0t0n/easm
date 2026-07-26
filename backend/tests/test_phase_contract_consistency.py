from __future__ import annotations

from pathlib import Path

import pytest


def _repo_file(*parts: str) -> Path:
    candidates = [
        Path.cwd().joinpath(*parts),
        Path(__file__).resolve().parents[1].joinpath(*parts),
        Path(__file__).resolve().parents[2].joinpath(*parts),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    pytest.skip(f"arquivo fora do mount deste ambiente: {'/'.join(parts)}")


def test_p18_contract_is_credential_exposure_not_tls() -> None:
    from app.services.offensive_operator_core import PHASE_CONTRACTS
    from app.services.scan_quality import QUALITY_PHASE_FALLBACKS

    p18 = PHASE_CONTRACTS["P18"]
    assert p18["name"] == "Credential Exposure Boundary"
    assert p18["required_tools"] == ["theharvester"]
    assert "theharvester" in QUALITY_PHASE_FALLBACKS["P18"]
    assert not {"sslscan", "testssl", "nmap-ssl-vuln"} & set(QUALITY_PHASE_FALLBACKS["P18"])


def test_intelligence_dag_matches_execution_gates_for_core_phases() -> None:
    from app.services.scan_intelligence import _PHASE_DEPS
    from app.services.scan_work_queue import PHASE_GATE

    assert PHASE_GATE["P18"] == "P02"
    assert _PHASE_DEPS["P18"] == ["P02"]
    for phase_id in ("P03", "P04", "P05", "P07", "P08", "P09", "P15", "P16"):
        assert PHASE_GATE[phase_id] == "P06"
        assert _PHASE_DEPS[phase_id] == ["P06"]
    for phase_id in ("P10", "P11", "P12", "P13", "P14", "P17", "P19", "P20"):
        assert PHASE_GATE[phase_id] == "P09"
        assert _PHASE_DEPS[phase_id] == ["P09"]


def test_scan_work_queue_phase_gate_has_single_p15_entry() -> None:
    source = _repo_file("app", "services", "scan_work_queue.py").read_text(encoding="utf-8")
    assert source.count('"P15": "P06"') == 1


def test_dashboard_phase_labels_match_engine_contract_names() -> None:
    source = _repo_file("frontend", "src", "pages", "ScansPage.jsx").read_text(encoding="utf-8")
    assert 'P18: "Credenciais e segredos"' in source
    assert "JS e segredos client-side" not in source
    assert "TLS e transporte" not in source


def test_runtime_phase_api_labels_match_engine_contract_names() -> None:
    source = _repo_file("app", "api", "routes_scans.py").read_text(encoding="utf-8")
    assert '"P18": "Credential Exposure Boundary"' in source
    assert "OSINT Extended" not in source
    assert '"P15": "Historical Recon"' not in source


def test_prompt_tool_catalog_does_not_assign_tls_tools_to_p18() -> None:
    from app.services.tool_catalog import TOOL_CATALOG

    assert "sslscan" not in TOOL_CATALOG
    assert "testssl" not in TOOL_CATALOG
    assert "nmap-ssl-vuln" not in TOOL_CATALOG


def test_mission_fallback_does_not_reintroduce_p18_tls_contract() -> None:
    from app.graph.mission import _PHASE_CONTRACTS_FALLBACK

    p18 = _PHASE_CONTRACTS_FALLBACK["P18"]
    assert p18["name"] == "Credential Exposure Boundary"
    assert p18["required_tools"] == ["theharvester"]
    assert "sslscan" not in p18["optional_tools"]
