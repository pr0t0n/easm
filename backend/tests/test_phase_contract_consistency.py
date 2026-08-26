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
    # theharvester alone used to be the whole phase (a scan-only signal); it's
    # now a real backend-local reviewer's required tool, with theharvester
    # demoted to one of several optional signal sources it reviews.
    assert p18["required_tools"] == ["credential-boundary-review"]
    assert "theharvester" in p18["optional_tools"]
    assert "theharvester" in QUALITY_PHASE_FALLBACKS["P18"]
    assert not {"sslscan", "testssl", "nmap-ssl-vuln"} & set(QUALITY_PHASE_FALLBACKS["P18"])


def test_p12_contract_tracks_reflected_and_stored_xss_separately() -> None:
    from app.services.offensive_operator_core import PHASE_CONTRACTS, PHASE_TOOL_BINDINGS

    p12 = PHASE_CONTRACTS["P12"]
    assert "skill.vuln.xss" in p12["required_skills"]
    assert "skill.stored_xss_testing" in p12["required_skills"]
    assert "dalfox" in p12["required_tools"]
    assert "curl" in p12["optional_tools"]
    assert PHASE_TOOL_BINDINGS["P12"]["dalfox"] == ["skill.vuln.xss"]
    assert PHASE_TOOL_BINDINGS["P12"]["curl"] == ["skill.stored_xss_testing"]


def test_p12_validator_does_not_complete_stored_xss_without_mutation_flow() -> None:
    from app.services.offensive_operator_core import PHASE_CONTRACTS, PhaseValidator

    p12 = PHASE_CONTRACTS["P12"]
    decision = PhaseValidator().validate(
        p12,
        {"tools": [{"tool_name": "dalfox", "required": True}]},
        [{"tool_name": "dalfox", "status": "success", "profile": "dalfox_xss"}],
        [{"evidence_strength": "medium", "tool_name": "dalfox", "skill_id": "skill.vuln.xss"}],
        [],
        {},
        {
            "skill.vuln.xss": {"status": "completed"},
            "skill.stored_xss_testing": {"status": "completed"},
        },
    )

    assert decision["status"] == "partial"
    assert decision["reason"] == "stored_xss_flow_not_covered"
    assert "authenticated_session" in decision["missing_requirements"]
    assert "state_changing_body_surface" in decision["missing_requirements"]


def test_p12_validator_accepts_stored_xss_request_response_coverage() -> None:
    from app.services.offensive_operator_core import PHASE_CONTRACTS, PhaseValidator

    p12 = PHASE_CONTRACTS["P12"]
    decision = PhaseValidator().validate(
        p12,
        {"tools": [{"tool_name": "dalfox", "required": True}, {"tool_name": "curl", "required": False}]},
        [
            {"tool_name": "dalfox", "status": "success", "profile": "dalfox_xss"},
            {
                "tool_name": "curl",
                "status": "success",
                "profile": "curl_probe",
                "stdout": "POST /api/items request_response_pair payload_used rendered_context negative_control",
            },
        ],
        [
            {"evidence_strength": "medium", "tool_name": "dalfox", "skill_id": "skill.vuln.xss"},
            {
                "evidence_strength": "medium",
                "tool_name": "curl",
                "skill_id": "skill.stored_xss_testing",
                "parsed_json": {"request_response_pair": True, "payload_used": True, "rendered_context": "html"},
            },
        ],
        [],
        {
            "tokens": ["test-token"],
            "discovered_parameterized_requests": [
                {
                    "method": "POST",
                    "url": "https://example.test/api/items",
                    "body_parameters": ["description"],
                    "body_template": '{"description":"FUZZ"}',
                }
            ],
        },
        {
            "skill.vuln.xss": {"status": "completed"},
            "skill.stored_xss_testing": {"status": "completed"},
        },
    )

    assert decision["status"] == "completed"
    assert decision["reason"] == "exit_criteria_satisfied"


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
    from app.graph.mission import _LEGACY_PHASE_CONTRACTS_UNUSED

    p18 = _LEGACY_PHASE_CONTRACTS_UNUSED["P18"]
    assert p18["name"] == "Credential Exposure Boundary"
    assert p18["required_tools"] == ["theharvester"]
    assert "sslscan" not in p18["optional_tools"]
