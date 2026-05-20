from __future__ import annotations


def test_adversary_catalog_has_detection_contracts() -> None:
    from app.services.adversary_technique_catalog import list_adversary_techniques

    techniques = list_adversary_techniques()

    assert len(techniques) >= 8
    for technique in techniques:
        assert technique["id"]
        assert technique["name"]
        assert technique["kill_chain_stage"]
        assert technique["skills"]
        assert technique["candidate_tools"]
        assert technique["control_objectives"]
        assert technique["expected_telemetry"]
        assert technique["offensive_success_criteria"]
        assert technique["defensive_success_criteria"]
        safe_execution = technique["safe_execution"]
        assert safe_execution["destructive_actions_allowed"] is False
        assert safe_execution["data_extraction_allowed"] is False
        assert safe_execution["persistence_allowed"] is False


def test_adversary_match_prefers_sqli_for_injection_context() -> None:
    from app.services.adversary_technique_catalog import match_adversary_techniques

    matches = match_adversary_techniques(
        skill_id="vuln-injection",
        tools=["sqlmap", "nuclei"],
        phase_refs=["P12"],
        kill_chain_stage="EXPLOITATION",
        limit=3,
    )

    assert matches
    assert matches[0]["id"] == "web-sqli-attempt"
    assert "WAF" in {item["source"] for item in matches[0]["expected_telemetry"]}


def test_detection_proof_pack_template_defaults_unknown() -> None:
    from app.services.adversary_technique_catalog import detection_proof_pack_template

    pack = detection_proof_pack_template("web-sqli-attempt")

    assert pack["technique_id"] == "web-sqli-attempt"
    assert pack["detection_status"] == "unknown"
    assert pack["expected_telemetry"]
    assert pack["defensive_success_criteria"]


def test_supervisor_prompt_includes_bas_catalog() -> None:
    from app.services.cyber_autoagent_alignment import build_supervisor_prompt_contract

    contract = build_supervisor_prompt_contract(
        target="https://example.test",
        objective="Validate detection controls",
        max_iterations=3,
        active_skills=[
            {
                "id": "vuln-injection",
                "category": "vulnerabilities",
                "description": "Injection validation",
                "playbook": ["sqlmap", "nuclei"],
                "phases": ["P12"],
            }
        ],
        authorized_targets=["https://example.test"],
    )

    assert "ADVERSARY TECHNIQUE CATALOG" in contract["system_prompt"]
    assert "web-sqli-attempt" in contract["system_prompt"]
    assert "selected_adversary_technique" in contract["tool_selection_supervisor_contract"]
    assert contract["adversary_technique_catalog"]
