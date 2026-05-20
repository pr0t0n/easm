from app.services.hypothesis_engine import extract_pentest_hypotheses
from app.services.recon_completion_gate import evaluate_recon_completion
from app.services.recon_graph_service import update_recon_graph
from app.services.skill_recommendation_engine import recommend_skills_from_recon_graph


def test_recon_graph_turns_parameters_into_skill_recommendations() -> None:
    state = {
        "target": "http://app.local",
        "detected_tech_stack": ["asp.net", "iis", "mssql"],
        "logs_terminais": [],
    }
    findings = [
        {
            "title": "Endpoint descoberto",
            "source_worker": "reconhecimento",
            "details": {
                "tool": "katana",
                "url": "http://app.local/products/search?q=test&id=1",
                "evidence": "URL parameterizada descoberta pelo crawler",
            },
        }
    ]

    graph = update_recon_graph(
        state,
        capability="asset_discovery",
        target="http://app.local",
        tools=["katana"],
        findings=findings,
        ports=[80],
        assets=[],
        port_evidence={80: {"tool": "httpx", "service": "http", "evidence": "http://app.local [200]"}},
    )

    assert graph["parameters"]
    assert graph["skill_recommendations"][0]["skill_id"] == "vuln-injection"
    assert "sqlmap" in graph["skill_recommendations"][0]["preferred_tools"]
    assert state["recon_skill_recommendations"] == graph["skill_recommendations"]
    assert state["recon_reanalyze_queue"]


def test_recon_completion_gate_blocks_phase_2_without_recommendations() -> None:
    gate = evaluate_recon_completion({"assets": [], "web_targets": [], "skill_recommendations": []}, {})

    assert gate["ready_for_phase_2"] is False
    assert "no_skill_recommendations" in gate["coverage_gaps"]


def test_skill_recommendation_engine_produces_phase_2_contract() -> None:
    graph = {
        "signals": [
            {
                "type": "parameter",
                "url": "http://app.local/api/orders?id=1",
                "name": "id",
                "confidence": 0.9,
                "recommended_skills": ["vuln-idor-access-control", "vuln-injection"],
                "recommended_tools": ["curl-headers", "sqlmap"],
                "reason": "identifier_or_authorization_param",
            }
        ],
        "technologies": [],
    }

    recs = recommend_skills_from_recon_graph(graph, {"target": "http://app.local"})

    assert recs[0]["skill_id"] == "vuln-idor-access-control"
    assert recs[0]["target"] == "http://app.local/api/orders?id=1"
    assert "request" in recs[0]["required_evidence"]


def test_hypothesis_engine_consumes_recon_graph_parameters() -> None:
    state = {
        "target": "http://app.local",
        "detected_tech_stack": ["asp.net", "iis", "mssql"],
        "vulnerabilidades_encontradas": [],
        "recon_graph": {
            "parameters": [
                {
                    "url": "http://app.local/products/search",
                    "name": "q",
                    "method": "GET",
                }
            ],
            "web_targets": [{"url": "http://app.local/products/search"}],
            "technologies": ["asp.net", "iis", "mssql"],
        },
    }

    hypotheses = extract_pentest_hypotheses(state)

    assert any(h["suggested_skill"] == "vuln-injection" for h in hypotheses)
    assert any(h["suggested_tool"] == "sqlmap" for h in hypotheses)
    assert any(h.get("target_param") == "q" for h in hypotheses)
