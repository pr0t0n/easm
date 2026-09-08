from types import SimpleNamespace

from app.services.api_skill_coverage import build_api_skill_coverage_snapshot
from app.services.api_skill_top20_runner import load_api_top20_skills


def _item(skill_id: str, *, observation_url: str = "https://api.example.test/api/users/1", method: str = "GET"):
    return SimpleNamespace(
        id=abs(hash(skill_id)) % 100000,
        status="completed",
        tool_name="api-skill-top20",
        target="https://api.example.test",
        attempts=1,
        item_metadata={"api_skill_id": skill_id},
        result={
            "parsed_result": {
                "api_skill_id": skill_id,
                "tool": "api-skill-top20",
                "mcp_used": True,
                "execution_path": "mcp",
                "skills_total": 1,
                "matched_endpoint_count": 1,
                "selected_endpoint_count": 1,
                "attempts": 1,
                "skill_results": [{
                    "skill_id": skill_id,
                    "findings": [],
                    "observations": [{
                        "method": method,
                        "url": observation_url,
                        "http_status": 200,
                    }],
                }],
                "response_observations": [{
                    "method": method,
                    "url": observation_url,
                    "http_status": 200,
                }],
            }
        },
    )


def test_api_skill_coverage_accepts_complete_top20_mcp_run():
    skill_ids = [skill["id"] for skill in load_api_top20_skills()["skills"]]
    snapshot = build_api_skill_coverage_snapshot(
        work_items=[_item(skill_id) for skill_id in skill_ids],
        swagger_endpoints=[
            SimpleNamespace(method="GET", url="http://api.example.test/api/users/1", source_tool="api-spec")
        ],
        state={"rag_warmup": {"ok": True}},
        expected_skill_ids=skill_ids,
    )

    assert snapshot["complete"] is True
    assert snapshot["expected_skills"] == 20
    assert len(snapshot["skills_completed_ids"]) == 20
    assert len(snapshot["skills_completed_via_mcp_ids"]) == 20
    assert snapshot["rag_used"] is True
    assert snapshot["swagger"]["paths_total"] == 1
    assert snapshot["swagger"]["paths_observed"] == 1
    assert snapshot["swagger"]["methods_observed"] == 1
    assert snapshot["gaps"] == []


def test_api_skill_coverage_blocks_api_inventory_without_materialized_top20_skills():
    skill_ids = [skill["id"] for skill in load_api_top20_skills()["skills"]]
    snapshot = build_api_skill_coverage_snapshot(
        work_items=[
            SimpleNamespace(
                id=27,
                status="completed",
                tool_name="api-skill-top20",
                target="https://api.example.test",
                attempts=1,
                item_metadata={"skill_id": "skill.discovery.generic"},
                result={
                    "parsed_result": {
                        "tool": "api-skill-top20",
                        "mcp_used": False,
                        "skills_total": 0,
                        "response_observations": [],
                    }
                },
            )
        ],
        swagger_endpoints=[
            SimpleNamespace(method="GET", url="https://api.example.test/api/users/1", source_tool="api-spec")
        ],
        state={},
        expected_skill_ids=skill_ids,
    )

    assert snapshot["complete"] is False
    assert snapshot["skills_completed_ids"] == []
    assert snapshot["skills_total_zero_items"] == [27]
    assert any(gap["severity"] == "high" and gap["area"] == "api_skill_dispatch" for gap in snapshot["gaps"])
    assert any(gap["severity"] == "high" and gap["area"] == "api_skill_mcp" for gap in snapshot["gaps"])
