from types import SimpleNamespace

import app.services.api_skill_top20_runner as api_runner
from app.services.api_skill_top20_runner import Endpoint, Identity, _anonymous_exposure_profile, _canonical_endpoint_url, _run_endpoint_skill, _select_endpoints, load_api_top20_skills
from app.services.offensive_operator_core import PHASE_CONTRACTS
from app.services.pentest_coverage_service import _work_item_matches_api_skill
from app.services.scan_work_queue import work_item_applicability_decision
from app.services.skill_rag_indexer import query_skills_by_phase, query_skills_by_tool
from app.services.skill_runtime import get_skill_by_id, load_all_runtime_skills
from app.workers.tasks import SCAN_PARALLEL_QUEUE, _work_item_execution_queue


def test_api_top20_catalog_has_twenty_ordered_skills():
    catalog = load_api_top20_skills()

    assert catalog["catalog_id"] == "api_security_top20"
    assert len(catalog["skills"]) == 20
    assert [skill["priority"] for skill in catalog["skills"]] == list(range(1, 21))
    assert catalog["skills"][0]["id"] == "skill.api.bola_idor"
    assert catalog["skills"][-1]["id"] == "skill.api.file_upload_content_handling"


def test_p16_contract_includes_api_top20_runner():
    tools = set(PHASE_CONTRACTS["P16"]["required_tools"] + PHASE_CONTRACTS["P16"]["optional_tools"])

    assert "zap-api" in tools
    assert "api-skill-top20" in tools


def test_api_top20_selector_uses_path_and_parameter_keywords():
    catalog = load_api_top20_skills()
    bola = next(skill for skill in catalog["skills"] if skill["id"] == "skill.api.bola_idor")
    endpoints = [
        Endpoint(
            method="GET",
            url="https://api.example.test/api/users/123",
            normalized_url="https://api.example.test/api/users/{id}",
            parameters=[],
            tags=["api"],
            source_tool="api-spec",
            documented=True,
            metadata={},
        ),
        Endpoint(
            method="GET",
            url="https://api.example.test/api/status",
            normalized_url="https://api.example.test/api/status",
            parameters=[],
            tags=["api"],
            source_tool="api-spec",
            documented=True,
            metadata={},
        ),
    ]

    selected = _select_endpoints(bola, endpoints, 10)

    assert [endpoint.url for endpoint in selected] == ["https://api.example.test/api/users/123"]


def test_api_top20_selector_allows_safe_head_or_options_probe_for_unsafe_surface():
    catalog = load_api_top20_skills()
    upload = next(skill for skill in catalog["skills"] if skill["id"] == "skill.api.file_upload_content_handling")
    endpoints = [
        Endpoint(
            method="POST",
            url="https://api.example.test/api/documents/upload",
            normalized_url="https://api.example.test/api/documents/upload",
            parameters=[],
            tags=["api"],
            source_tool="api-spec",
            documented=True,
            metadata={},
        )
    ]

    selected = _select_endpoints(upload, endpoints, 10)

    assert [endpoint.url for endpoint in selected] == ["https://api.example.test/api/documents/upload"]


def test_api_top20_reanchors_reused_inventory_to_current_target_scheme():
    url = _canonical_endpoint_url(
        "http://api.example.test/api/users/123",
        "https://api.example.test",
    )

    assert url == "https://api.example.test/api/users/123"


class FakeResponse:
    def __init__(self, status_code=200, text='{"ok":true}', headers=None, json_value=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"content-type": "application/json"}
        self._json_value = json_value if json_value is not None else {"ok": True}

    def json(self):
        return self._json_value


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        return self.response


def test_api_top20_auth_skill_tests_anonymous_exposure_without_credentials(monkeypatch):
    catalog = load_api_top20_skills()
    bfla = next(skill for skill in catalog["skills"] if skill["id"] == "skill.api.bfla_privilege_escalation")
    fake_session = FakeSession(FakeResponse(status_code=200))
    monkeypatch.setattr(api_runner.requests, "Session", lambda: fake_session)
    endpoint = Endpoint(
        method="GET",
        url="https://api.example.test/api/admin/users",
        normalized_url="https://api.example.test/api/admin/users",
        parameters=[],
        tags=["api"],
        source_tool="api-spec",
        documented=True,
        metadata={},
    )

    result = _run_endpoint_skill(
        bfla,
        [endpoint],
        [Identity(key="anonymous", role="", headers={}, cookies={})],
        {"max_endpoints_per_skill": 10, "max_requests_per_skill": 10, "timeout_seconds": 1},
        True,
    )

    assert result["status"] == "completed"
    assert result["attempts"] == 1
    assert len(result["findings"]) == 1
    details = result["findings"][0]["details"]
    assert details["anonymous_access"] is True
    assert details["http_status"] == 200
    assert details["response_fingerprint"]["body_sha256"]
    assert result["observations"][0]["http_status"] == 200


def test_api_top20_bola_without_second_identity_still_creates_anonymous_candidate(monkeypatch):
    catalog = load_api_top20_skills()
    bola = next(skill for skill in catalog["skills"] if skill["id"] == "skill.api.bola_idor")
    monkeypatch.setattr(api_runner.requests, "Session", lambda: FakeSession(FakeResponse(status_code=200)))
    endpoint = Endpoint(
        method="GET",
        url="https://api.example.test/api/users/123",
        normalized_url="https://api.example.test/api/users/{id}",
        parameters=[],
        tags=["api"],
        source_tool="api-spec",
        documented=True,
        metadata={},
    )

    result = _run_endpoint_skill(
        bola,
        [endpoint],
        [Identity(key="anonymous", role="", headers={}, cookies={})],
        {"max_endpoints_per_skill": 10, "max_requests_per_skill": 10, "timeout_seconds": 1},
        True,
    )

    assert result["blocked_reason"] == "second_identity_required_for_confirmation"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["details"]["anonymous_access"] is True


def test_api_top20_weak_operational_anonymous_endpoint_is_not_high_confidence():
    catalog = load_api_top20_skills()
    bopla = next(skill for skill in catalog["skills"] if skill["id"] == "skill.api.bopla")
    endpoint = Endpoint(
        method="GET",
        url="https://api.example.test/api/Exam/server-hour",
        normalized_url="https://api.example.test/api/Exam/server-hour",
        parameters=[],
        tags=["api"],
        source_tool="api-spec",
        documented=True,
        metadata={},
    )

    profile = _anonymous_exposure_profile(bopla, endpoint, ["time", "server-hour"], 200)

    assert profile["severity"] == "medium"
    assert profile["confidence_score"] == 35
    assert profile["signal_strength"] == "weak_operational_endpoint"


def test_api_top20_sensitive_anonymous_endpoint_keeps_high_risk_profile():
    catalog = load_api_top20_skills()
    bola = next(skill for skill in catalog["skills"] if skill["id"] == "skill.api.bola_idor")
    endpoint = Endpoint(
        method="GET",
        url="https://api.example.test/api/Exam/is-certificate-required-by-user-cpf",
        normalized_url="https://api.example.test/api/Exam/is-certificate-required-by-user-cpf",
        parameters=[],
        tags=["api"],
        source_tool="api-spec",
        documented=True,
        metadata={},
    )

    profile = _anonymous_exposure_profile(bola, endpoint, ["cpf", "certificate"], 200)

    assert profile["severity"] == "high"
    assert profile["confidence_score"] == 72
    assert profile["signal_strength"] == "strong_sensitive_endpoint"


def test_api_top20_coverage_maps_specific_skill_to_test_class():
    item = SimpleNamespace(
        tool_name="api-skill-top20",
        item_metadata={"api_skill_id": "skill.api.bola_idor"},
    )

    assert _work_item_matches_api_skill("idor_bola", item)
    assert not _work_item_matches_api_skill("injection_sqli", item)


def test_api_top20_applicability_uses_execution_target_not_queue_suffix():
    item = SimpleNamespace(
        phase_id="P16",
        tool_name="api-skill-top20",
        target="https://api.example.test#api-top20-skill-api-bola-idor",
        item_metadata={"execution_target": "https://api.example.test"},
    )

    decision = work_item_applicability_decision(item, {}, at="dispatch")

    assert decision["target"] == "https://api.example.test"


def test_zap_api_applicability_accepts_api_scan_config_spec_url():
    item = SimpleNamespace(
        phase_id="P16",
        tool_name="zap-api",
        target="https://api.example.test",
        item_metadata={},
    )
    state = {
        "api_scan_config": {
            "enabled": True,
            "allow_mutations": True,
            "spec_url": "https://api.example.test/openapi.json",
            "ingestion": {"endpoints": 146},
        }
    }

    decision = work_item_applicability_decision(item, state, at="dispatch")

    assert decision["applicable"] is True
    assert "api_scan_config.spec_url" in decision["evidence"]["matched_keys"]


def test_api_top20_applicability_accepts_api_scan_config_spec_url_without_http_preflight():
    item = SimpleNamespace(
        phase_id="P16",
        tool_name="api-skill-top20",
        target="https://api.example.test#api-top20-skill-api-bola-idor",
        item_metadata={"execution_target": "https://api.example.test"},
    )
    state = {
        "preflight": {
            "targets": {
                "https://api.example.test": {
                    "status": "no_http_response",
                    "http": [],
                    "open_ports": [443],
                }
            }
        },
        "api_scan_config": {
            "enabled": True,
            "allow_mutations": True,
            "spec_url": "https://api.example.test/openapi.json",
            "ingestion": {"endpoints": 146},
        },
    }

    decision = work_item_applicability_decision(item, state, at="dispatch")

    assert decision["applicable"] is True
    assert decision["target"] == "https://api.example.test"
    assert "api_scan_config.spec_url" in decision["evidence"]["matched_keys"]


def test_api_top20_yaml_skills_are_runtime_and_rag_visible():
    skills = load_all_runtime_skills()
    api_skill = get_skill_by_id("skill.api.bola_idor")
    tool_docs = query_skills_by_tool("api-skill-top20")
    phase_docs = query_skills_by_phase("P16")

    assert len([sid for sid in skills if sid.startswith("skill.api.")]) == 20
    assert api_skill and api_skill["required_tools"] == ["api-skill-top20"]
    assert len([doc for doc in tool_docs if doc["skill_id"].startswith("skill.api.")]) == 20
    assert any(doc["skill_id"] == "skill.api.bola_idor" for doc in phase_docs)


def test_api_top20_work_items_route_to_parallel_queue():
    item = SimpleNamespace(tool_name="api-skill-top20", phase_id="P16")

    assert _work_item_execution_queue(item, "unit") == SCAN_PARALLEL_QUEUE
