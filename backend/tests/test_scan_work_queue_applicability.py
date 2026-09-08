from __future__ import annotations

from types import SimpleNamespace

from app.services.endpoint_analysis_pipeline import build_parameterized_surface_state
from app.services.scan_work_queue import (
    _seed_api_scan_work_item,
    _seed_api_top20_skill_work_items,
    apply_phase_tool_metadata,
    requeue_evidence_ready_work_items,
    triage_post_p09_injection,
    update_skill_execution_score,
    validate_skill_applicability,
    work_item_applicability_decision,
)


def _state_for(target: str, profile: dict, *, tech: list[str] | None = None) -> dict:
    return {
        "preflight": {"targets": {target: profile}},
        "detected_tech_stack": tech or [],
    }


def test_unknown_recon_context_is_deferred_not_skipped() -> None:
    decision = validate_skill_applicability(
        "P06",
        "skill.recon.port_service_discovery",
        "httpx",
        "unknown.example.com",
        {},
        at="enqueue",
    )

    assert decision["applicable"] is True
    assert decision["reason"] == "insufficient_context_defer_to_dispatch"


def test_http_tool_is_skipped_when_preflight_proves_no_http_surface() -> None:
    state = _state_for(
        "dead.example.com",
        {"status": "tcp_closed", "open_ports": [], "http": [], "reason": "no web ports"},
    )

    decision = validate_skill_applicability(
        "P03",
        "skill.discovery.endpoint_discovery",
        "ffuf",
        "dead.example.com",
        state,
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"] == "no_http_surface:tcp_closed"


def test_http_tool_is_skipped_after_authoritative_p06_no_response() -> None:
    state = _state_for(
        "dead.example.com",
        {
            "status": "no_http_response",
            "open_ports": [],
            "http": [],
            "p02_complete": True,
            "p06_complete": True,
            "p06_http_live": False,
        },
    )

    decision = validate_skill_applicability(
        "P15",
        "skill.chain.exposed_git_to_credential_leak",
        "nuclei-exposure",
        "dead.example.com",
        state,
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"] == "no_http_surface:tcp_closed"


def test_p06_http_probe_does_not_require_http_surface_before_it_classifies_surface() -> None:
    state = _state_for(
        "candidate.example.com",
        {
            "status": "tcp_scanned_no_open_ports",
            "open_ports": [],
            "http": [],
            "p02_complete": True,
            "p06_complete": False,
        },
    )

    decision = validate_skill_applicability(
        "P06",
        "skill.recon.port_service_discovery",
        "httpx",
        "candidate.example.com",
        state,
        at="dispatch",
    )

    assert decision["applicable"] is True


def test_technology_specific_tool_skips_when_known_tech_is_incompatible() -> None:
    state = _state_for(
        "https://app.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"server": "nginx"}]},
        tech=["nginx", "react"],
    )

    decision = validate_skill_applicability(
        "P07",
        "skill.recon.port_service_discovery",
        "wpscan",
        "https://app.example.com",
        state,
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"].startswith("required_technology_absent:")


def test_port_specific_tool_skips_when_required_ports_are_known_absent() -> None:
    state = _state_for(
        "web.example.com",
        {"status": "http_live", "open_ports": [80, 443], "http": [{"status_code": 200}]},
    )

    decision = validate_skill_applicability(
        "P14",
        "skill.vuln.auth_bypass",
        "crackmapexec",
        "web.example.com",
        state,
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"].startswith("required_port_absent:")


def test_source_code_tool_is_skipped_for_external_domain() -> None:
    decision = validate_skill_applicability(
        "P18",
        "skill.code.sast",
        "semgrep",
        "app.example.com",
        {},
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"] == "source_code_required"


def test_trivy_requires_source_or_local_path_not_remote_hostname() -> None:
    decision = validate_skill_applicability(
        "P18",
        "skill.code.sast",
        "trivy",
        "app.example.com",
        {},
        at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"] == "source_code_required"


def test_source_code_tool_accepts_existing_local_path(tmp_path) -> None:
    decision = validate_skill_applicability(
        "P18",
        "skill.code.sast",
        "bandit",
        str(tmp_path),
        {},
        at="dispatch",
    )

    assert decision["applicable"] is True


def test_repository_secret_scanner_requires_repo_reference() -> None:
    external = validate_skill_applicability(
        "P18",
        "skill.code.secret_detection",
        "trufflehog",
        "app.example.com",
        {},
        at="dispatch",
    )
    repository = validate_skill_applicability(
        "P18",
        "skill.code.secret_detection",
        "trufflehog",
        "https://github.com/example/project.git",
        {},
        at="dispatch",
    )

    assert external["applicable"] is False
    assert external["reason"] == "source_code_required"
    assert repository["applicable"] is True


def test_h8mail_requires_observed_email_evidence() -> None:
    missing = validate_skill_applicability(
        "P18",
        "skill.chain.exposed_git_to_credential_leak",
        "h8mail",
        "example.com",
        {},
        at="dispatch",
    )
    present = validate_skill_applicability(
        "P18",
        "skill.chain.exposed_git_to_credential_leak",
        "h8mail",
        "example.com",
        {"discovered_emails": ["ops@example.com"]},
        at="dispatch",
    )

    assert missing["applicable"] is False
    assert missing["reason"].startswith("required_evidence_absent:")
    assert present["applicable"] is True


def test_batch_applicability_keeps_only_targets_that_still_apply() -> None:
    state = {
        "preflight": {
            "targets": {
                "alive.example.com": {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
                "dead.example.com": {"status": "tcp_closed", "open_ports": [], "http": []},
            }
        }
    }
    item = SimpleNamespace(
        phase_id="P03",
        tool_name="ffuf",
        target="__batch__",
        item_metadata={"batch_targets": ["alive.example.com", "dead.example.com"]},
    )

    decision = work_item_applicability_decision(item, state, at="dispatch")  # type: ignore[arg-type]

    assert decision["applicable"] is True
    assert decision["batch_targets"] == ["alive.example.com"]
    assert decision["skipped_batch_targets"] == [
        {"target": "dead.example.com", "reason": "no_http_surface:tcp_closed"}
    ]


# ── Score real (Frente B) ────────────────────────────────────────────────────


def test_raw_finding_does_not_inflate_validated_precision() -> None:
    state: dict = {}
    record = update_skill_execution_score(state, "skill.vuln.xss", "dalfox", "positive", findings_count=3)
    assert record["runs"] == 1
    assert record["positives"] == 0
    assert record["validated_observations"] == 0
    assert record["raw_findings"] == 3
    assert record["positive_rate"] == 0.5
    assert "skill_execution_scores" in state


def test_update_skill_execution_score_accumulates() -> None:
    state: dict = {}
    for _ in range(5):
        update_skill_execution_score(state, "skill.vuln.xss", "dalfox", "refuted", findings_count=0)
    record = state["skill_execution_scores"]["skill.vuln.xss:dalfox"]
    assert record["runs"] == 5
    assert record["positives"] == 0
    assert record["positive_rate"] < 0.4  # dropped from neutral 0.5


def test_update_skill_execution_score_accepts_productive_unproductive_vocabulary() -> None:
    from app.services.scan_work_queue import update_skill_execution_score

    state: dict = {}
    update_skill_execution_score(state, "skill.discovery.endpoint_discovery", "ffuf", "productive", findings_count=2)
    record = update_skill_execution_score(state, "skill.discovery.endpoint_discovery", "ffuf", "unproductive")

    assert record["validated_observations"] == 0
    assert record["utility_observations"] == 2
    assert record["positives"] == 0
    assert record["raw_findings"] == 2
    assert record["positive_rate"] == 0.5
    assert record["utility_rate"] != 0.5


def test_validate_skill_adjusts_score_after_history() -> None:
    state: dict = {}
    # prime 3 negative runs for wpscan
    for _ in range(3):
        update_skill_execution_score(state, "skill.recon.tech_detect", "wpscan", "negative")
    state_with_preflight = {
        **state,
        "preflight": {
            "targets": {
                "https://app.example.com": {
                    "status": "http_live",
                    "open_ports": [443],
                    "http": [{"server": "nginx"}],
                }
            }
        },
        "detected_tech_stack": ["nginx"],
    }
    d_with_history = validate_skill_applicability(
        "P07", "skill.recon.tech_detect", "wpscan", "https://app.example.com",
        state_with_preflight, at="dispatch",
    )
    d_no_history = validate_skill_applicability(
        "P07", "skill.recon.tech_detect", "wpscan", "https://app.example.com",
        {"preflight": state_with_preflight["preflight"], "detected_tech_stack": ["nginx"]},
        at="dispatch",
    )
    # wpscan requires wordpress tech → not applicable regardless of history
    # but score modulation is not reached when applicable=False
    assert d_with_history["applicable"] is False  # still blocked by TECH_REQUIRED_TOOLS


def test_validate_skill_score_adjusted_for_low_yield_tool() -> None:
    state: dict = {}
    for _ in range(3):
        update_skill_execution_score(state, "skill.vuln.sqli", "sqlmap", "refuted")
    state["preflight"] = {
        "targets": {"target.example.com": {"status": "http_live", "open_ports": [443], "http": [{}]}}
    }
    state["discovered_parameterized_urls"] = ["https://target.example.com/page?id=1"]
    d = validate_skill_applicability(
        "P10", "skill.vuln.sqli", "sqlmap", "target.example.com", state, at="dispatch",
    )
    assert d["applicable"] is True
    assert d.get("score_history_adjusted") is True
    assert d["score"] < 1.0  # blended down by low historical yield


# ── Evidence-required tools (Fase 1, item 4) ─────────────────────────────────


def test_sqlmap_blocked_without_discovered_parameters() -> None:
    state = _state_for(
        "target.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )
    decision = validate_skill_applicability(
        "P10", "skill.vuln.sqli", "sqlmap", "target.example.com", state, at="dispatch",
    )
    assert decision["applicable"] is False
    assert decision["reason"].startswith("required_evidence_absent:")
    assert "discovered_parameterized_urls" in decision["reason"]


def test_sqlmap_allowed_once_parameters_are_discovered() -> None:
    state = _state_for(
        "target.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )
    state["discovered_parameterized_urls"] = ["https://target.example.com/search?q=1"]
    decision = validate_skill_applicability(
        "P10", "skill.vuln.sqli", "sqlmap", "target.example.com", state, at="dispatch",
    )
    assert decision["applicable"] is True
    assert decision["evidence"]["matched_keys"] == ["discovered_parameterized_urls"]


def test_sqlmap_allowed_by_known_parameters_alias() -> None:
    state = _state_for(
        "target.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )
    state["known_parameters"] = [{"url": "https://target.example.com/search", "name": "q"}]

    decision = validate_skill_applicability(
        "P10", "skill.vuln.sqli", "sqlmap", "target.example.com", state, at="dispatch",
    )

    assert decision["applicable"] is True
    assert decision["evidence"]["matched_keys"] == ["known_parameters"]


def test_endpoint_inventory_materializes_parameter_evidence_for_sqlmap() -> None:
    endpoint = SimpleNamespace(
        url="https://target.example.com/search?q=invoice",
        normalized_url="https://target.example.com/search?q=invoice",
        method="GET",
        auth_context="anonymous",
    )
    parameter = SimpleNamespace(
        name="q",
        location="query",
        type_hint="string",
        risk_hint="",
    )

    state = _state_for(
        "target.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )
    state.update(build_parameterized_surface_state([(endpoint, [parameter], "external")]))

    decision = validate_skill_applicability(
        "P10", "skill.vuln.sqli", "sqlmap", "target.example.com", state, at="dispatch",
    )

    assert decision["applicable"] is True
    assert "known_parameters" in decision["evidence"]["matched_keys"]
    assert state["discovered_parameterized_urls"] == ["https://target.example.com/search?q=invoice"]
    assert state["parameterized_endpoints"][0]["parameter_count"] == 1


def test_evidence_from_another_host_does_not_unlock_tool() -> None:
    state = _state_for(
        "target.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )
    state["discovered_parameterized_urls"] = ["https://other.example.com/search?q=1"]

    decision = validate_skill_applicability(
        "P10", "skill.vuln.sqli", "sqlmap", "target.example.com", state, at="dispatch",
    )

    assert decision["applicable"] is False
    assert decision["reason"].startswith("required_evidence_absent:")


def test_dalfox_and_nuclei_xss_require_input_evidence() -> None:
    state = _state_for(
        "target.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )

    blocked = validate_skill_applicability(
        "P10", "skill.vuln.xss", "dalfox", "target.example.com", state, at="dispatch",
    )
    assert blocked["applicable"] is False
    assert blocked["reason"].startswith("required_evidence_absent:")

    state["reflected_parameters"] = [{"url": "https://target.example.com/search?q=hello", "name": "q"}]
    allowed = validate_skill_applicability(
        "P10", "skill.vuln.xss", "nuclei-xss", "target.example.com", state, at="dispatch",
    )
    assert allowed["applicable"] is True
    assert allowed["evidence"]["matched_keys"] == ["reflected_parameters"]


def test_zap_api_requires_openapi_or_swagger_evidence() -> None:
    state = _state_for(
        "https://api.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )
    state["api_scan_config"] = {"allow_mutations": True}

    blocked = validate_skill_applicability(
        "P16", "skill.discovery.api_surface", "zap-api", "https://api.example.com", state, at="dispatch",
    )
    assert blocked["applicable"] is False
    assert "openapi_urls" in blocked["reason"]

    state["swagger_urls"] = ["https://api.example.com/swagger.json"]
    allowed = validate_skill_applicability(
        "P16", "skill.discovery.api_surface", "zap-api", "https://api.example.com", state, at="dispatch",
    )
    assert allowed["applicable"] is True
    assert allowed["evidence"]["matched_keys"] == ["swagger_urls"]


def test_zap_api_requires_explicit_mutation_authorization() -> None:
    state = _state_for(
        "https://api.example.com",
        {"status": "http_live", "open_ports": [443], "http": [{"status_code": 200}]},
    )
    state["swagger_urls"] = ["https://api.example.com/swagger.json"]
    state["api_scan_config"] = {"allow_mutations": False}

    blocked = validate_skill_applicability(
        "P16", "skill.discovery.api_surface", "zap-api", "https://api.example.com", state, at="dispatch",
    )
    assert blocked["applicable"] is False
    assert blocked["reason"] == "api_mutation_guardrail_requires_explicit_authorization"

    state["api_scan_config"] = {"allow_mutations": True}
    allowed = validate_skill_applicability(
        "P16", "skill.discovery.api_surface", "zap-api", "https://api.example.com", state, at="dispatch",
    )
    assert allowed["applicable"] is True
    assert allowed["evidence"]["matched_keys"] == ["swagger_urls"]


def test_requeue_evidence_ready_work_items_revives_missing_evidence_skip() -> None:
    item = SimpleNamespace(
        id=42,
        scan_job_id=7,
        phase_id="P10",
        skill_id="skill.vuln.sqli",
        tool_name="sqlmap",
        target="target.example.com",
        status="skipped",
        last_error="skipped:applicability:required_evidence_absent:discovered_parameterized_urls",
        result={"status": "skipped"},
        item_metadata={"skill_ids": ["skill.vuln.sqli"]},
        lease_until=None,
        finished_at="earlier",
        updated_at=None,
    )
    job = SimpleNamespace(
        id=7,
        status="completed_with_gaps",
        current_step="P21 Quality Gate",
        mission_progress=100,
        state_data={
            "preflight": {
                "targets": {
                    "target.example.com": {
                        "status": "http_live",
                        "open_ports": [443],
                        "http": [{"status_code": 200}],
                    }
                }
            },
            "known_parameters": [{"url": "https://target.example.com/item", "name": "id"}],
        },
    )

    class FakeQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return [item]

    class FakeDb:
        def __init__(self):
            self.added = []

        def query(self, *_args, **_kwargs):
            return FakeQuery()

        def add(self, obj):
            self.added.append(obj)

    requeued = requeue_evidence_ready_work_items(FakeDb(), job)  # type: ignore[arg-type]

    assert requeued == 1
    assert item.status == "queued"
    assert item.last_error is None
    assert item.result["reason"] == "applicability_prerequisite_now_present"
    assert item.item_metadata["requeued_after_evidence"] is True
    assert job.status == "running"
    assert job.mission_progress == 99
    assert job.state_data["quality_gate_active"] is True


def test_requeue_evidence_ready_work_items_revives_stale_http_surface_skip() -> None:
    item = SimpleNamespace(
        id=43,
        scan_job_id=7,
        phase_id="P18",
        skill_id="skill.chain.exposed_git_to_credential_leak",
        tool_name="nuclei-exposure",
        target="target.example.com",
        status="skipped",
        last_error="skipped:applicability:no_http_surface:tcp_closed",
        result={"status": "skipped"},
        item_metadata={"skill_ids": ["skill.chain.exposed_git_to_credential_leak"]},
        lease_until=None,
        finished_at="earlier",
        updated_at=None,
    )
    job = SimpleNamespace(
        id=7,
        status="completed_with_gaps",
        current_step="P21 Quality Gate",
        mission_progress=100,
        state_data={
            "preflight": {
                "targets": {
                    "target.example.com": {
                        "status": "http_live",
                        "open_ports": [443],
                        "http": [{"status_code": 200}],
                        "p06_complete": True,
                        "p06_http_live": True,
                    }
                }
            }
        },
    )

    class FakeQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return [item]

    class FakeDb:
        def __init__(self):
            self.added = []

        def query(self, *_args, **_kwargs):
            return FakeQuery()

        def add(self, obj):
            self.added.append(obj)

    requeued = requeue_evidence_ready_work_items(FakeDb(), job)  # type: ignore[arg-type]

    assert requeued == 1
    assert item.status == "queued"
    assert item.last_error is None
    assert item.result["reason"] == "applicability_prerequisite_now_present"


def test_requeue_evidence_ready_work_items_does_not_mutate_completed_scan() -> None:
    item = SimpleNamespace(
        id=44,
        scan_job_id=7,
        phase_id="P18",
        skill_id="skill.chain.exposed_git_to_credential_leak",
        tool_name="nuclei-exposure",
        target="target.example.com",
        status="skipped",
        last_error="skipped:applicability:no_http_surface:tcp_closed",
        result={"status": "skipped"},
        item_metadata={},
    )
    job = SimpleNamespace(id=7, status="completed", state_data={})

    class FakeDb:
        def query(self, *_args, **_kwargs):
            raise AssertionError("terminal completed scans must not query mutable work items")

    assert requeue_evidence_ready_work_items(FakeDb(), job) == 0  # type: ignore[arg-type]
    assert item.status == "skipped"


def test_zap_api_metadata_carries_openapi_url_from_api_scan_config() -> None:
    meta = apply_phase_tool_metadata(
        {"api_scan_config": {"spec_url": "https://api.example.test/openapi.json"}},
        "P16",
        "zap-api",
    )

    assert meta["openapi_url"] == "https://api.example.test/openapi.json"
    assert meta["swagger_url"] == "https://api.example.test/openapi.json"


def test_api_scan_seed_creates_visible_zap_api_work_item() -> None:
    added = []

    class Query:
        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return None

    class DB:
        def query(self, *_args, **_kwargs):
            return Query()

        def add(self, obj):
            added.append(obj)

        def flush(self):
            for index, obj in enumerate(added, start=1):
                if getattr(obj, "id", None) is None:
                    obj.id = index

    job = SimpleNamespace(id=15, target_query="api.example.test")
    state = {
        "api_scan_config": {
            "enabled": True,
            "spec_url": "https://api.example.test/openapi.json",
            "spec_type": "openapi",
            "allow_mutations": True,
            "execution_contexts": ["anonymous"],
            "ingestion": {"endpoints": 146},
        },
        "openapi_urls": ["https://api.example.test/openapi.json"],
        "swagger_urls": ["https://api.example.test/openapi.json"],
    }

    created, existing, skipped = _seed_api_scan_work_item(
        DB(),
        job,
        state,
        ["api.example.test"],
        [],
        source="unit",
    )

    work_items = [obj for obj in added if obj.__class__.__name__ == "ScanWorkItem"]
    assert created == 1
    assert existing == 0
    assert skipped == 0
    assert len(work_items) == 1
    item = work_items[0]
    assert item.phase_id == "P16"
    assert item.tool_name == "zap-api"
    assert item.status == "queued"
    assert item.target == "https://api.example.test"
    assert item.item_metadata["openapi_url"] == "https://api.example.test/openapi.json"
    assert item.item_metadata["api_observability"]["scanner"] == "OWASP ZAP"
    assert item.item_metadata["api_observability"]["ingested_endpoints"] == 146


def test_api_top20_seed_uses_api_inventory_without_zap_config() -> None:
    added = []

    class Query:
        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return None

    class DB:
        def query(self, *_args, **_kwargs):
            return Query()

        def add(self, obj):
            added.append(obj)

        def flush(self):
            for index, obj in enumerate(added, start=1):
                if getattr(obj, "id", None) is None:
                    obj.id = index

    job = SimpleNamespace(id=27, target_query="api.example.test", state_data={})
    state = {
        "discovered_endpoints": [
            "https://api.example.test/api/users/123",
            "https://api.example.test/api/admin/users",
        ],
    }

    created, existing, skipped = _seed_api_top20_skill_work_items(
        DB(),
        job,
        state,
        ["api.example.test"],
        ["api.example.test"],
        source="unit",
    )

    work_items = [obj for obj in added if obj.__class__.__name__ == "ScanWorkItem"]
    assert created == 20
    assert existing == 0
    assert skipped == 0
    assert len(work_items) == 20
    assert all(item.tool_name == "api-skill-top20" for item in work_items)
    assert all(item.item_metadata["skill_id"].startswith("skill.api.") for item in work_items)
    assert any(item.item_metadata["api_skill_id"] == "skill.api.bola_idor" for item in work_items)


def test_post_p09_triage_keeps_high_cost_tool_when_direct_evidence_exists() -> None:
    from app.models.models import Finding, ScanJob, ScanWorkItem

    item = SimpleNamespace(
        scan_job_id=7,
        phase_id="P10",
        tool_name="sqlmap",
        target="target.example.com",
        status="queued",
        item_metadata={},
        updated_at=None,
    )
    job = SimpleNamespace(
        id=7,
        state_data={
            "known_parameters": [{"url": "https://target.example.com/item", "name": "id"}],
        },
    )

    class FakeQuery:
        def __init__(self, *, first_value=None, all_value=None, scalar_value=0):
            self._first_value = first_value
            self._all_value = all_value or []
            self._scalar_value = scalar_value

        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return self._all_value

        def first(self):
            return self._first_value

        def scalar(self):
            return self._scalar_value

    class FakeDb:
        def __init__(self):
            self.added = []
            self.commits = 0

        def query(self, model, *_args, **_kwargs):
            if model is Finding:
                return FakeQuery(all_value=[])
            if model is ScanJob:
                return FakeQuery(first_value=job)
            if model is ScanWorkItem:
                return FakeQuery(all_value=[item])
            return FakeQuery(scalar_value=1)

        def add(self, obj):
            self.added.append(obj)

        def commit(self):
            self.commits += 1

    result = triage_post_p09_injection(FakeDb(), 7)  # type: ignore[arg-type]

    assert result["cancelled"] == 0
    assert result["kept_by_direct_evidence"] == 1
    assert item.status == "queued"
    assert item.item_metadata["triage_post_p09"]["decision"] == "kept_by_direct_evidence"


def test_post_p09_negative_signal_does_not_cancel_independent_methodology() -> None:
    from app.models.models import Finding, ScanJob, ScanWorkItem

    item = SimpleNamespace(
        scan_job_id=8,
        phase_id="P13",
        tool_name="bl-test",
        target="app.example.com",
        status="blocked",
        item_metadata={},
        updated_at=None,
    )
    job = SimpleNamespace(id=8, state_data={})

    class FakeQuery:
        def __init__(self, *, first_value=None, all_value=None, scalar_value=0):
            self._first_value = first_value
            self._all_value = all_value or []
            self._scalar_value = scalar_value

        def filter(self, *_args, **_kwargs):
            return self

        def all(self):
            return self._all_value

        def first(self):
            return self._first_value

        def scalar(self):
            return self._scalar_value

    class FakeDb:
        def query(self, model, *_args, **_kwargs):
            if model is Finding:
                return FakeQuery(all_value=[])
            if model is ScanJob:
                return FakeQuery(first_value=job)
            if model is ScanWorkItem:
                return FakeQuery(all_value=[item])
            return FakeQuery(scalar_value=1)

        def add(self, _obj):
            return None

        def commit(self):
            return None

    result = triage_post_p09_injection(FakeDb(), 8)  # type: ignore[arg-type]

    assert result["cancelled"] == 0
    assert result["kept_by_policy"] == 1
    assert item.status == "blocked"
    assert item.item_metadata["triage_post_p09"]["decision"] == "kept_for_independent_methodology"


def test_masscan_requires_aggressive_profile_or_crown_jewel() -> None:
    target = "api.example.com"
    profile = {"status": "dns_live", "open_ports": []}

    standard = validate_skill_applicability(
        "P02",
        "skill.recon.port_service_discovery",
        "masscan",
        target,
        {**_state_for(target, profile), "scan_level": "full"},
        at="enqueue",
    )
    aggressive = validate_skill_applicability(
        "P02",
        "skill.recon.port_service_discovery",
        "masscan",
        target,
        {**_state_for(target, profile), "scan_level": "aggressive"},
        at="enqueue",
    )

    assert standard["applicable"] is False
    assert standard["reason"] == "full_tcp_requires_aggressive_profile_or_crown_jewel"
    assert aggressive["applicable"] is True
    assert aggressive["reason"] == "full_tcp_authorized_by_aggressive_profile"
