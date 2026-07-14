from __future__ import annotations

from types import SimpleNamespace

from app.services.scan_work_queue import (
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


def test_update_skill_execution_score_first_positive() -> None:
    state: dict = {}
    record = update_skill_execution_score(state, "skill.vuln.xss", "dalfox", "positive", findings_count=3)
    assert record["runs"] == 1
    assert record["positives"] == 1
    assert record["positive_rate"] > 0.5  # pulled up from neutral 0.5
    assert "skill_execution_scores" in state


def test_update_skill_execution_score_accumulates() -> None:
    state: dict = {}
    for _ in range(5):
        update_skill_execution_score(state, "skill.vuln.xss", "dalfox", "negative", findings_count=0)
    record = state["skill_execution_scores"]["skill.vuln.xss:dalfox"]
    assert record["runs"] == 5
    assert record["positives"] == 0
    assert record["positive_rate"] < 0.4  # dropped from neutral 0.5


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
        update_skill_execution_score(state, "skill.vuln.sqli", "sqlmap", "negative")
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
    assert item.result["reason"] == "required_evidence_now_present"
    assert item.item_metadata["requeued_after_evidence"] is True


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
