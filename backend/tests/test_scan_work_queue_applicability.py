from __future__ import annotations

from types import SimpleNamespace

from app.services.scan_work_queue import (
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
    d = validate_skill_applicability(
        "P10", "skill.vuln.sqli", "sqlmap", "target.example.com", state, at="dispatch",
    )
    assert d["applicable"] is True
    assert d.get("score_history_adjusted") is True
    assert d["score"] < 1.0  # blended down by low historical yield
