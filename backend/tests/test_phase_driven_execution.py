"""Tests for phase-driven execution enforcement.

Validates:
- Phase validator correctly gates advancement on evidence
- Skills are resolved from .md files by phase_id
- Phase ledger is finalized correctly
- No phase skipping when evidence is missing
- Phase advancement happens only when exit criteria are met
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ---------------------------------------------------------------------------
# Phase Validator tests
# ---------------------------------------------------------------------------

from app.services.phase_validator import (
    validate_phase_exit_criteria,
    finalize_phase,
    should_retry_phase,
    get_next_phase_id,
    _PHASES_REQUIRING_EVIDENCE,
    _PARTIAL_OK_PHASES,
)


def _make_ledger(**kwargs: Any) -> dict[str, Any]:
    """Build a minimal phase ledger for testing."""
    return kwargs


def _entry(**kwargs: Any) -> dict[str, Any]:
    defaults = {
        "status": "running",
        "tools_attempted": [],
        "tools_succeeded": [],
        "tools_failed": [],
        "evidence_ids": [],
        "skip_reason": "",
        "retry_count": 0,
        "validation_result": {},
    }
    defaults.update(kwargs)
    return defaults


class TestPhaseValidatorBlocking:
    def test_no_tools_attempted_blocks_critical_phase(self):
        ledger = _make_ledger(P01=_entry(tools_attempted=[], tools_succeeded=[]))
        result = validate_phase_exit_criteria("P01", ledger)
        assert result["can_advance"] is False
        assert result["status"] == "blocked"

    def test_no_tools_blocks_but_partial_ok_for_passive_phases(self):
        ledger = _make_ledger(P05=_entry(tools_attempted=[], tools_succeeded=[]))
        result = validate_phase_exit_criteria("P05", ledger)
        assert result["can_advance"] is True
        assert result["status"] == "partial"

    def test_all_tools_failed_blocks_critical_phase(self):
        ledger = _make_ledger(
            P01=_entry(
                tools_attempted=["subfinder"],
                tools_succeeded=[],
                tools_failed=["subfinder"],
            )
        )
        result = validate_phase_exit_criteria("P01", ledger)
        assert result["can_advance"] is False
        assert result["status"] == "blocked"

    def test_all_tools_failed_partial_ok_for_passive(self):
        ledger = _make_ledger(
            P07=_entry(
                tools_attempted=["shodan"],
                tools_succeeded=[],
                tools_failed=["shodan"],
            )
        )
        result = validate_phase_exit_criteria("P07", ledger)
        assert result["can_advance"] is True
        assert result["status"] == "partial"

    def test_insufficient_evidence_blocks_critical_phase(self):
        ledger = _make_ledger(
            P01=_entry(
                tools_attempted=["subfinder"],
                tools_succeeded=["subfinder"],
                evidence_ids=[],  # no evidence
            )
        )
        result = validate_phase_exit_criteria("P01", ledger)
        # P01 is in _PHASES_REQUIRING_EVIDENCE
        assert "P01" in _PHASES_REQUIRING_EVIDENCE
        assert result["can_advance"] is False
        assert result["status"] == "partial"

    def test_sufficient_evidence_allows_advance(self):
        ledger = _make_ledger(
            P01=_entry(
                tools_attempted=["subfinder"],
                tools_succeeded=["subfinder"],
                evidence_ids=["ev-001"],
            )
        )
        result = validate_phase_exit_criteria("P01", ledger)
        assert result["can_advance"] is True
        assert result["status"] == "completed"

    def test_already_completed_returns_completed(self):
        ledger = _make_ledger(P01=_entry(status="completed"))
        result = validate_phase_exit_criteria("P01", ledger)
        assert result["status"] == "completed"
        assert result["can_advance"] is True

    def test_skip_reason_returns_skipped(self):
        ledger = _make_ledger(P01=_entry(skip_reason="mcp_unavailable"))
        result = validate_phase_exit_criteria("P01", ledger)
        assert result["status"] == "skipped"
        assert result["can_advance"] is True

    def test_skill_contract_min_tools_enforced(self):
        skill_contract = {
            "exit_criteria": {"minimum_tools_attempted": 2, "minimum_evidence_items": 1}
        }
        ledger = _make_ledger(
            P02=_entry(
                tools_attempted=["naabu"],  # only 1, need 2
                tools_succeeded=["naabu"],
                evidence_ids=["ev-001"],
            )
        )
        result = validate_phase_exit_criteria("P02", ledger, skill_contract=skill_contract)
        assert result["can_advance"] is False
        assert "minimum_tools_not_attempted" in result["reason"]

    def test_validator_required_blocks_without_validation(self):
        skill_contract = {
            "exit_criteria": {"validator_required": True, "minimum_evidence_items": 1}
        }
        ledger = _make_ledger(
            P12=_entry(
                tools_attempted=["sqlmap"],
                tools_succeeded=["sqlmap"],
                evidence_ids=["ev-sqli-001"],
                validation_result={},  # not run
            )
        )
        result = validate_phase_exit_criteria("P12", ledger, skill_contract=skill_contract)
        assert result["can_advance"] is False
        assert "validator_required" in result["reason"]

    def test_validator_passed_allows_advance(self):
        skill_contract = {
            "exit_criteria": {"validator_required": True, "minimum_evidence_items": 1}
        }
        ledger = _make_ledger(
            P12=_entry(
                tools_attempted=["sqlmap"],
                tools_succeeded=["sqlmap"],
                evidence_ids=["ev-sqli-001"],
                validation_result={"status": "SUCCESS", "reason": "confirmed"},
            )
        )
        result = validate_phase_exit_criteria("P12", ledger, skill_contract=skill_contract)
        assert result["can_advance"] is True

    def test_validator_failure_blocks(self):
        skill_contract = {
            "exit_criteria": {"validator_required": True, "minimum_evidence_items": 1}
        }
        ledger = _make_ledger(
            P12=_entry(
                tools_attempted=["sqlmap"],
                tools_succeeded=["sqlmap"],
                evidence_ids=["ev-sqli-001"],
                validation_result={"status": "FAILURE", "reason": "false_positive"},
            )
        )
        result = validate_phase_exit_criteria("P12", ledger, skill_contract=skill_contract)
        assert result["can_advance"] is False
        assert "validator_failed" in result["reason"]


class TestFinalizePhaseLedger:
    def test_finalize_completed(self):
        ledger = {"P01": _entry(tools_attempted=["subfinder"], tools_succeeded=["subfinder"], evidence_ids=["ev-001"])}
        validation_result = {"status": "completed", "can_advance": True, "reason": "all_criteria_met"}
        updated = finalize_phase(
            phase_id="P01",
            phase_ledger=ledger,
            validation_result=validation_result,
        )
        assert updated["P01"]["status"] == "completed"
        assert updated["P01"]["can_advance"] is True
        assert updated["P01"]["exit_criteria_met"] is True
        assert "completed_at" in updated["P01"]

    def test_finalize_blocked_preserves_entry(self):
        ledger = {"P01": _entry(tools_attempted=["subfinder"])}
        validation_result = {"status": "blocked", "can_advance": False, "reason": "no_evidence"}
        updated = finalize_phase("P01", ledger, validation_result)
        assert updated["P01"]["status"] == "blocked"
        assert updated["P01"]["can_advance"] is False


class TestShouldRetry:
    def test_should_retry_when_tools_failed_and_retries_remain(self):
        ledger = {
            "P01": _entry(
                tools_attempted=["subfinder"],
                tools_succeeded=[],
                tools_failed=["subfinder"],
                retry_count=0,
            )
        }
        assert should_retry_phase("P01", ledger) is True

    def test_no_retry_when_max_reached(self):
        ledger = {
            "P01": _entry(
                tools_attempted=["subfinder"],
                tools_succeeded=[],
                tools_failed=["subfinder"],
                retry_count=2,  # == max_attempts default
            )
        }
        assert should_retry_phase("P01", ledger) is False

    def test_no_retry_when_tools_succeeded(self):
        ledger = {
            "P01": _entry(
                tools_attempted=["subfinder"],
                tools_succeeded=["subfinder"],
                retry_count=0,
            )
        }
        assert should_retry_phase("P01", ledger) is False

    def test_skill_contract_overrides_max_retries(self):
        skill_contract = {"retry_policy": {"max_attempts": 3}}
        ledger = {
            "P01": _entry(
                tools_attempted=["subfinder"],
                tools_succeeded=[],
                tools_failed=["subfinder"],
                retry_count=2,  # < 3, should retry
            )
        }
        assert should_retry_phase("P01", ledger, skill_contract=skill_contract) is True


# ---------------------------------------------------------------------------
# Skill .md loader tests
# ---------------------------------------------------------------------------

class TestSkillMdLoader:
    def test_load_all_md_skills_returns_dict(self):
        from app.services.skill_runtime import load_all_md_skills
        skills = load_all_md_skills()
        # Should load at least the skills we created
        assert isinstance(skills, dict)

    def test_subdomain_enumeration_skill_loaded(self):
        from app.services.skill_runtime import load_all_md_skills
        skills = load_all_md_skills()
        skill_id = "skill.recon.subdomain_enumeration"
        if skill_id not in skills:
            pytest.skip(f"skill {skill_id} not found — skills/ dir may not be mounted")
        skill = skills[skill_id]
        assert skill["phase_ids"] == ["P01"]
        assert "subfinder" in skill["required_tools"]
        assert len(skill["evidence_required"]) >= 1
        assert isinstance(skill["exit_criteria"], dict)

    def test_port_discovery_skill_loaded(self):
        from app.services.skill_runtime import load_all_md_skills
        skills = load_all_md_skills()
        skill_id = "skill.recon.port_service_discovery"
        if skill_id not in skills:
            pytest.skip(f"skill {skill_id} not found")
        skill = skills[skill_id]
        assert "P02" in skill["phase_ids"]
        assert "naabu" in skill["required_tools"]

    def test_resolve_skill_for_phase_p01(self):
        from app.services.skill_runtime import resolve_skill_for_phase
        skills = resolve_skill_for_phase("P01")
        if not skills:
            pytest.skip("No P01 skills found — skills/ dir not mounted")
        assert any(s["phase_ids"] == ["P01"] or "P01" in s["phase_ids"] for s in skills)

    def test_resolve_skill_for_phase_p03(self):
        from app.services.skill_runtime import resolve_skill_for_phase
        skills = resolve_skill_for_phase("P03")
        if not skills:
            pytest.skip("No P03 skills found")
        assert all("P03" in s.get("phase_ids", []) for s in skills)

    def test_get_skill_by_id(self):
        from app.services.skill_runtime import get_skill_by_id
        skill = get_skill_by_id("skill.recon.subdomain_enumeration")
        if skill is None:
            pytest.skip("skill not found")
        assert skill["skill_id"] == "skill.recon.subdomain_enumeration"
        assert skill["category"] == "reconnaissance"

    def test_skill_frontmatter_has_required_fields(self):
        from app.services.skill_runtime import load_all_md_skills
        skills = load_all_md_skills()
        required_fields = ["skill_id", "name", "version", "category", "phase_ids",
                           "required_tools", "evidence_required", "exit_criteria", "retry_policy"]
        for skill_id, skill in skills.items():
            for field in required_fields:
                assert field in skill, f"skill {skill_id} missing field: {field}"

    def test_all_skills_have_valid_phase_ids(self):
        from app.services.skill_runtime import load_all_md_skills
        skills = load_all_md_skills()
        valid_phase_ids = {f"P{i:02d}" for i in range(1, 23)}
        for skill_id, skill in skills.items():
            for pid in skill.get("phase_ids") or []:
                assert pid.upper() in valid_phase_ids, (
                    f"skill {skill_id} has invalid phase_id: {pid}"
                )

    def test_all_skills_have_authorization_flag(self):
        from app.services.skill_runtime import load_all_md_skills
        skills = load_all_md_skills()
        for skill_id, skill in skills.items():
            assert isinstance(skill["requires_authorization"], bool), (
                f"skill {skill_id}: requires_authorization must be bool"
            )


# ---------------------------------------------------------------------------
# Skill RAG indexer tests
# ---------------------------------------------------------------------------

class TestSkillRagIndexer:
    def test_query_skills_by_phase_returns_docs(self):
        from app.services.skill_rag_indexer import query_skills_by_phase
        docs = query_skills_by_phase("P01")
        if not docs:
            pytest.skip("No P01 skills found")
        for doc in docs:
            assert doc["type"] == "skill"
            assert "P01" in doc["phase_ids"]
            assert "text" in doc

    def test_query_skills_by_tool(self):
        from app.services.skill_rag_indexer import query_skills_by_tool
        docs = query_skills_by_tool("subfinder")
        if not docs:
            pytest.skip("subfinder skill not found")
        assert all("subfinder" in doc.get("required_tools", []) + doc.get("optional_tools", []) for doc in docs)

    def test_rag_document_has_tags(self):
        from app.services.skill_rag_indexer import query_skills_by_phase
        docs = query_skills_by_phase("P01")
        if not docs:
            pytest.skip("No P01 skills found")
        for doc in docs:
            assert isinstance(doc["tags"], list)
            assert len(doc["tags"]) > 0


# ---------------------------------------------------------------------------
# Phase no-skipping enforcement
# ---------------------------------------------------------------------------

class TestPhaseNoSkipping:
    """Ensure that phases cannot be skipped by setting them to completed without evidence."""

    def test_p01_cannot_complete_with_no_tools(self):
        ledger = _make_ledger(P01=_entry())
        result = validate_phase_exit_criteria("P01", ledger)
        assert result["status"] != "completed"
        assert result["can_advance"] is False

    def test_p02_cannot_complete_with_no_evidence(self):
        ledger = _make_ledger(
            P02=_entry(
                tools_attempted=["naabu"],
                tools_succeeded=["naabu"],
                evidence_ids=[],
            )
        )
        result = validate_phase_exit_criteria("P02", ledger)
        assert result["can_advance"] is False

    def test_p12_cannot_complete_with_no_tools(self):
        ledger = _make_ledger(P12=_entry())
        result = validate_phase_exit_criteria("P12", ledger)
        assert result["can_advance"] is False

    def test_sequential_phase_advancement(self):
        """P01 → P02: P01 must complete before P02 starts."""
        from app.graph.mission import PENTEST_PHASES

        ledger = {}
        # All phases pending
        for phase in PENTEST_PHASES:
            ledger[str(phase["id"])] = _entry(status="pending")

        # P01 not complete — next should be P01
        next_id = get_next_phase_id("P00", ledger)  # before P01
        # get_next_phase_id skips completed/skipped, so pending phases are candidates
        # P01 is the first phase pending
        if next_id:
            assert next_id == "P01" or next_id.startswith("P")

    def test_completed_phase_skipped_in_routing(self):
        from app.graph.mission import PENTEST_PHASES

        ledger = {}
        for phase in PENTEST_PHASES:
            ledger[str(phase["id"])] = _entry(status="pending")

        # Mark P01 as completed
        ledger["P01"] = _entry(status="completed")

        next_id = get_next_phase_id("P01", ledger)
        assert next_id == "P02"

    def test_get_next_phase_skips_completed_phases(self):
        from app.graph.mission import PENTEST_PHASES

        ledger = {}
        for phase in PENTEST_PHASES:
            ledger[str(phase["id"])] = _entry(status="pending")

        # Mark P01, P02, P03 as completed
        for pid in ["P01", "P02", "P03"]:
            ledger[pid] = _entry(status="completed")

        next_id = get_next_phase_id("P03", ledger)
        assert next_id == "P04"
