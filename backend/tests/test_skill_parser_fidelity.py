"""SKILL-001 regression tests.

skill_runtime.py's old hand-rolled frontmatter parser had no concept of
nested YAML mappings: a skill's `safety_rules:`/`exit_criteria:`/
`retry_policy:` sub-keys silently flattened onto the top-level metadata dict,
and several safety-relevant flags were dropped entirely rather than
copied into the loaded skill object. This asserts real nested-mapping
fidelity against the actual skill file that declares all 6 safety_rules
sub-keys, not a synthetic fixture.
"""
from __future__ import annotations

from app.services import skill_runtime

# skill_runtime._SKILLS_ROOT already resolves the host-vs-container layout
# difference (repo/skills on a dev host, /app/skills bind-mounted in the
# backend container) — reuse it rather than re-deriving the path here.
_RBAC_SKILL_PATH = skill_runtime._SKILLS_ROOT / "vulnerability_testing" / "rbac_role_self_escalation.md"


def test_rbac_skill_file_exists_with_all_six_safety_rules_subkeys():
    # Guards the fixture itself against silent drift before trusting the
    # assertions below.
    assert _RBAC_SKILL_PATH.is_file()
    text = _RBAC_SKILL_PATH.read_text(encoding="utf-8")
    for key in (
        "destructive_payloads_allowed",
        "self_revert_mutation_allowed",
        "weak_secret_guessing_allowed",
        "scope_guard_required",
        "authenticated_testing_requires_authorized_session",
        "no_pii_exfiltration",
    ):
        assert f"{key}:" in text


def test_load_skill_file_preserves_nested_safety_rules_mapping():
    skill = skill_runtime._load_skill_file(_RBAC_SKILL_PATH)
    assert skill is not None
    assert skill["skill_id"] == "skill.vuln.rbac_role_self_escalation"

    safety_rules = skill["safety_rules"]
    assert isinstance(safety_rules, dict)
    assert safety_rules == {
        "destructive_payloads_allowed": False,
        "self_revert_mutation_allowed": True,
        "weak_secret_guessing_allowed": True,
        "scope_guard_required": True,
        "authenticated_testing_requires_authorized_session": True,
        "no_pii_exfiltration": True,
    }


def test_load_skill_file_exposes_all_six_flat_safety_flags_not_just_three():
    skill = skill_runtime._load_skill_file(_RBAC_SKILL_PATH)
    assert skill is not None

    # Previously wired (these already worked via parser-flattening leakage).
    assert skill["destructive_payloads_allowed"] is False
    assert skill["self_revert_mutation_allowed"] is True
    assert skill["weak_secret_guessing_allowed"] is True

    # Previously silently dropped entirely — not even reachable as a flat
    # top-level field, let alone nested.
    assert skill["scope_guard_required"] is True
    assert skill["authenticated_testing_requires_authorized_session"] is True
    assert skill["no_pii_exfiltration"] is True


def test_load_skill_file_preserves_nested_exit_criteria_and_retry_policy():
    skill = skill_runtime._load_skill_file(_RBAC_SKILL_PATH)
    assert skill is not None

    assert skill["exit_criteria"] == {
        "minimum_tools_attempted": 1,
        "minimum_evidence_items": 3,
        "validator_required": True,
    }
    assert skill["retry_policy"] == {
        "max_attempts": 2,
        "change_identifier_on_retry": False,
        "require_fresh_baseline_on_retry": True,
    }


def test_load_skill_file_still_loads_scalar_and_list_frontmatter_fields():
    skill = skill_runtime._load_skill_file(_RBAC_SKILL_PATH)
    assert skill is not None

    assert skill["category"] == "vulnerability_testing"
    assert skill["risk_level"] == "critical"
    assert skill["noise_level"] == "low"
    assert set(skill["phase_ids"]) == {"P16", "P19", "P14"}
    assert skill["required_tools"] == ["curl"]
    assert "bola_probe" in skill["optional_tools"]
    assert "role_enumeration_response" in skill["evidence_required"]
