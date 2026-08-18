from __future__ import annotations

from types import SimpleNamespace

from app.models.models import ValidationWire
from app.services.finding_adjudication import (
    classify_validation_wire_result,
    determine_cve_applicability,
    deterministic_verdict,
    estimate_cvss31_for_finding,
    link_existing_work_item_wire,
    validate_llm_proposal,
)
from app.services.poc_outcome import classify_poc_work_item


def _dossier(**overrides):
    value = {
        "finding": {"id": 42, "verification_status": "candidate", "family": "sqli"},
        "target": {"target_ref": "https://example.test/search?q=1", "in_scope": True},
        "context": {"details": {}, "available_identities": []},
        "evidence": [{"artifact_id": 7}],
        "quality": {
            "missing_artifacts": ["baseline_vs_exploit"],
            "contradictions": [],
            "deterministic_decision": {"status": "candidate", "can_promote": False},
        },
        "intelligence": {},
    }
    value.update(overrides)
    return value


def test_missing_information_is_inconclusive_never_false_positive():
    result = deterministic_verdict(_dossier())

    assert result["verdict"] == "inconclusive"
    assert result["reason_code"] == "missing_baseline_or_attempt"


def test_parser_or_truncated_artifact_is_invalid_evidence_not_refuted():
    dossier = _dossier(context={"details": {"stdout_truncated_for_parser": True}, "available_identities": []})

    result = deterministic_verdict(dossier)

    assert result["verdict"] == "invalid_evidence"
    assert result["reason_code"] == "parser_or_artifact_incomplete"


def test_out_of_scope_target_is_blocked_before_any_wire_can_execute():
    dossier = _dossier(target={"target_ref": "https://outside.test/", "in_scope": False})

    result = deterministic_verdict(dossier)

    assert result == {"verdict": "blocked", "reason_code": "scope_blocked", "confidence": 1.0}


def test_llm_cannot_replace_the_bound_target():
    proposal = {
        "proposed_verdict": "inconclusive",
        "confidence": 0.7,
        "supporting_evidence_ids": ["E-7"],
        "next_action": {
            "action_id": "run_family_validator",
            "target_ref": "https://attacker.invalid/",
            "input_bindings": {},
        },
    }

    assert validate_llm_proposal(proposal, _dossier()) == {}


def test_llm_can_only_reference_existing_evidence():
    proposal = {
        "proposed_verdict": "confirmed",
        "confidence": 0.99,
        "supporting_evidence_ids": ["E-999"],
        "next_action": None,
    }

    assert validate_llm_proposal(proposal, _dossier()) == {}


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.rows[0] if self.rows else None


class _WireDb:
    def __init__(self):
        self.wires = []
        self.added = []

    def query(self, model):
        return _Query(self.wires if model is ValidationWire else [])

    def add(self, row):
        self.added.append(row)
        if isinstance(row, ValidationWire) and row not in self.wires:
            self.wires.append(row)

    def flush(self):
        for index, row in enumerate(self.added, start=1):
            if getattr(row, "id", None) is None:
                row.id = index


def test_legacy_p21_item_is_wrapped_in_exact_persistent_wire():
    db = _WireDb()
    job = SimpleNamespace(id=9)
    finding = SimpleNamespace(
        id=42,
        details={"parameter": "q"},
        url="https://example.test/search?q=1",
        domain="example.test",
    )
    item = SimpleNamespace(
        id=81,
        tool_name="sqlmap",
        profile="sqlmap",
        attempts=0,
        max_attempts=2,
        item_metadata={
            "execution_target": "https://example.test/search?q=1",
            "target_parameter": "q",
        },
    )

    wire = link_existing_work_item_wire(db, job, finding, item)

    assert wire.finding_id == 42
    assert wire.work_item_id == 81
    assert wire.target_ref == "https://example.test/search?q=1"
    assert wire.parameter_ref == "q"
    assert wire.tool_name == "sqlmap"
    assert wire.input_bindings["source"] == "legacy_poc_validator"
    assert item.item_metadata["validation_wire_id"] == wire.id
    assert item.item_metadata["wire_re_evaluate_on_terminal"] is True


def test_existing_work_item_wire_is_idempotent():
    db = _WireDb()
    job = SimpleNamespace(id=9)
    finding = SimpleNamespace(id=42, details={}, url="https://example.test/", domain="example.test")
    item = SimpleNamespace(id=81, tool_name="nuclei", profile="nuclei", attempts=1, max_attempts=2, item_metadata={})

    first = link_existing_work_item_wire(db, job, finding, item)
    second = link_existing_work_item_wire(db, job, finding, item)

    assert second is first
    assert len(db.wires) == 1


def test_nvd_cpe_range_proves_cve_applicable_and_not_applicable():
    ranges = [{
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.4.49",
        "versionEndIncluding": "2.4.50",
    }]

    applicable = determine_cve_applicability(
        product="Apache HTTP Server", version="2.4.49", affected_ranges=ranges,
    )
    patched = determine_cve_applicability(
        product="Apache HTTP Server", version="2.4.51", affected_ranges=ranges,
    )

    assert applicable == ("applicable", "observed_version_matches_nvd_affected_range")
    assert patched == ("not_applicable", "observed_version_outside_nvd_affected_ranges")


def test_non_cve_confirmed_logic_flaw_gets_justified_cvss31_vector():
    finding = SimpleNamespace(
        title="IDOR cross-tenant object access",
        tool="bl-test",
        severity="high",
        details={"identity_key": "owner", "owasp_category": "A01 Broken Access Control"},
    )

    result = estimate_cvss31_for_finding(finding)

    assert result["vector"].startswith("CVSS:3.1/AV:N/AC:L/PR:L/")
    assert 0.1 <= result["score"] <= 10.0
    assert result["source"] == "deterministic_platform_estimate"


def test_structured_negative_control_is_explicit_refutation():
    item = SimpleNamespace(
        status="completed",
        tool_name="bl-test",
        result={"parsed_result": {"negative_control_passed": True, "vulnerable": False}},
    )

    result = classify_poc_work_item(item)

    assert result["result"] == "refuted"
    assert result["reason"] == "explicit_negative_signal:structured_negative_control_passed"


def test_nuclei_info_match_does_not_confirm_high_credential_exposure_claim():
    wire = SimpleNamespace(action_id="run_family_validator")
    finding = SimpleNamespace(
        title="Credential Exposure Boundary: OSINT harvest found public email addresses",
        tool="nuclei-exposure, theharvester, h8mail",
        severity="high",
        cve=None,
        details={},
    )
    item = SimpleNamespace(
        status="completed",
        tool_name="nuclei-exposure",
        result={
            "stdout_full": '"matched-at":"https://login.microsoftonline.com/example.test"',
            "parsed_result": [{
                "template-id": "azure-domain-tenant",
                "matched-at": "https://login.microsoftonline.com/example.test",
                "info": {
                    "name": "Microsoft Azure Domain Tenant ID - Detect",
                    "description": "Microsoft Azure Domain Tenant ID was detected.",
                    "tags": ["azure", "microsoft", "cloud", "exposure"],
                    "severity": "info",
                },
            }],
        },
    )

    result = classify_validation_wire_result(wire, item, finding)

    assert result["result"] == "refuted"
    assert result["negative_signal"] is True
    assert result["reason"] == "claim_mismatch:no_credential_or_secret_exposure_observed"
    assert result["generic_tool_outcome"]["result"] == "confirmed"
