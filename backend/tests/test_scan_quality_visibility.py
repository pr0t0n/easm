from types import SimpleNamespace

from app.models.models import EvidenceArtifact, Finding, ValidationRun


def test_quality_state_persists_preflight_and_precondition_summaries() -> None:
    from app.services.scan_quality import _persist_quality_state

    added = []

    class Db:
        def add(self, row):
            added.append(row)

    job = SimpleNamespace(id=13, state_data={})
    state = {}
    gate = {"status": "completed_with_gaps", "last_score": 64.9}
    quality = {
        "score": 64.9,
        "grade": "C",
        "runtime_visibility": {"heavy": "omitted from snapshot"},
        "phase_monitor_issues": ["omitted from snapshot"],
        "preflight_summary": {"p02": {"complete_targets": 37}},
        "auth_precondition_summary": {"blocked": True, "reason": "missing_valid_identity_pair"},
        "business_logic_precondition_summary": {"blocked_endpoints": 4},
    }

    result = _persist_quality_state(Db(), job, state, quality, gate)

    assert result["quality_snapshot"]["score"] == 64.9
    assert result["quality_snapshot"]["quality_gate"] == gate
    assert "runtime_visibility" not in result["quality_snapshot"]
    assert "phase_monitor_issues" not in result["quality_snapshot"]
    assert result["preflight_summary"]["p02"]["complete_targets"] == 37
    assert result["auth_precondition_summary"]["reason"] == "missing_valid_identity_pair"
    assert result["business_logic_precondition_summary"]["blocked_endpoints"] == 4
    assert added == [job]


def test_auth_precondition_summary_explains_missing_identity_pair() -> None:
    from app.services.scan_quality import _build_auth_precondition_summary

    summary = _build_auth_precondition_summary(
        external_preconditions={
            "identity_pair_required": True,
            "valid_auth_sessions": 0,
            "auth_required_endpoints": 12,
            "jwt_required_items": 0,
        },
        components={
            "test_depth": {
                "endpoints_auth_classified": 3,
                "endpoints_auth_classifiable": 12,
                "endpoints_auth_unknown": 9,
            }
        },
    )

    assert summary["blocked"] is True
    assert summary["reason"] == "missing_valid_identity_pair"
    assert summary["evidence"]["valid_auth_sessions"] == 0
    assert summary["evidence"]["required_valid_sessions_for_horizontal_tests"] == 2
    assert "duas identidades" in summary["operator_message"]


def test_business_logic_precondition_summary_keeps_blocker_counts() -> None:
    from app.services.scan_quality import _build_business_logic_precondition_summary

    summary = _build_business_logic_precondition_summary({
        "relevant_endpoints": 8,
        "contracted_endpoints": 8,
        "high_risk_endpoints": 4,
        "ready_read_only": 4,
        "blocked_endpoints": 4,
        "blocked": {"missing_observed_parameter": 4},
        "execution_guardrails": {"object_id_guessing": False},
    })

    assert summary["blocked_endpoints"] == 4
    assert summary["blockers"] == {"missing_observed_parameter": 4}
    assert summary["guardrails"]["object_id_guessing"] is False


def test_explicit_inventory_excludes_deliberately_skipped_p01_from_quality() -> None:
    from app.services.scan_quality import _quality_scored_phase_ids

    phases = _quality_scored_phase_ids(SimpleNamespace(
        state_data={
            "scan_level": "aggressive",
            "explicit_target_inventory": True,
            "skip_p01_subdomain_enumeration": True,
        }
    ))

    assert "P01" not in phases
    assert "P02" in phases
    assert "P21" not in phases
    assert "P22" not in phases


def test_legacy_p21_audit_requires_validated_source_artifact() -> None:
    from app.services.scan_quality import _validation_has_independent_evidence

    validation = ValidationRun(
        id=20,
        scan_job_id=13,
        validator_name="quality-gate-audit",
        result="validated",
        run_metadata={"phase_id": "P21", "source_artifact_id": 5},
    )
    candidate = EvidenceArtifact(
        id=5,
        scan_job_id=13,
        validation_status="candidate",
    )
    validated = EvidenceArtifact(
        id=5,
        scan_job_id=13,
        validation_status="validated",
    )

    assert _validation_has_independent_evidence(validation, {5: candidate}) is False
    assert _validation_has_independent_evidence(validation, {5: validated}) is True


def test_non_p21_validator_is_not_subject_to_p21_source_contract() -> None:
    from app.services.scan_quality import _validation_has_independent_evidence

    validation = ValidationRun(
        id=21,
        scan_job_id=13,
        validator_name="read-only-validator",
        result="refuted",
        run_metadata={},
    )

    assert _validation_has_independent_evidence(validation, {}) is True


def test_legacy_rate_limited_refutation_does_not_improve_quality() -> None:
    from app.services.scan_quality import _validation_has_independent_evidence

    validation = ValidationRun(
        id=22,
        scan_job_id=13,
        validator_name="read-only-validator",
        result="refuted",
        reason="sensitive_file_refuted_status_429",
        run_metadata={},
    )

    assert _validation_has_independent_evidence(validation, {}) is False


def test_p21_audit_flushes_validation_id_before_coverage(monkeypatch) -> None:
    from app.services.scan_quality import _record_p21_evidence_audits

    source = EvidenceArtifact(
        id=5,
        scan_job_id=13,
        finding_id=7,
        validation_status="validated",
        confidence_score=80,
        baseline_request={"method": "GET"},
        exploit_request={"method": "GET"},
        reproduction_steps=["repeat request"],
    )
    finding = Finding(
        id=7,
        scan_job_id=13,
        title="Validated issue",
        severity="medium",
        risk_score=5,
        is_false_positive=False,
        verification_status="candidate",
        details={"asset": "api.example.test"},
        domain="api.example.test",
    )

    class Query:
        def __init__(self, rows):
            self.rows = rows

        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def limit(self, *args):
            return self

        def all(self):
            return list(self.rows)

    class Db:
        def __init__(self):
            self.added = []
            self.next_id = 100

        def query(self, model):
            if model is EvidenceArtifact:
                return Query([source])
            if model is Finding:
                return Query([finding])
            if model is ValidationRun:
                return Query([])
            return Query([])

        def add(self, row):
            self.added.append(row)

        def flush(self):
            for row in self.added:
                if getattr(row, "id", None) is None:
                    row.id = self.next_id
                    self.next_id += 1

    coverage_calls = []

    class Inventory:
        def __init__(self, db, job):
            pass

        def upsert_coverage(self, **kwargs):
            coverage_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.offensive_inventory_service.OffensiveInventoryService",
        Inventory,
    )
    db = Db()

    recorded = _record_p21_evidence_audits(
        db,
        SimpleNamespace(id=13, target_query="api.example.test"),
    )

    validation = next(row for row in db.added if isinstance(row, ValidationRun))
    assert recorded == 1
    assert validation.id is not None
    assert coverage_calls[0]["metadata"]["validation_run_id"] == validation.id


def test_p21_audit_ignores_candidate_tool_execution_artifact(monkeypatch) -> None:
    from app.services.scan_quality import _record_p21_evidence_audits

    class Query:
        def filter(self, *args):
            return self

        def all(self):
            return [SimpleNamespace(finding_id=7, validation_status="candidate")]

    class Db:
        def query(self, model):
            return Query()

    assert _record_p21_evidence_audits(
        Db(), SimpleNamespace(id=13, target_query="api.example.test")
    ) == 0
