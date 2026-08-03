from types import SimpleNamespace

from app.models.models import CoverageItem, EvidenceArtifact, Finding
from app.services.evidence_contract_service import (
    _artifact_status_for_finding,
    _best_finding_match,
    apply_finding_validation,
)
from app.services.pentest_contracts import ValidationDecision


def _finding(fid: int, *, tool: str, host: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=fid,
        tool=tool,
        domain=host,
        url=f"https://{host}/",
        details={"tool": tool, "asset": host, "phase_id": "P13"},
    )


def test_multitarget_job_query_cannot_link_unrelated_artifact() -> None:
    artifact = SimpleNamespace(
        tool_name="bl-test",
        target="api.example.test",
        phase_id="P13",
        validation_status="candidate",
    )
    job = SimpleNamespace(target_query="api.example.test;other.example.test")

    assert _best_finding_match(
        artifact,
        [_finding(1, tool="shodan-cli", host="api.example.test")],
        job,
    ) is None


def test_ambiguous_host_level_artifact_remains_unlinked() -> None:
    artifact = SimpleNamespace(
        tool_name="nuclei",
        target="api.example.test",
        phase_id="P15",
        validation_status="candidate",
    )
    findings = [
        _finding(1, tool="nuclei", host="api.example.test"),
        _finding(2, tool="nuclei", host="api.example.test"),
    ]

    assert _best_finding_match(artifact, findings, SimpleNamespace(target_query="api.example.test")) is None


def test_unique_same_tool_same_target_artifact_can_link() -> None:
    artifact = SimpleNamespace(
        tool_name="nuclei",
        target="api.example.test",
        phase_id="P13",
        validation_status="candidate",
    )
    expected = _finding(1, tool="nuclei", host="api.example.test")

    assert _best_finding_match(
        artifact,
        [expected, _finding(2, tool="nuclei", host="other.example.test")],
        SimpleNamespace(target_query="api.example.test;other.example.test"),
    ) is expected


def test_confirmed_finding_does_not_promote_candidate_artifact() -> None:
    artifact = SimpleNamespace(validation_status="candidate")
    finding = SimpleNamespace(verification_status="confirmed", details={})

    assert _artifact_status_for_finding(artifact, finding) == "candidate"


def test_validation_decision_syncs_finding_details_and_coverage(monkeypatch) -> None:
    finding = SimpleNamespace(
        id=7,
        title="Possible auth bypass",
        severity="high",
        details={"verification_status": "confirmed"},
        verification_status="confirmed",
    )
    coverage = SimpleNamespace(
        status="confirmed",
        coverage_metadata={},
    )

    class Query:
        def filter(self, *args):
            return self

        def all(self):
            return [coverage]

    class Db:
        def __init__(self):
            self.added = []

        def query(self, model):
            assert model is CoverageItem
            return Query()

        def add(self, row):
            self.added.append(row)

    decision = ValidationDecision(
        status="candidate",
        can_promote=False,
        reason="missing_required_evidence",
        required_artifacts=["proof_pack"],
        missing_artifacts=["proof_pack"],
    )
    monkeypatch.setattr(
        "app.services.evidence_contract_service.evaluate_finding_promotion",
        lambda db, row: decision,
    )
    monkeypatch.setattr(
        "app.services.evidence_contract_service._sync_linked_vulnerability",
        lambda db, row: None,
    )

    apply_finding_validation(Db(), finding)

    assert finding.verification_status == "candidate"
    assert finding.details["verification_status"] == "candidate"
    assert coverage.status == "candidate"
    assert coverage.coverage_metadata["validation_decision"]["status"] == "candidate"
