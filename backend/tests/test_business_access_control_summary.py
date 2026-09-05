from types import SimpleNamespace

from app.models.models import EvidenceArtifact
from app.services.evidence_contract_service import evaluate_finding_promotion
from app.services.findings_extractor import _persist_finding_evidence_artifact
from app.services.pentest_report_builder import _business_access_control_summary


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def order_by(self, *_args, **_kwargs):
        return self

    def all(self):
        return self.rows


class _Db:
    def __init__(self, findings, artifacts):
        self.calls = 0
        self.findings = findings
        self.artifacts = artifacts

    def query(self, *_args, **_kwargs):
        self.calls += 1
        return _Query(self.findings if self.calls == 1 else self.artifacts)


class _ArtifactDb:
    def __init__(self):
        self.rows = {EvidenceArtifact: []}
        self.next_id = 1

    def query(self, model):
        return _Query(self.rows.get(model, []))

    def add(self, row):
        bucket = self.rows.get(type(row))
        if bucket is not None and row not in bucket:
            bucket.append(row)

    def flush(self):
        for rows in self.rows.values():
            for row in rows:
                if getattr(row, "id", None) is None:
                    row.id = self.next_id
                    self.next_id += 1


def test_business_access_control_summary_lists_bac_200_endpoints() -> None:
    finding = SimpleNamespace(
        id=10,
        scan_job_id=7,
        title="Broken Access Control confirmado",
        severity="high",
        verification_status="confirmed",
        url="https://api.example.test/orders/42",
        details={
            "finding_class": "bac_200_cross_identity",
            "method": "GET",
            "primary_identity_key": "user_a",
            "secondary_identity_key": "user_b",
            "primary_status_code": 200,
            "secondary_status_code": 200,
            "object_attribution": "observed_per_identity",
            "evidence": "GET https://api.example.test/orders/42 returned HTTP 200 for both identities.",
        },
    )
    artifact = SimpleNamespace(
        id=99,
        finding_id=10,
        artifact_type="tool_result",
        validation_status="confirmed",
        workspace_path="/tmp/easm-evidence/scan-7/proof-pack.json",
    )
    summary = _business_access_control_summary(_Db([finding], [artifact]), SimpleNamespace(id=7))

    assert summary["visible"] is True
    assert summary["total"] == 1
    assert summary["confirmed"] == 1
    assert summary["returning_200"] == 1
    assert summary["endpoints"][0]["endpoint"] == "https://api.example.test/orders/42"
    assert summary["endpoints"][0]["secondary_status_code"] == 200
    assert summary["endpoints"][0]["evidence_artifacts"][0]["id"] == 99


def test_bac_200_persisted_artifact_satisfies_promotion_contract() -> None:
    db = _ArtifactDb()
    details = {
        "finding_class": "bac_200_cross_identity",
        "vuln_family": "broken_access_control",
        "verification_status": "confirmed",
        "method": "GET",
        "endpoint": "https://api.example.test/orders/42",
        "url": "https://api.example.test/orders/42",
        "primary_identity_key": "user_a",
        "secondary_identity_key": "user_b",
        "primary_status_code": 200,
        "secondary_status_code": 200,
        "body_fingerprint": "sha256:abc",
        "false_positive_controls_passed": True,
        "validation_contract_satisfied": True,
        "evidence": "A/B authorization bypass returned 200 for user_b.",
    }
    finding = SimpleNamespace(
        id=10,
        title="Broken Access Control confirmado",
        severity="high",
        verification_status="confirmed",
        tool="bl-test",
        cve=None,
        url="https://api.example.test/orders/42",
        domain="api.example.test",
        details=dict(details),
    )
    source_item = SimpleNamespace(
        phase_id="P17",
        result={"status": "done", "command": "bl-test", "evidence_path": "/tmp/proof.txt"},
        item_metadata={},
    )

    _persist_finding_evidence_artifact(
        db,
        SimpleNamespace(id=7),
        finding,
        details=details,
        tool_col="bl-test",
        domain_col="api.example.test",
        finding_url="https://api.example.test/orders/42",
        source_item=source_item,
        raw_stdout="https://api.example.test/orders/42",
    )

    artifact = db.rows[EvidenceArtifact][0]
    decision = evaluate_finding_promotion(db, finding)

    assert artifact.validation_status == "confirmed"
    assert artifact.identity_key == "user_a,user_b"
    assert artifact.baseline_request["identity_key"] == "user_a"
    assert artifact.exploit_request["identity_key"] == "user_b"
    assert artifact.artifact_metadata["negative_control"] is True
    assert artifact.artifact_metadata["false_positive_controls_passed"] is True
    assert decision.status == "confirmed"
    assert decision.missing_artifacts == []
