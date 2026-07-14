from types import SimpleNamespace

from app.models.models import CoverageItem, EvidenceArtifact, ValidationRun
from app.services.exploitation_evidence import persist_p21_validation_record


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return list(self.rows)

    def first(self):
        return self.rows[0] if self.rows else None


class _FakeDb:
    def __init__(self):
        self.rows = {
            EvidenceArtifact: [],
            ValidationRun: [],
            CoverageItem: [],
        }
        self.next_id = 1

    def query(self, model):
        return _Query(self.rows.get(model, []))

    def add(self, row):
        bucket = self.rows[type(row)]
        if row not in bucket:
            bucket.append(row)

    def flush(self):
        for bucket in self.rows.values():
            for row in bucket:
                if getattr(row, "id", None) is None:
                    row.id = self.next_id
                    self.next_id += 1


def _scan():
    return SimpleNamespace(id=7, target_query="https://app.example.test")


def _finding():
    return SimpleNamespace(
        id=42,
        title="SQL Injection candidate",
        severity="high",
        url="https://app.example.test/search?q=1",
        domain="app.example.test",
        details={"payload": "' OR 1=1 --"},
    )


def _item(status="completed"):
    return SimpleNamespace(
        id=99,
        phase_id="P21",
        status=status,
        tool_name="sqlmap",
        target="https://app.example.test/search?q=1",
        item_metadata={"quality_gate_reason": "unit-test"},
        result={
            "command": "sqlmap -u https://app.example.test/search?q=1 --batch",
            "stdout_preview": "parameter q appears injectable",
            "return_code": 0,
        },
    )


def test_p21_validation_persists_artifact_validation_and_coverage():
    db = _FakeDb()

    record = persist_p21_validation_record(db, _scan(), _finding(), _item(), confirmed=True)

    assert record["status"] == "confirmed"
    assert len(db.rows[EvidenceArtifact]) == 1
    assert len(db.rows[ValidationRun]) == 1
    assert len(db.rows[CoverageItem]) == 1
    artifact = db.rows[EvidenceArtifact][0]
    validation = db.rows[ValidationRun][0]
    coverage = db.rows[CoverageItem][0]
    assert artifact.validation_status == "confirmed"
    assert artifact.artifact_type == "p21_validation"
    assert artifact.artifact_metadata["work_item_id"] == 99
    assert validation.result == "confirmed"
    assert validation.attempt_artifact_id == artifact.id
    assert coverage.status == "confirmed"
    assert coverage.coverage_metadata["validation_run_id"] == validation.id


def test_p21_validation_record_is_idempotent_for_same_work_item():
    db = _FakeDb()
    scan = _scan()
    finding = _finding()
    item = _item()

    first = persist_p21_validation_record(db, scan, finding, item, confirmed=True)
    second = persist_p21_validation_record(db, scan, finding, item, confirmed=True)

    assert second == first
    assert len(db.rows[EvidenceArtifact]) == 1
    assert len(db.rows[ValidationRun]) == 1
    assert len(db.rows[CoverageItem]) == 1


def test_p21_refutation_is_recorded_as_refuted():
    db = _FakeDb()

    record = persist_p21_validation_record(db, _scan(), _finding(), _item(status="failed"), confirmed=False)

    assert record["status"] == "refuted"
    assert db.rows[EvidenceArtifact][0].validation_status == "refuted"
    assert db.rows[ValidationRun][0].result == "refuted"
    assert db.rows[CoverageItem][0].status == "refuted"
