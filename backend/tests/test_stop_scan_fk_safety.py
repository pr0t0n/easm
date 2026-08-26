"""Regression test: /scans/{id}/stop must not violate any of the 9 FKs that
point at findings.id (none of them has an ON DELETE clause) when a stopped
scan has findings that already produced dependent rows in those tables.

stop_scan bulk-deletes Finding rows for the scan; before doing so it must:
  - null out finding_id on the 5 tables where that column is nullable
    (Vulnerability, EvidenceArtifact, ValidationRun, CoverageItem, BasJob) --
    the row survives, it just stops pointing at the removed finding, mirroring
    the pattern delete_scan already used for Vulnerability;
  - delete the row outright on the 4 tables where finding_id is NOT NULL
    (FindingAdjudication, ValidationWire, FindingIntelligenceSnapshot,
    RetestRun) -- those rows are meaningless once their finding is gone.

Discovered live: a real /stop call 500'd with
psycopg2.errors.ForeignKeyViolation on coverage_items_finding_id_fkey --
the original Marco 1 fix only handled Vulnerability.
"""
from types import SimpleNamespace

from app.api import routes_scans
from app.models.models import (
    BasJob,
    CoverageItem,
    EvidenceArtifact,
    Finding,
    FindingAdjudication,
    FindingIntelligenceSnapshot,
    RetestRun,
    ValidationRun,
    ValidationWire,
    Vulnerability,
)

NULLABLE_MODELS = (Vulnerability, EvidenceArtifact, ValidationRun, CoverageItem, BasJob)
DELETE_MODELS = (FindingAdjudication, ValidationWire, FindingIntelligenceSnapshot, RetestRun)


class _FindingIdQuery:
    """query(Finding.id).filter(...).all() -> [(id,), ...]"""

    def __init__(self, finding_ids):
        self._finding_ids = finding_ids

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return [(fid,) for fid in self._finding_ids]


class _UpdateQuery:
    def __init__(self, recorder, label):
        self._recorder = recorder
        self._label = label

    def filter(self, *args, **kwargs):
        return self

    def update(self, values, synchronize_session=False):
        self._recorder.append((f"{self._label}_update", dict(values)))
        return 1


class _DeleteQuery:
    def __init__(self, recorder, label, count=1):
        self._recorder = recorder
        self._label = label
        self._count = count

    def filter(self, *args, **kwargs):
        return self

    def delete(self, synchronize_session=False):
        self._recorder.append((f"{self._label}_delete", None))
        return self._count


class _FakeDb:
    def __init__(self, finding_ids):
        self._finding_ids = finding_ids
        self.calls = []
        self.added = []
        self.committed = False

    def query(self, target):
        if target is Finding.id:
            return _FindingIdQuery(self._finding_ids)
        if target is Finding:
            return _DeleteQuery(self.calls, "finding", count=len(self._finding_ids))
        for model in NULLABLE_MODELS:
            if target is model:
                return _UpdateQuery(self.calls, model.__name__)
        for model in DELETE_MODELS:
            if target is model:
                return _DeleteQuery(self.calls, model.__name__)
        raise AssertionError(f"unexpected query target: {target}")

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.committed = True


def _patch_stop_scan_dependencies(monkeypatch, job):
    monkeypatch.setattr(
        routes_scans,
        "_authorized_scan_query",
        lambda db_, user: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: job)),
    )
    monkeypatch.setattr(routes_scans, "_active_scan_task_ids", lambda scan_id_, db_: ["task-1"])
    monkeypatch.setattr(routes_scans, "cancel_scan_jobs_in_kali_runner", lambda scan_id_, reason: {"cancelled": True})
    monkeypatch.setattr(routes_scans, "_clear_scan_worker_heartbeat", lambda db_, scan_id_: None)
    monkeypatch.setattr(routes_scans, "log_audit", lambda *a, **k: None)
    monkeypatch.setattr(
        routes_scans,
        "celery",
        SimpleNamespace(control=SimpleNamespace(revoke=lambda *a, **k: None)),
    )


def test_stop_scan_clears_all_nine_finding_fk_tables_before_deleting_findings(monkeypatch):
    scan_id = 42
    job = SimpleNamespace(
        id=scan_id, status="running", state_data={}, current_step="",
        next_retry_at=None, last_error=None,
    )
    db = _FakeDb(finding_ids=[101, 102])
    _patch_stop_scan_dependencies(monkeypatch, job)

    result = routes_scans.stop_scan(scan_id, db=db, current_user=SimpleNamespace(id=7))

    assert result["ok"] is True
    assert result["findings_deleted"] == 2

    call_names = [name for name, _ in db.calls]
    expected_updates = {f"{model.__name__}_update" for model in NULLABLE_MODELS}
    expected_deletes = {f"{model.__name__}_delete" for model in DELETE_MODELS}

    assert set(call_names) & expected_updates == expected_updates, call_names
    assert set(call_names) & expected_deletes == expected_deletes, call_names
    assert call_names[-1] == "finding_delete", (
        f"Finding bulk-delete must happen LAST, after every dependent table is cleared, got {call_names}"
    )

    for update_name, values in db.calls:
        if update_name.endswith("_update"):
            model = next(m for m in NULLABLE_MODELS if f"{m.__name__}_update" == update_name)
            assert values == {model.finding_id: None}

    assert db.committed is True


def test_stop_scan_skips_all_fk_cleanup_when_no_findings(monkeypatch):
    scan_id = 43
    job = SimpleNamespace(
        id=scan_id, status="running", state_data={}, current_step="",
        next_retry_at=None, last_error=None,
    )
    db = _FakeDb(finding_ids=[])
    _patch_stop_scan_dependencies(monkeypatch, job)

    result = routes_scans.stop_scan(scan_id, db=db, current_user=SimpleNamespace(id=7))

    assert result["findings_deleted"] == 0
    assert [name for name, _ in db.calls] == ["finding_delete"]
