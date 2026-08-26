"""Regression test: /scans/{id}/stop must not violate the
findings -> vulnerabilities FK when a stopped scan has findings that already
produced Vulnerability rows (Vulnerability.finding_id has no ON DELETE clause).

stop_scan bulk-deletes Finding rows for the scan; before doing so it must
null out Vulnerability.finding_id for any vulnerability pointing at one of
those findings, mirroring the pattern already used by delete_scan.
"""
from types import SimpleNamespace

from app.api import routes_scans
from app.models.models import Finding, ScanLog, Vulnerability


class _FindingIdQuery:
    """query(Finding.id).filter(...).all() -> [(id,), ...]"""

    def __init__(self, finding_ids):
        self._finding_ids = finding_ids

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return [(fid,) for fid in self._finding_ids]


class _VulnerabilityUpdateQuery:
    def __init__(self, recorder):
        self._recorder = recorder

    def filter(self, *args, **kwargs):
        return self

    def update(self, values, synchronize_session=False):
        self._recorder.append(("vulnerability_update", dict(values)))
        return 1


class _FindingDeleteQuery:
    def __init__(self, recorder, count):
        self._recorder = recorder
        self._count = count

    def filter(self, *args, **kwargs):
        return self

    def delete(self, synchronize_session=False):
        self._recorder.append(("finding_delete", None))
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
        if target is Vulnerability:
            return _VulnerabilityUpdateQuery(self.calls)
        if target is Finding:
            return _FindingDeleteQuery(self.calls, len(self._finding_ids))
        raise AssertionError(f"unexpected query target: {target}")

    def add(self, row):
        self.added.append(row)

    def commit(self):
        self.committed = True


def test_stop_scan_nulls_vulnerability_fk_before_deleting_findings(monkeypatch):
    scan_id = 42
    job = SimpleNamespace(
        id=scan_id,
        status="running",
        state_data={},
        current_step="",
        next_retry_at=None,
        last_error=None,
    )
    db = _FakeDb(finding_ids=[101, 102])
    current_user = SimpleNamespace(id=7)

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

    result = routes_scans.stop_scan(scan_id, db=db, current_user=current_user)

    assert result["ok"] is True
    assert result["findings_deleted"] == 2

    call_order = [name for name, _ in db.calls]
    assert call_order == ["vulnerability_update", "finding_delete"], (
        "Vulnerability.finding_id must be nulled out BEFORE the Finding bulk-delete, "
        f"got order={call_order}"
    )
    vuln_update_values = db.calls[0][1]
    assert vuln_update_values == {Vulnerability.finding_id: None}
    assert db.committed is True


def test_stop_scan_skips_vulnerability_update_when_no_findings(monkeypatch):
    scan_id = 43
    job = SimpleNamespace(
        id=scan_id,
        status="running",
        state_data={},
        current_step="",
        next_retry_at=None,
        last_error=None,
    )
    db = _FakeDb(finding_ids=[])
    current_user = SimpleNamespace(id=7)

    monkeypatch.setattr(
        routes_scans,
        "_authorized_scan_query",
        lambda db_, user: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: job)),
    )
    monkeypatch.setattr(routes_scans, "_active_scan_task_ids", lambda scan_id_, db_: [])
    monkeypatch.setattr(routes_scans, "cancel_scan_jobs_in_kali_runner", lambda scan_id_, reason: {"cancelled": True})
    monkeypatch.setattr(routes_scans, "_clear_scan_worker_heartbeat", lambda db_, scan_id_: None)
    monkeypatch.setattr(routes_scans, "log_audit", lambda *a, **k: None)
    monkeypatch.setattr(
        routes_scans,
        "celery",
        SimpleNamespace(control=SimpleNamespace(revoke=lambda *a, **k: None)),
    )

    result = routes_scans.stop_scan(scan_id, db=db, current_user=current_user)

    assert result["findings_deleted"] == 0
    call_order = [name for name, _ in db.calls]
    assert call_order == ["finding_delete"]
