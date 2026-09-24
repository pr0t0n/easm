"""Regression test: DELETE /scans/{id} must not violate the NO ACTION FKs
that bas_jobs.scan_job_id and observed_requests.scan_job_id/endpoint_id hold
against scan_jobs/offensive_endpoints.

Both tables were added after delete_scan was written and never got the same
cleanup treatment reset_operational_scans already has for them -- the exact
same gap the code's own comment documents for endpoint_observations/
scan_execution_contexts/processor_checkpoints. Discovered live: scans #29/#34
each carry observed_requests rows, so a real DELETE call would 500 with
psycopg2.errors.ForeignKeyViolation once it reached OffensiveEndpoint (or the
final scan_jobs delete) without this fix.
"""
from types import SimpleNamespace

from app.api import routes_scans
from app.models.models import BasJob, ObservedRequest, OffensiveEndpoint


class _Query:
    def __init__(self, recorder, target):
        self._recorder = recorder
        self._target = target

    def filter(self, *args, **kwargs):
        return self

    def update(self, values, synchronize_session=False):
        name = getattr(self._target, "__name__", str(self._target))
        self._recorder.append((f"{name}_update", dict(values)))
        return 0

    def delete(self, synchronize_session=False):
        name = getattr(self._target, "__name__", str(self._target))
        self._recorder.append((f"{name}_delete", None))
        return 0

    def all(self):
        return []

    def first(self):
        return None


class _FakeDb:
    def __init__(self):
        self.calls = []
        self.added = []
        self.committed = False

    def query(self, target):
        return _Query(self.calls, target)

    def execute(self, *args, **kwargs):
        self.calls.append(("raw_execute", None))

    def add(self, row):
        self.added.append(row)

    def delete(self, obj):
        self.calls.append(("scan_job_delete", None))

    def commit(self):
        self.committed = True


def _patch_delete_scan_dependencies(monkeypatch, job):
    monkeypatch.setattr(
        routes_scans,
        "_authorized_scan_query",
        lambda db_, user: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: job)),
    )
    monkeypatch.setattr(routes_scans, "cancel_scan_jobs_in_kali_runner", lambda scan_id_, reason: {"cancelled": True})
    monkeypatch.setattr(routes_scans, "log_audit", lambda *a, **k: None)


def test_delete_scan_clears_bas_jobs_and_observed_requests_before_endpoints(monkeypatch):
    scan_id = 34
    job = SimpleNamespace(id=scan_id, status="failed", findings=[])
    db = _FakeDb()
    _patch_delete_scan_dependencies(monkeypatch, job)

    result = routes_scans.delete_scan(scan_id, db=db, current_user=SimpleNamespace(id=1))

    assert result["ok"] is True
    call_names = [name for name, _ in db.calls]

    assert f"{BasJob.__name__}_delete" in call_names, call_names
    assert f"{ObservedRequest.__name__}_delete" in call_names, call_names
    assert f"{OffensiveEndpoint.__name__}_delete" in call_names, call_names

    observed_idx = call_names.index(f"{ObservedRequest.__name__}_delete")
    endpoint_idx = call_names.index(f"{OffensiveEndpoint.__name__}_delete")
    assert observed_idx < endpoint_idx, (
        "ObservedRequest FKs to OffensiveEndpoint (NO ACTION) — must be deleted first, "
        f"got {call_names}"
    )
    assert call_names[-1] == "scan_job_delete", (
        f"scan_jobs row must be deleted last, after every dependent table is cleared, got {call_names}"
    )
    assert db.committed is True
