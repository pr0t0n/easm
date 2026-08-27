"""Regression test: DELETE /api/bas/schedules/{id} must not violate the
bas_jobs -> findings FK (bas_jobs_finding_id_fkey) when the schedule has
already fired at least once. delete_schedule now purges everything the
schedule produced -- its BasJobs, the BAS findings those jobs raised, and
the shadow ScanJob rows -- so a deleted test stops showing up in the
dashboard/report/heatmap. BasJob rows must be deleted before the Finding
rows they reference (same FK order as delete_agent/delete_jobs).
"""
from types import SimpleNamespace

from app.api import routes_bas
from app.models.models import BasJob, BasSchedule, Finding, ScanJob


class _DeleteQuery:
    def __init__(self, recorder, name, rows=None):
        self._recorder = recorder
        self._name = name
        self._rows = rows

    def filter(self, *args, **kwargs):
        return self

    def distinct(self):
        return self

    def all(self):
        return self._rows or []

    def delete(self, synchronize_session=False):
        self._recorder.append(self._name)
        return len(self._rows or [])

    def update(self, values, synchronize_session=False):
        self._recorder.append(self._name)
        return len(self._rows or [])


class _FakeDb:
    """`_purge_bas_scan_jobs` also touches WorkerHeartbeat/Asset/etc. --
    those aren't relevant to the bas_jobs-before-findings ordering this test
    exists to check, so anything not explicitly named below falls through to
    a no-op stub instead of raising."""

    def __init__(self, schedule, jobs):
        self._schedule = schedule
        self._jobs = jobs
        self.calls = []
        self.deleted = []
        self.committed = False

    def query(self, target):
        if target is BasJob:
            return _DeleteQuery(self.calls, "bas_job_delete", self._jobs)
        if target is Finding:
            return _DeleteQuery(self.calls, "finding_delete")
        if target is ScanJob:
            return _DeleteQuery(self.calls, "scan_job_delete")
        if target is BasSchedule:
            return None  # apply_company_scope is monkeypatched to ignore this
        return _DeleteQuery(self.calls, f"other:{getattr(target, '__name__', target)}")

    def delete(self, obj):
        self.calls.append("schedule_delete")
        self.deleted.append(obj)

    def commit(self):
        self.committed = True


def test_delete_schedule_deletes_bas_jobs_and_findings_before_schedule(monkeypatch):
    schedule = SimpleNamespace(id=9)
    jobs = [SimpleNamespace(id=68, finding_id=1068, scan_job_id=2068), SimpleNamespace(id=69, finding_id=None, scan_job_id=2069)]
    db = _FakeDb(schedule, jobs)
    monkeypatch.setattr(
        routes_bas,
        "apply_company_scope",
        lambda query, user, model: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: schedule)),
    )

    routes_bas.delete_schedule(9, db=db, current_user=SimpleNamespace(id=1, is_admin=True))

    assert db.calls.index("bas_job_delete") < db.calls.index("finding_delete"), (
        "BasJob rows must be deleted BEFORE the Finding rows they reference "
        f"(bas_jobs.finding_id -> findings.id), got order={db.calls}"
    )
    assert "scan_job_delete" in db.calls
    assert db.calls[-1] == "schedule_delete", "schedule delete must come after cleaning up its dependents"
    assert db.deleted == [schedule]
    assert db.committed is True
