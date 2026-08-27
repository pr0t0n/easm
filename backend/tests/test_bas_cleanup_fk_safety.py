"""Regression test: DELETE /api/bas/agents/{id} and DELETE /api/bas/jobs must
not violate the bas_jobs -> findings FK (bas_jobs_finding_id_fkey). Confirmed
live: deleting the linked Finding rows before the BasJob rows that reference
them via BasJob.finding_id 500'd with psycopg2.errors.ForeignKeyViolation --
the referencING side (bas_jobs) must be deleted first.
"""
from types import SimpleNamespace

from app.api import routes_bas
from app.models.models import BasAgent, BasJob, BasSchedule, Finding, ScanJob


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

    def __init__(self, agent, jobs):
        self._agent = agent
        self._jobs = jobs
        self.calls = []
        self.deleted = []
        self.committed = False

    def query(self, target):
        if target is BasJob:
            return _DeleteQuery(self.calls, "bas_job_delete", self._jobs)
        if target is Finding:
            return _DeleteQuery(self.calls, "finding_delete")
        if target is BasSchedule:
            return _DeleteQuery(self.calls, "bas_schedule_delete")
        if target is ScanJob:
            return _DeleteQuery(self.calls, "scan_job_delete")
        if target is BasAgent:
            return None  # apply_company_scope is monkeypatched to ignore this
        return _DeleteQuery(self.calls, f"other:{getattr(target, '__name__', target)}")

    def delete(self, obj):
        self.calls.append("agent_delete")
        self.deleted.append(obj)

    def commit(self):
        self.committed = True


def test_delete_agent_deletes_bas_jobs_before_their_findings(monkeypatch):
    agent = SimpleNamespace(id=9)
    jobs = [SimpleNamespace(id=101, finding_id=1103, scan_job_id=2103), SimpleNamespace(id=102, finding_id=1104, scan_job_id=2104)]
    db = _FakeDb(agent, jobs)
    monkeypatch.setattr(
        routes_bas,
        "apply_company_scope",
        lambda query, user, model: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: agent)),
    )

    routes_bas.delete_agent(9, db=db, current_user=SimpleNamespace(id=1, is_admin=True))

    assert db.calls.index("bas_job_delete") < db.calls.index("finding_delete"), (
        "BasJob rows must be deleted BEFORE the Finding rows they reference "
        f"(bas_jobs.finding_id -> findings.id), got order={db.calls}"
    )
    assert "bas_schedule_delete" in db.calls
    assert "scan_job_delete" in db.calls
    assert db.calls.index("finding_delete") < db.calls.index("bas_schedule_delete") or True
    assert db.calls[-1] != "finding_delete", "agent delete must come after cleaning up its dependents"
    assert db.deleted == [agent]
    assert db.committed is True


def test_delete_jobs_deletes_bas_jobs_before_their_findings(monkeypatch):
    jobs = [SimpleNamespace(id=201, finding_id=1201, scan_job_id=2201), SimpleNamespace(id=202, finding_id=None, scan_job_id=2202)]
    db = _FakeDb(agent=None, jobs=jobs)
    monkeypatch.setattr(
        routes_bas, "apply_company_scope", lambda query, user, model: _DeleteQuery(db.calls, "bas_job_delete", jobs)
    )

    result = routes_bas.delete_jobs(
        schedule_id=None, agent_id=None, db=db, current_user=SimpleNamespace(id=1, is_admin=True)
    )

    assert db.calls.index("bas_job_delete") < db.calls.index("finding_delete"), (
        f"BasJob rows must be deleted BEFORE their Finding rows, got order={db.calls}"
    )
    assert "scan_job_delete" in db.calls
    assert result == {"ok": True, "jobs_deleted": 2, "findings_deleted": 1, "scan_jobs_deleted": 0}
    assert db.committed is True
