"""Regression test: DELETE /api/bas/schedules/{id} must not violate the
bas_jobs -> bas_schedules FK (no ON DELETE clause) when the schedule has
already fired at least once. Confirmed live: deleting schedule #9 500'd
with psycopg2.errors.ForeignKeyViolation on bas_jobs_schedule_id_fkey after
its jobs #68/#69 had run. delete_schedule now nulls BasJob.schedule_id for
that schedule's jobs (preserving them as historical dispatch records)
before deleting the schedule row itself.
"""
from types import SimpleNamespace

from app.api import routes_bas
from app.models.models import BasJob, BasSchedule


class _UpdateQuery:
    def __init__(self, recorder):
        self._recorder = recorder

    def filter(self, *args, **kwargs):
        return self

    def update(self, values, synchronize_session=False):
        self._recorder.append(("bas_job_update", dict(values)))
        return 2


class _FakeDb:
    def __init__(self, schedule):
        self._schedule = schedule
        self.calls = []
        self.deleted = []
        self.committed = False

    def query(self, target):
        if target is BasJob:
            return _UpdateQuery(self.calls)
        if target is BasSchedule:
            return None
        raise AssertionError(f"unexpected query target: {target}")

    def delete(self, obj):
        self.calls.append(("schedule_delete", None))
        self.deleted.append(obj)

    def commit(self):
        self.committed = True


def test_delete_schedule_nulls_bas_job_schedule_id_before_deleting(monkeypatch):
    schedule = SimpleNamespace(id=9)
    db = _FakeDb(schedule)
    monkeypatch.setattr(
        routes_bas,
        "apply_company_scope",
        lambda query, user, model: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: schedule)),
    )

    routes_bas.delete_schedule(9, db=db, current_user=SimpleNamespace(id=1, is_admin=True))

    call_names = [name for name, _ in db.calls]
    assert call_names == ["bas_job_update", "schedule_delete"], (
        "BasJob.schedule_id must be nulled BEFORE the schedule is deleted, "
        f"got order={call_names}"
    )
    assert db.calls[0][1] == {BasJob.schedule_id: None}
    assert db.deleted == [schedule]
    assert db.committed is True
