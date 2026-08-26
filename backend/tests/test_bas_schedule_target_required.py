"""BAS schedules with a blank target_hint used to save successfully and then
fail every single future firing: bas_scheduler._create_shadow_scan_job()
falls back to a synthetic "bas-unset-target-schedule-{id}" label (a
deliberate fail-closed placeholder, since kali_runner requires a real
authorized_scope), which kali_runner then rejects with a 400 Bad Request on
every dispatch -- with no signal at creation time that anything was wrong.
POST/PATCH /api/bas/schedules now reject a blank target_hint, EXCEPT when
every selected technique accepts_range -- those default to the dispatching
agent's own self-reported local_network_cidr at fire time instead (Marco
3.6: the operator shouldn't have to type an internal IP for a technique
whose whole point is testing a network segment).
"""
import pytest
from fastapi import HTTPException

from app.api import routes_bas


class _Payload:
    def __init__(self, target_hint):
        self.target_hint = target_hint


def test_create_schedule_rejects_blank_target_hint_with_no_techniques_selected():
    payload = routes_bas.ScheduleCreate(agent_id=1, target_hint="   ")

    with pytest.raises(HTTPException) as exc_info:
        routes_bas.create_schedule(payload, db=None, current_user=None)

    assert exc_info.value.status_code == 400
    assert "obrigat" in exc_info.value.detail.lower()


def test_create_schedule_rejects_blank_target_hint_when_any_technique_needs_one():
    payload = routes_bas.ScheduleCreate(
        agent_id=1, target_hint="",
        technique_keys=["port_service_scan", "owasp_web_app_scan"],  # 2nd one is app-specific
    )

    with pytest.raises(HTTPException) as exc_info:
        routes_bas.create_schedule(payload, db=None, current_user=None)

    assert exc_info.value.status_code == 400


def test_create_schedule_allows_blank_target_hint_when_every_technique_accepts_range():
    payload = routes_bas.ScheduleCreate(
        agent_id=1, target_hint="",
        technique_keys=["port_service_scan", "firewall_segmentation_test", "smb_enum_cme"],
    )

    # Should NOT raise before ever touching db/current_user (both None here).
    with pytest.raises(AttributeError):
        # Fails downstream on the DB-dependent lookups, NOT on the target
        # validation this test is actually about -- proves validation passed.
        routes_bas.create_schedule(payload, db=None, current_user=None)


def test_patch_schedule_rejects_blank_target_hint(monkeypatch):
    from types import SimpleNamespace

    class _FakeDb:
        def query(self, model):
            return None

    fake_schedule = SimpleNamespace(id=9, technique_keys=["owasp_web_app_scan"], chain_key=None)
    monkeypatch.setattr(
        routes_bas,
        "apply_company_scope",
        lambda query, user, model: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: fake_schedule)),
    )
    payload = routes_bas.SchedulePatch(target_hint="   ")

    with pytest.raises(HTTPException) as exc_info:
        routes_bas.patch_schedule(9, payload, db=_FakeDb(), current_user=None)

    assert exc_info.value.status_code == 400


def test_patch_schedule_allows_blank_target_hint_when_schedules_techniques_all_accept_range(monkeypatch):
    from types import SimpleNamespace

    class _FakeDb:
        def query(self, model):
            return None

    fake_schedule = SimpleNamespace(id=9, technique_keys=["port_service_scan", "smb_enum_cme"], chain_key=None)
    monkeypatch.setattr(
        routes_bas,
        "apply_company_scope",
        lambda query, user, model: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: fake_schedule)),
    )
    payload = routes_bas.SchedulePatch(target_hint="")

    # Should pass the target validation and fail later on db.commit() (None
    # query result has no .update/.commit) -- proves validation didn't raise.
    with pytest.raises(AttributeError):
        routes_bas.patch_schedule(9, payload, db=_FakeDb(), current_user=None)


def test_patch_schedule_allows_omitting_target_hint(monkeypatch):
    """target_hint=None (field simply not in the PATCH payload) must NOT be
    treated as blanking it out -- only an explicit empty/whitespace string
    is rejected."""
    from types import SimpleNamespace

    class _FakeDb:
        def query(self, model):
            return None

        def commit(self):
            pass

        def refresh(self, obj):
            pass

    fake_schedule = SimpleNamespace(
        id=9, name="x", enabled=True, target_hint="10.10.10.5", chain_key=None,
    )
    monkeypatch.setattr(
        routes_bas,
        "apply_company_scope",
        lambda query, user, model: SimpleNamespace(filter=lambda *a, **k: SimpleNamespace(first=lambda: fake_schedule)),
    )
    monkeypatch.setattr(
        routes_bas, "_schedule_to_dict", lambda schedule, db: {"id": schedule.id, "target_hint": schedule.target_hint}
    )
    payload = routes_bas.SchedulePatch(enabled=True)

    result = routes_bas.patch_schedule(9, payload, db=_FakeDb(), current_user=None)

    assert result["target_hint"] == "10.10.10.5"
