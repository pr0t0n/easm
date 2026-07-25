def test_watchdog_stale_does_not_restart_worker_scope_with_active_scan(monkeypatch):
    from app.services import platform_health

    restarts = []

    monkeypatch.setattr(platform_health, "_watchdog_heartbeat_age", lambda: 999.0)
    monkeypatch.setattr(platform_health, "_worker_has_active_scan_task", lambda short: short == "worker_scope")
    monkeypatch.setattr(
        platform_health,
        "_restart_container",
        lambda short, reason: restarts.append((short, reason)) or {
            "container": short,
            "action": "restarted",
            "reason": reason,
        },
    )

    report = platform_health.run_platform_self_heal(db=None, source="test", force=True, docker_view={"source": "docker", "containers": []})

    assert ("celery_beat", "watchdog_stale(age=999.0)") in restarts
    assert all(short != "worker_scope" for short, _reason in restarts)
    assert {
        "container": "worker_scope",
        "action": "skip_active_scan_task",
        "reason": "watchdog_stale(age=999.0)",
    } in report["corrections"]


def test_watchdog_stale_restarts_worker_scope_when_no_scan_task(monkeypatch):
    from app.services import platform_health

    restarts = []

    monkeypatch.setattr(platform_health, "_watchdog_heartbeat_age", lambda: 999.0)
    monkeypatch.setattr(platform_health, "_worker_has_active_scan_task", lambda short: False)
    monkeypatch.setattr(
        platform_health,
        "_restart_container",
        lambda short, reason: restarts.append((short, reason)) or {
            "container": short,
            "action": "restarted",
            "reason": reason,
        },
    )

    platform_health.run_platform_self_heal(db=None, source="test", force=True, docker_view={"source": "docker", "containers": []})

    assert ("celery_beat", "watchdog_stale(age=999.0)") in restarts
    assert ("worker_scope", "watchdog_stale(age=999.0)") in restarts
