from __future__ import annotations

from types import SimpleNamespace


class _Db:
    def add(self, *_args, **_kwargs):
        return None

    def flush(self):
        return None


def _artifact() -> SimpleNamespace:
    return SimpleNamespace(
        id=7,
        scan_job_id=3,
        target="https://app.example.test/base",
        baseline_request={"method": "GET", "url": "https://app.example.test/base"},
        exploit_request={"method": "GET", "url": "https://app.example.test/payload"},
        artifact_metadata={},
        payload="owned",
        tool_name="xss-validator",
    )


def test_replay_pair_confirms_only_after_stable_samples(monkeypatch) -> None:
    from app.services import artifact_store as store

    responses = iter([
        {"ok": True, "status_code": 200, "content_type": "text/html", "location": "", "body_len": 100, "json_keys": [], "body_preview": "base"},
        {"ok": True, "status_code": 200, "content_type": "text/html", "location": "", "body_len": 100, "json_keys": [], "body_preview": "base"},
        {"ok": True, "status_code": 200, "content_type": "text/html", "location": "", "body_len": 250, "json_keys": [], "body_preview": "owned"},
        {"ok": True, "status_code": 200, "content_type": "text/html", "location": "", "body_len": 250, "json_keys": [], "body_preview": "owned"},
    ])
    monkeypatch.setattr(store, "_execute_request", lambda *_args, **_kwargs: next(responses))
    monkeypatch.setattr(store, "write_artifact_file", lambda *_args, **_kwargs: "/tmp/replay.json")

    replay = store.replay_artifact_pair(_Db(), _artifact())

    assert replay["inconclusive"] is False
    assert replay["confirmed"] is True


def test_replay_pair_marks_unstable_samples_inconclusive(monkeypatch) -> None:
    from app.services import artifact_store as store

    responses = iter([
        {"ok": True, "status_code": 200, "content_type": "text/html", "location": "", "body_len": 100, "json_keys": [], "body_preview": "base"},
        {"ok": True, "status_code": 503, "content_type": "text/html", "location": "", "body_len": 100, "json_keys": [], "body_preview": "waf"},
        {"ok": True, "status_code": 200, "content_type": "text/html", "location": "", "body_len": 250, "json_keys": [], "body_preview": "owned"},
        {"ok": True, "status_code": 200, "content_type": "text/html", "location": "", "body_len": 250, "json_keys": [], "body_preview": "owned"},
    ])
    monkeypatch.setattr(store, "_execute_request", lambda *_args, **_kwargs: next(responses))
    monkeypatch.setattr(store, "write_artifact_file", lambda *_args, **_kwargs: "/tmp/replay.json")

    replay = store.replay_artifact_pair(_Db(), _artifact())

    assert replay["inconclusive"] is True
    assert replay["confirmed"] is False
    assert replay["baseline"]["unstable"] is True
