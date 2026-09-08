from __future__ import annotations

from types import SimpleNamespace


class _Db:
    def add(self, *_args, **_kwargs):
        return None

    def flush(self):
        return None

    def query(self, *_args, **_kwargs):
        return self

    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        return SimpleNamespace(target_query="app.example.test")


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


def test_expire_retained_artifact_payloads_scrubs_expired_payload(tmp_path):
    from datetime import datetime, timedelta

    from app.services import artifact_store as store

    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text("sensitive", encoding="utf-8")
    artifact = SimpleNamespace(
        id=1,
        baseline_request={"method": "GET"},
        exploit_request={"method": "GET"},
        baseline_response_ref=str(artifact_path),
        exploit_response_ref=str(artifact_path),
        payload="body",
        diff_summary="diff",
        workspace_path=str(artifact_path),
        artifact_metadata={
            "retention_policy": "delete_after_retest_or_expiry",
            "expires_at": (datetime.now() - timedelta(days=1)).isoformat(),
            "artifact_path": str(artifact_path),
        },
    )

    class _Query:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

        def all(self):
            return [artifact]

    class _RetentionDb:
        def query(self, *_args, **_kwargs):
            return _Query()

        def add(self, *_args, **_kwargs):
            return None

        def flush(self):
            return None

    expired = store.expire_retained_artifact_payloads(_RetentionDb())

    assert expired == 1
    assert artifact.workspace_path is None
    assert artifact.baseline_request == {}
    assert artifact.exploit_request == {}
    assert artifact_path.exists() is False
