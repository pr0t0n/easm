from __future__ import annotations

import hashlib
from types import SimpleNamespace


class _Db:
    def add(self, *_args, **_kwargs):
        return None

    def flush(self):
        return None


class _Response:
    status_code = 200
    text = '{"required":true}'
    headers = {"content-type": "application/json"}


def test_api_skill_anonymous_retest_confirms_stable_public_access(monkeypatch):
    from app.services import retest_service

    body_hash = hashlib.sha256(_Response.text.encode("utf-8")).hexdigest()
    artifact = SimpleNamespace(
        id=10,
        scan_job_id=24,
        target="https://api.example.test/api/Exam/is-certificate-required-by-user-cpf",
        baseline_request={"method": "GET", "url": "https://api.example.test/api/Exam/is-certificate-required-by-user-cpf"},
        exploit_request={"method": "GET", "url": "https://api.example.test/api/Exam/is-certificate-required-by-user-cpf"},
        artifact_metadata={
            "api_skill_top20_anonymous_exposure": True,
            "expected_status_code": 200,
            "expected_body_sha256": body_hash,
        },
        validation_status="candidate",
    )
    finding = SimpleNamespace(url=artifact.target)
    monkeypatch.setattr(retest_service.requests, "request", lambda *_args, **_kwargs: _Response())

    replay = retest_service._run_api_skill_anonymous_retest(_Db(), artifact, finding)

    assert replay["ok"] is True
    assert replay["confirmed"] is True
    assert replay["anonymous_access_still_observable"] is True
    assert artifact.validation_status == "confirmed"
