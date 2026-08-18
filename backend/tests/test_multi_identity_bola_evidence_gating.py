"""EVID-001 regression test (multi_identity_tester.py).

test_bola()'s only signal is exact response-body equality between two
identities -- it never checks any real ownership marker, so a PUBLIC
endpoint any authenticated user can read triggers the exact same condition
as a real BOLA. Findings from this signal must be "candidate" (needs
re-test/human review), never hardcoded "confirmed" with a fixed high
confidence score regardless of what was actually observed.
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def test_bola_finding_dict_is_candidate_not_confirmed():
    from app.services.multi_identity_tester import MultiIdentityTester, BOLA_TEST_PATHS

    tester = MultiIdentityTester("https://example.com", timeout=10)

    with patch.object(tester, "_detect_auth_endpoint", return_value="/api/login"), \
         patch.object(tester, "_detect_register_endpoint", return_value="/api/register"), \
         patch.object(tester, "_register_user", return_value=None), \
         patch.object(tester, "_login", side_effect=["token-a", "token-b"]), \
         patch.object(tester, "_get_resource", return_value=(200, "same-body")):
        findings = tester.test_bola()

    assert findings, "expected at least one candidate finding from the mocked equal-body responses"
    for f in findings:
        assert f["verification_status"] == "candidate"


def test_run_multi_identity_test_persists_candidate_with_lower_confidence():
    from app.services.multi_identity_tester import run_multi_identity_test

    job = SimpleNamespace(id=7)
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = [MagicMock()]  # http_items present

    fake_result = {
        "base_url": "https://example.com",
        "bola_findings": [{
            "title": "BOLA: User B can access User A's resource at /api/x/1",
            "severity": "high",
            "verification_status": "candidate",
            "evidence": {"path": "/api/x/1"},
            "risk_score": 8,
            "url": "https://example.com/api/x/1",
        }],
        "total_findings": 1,
    }

    with patch("app.services.multi_identity_tester.MultiIdentityTester") as mock_cls:
        mock_cls.return_value.run.return_value = fake_result
        result = run_multi_identity_test(db, job, "example.com")

    assert result["findings_created"] == 1
    created_finding = db.add.call_args_list[0].args[0]
    assert created_finding.verification_status == "candidate"
    assert created_finding.confidence_score == 55


def test_run_multi_identity_test_defaults_missing_status_to_candidate_not_confirmed():
    """Defense in depth: even if a future code path omits verification_status
    from the dict entirely, the Finding constructor must not silently upgrade
    it to "confirmed"."""
    from app.services.multi_identity_tester import run_multi_identity_test

    job = SimpleNamespace(id=7)
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = [MagicMock()]

    fake_result = {
        "base_url": "https://example.com",
        "bola_findings": [{
            "title": "BOLA: User B can access User A's resource at /api/x/1",
            "severity": "high",
            # verification_status intentionally omitted
            "evidence": {"path": "/api/x/1"},
            "risk_score": 8,
            "url": "https://example.com/api/x/1",
        }],
        "total_findings": 1,
    }

    with patch("app.services.multi_identity_tester.MultiIdentityTester") as mock_cls:
        mock_cls.return_value.run.return_value = fake_result
        run_multi_identity_test(db, job, "example.com")

    created_finding = db.add.call_args_list[0].args[0]
    assert created_finding.verification_status == "candidate"
