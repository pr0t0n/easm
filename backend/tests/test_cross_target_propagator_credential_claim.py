"""cross_target_propagator.py must never claim "credential stuffing" -- it
only seeds a GENERIC default-credentials probe on other targets, never the
literal leaked secret value. The old "credential_stuffing" label overclaimed
what actually runs; this locks the honest label in and checks the raw secret
text never ends up in anything persisted.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.cross_target_propagator import propagate_credential_findings


def test_propagation_never_claims_credential_stuffing_and_never_persists_the_raw_secret():
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None  # nothing already queued/persisted

    result = {
        "parsed_result": [
            {"Secret": "sk_live_super_secret_value_123", "RuleID": "generic-api-key", "Commit": "abc123"},
        ],
    }

    with patch(
        "app.services.cross_target_propagator._get_all_scan_targets",
        return_value=["auth.valid.com", "api.valid.com"],
    ), patch(
        "app.services.cross_target_propagator._get_auth_endpoints_for_scan",
        return_value=[("auth.valid.com", "https://auth.valid.com/login")],
    ):
        out = propagate_credential_findings(db, scan_id=1, source_target="repo.valid.com", tool_name="gitleaks", result=result)

    assert out["propagated"] >= 1

    persisted = [call.args[0] for call in db.add.call_args_list]
    work_items = [row for row in persisted if hasattr(row, "item_metadata")]
    findings = [row for row in persisted if hasattr(row, "details") and not hasattr(row, "item_metadata")]

    assert work_items, "expected a ScanWorkItem to be queued"
    for item in work_items:
        assert item.item_metadata.get("propagation_type") == "default_credential_probe"
        assert "credential_stuffing" not in str(item.item_metadata)
        assert "sk_live_super_secret_value_123" not in str(item.item_metadata)

    assert findings, "expected a leak-detected Finding to be persisted"
    for finding in findings:
        assert finding.details.get("propagation_type") == "default_credential_probe"
        assert "credential_stuffing" not in str(finding.details)
        assert "sk_live_super_secret_value_123" not in str(finding.details)
        assert "sk_live_super_secret_value_123" not in finding.title
