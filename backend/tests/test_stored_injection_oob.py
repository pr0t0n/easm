"""Tests for wiring the already-existing interactsh OOB client into a
stored-content write path (finding: HTML injection rendered in an internal
email template, invisible to any re-fetch-and-check tester).
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import app.services.business_logic_analyzer as business_logic_analyzer
from app.services.interactsh_callback import check_and_confirm_oob_findings

_discovered_input_surface_paths = business_logic_analyzer._discovered_input_surface_paths
_run_stored_html_injection_oob = business_logic_analyzer.test_stored_html_injection_oob


def _mock_resp(status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def test_stored_html_injection_oob_creates_finding_with_probe_slug() -> None:
    with (
        patch(
            "app.services.interactsh_callback.generate_oob_payload",
            return_value="http://f0-stored-abc123.correlation.oast.fun",
        ),
        patch("app.services.business_logic_analyzer._safe_post", return_value=_mock_resp(201)),
    ):
        findings = _run_stored_html_injection_oob(
            "https://api.example.com", "example.com", ["/api/host/support/tickets"],
        )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.test_type == "stored_html_injection_oob"
    assert finding.extra_details["oob_probe_slug"] == "f0-stored-abc123"
    assert finding.extra_details["needs_verification"] is True
    assert finding.extra_details["verification_status"] == "candidate"


def test_stored_html_injection_oob_skips_when_registration_fails() -> None:
    """generate_oob_payload falls back to a *.invalid URL when it can't
    reach an interactsh server -- nothing to correlate later, so no finding
    should be created (it could never be confirmed)."""
    with (
        patch(
            "app.services.interactsh_callback.generate_oob_payload",
            return_value="http://easm-oob-deadbeef.example.invalid",
        ),
        patch("app.services.business_logic_analyzer._safe_post") as mock_post,
    ):
        findings = _run_stored_html_injection_oob(
            "https://api.example.com", "example.com", ["/api/host/support/tickets"],
        )

    assert findings == []
    mock_post.assert_not_called()


def test_stored_html_injection_oob_skips_when_write_rejected() -> None:
    with (
        patch(
            "app.services.interactsh_callback.generate_oob_payload",
            return_value="http://f0-stored-abc123.correlation.oast.fun",
        ),
        patch("app.services.business_logic_analyzer._safe_post", return_value=_mock_resp(403)),
    ):
        findings = _run_stored_html_injection_oob(
            "https://api.example.com", "example.com", ["/api/host/support/tickets"],
        )
    assert findings == []


def test_stored_html_injection_oob_no_paths_no_findings() -> None:
    findings = _run_stored_html_injection_oob("https://api.example.com", "example.com", None)
    assert findings == []


def test_discovered_input_surface_paths_filters_by_keyword() -> None:
    rows = [
        ("https://api.example.com/api/host/support/tickets", "POST"),
        ("https://api.example.com/api/host/organizations/1/roles", "POST"),
        ("https://api.example.com/api/host/feedback", "POST"),
    ]
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = rows
    paths = _discovered_input_surface_paths(db, scan_id=1, domain="api.example.com")
    assert "/api/host/support/tickets" in paths
    assert "/api/host/feedback" in paths
    assert "/api/host/organizations/1/roles" not in paths


# ── check_and_confirm_oob_findings correlation ──────────────────────────────

def test_check_and_confirm_matches_by_legacy_finding_id_slug() -> None:
    fake_finding = SimpleNamespace(id=42, verification_status="candidate", details={})
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = fake_finding

    with patch(
        "app.services.interactsh_callback.poll_callbacks",
        return_value=[{"unique_id": "f42-ssrf-abc123", "protocol": "http"}],
    ):
        confirmed = check_and_confirm_oob_findings(db, scan_id=1)

    assert confirmed == 1
    assert fake_finding.verification_status == "confirmed"
    assert fake_finding.details["needs_verification"] is False


def test_check_and_confirm_falls_back_to_oob_probe_slug_match() -> None:
    """No finding exists at id=0 (legacy scheme would look up Finding.id==0
    and find nothing) -- must fall back to matching on the stored slug."""
    fake_finding = SimpleNamespace(id=99, verification_status="candidate", details={"oob_probe_slug": "f0-stored-abc123"})

    db = MagicMock()
    # First filter() call (legacy id-based) finds nothing; second (slug-based) finds it.
    id_lookup = MagicMock()
    id_lookup.first.return_value = None
    slug_lookup = MagicMock()
    slug_lookup.first.return_value = fake_finding
    db.query.return_value.filter.side_effect = [id_lookup, slug_lookup]

    with patch(
        "app.services.interactsh_callback.poll_callbacks",
        return_value=[{"unique_id": "f0-stored-abc123", "protocol": "http"}],
    ):
        confirmed = check_and_confirm_oob_findings(db, scan_id=1)

    assert confirmed == 1
    assert fake_finding.verification_status == "confirmed"


def test_check_and_confirm_no_callbacks_returns_zero() -> None:
    db = MagicMock()
    with patch("app.services.interactsh_callback.poll_callbacks", return_value=[]):
        assert check_and_confirm_oob_findings(db, scan_id=1) == 0
