"""EVID-001 regression tests (finding_intelligence.py::analyze_business_risks).

Three of analyze_business_risks' Finding() sites derive findings purely from
subdomain-name keyword matching (no HTTP probe or other verification) --
"portainer" in a hostname triggers a "critical infra exposed" finding just
from the DNS label existing. These must be marked verification_status=
"candidate" (an unverified naming-convention signal), never left with no
status at all -- indistinguishable from a genuinely tool-confirmed finding.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch


def _db_returning_targets(targets):
    db = MagicMock()
    db.query.return_value.filter.return_value.distinct.return_value.all.return_value = [(t,) for t in targets]
    db.query.return_value.filter.return_value.first.return_value = None  # no existing dup
    return db


def test_infra_ops_keyword_finding_is_candidate_not_unmarked():
    from app.services.finding_intelligence import analyze_business_risks

    db = _db_returning_targets(["portainer.example.com"])
    created = analyze_business_risks(db, scan_id=1)

    assert created >= 1
    finding = db.add.call_args_list[0].args[0]
    assert finding.verification_status == "candidate"
    assert finding.confidence_score < 80  # was a flat 80 regardless of signal strength


def test_dev_environment_keyword_finding_is_candidate_not_unmarked():
    from app.services.finding_intelligence import analyze_business_risks

    db = _db_returning_targets(["dev-api.example.com", "staging.example.com"])
    created = analyze_business_risks(db, scan_id=1)

    dev_calls = [
        c.args[0] for c in db.add.call_args_list
        if getattr(c.args[0], "details", {}).get("business_risk") == "dev_environment_exposed"
    ]
    assert dev_calls, "expected a dev_environment_exposed finding for 2+ dev-pattern subdomains on the same root"
    assert dev_calls[0].verification_status == "candidate"
    assert dev_calls[0].confidence_score < 90  # was a flat 90 regardless of signal strength


def test_lgpd_finding_is_candidate_when_headers_and_keyword_both_present():
    """"payment" is a recognized sensitive-data keyword (_SENSITIVE_DATA_KEYWORDS).
    With no dev/infra keyword matches, this target triggers exactly 2 sequential
    .first() calls in the LGPD branch: (1) has_missing_headers -> truthy,
    (2) dedup exists-check -> falsy (no prior finding)."""
    from app.services.finding_intelligence import analyze_business_risks

    db = _db_returning_targets(["payment.example.com"])
    db.query.return_value.filter.return_value.first.side_effect = [MagicMock(), None]

    analyze_business_risks(db, scan_id=1)

    lgpd_calls = [
        c.args[0] for c in db.add.call_args_list
        if getattr(c.args[0], "details", {}).get("business_risk") == "lgpd_compliance_risk"
    ]
    assert lgpd_calls, "expected an lgpd_compliance_risk finding for a sensitive-data-keyword target with missing headers"
    assert lgpd_calls[0].verification_status == "candidate"
