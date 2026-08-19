"""VALID-001 regression tests.

rce-typed hypotheses previously always hit an unconditional
_record_skipped("operator_authorization_required_for_rce") in
validate_hypothesis, regardless of whether a real endpoint existed --
rce_proof.verify_rce (a bounded, read-only, guardrail-respecting active
proof) was only ever reachable via exploit_chain.py's chain-correlation
path, never as a primary per-hypothesis validator.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _hypothesis(hyp_id=1, target_ref="https://example.com/api/upload", metadata=None):
    return SimpleNamespace(
        id=hyp_id,
        hypothesis_type="rce",
        target_ref=target_ref,
        scan_job_id=7,
        hypothesis_metadata=metadata or {},
    )


def _endpoint(url="https://example.com/api/upload"):
    return SimpleNamespace(id=99, url=url, normalized_url=url)


def test_validate_hypothesis_dispatches_rce_type_to_rce_validator():
    from app.services.pentest_validators import validate_hypothesis

    db = MagicMock()
    scan = MagicMock()
    hyp = _hypothesis()

    with patch("app.services.pentest_validators.validate_rce_hypothesis", return_value={"result": "refuted"}) as mock_validate:
        result = validate_hypothesis(db, scan, hyp)

    mock_validate.assert_called_once_with(db, scan, hyp)
    assert result == {"result": "refuted"}


def test_rce_validator_skips_without_a_resolvable_endpoint():
    from app.services.pentest_validators import validate_rce_hypothesis

    db = MagicMock()
    scan = MagicMock()
    hyp = _hypothesis()

    with patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=None):
        result = validate_rce_hypothesis(db, scan, hyp)

    assert result["result"] == "skipped"
    assert result["reason"] == "endpoint_not_found"


def test_rce_validator_confirms_when_verify_rce_confirms():
    from app.services.pentest_validators import validate_rce_hypothesis

    db = MagicMock()
    scan = MagicMock()
    hyp = _hypothesis()
    endpoint = _endpoint()
    fake_proof = {
        "target": endpoint.url, "confirmed": True, "vector": "cmd-param:cmd",
        "command": "id", "evidence": "uid=0(root) gid=0(root)", "attempts": 3, "note": None,
    }
    fake_artifact = SimpleNamespace(id=555)

    with patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=endpoint), \
         patch("app.services.rce_proof.verify_rce", return_value=fake_proof) as mock_verify, \
         patch("app.services.pentest_validators.create_request_response_artifact", return_value=fake_artifact) as mock_artifact, \
         patch("app.services.pentest_validators.OffensiveInventoryService") as mock_inv_cls:
        mock_inv = mock_inv_cls.return_value
        result = validate_rce_hypothesis(db, scan, hyp)

    mock_verify.assert_called_once_with(endpoint.url, observed_parameter=None)
    assert result["result"] == "confirmed"
    assert result["artifact_id"] == 555
    assert "cmd-param:cmd" in result["reason"]

    mock_artifact.assert_called_once()
    assert mock_artifact.call_args.kwargs["validation_status"] == "confirmed"
    assert mock_artifact.call_args.kwargs["confidence_score"] == 98

    mock_inv.record_validation.assert_called_once()
    assert mock_inv.record_validation.call_args.kwargs["validator_name"] == "rce-proof-validator"
    assert mock_inv.record_validation.call_args.kwargs["result"] == "confirmed"
    assert mock_inv.record_validation.call_args.kwargs["baseline_artifact_id"] == 555

    mock_inv.upsert_coverage.assert_called_once()
    assert mock_inv.upsert_coverage.call_args.kwargs["test_class"] == "rce"
    assert mock_inv.upsert_coverage.call_args.kwargs["status"] == "confirmed"


def test_rce_validator_refutes_honestly_when_verify_rce_does_not_confirm():
    from app.services.pentest_validators import validate_rce_hypothesis

    db = MagicMock()
    scan = MagicMock()
    hyp = _hypothesis()
    endpoint = _endpoint()
    fake_proof = {
        "target": endpoint.url, "confirmed": False, "vector": None,
        "command": "id", "evidence": None, "attempts": 12,
        "note": "Nenhum comando executou em 12 tentativas — RCE NÃO comprovado (refutado).",
    }
    fake_artifact = SimpleNamespace(id=556)

    with patch("app.services.pentest_validators._endpoint_for_hypothesis", return_value=endpoint), \
         patch("app.services.rce_proof.verify_rce", return_value=fake_proof), \
         patch("app.services.pentest_validators.create_request_response_artifact", return_value=fake_artifact) as mock_artifact, \
         patch("app.services.pentest_validators.OffensiveInventoryService") as mock_inv_cls:
        mock_inv = mock_inv_cls.return_value
        result = validate_rce_hypothesis(db, scan, hyp)

    # No negative-control-backed disproof ran — 12 failed attempts is an
    # absence of proof, not proof of absence, so this stays inconclusive
    # rather than a dishonest "refuted".
    assert result["result"] == "inconclusive"
    assert mock_artifact.call_args.kwargs["validation_status"] == "inconclusive"
    assert mock_artifact.call_args.kwargs["confidence_score"] == 20
    assert mock_inv.record_validation.call_args.kwargs["result"] == "inconclusive"
