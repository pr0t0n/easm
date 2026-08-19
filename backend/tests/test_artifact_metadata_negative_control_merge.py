"""create_request_response_artifact has two ways a caller can supply
negative-control data: the dedicated `negative_control=` kwarg, or (by
mistake) nesting it inside `metadata=`. The metadata merge used to always
win with `redact(negative_control or {})`, silently clobbering a caller's
own metadata["negative_control"] back to {} whenever they hadn't also used
the dedicated kwarg -- exactly what pentest_validators.validate_rce_hypothesis
did. evaluate_finding_promotion reads this exact key to gate "confirmed",
so the clobber silently stranded confirmed findings at "candidate" forever.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.artifact_store import create_request_response_artifact


def _db():
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    return db


def test_negative_control_supplied_only_inside_metadata_is_preserved():
    db = _db()
    scan = MagicMock(id=1)

    with patch("app.services.artifact_store.write_artifact_file", return_value="/tmp/a.json"):
        artifact = create_request_response_artifact(
            db, scan, target="https://x.test", tool_name="rce-proof-validator",
            validation_status="confirmed", confidence_score=98,
            metadata={"hypothesis_id": 1, "negative_control": True},
        )

    assert artifact.artifact_metadata["negative_control"] is True


def test_dedicated_kwarg_still_wins_over_a_conflicting_metadata_value():
    db = _db()
    scan = MagicMock(id=1)

    with patch("app.services.artifact_store.write_artifact_file", return_value="/tmp/a.json"):
        artifact = create_request_response_artifact(
            db, scan, target="https://x.test", tool_name="idor-validator",
            validation_status="confirmed", confidence_score=90,
            negative_control={"status_code": 403},
            metadata={"hypothesis_id": 1, "negative_control": False},
        )

    assert artifact.artifact_metadata["negative_control"] == {"status_code": 403}


def test_neither_supplied_defaults_to_empty():
    db = _db()
    scan = MagicMock(id=1)

    with patch("app.services.artifact_store.write_artifact_file", return_value="/tmp/a.json"):
        artifact = create_request_response_artifact(
            db, scan, target="https://x.test", tool_name="open-redirect-validator",
            validation_status="candidate", confidence_score=50,
        )

    assert artifact.artifact_metadata["negative_control"] == {}
