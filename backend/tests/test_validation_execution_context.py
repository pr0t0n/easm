from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services.validation_execution_context import resolve_validation_execution_context


def test_resolution_uses_exact_request_from_source_artifact():
    artifact = SimpleNamespace(
        id=6963,
        baseline_request={"method": "GET", "target": "http://example.test/Comments.aspx?id=2"},
        exploit_request={},
        created_at=None,
    )
    wire = SimpleNamespace(
        id=1241,
        finding_id=1856,
        source_artifact_id=6963,
        endpoint_id=None,
        target_ref="example.test",
        parameter_ref="id",
        input_bindings={"method": "GET"},
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = artifact
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
    item = SimpleNamespace(id=81831, scan_job_id=37, target="example.test#easm-wire-1241", item_metadata={"validation_wire_id": 1241})

    result = resolve_validation_execution_context(db, item, wire=wire)

    assert result["status"] == "resolved"
    assert result["execution_target"] == "http://example.test/Comments.aspx?id=2"
    assert result["method"] == "GET"
    assert result["parameter_ref"] == "id"
    assert result["source"] == "artifact:6963:baseline_request"


def test_resolution_blocks_mutating_request_without_body():
    artifact = SimpleNamespace(
        id=12,
        baseline_request={"method": "POST", "target": "https://example.test/update"},
        exploit_request={},
        created_at=None,
    )
    wire = SimpleNamespace(
        id=13,
        finding_id=14,
        source_artifact_id=12,
        endpoint_id=None,
        target_ref="example.test",
        parameter_ref=None,
        input_bindings={"method": "POST"},
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.side_effect = [artifact, None]
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
    item = SimpleNamespace(id=15, scan_job_id=16, target="example.test#easm-wire-13", item_metadata={"validation_wire_id": 13})

    result = resolve_validation_execution_context(db, item, wire=wire)

    assert result["status"] == "awaiting_evidence"
    assert result["reason"] == "required_evidence_absent:post_body"
