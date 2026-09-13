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


def test_response_header_reference_does_not_require_query_parameter():
    wire = SimpleNamespace(
        id=20,
        finding_id=None,
        source_artifact_id=None,
        endpoint_id=None,
        target_ref="https://example.test/login",
        parameter_ref="x-frame-options",
        tool_name="nuclei-headers",
        input_bindings={"method": "GET"},
    )
    db = MagicMock()
    item = SimpleNamespace(
        id=21,
        scan_job_id=22,
        target="https://example.test/login#easm-wire-20",
        tool_name="nuclei-headers",
        item_metadata={"validation_wire_id": 20},
    )

    result = resolve_validation_execution_context(db, item, wire=wire)

    assert result["status"] == "resolved"
    assert result["execution_target"] == "https://example.test/login"
    assert result["parameter_ref"] == "x-frame-options"
    assert result["parameter_location"] == "response_header"
