from types import SimpleNamespace
from unittest.mock import MagicMock

from app.models.models import ObservedRequest
from app.services.request_execution_contract import adapt_execution_to_request_contract
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


def test_observed_request_corrects_derived_method_and_parameter_location():
    observed = SimpleNamespace(
        id=30,
        endpoint_id=31,
        method="POST",
        url="https://example.test/login",
        request_body={"body": "username=user&submit=Login"},
        request_content_type="application/x-www-form-urlencoded",
    )
    wire = SimpleNamespace(
        id=32,
        finding_id=None,
        source_artifact_id=None,
        endpoint_id=20,
        target_ref="https://example.test/login",
        parameter_ref="submit",
        tool_name="dalfox",
        input_bindings={"method": "GET", "parameter_location": "query", "endpoint_id": 20},
        updated_at=None,
    )

    class Query:
        def __init__(self, rows):
            self.rows = rows

        def filter(self, *args):
            return self

        def order_by(self, *args):
            return self

        def limit(self, value):
            return self

        def all(self):
            return self.rows

        def first(self):
            return self.rows[0] if self.rows else None

    db = MagicMock()
    db.query.side_effect = lambda model: Query(
        [observed] if model is ObservedRequest else []
    )
    item = SimpleNamespace(
        id=33,
        scan_job_id=34,
        target="https://example.test/login#easm-wire-32",
        tool_name="dalfox",
        item_metadata={"validation_wire_id": 32},
    )

    result = resolve_validation_execution_context(db, item, wire=wire)

    assert result["status"] == "resolved"
    assert result["method"] == "POST"
    assert result["parameter_location"] == "body"
    assert result["body"] == "username=user&submit=Login"
    assert result["source"] == "observed_request:30"
    assert wire.input_bindings["method"] == "POST"
    assert wire.input_bindings["parameter_location"] == "body"
    assert item.item_metadata["binding_corrections"][0]["source"] == "observed_request:30"


def test_request_contract_adapter_materializes_body_capability():
    execution = {
        "tool_name": "dalfox",
        "profile": "dalfox_xss",
        "arguments": {"scan_id": 4},
    }
    resolution = {
        "status": "resolved",
        "method": "POST",
        "parameter_location": "body",
        "parameter_ref": "submit",
        "body": "username=user&submit=Login",
        "content_type": "application/x-www-form-urlencoded",
        "source": "observed_request:30",
        "endpoint_id": 31,
    }

    catalog = {
        "plain_profile": {"tool": "validator", "command": ["validator", "{url}"]},
        "captured_request_profile": {
            "tool": "validator",
            "command": [
                "validator", "{url}", "--method", "{env_SCAN_HTTP_METHOD}",
                "--body", "{env_SCAN_FUZZ_POST_DATA}",
                "--content-type", "{env_SCAN_FUZZ_CONTENT_TYPE}",
            ],
            "command_executable_available": True,
        },
    }
    execution["tool_name"] = "validator"
    execution["profile"] = "plain_profile"

    result = adapt_execution_to_request_contract(execution, resolution, profile_catalog=catalog)

    assert result["compatible"] is True
    assert result["adapted"] is True
    assert result["execution"]["profile"] == "captured_request_profile"
    assert result["execution"]["arguments"]["env_vars"] == {
        "SCAN_HTTP_METHOD": "POST",
        "SCAN_FUZZ_POST_DATA": "username=user&submit=Login",
        "SCAN_FUZZ_CONTENT_TYPE": "application/x-www-form-urlencoded",
        "SCAN_FUZZ_PARAM": "submit",
    }


def test_request_contract_adapter_rejects_catalog_without_required_capability():
    execution = {
        "tool_name": "validator",
        "profile": "plain_profile",
        "arguments": {"scan_id": 4},
    }
    resolution = {
        "status": "resolved",
        "method": "POST",
        "parameter_location": "body",
        "body": "submit=Login",
    }

    result = adapt_execution_to_request_contract(
        execution,
        resolution,
        profile_catalog={"plain_profile": {"tool": "validator", "command": ["validator", "{url}"]}},
    )

    assert result["compatible"] is False
    assert result["reason"] == "capability_contract_degraded:request_body_unsupported"
