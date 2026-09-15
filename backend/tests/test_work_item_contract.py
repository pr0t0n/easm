import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.models.models import ScanWorkItem
from app.services.work_item_contract import (
    build_scan_work_item,
    normalize_scan_work_item_contracts,
)


def test_factory_normalizes_profile_and_separates_execution_target():
    item = build_scan_work_item(
        scan_job_id=4,
        phase_id="P21",
        target="https://example.test/path#easm-wire-12",
        tool_name="httpx",
        profile="httpx",
        resource_class="light",
        priority=10,
        status="queued",
        max_attempts=1,
        item_metadata={"source": "validation_wire"},
    )

    assert item.profile == "httpx_probe"
    assert item.item_metadata["execution_target"] == "https://example.test/path"
    assert item.item_metadata["work_item_contract"]["validation_depth"] == 1


def test_factory_rejects_recursive_validation_lineage():
    parent = build_scan_work_item(
        scan_job_id=4,
        phase_id="P21",
        target="https://example.test/path#easm-wire-12",
        tool_name="httpx",
        profile="httpx",
        resource_class="light",
        priority=10,
        status="completed",
        max_attempts=1,
        item_metadata={"source": "validation_wire"},
    )
    parent.id = 50

    with pytest.raises(ValueError, match="recursive_validation_lineage"):
        build_scan_work_item(
            parent_work_item=parent,
            derivation_kind="verification",
            scan_job_id=4,
            phase_id="P21",
            target="https://example.test/path",
            tool_name="nuclei",
            profile="",
            resource_class="medium",
            priority=9,
            status="queued",
            max_attempts=1,
            item_metadata={"source": "evidence_gate_stage2"},
        )


def test_dispatch_contract_invalidates_legacy_recursive_validator():
    db = MagicMock()
    item = ScanWorkItem(
        scan_job_id=38,
        phase_id="P21",
        target="example.test#easm-wire-10",
        tool_name="nuclei",
        profile="nuclei",
        resource_class="medium",
        priority=10,
        status="failed",
        max_attempts=1,
        item_metadata={"source": "evidence_gate_stage2"},
    )
    item.id = 90
    item.result = {}
    db.query.return_value.filter.return_value.all.return_value = [item]

    result = normalize_scan_work_item_contracts(db, 38)

    assert result == {"normalized": 1, "invalidated": 1}
    assert item.status == "skipped"
    assert item.last_error == "invalidated:recursive_validation_lineage"
    assert item.profile == "nuclei_cves"


def test_scan_work_item_construction_is_centralized():
    services = Path(__file__).resolve().parents[1] / "app" / "services"
    violations = []
    for path in services.glob("*.py"):
        if path.name == "work_item_contract.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ScanWorkItem":
                violations.append(f"{path.name}:{node.lineno}")

    assert violations == []
