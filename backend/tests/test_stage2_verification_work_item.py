from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services import findings_extractor


def source_item(**values):
    defaults = {
        "target": "https://example.test/source#easm-wire-10",
        "phase_id": "P09",
        "priority": 100,
        "item_metadata": {},
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def finding(**values):
    defaults = {
        "id": 9,
        "title": "Service detected",
        "domain": "example.test",
        "cve": None,
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def test_stage2_item_uses_canonical_profile_and_execution_url(monkeypatch):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.begin_nested.return_value = nullcontext()
    monkeypatch.setattr("app.services.scan_work_queue._tool_profile", lambda tool: f"profile-{tool}")

    findings_extractor._seed_verification_work_item(
        db,
        SimpleNamespace(id=3),
        source_item(),
        finding(),
        "nmap",
        "https://example.test/proof",
    )

    created = db.add.call_args.args[0]
    assert created.target == "https://example.test/proof"
    assert created.profile == "profile-nuclei"


def test_validator_result_does_not_spawn_recursive_stage2_item():
    db = MagicMock()

    findings_extractor._seed_verification_work_item(
        db,
        SimpleNamespace(id=3),
        source_item(item_metadata={"verifies_finding_id": 9}),
        finding(),
        "nuclei-exposure",
        "https://example.test/proof",
    )

    db.add.assert_not_called()
