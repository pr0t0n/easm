from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import routes_management, routes_scans
from app.schemas.scan import ScanCreate


class _DbRejectAdd:
    def add(self, *_args, **_kwargs):
        raise AssertionError("unauthorized scan must not be persisted")

    def flush(self):
        raise AssertionError("unauthorized scan must not be flushed")


def test_create_scan_rejects_public_target_without_persisting(monkeypatch) -> None:
    monkeypatch.setattr(routes_scans, "_resolve_access_group_id", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        routes_scans,
        "evaluate_scan_authorization",
        lambda *_args, **_kwargs: {
            "approved": False,
            "mode": "blocked_missing_authorization",
            "reason": "public target requires explicit operator authorization attestation",
            "public_targets": ["api.example.com"],
            "authorized_scope": [],
        },
    )

    with pytest.raises(HTTPException) as exc:
        routes_scans.create_scan(
            ScanCreate(target_query="api.example.com", access_group_id=1),
            db=_DbRejectAdd(),
            current_user=SimpleNamespace(id=7),
        )

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "scan_authorization_required"
    assert exc.value.detail["public_targets"] == ["api.example.com"]


def test_scheduled_scan_rejects_public_target_without_persisting(monkeypatch) -> None:
    monkeypatch.setattr(routes_management, "_warm_skill_rag_for_scan", lambda: {"ok": True})
    monkeypatch.setattr(
        routes_management,
        "evaluate_scan_authorization",
        lambda *_args, **_kwargs: {
            "approved": False,
            "mode": "blocked_missing_authorization",
            "reason": "public target requires explicit operator authorization attestation",
            "public_targets": ["api.example.com"],
            "authorized_scope": [],
        },
    )

    with pytest.raises(HTTPException) as exc:
        routes_management._create_scan_from_schedule(
            _DbRejectAdd(),
            actor_user=SimpleNamespace(id=7),
            owner_id=7,
            target="api.example.com",
            authorization_code=None,
            access_group_id=1,
        )

    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "scan_authorization_required"
    assert exc.value.detail["public_targets"] == ["api.example.com"]
