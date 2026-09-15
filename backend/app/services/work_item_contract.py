from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import ScanWorkItem
from app.services.kali_executor import profile_for_tool


CONTRACT_VERSION = "work-item-v2"
VALIDATION_SOURCES = {"evidence_gate_stage2", "validation_wire", "poc_validation"}


def canonical_work_item_profile(tool_name: str, profile: str | None = None) -> str:
    tool = str(tool_name or "").strip().lower()
    supplied = str(profile or "").strip()
    mapped = str(profile_for_tool(tool) or "").strip()
    if mapped and (not supplied or supplied.lower() == tool):
        return mapped
    return supplied or mapped or tool


def work_item_execution_target(target: str | None, metadata: dict[str, Any] | None = None) -> str:
    values = dict(metadata or {})
    explicit = str(values.get("execution_target") or "").strip()
    if explicit:
        return explicit.split("#easm-wire-", 1)[0]
    return str(target or "").strip().split("#easm-wire-", 1)[0]


def _lineage_contract(
    metadata: dict[str, Any],
    *,
    parent_work_item: ScanWorkItem | None,
    derivation_kind: str | None,
) -> dict[str, Any]:
    parent_metadata = dict(getattr(parent_work_item, "item_metadata", None) or {})
    parent_contract = dict(parent_metadata.get("work_item_contract") or {})
    current_contract = dict(metadata.get("work_item_contract") or {})
    base_contract = parent_contract if parent_work_item is not None else current_contract
    parent_depth = int(base_contract.get("derivation_depth") or 0)
    parent_validation_depth = int(base_contract.get("validation_depth") or 0)
    kind = str(
        derivation_kind
        or metadata.get("derivation_kind")
        or base_contract.get("derivation_kind")
        or "primary"
    ).strip().lower()
    if kind == "primary" and str(metadata.get("source") or "").lower() in VALIDATION_SOURCES:
        kind = "verification"
    validation_depth = parent_validation_depth + 1 if kind == "verification" and parent_work_item is not None else parent_validation_depth
    if kind == "verification" and validation_depth == 0:
        validation_depth = 1
    if validation_depth > 1:
        raise ValueError("recursive_validation_lineage")
    parent_id = int(getattr(parent_work_item, "id", 0) or metadata.get("parent_work_item_id") or 0)
    root_id = int(base_contract.get("lineage_root_work_item_id") or parent_id or 0)
    return {
        "version": CONTRACT_VERSION,
        "derivation_kind": kind,
        "derivation_depth": parent_depth + 1 if parent_id else int(metadata.get("derivation_depth") or 0),
        "validation_depth": validation_depth,
        "parent_work_item_id": parent_id or None,
        "lineage_root_work_item_id": root_id or None,
    }


def normalize_work_item_contract(item: ScanWorkItem) -> list[str]:
    changes: list[str] = []
    tool = str(item.tool_name or "").strip().lower()
    if item.tool_name != tool:
        item.tool_name = tool
        changes.append("tool_name")
    profile = canonical_work_item_profile(tool, item.profile)
    if item.profile != profile:
        item.profile = profile[:120]
        changes.append("profile")
    metadata = dict(item.item_metadata or {})
    execution_target = work_item_execution_target(item.target, metadata)
    if metadata.get("execution_target") != execution_target:
        metadata["execution_target"] = execution_target
        changes.append("execution_target")
    contract = dict(metadata.get("work_item_contract") or {})
    source = str(metadata.get("source") or "").lower()
    kind = str(contract.get("derivation_kind") or metadata.get("derivation_kind") or "primary").lower()
    if kind == "primary" and source in VALIDATION_SOURCES:
        kind = "verification"
    normalized_contract = {
        **contract,
        "version": CONTRACT_VERSION,
        "derivation_kind": kind,
        "derivation_depth": int(contract.get("derivation_depth") or metadata.get("derivation_depth") or 0),
        "validation_depth": max(
            int(contract.get("validation_depth") or 0),
            1 if kind == "verification" else 0,
        ),
        "parent_work_item_id": contract.get("parent_work_item_id") or metadata.get("parent_work_item_id"),
        "lineage_root_work_item_id": contract.get("lineage_root_work_item_id") or metadata.get("lineage_root_work_item_id"),
        "execution_target": execution_target,
        "tool_name": tool,
        "profile": profile,
    }
    if contract != normalized_contract:
        metadata["work_item_contract"] = normalized_contract
        changes.append("work_item_contract")
    if changes:
        item.item_metadata = metadata
        item.updated_at = datetime.now()
    return changes


def build_scan_work_item(
    *,
    parent_work_item: ScanWorkItem | None = None,
    derivation_kind: str | None = None,
    **values: Any,
) -> ScanWorkItem:
    metadata = dict(values.get("item_metadata") or {})
    metadata["work_item_contract"] = {
        **_lineage_contract(
            metadata,
            parent_work_item=parent_work_item,
            derivation_kind=derivation_kind,
        ),
        "execution_target": work_item_execution_target(values.get("target"), metadata),
    }
    values["item_metadata"] = metadata
    values["profile"] = canonical_work_item_profile(
        str(values.get("tool_name") or ""),
        values.get("profile"),
    )[:120]
    item = ScanWorkItem(**values)
    normalize_work_item_contract(item)
    return item


def normalize_scan_work_item_contracts(db: Session, scan_id: int) -> dict[str, int]:
    rows = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == int(scan_id)).all()
    normalized = 0
    invalidated = 0
    for item in rows:
        changes = normalize_work_item_contract(item)
        metadata = dict(item.item_metadata or {})
        recursive_legacy = (
            str(metadata.get("source") or "").lower() == "evidence_gate_stage2"
            and "#easm-wire-" in str(item.target or "")
        )
        if recursive_legacy and item.status in {"queued", "retry", "dispatched", "running", "failed"}:
            previous = {"status": item.status, "error": item.last_error, "result": dict(item.result or {})}
            item.status = "skipped"
            item.lease_until = None
            item.finished_at = item.finished_at or datetime.now()
            item.last_error = "invalidated:recursive_validation_lineage"
            item.result = {
                "status": "skipped",
                "reason": "recursive_validation_lineage",
                "invalidated_previous_state": previous,
                "finished_at": item.finished_at.isoformat(),
            }
            metadata = dict(item.item_metadata or {})
            metadata["contract_invalidation"] = {
                "reason": "recursive_validation_lineage",
                "at": datetime.now().isoformat(),
            }
            item.item_metadata = metadata
            invalidated += 1
            changes.append("invalidated")
        if changes:
            normalized += 1
            db.add(item)
    return {"normalized": normalized, "invalidated": invalidated}
