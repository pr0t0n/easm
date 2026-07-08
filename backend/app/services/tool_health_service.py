"""Operational tool health matrix."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import ToolHealthSnapshot
from app.services.kali_catalog import build_kali_tool_matrix
from app.services.pentest_contracts import ToolHealthContract


TOOLS_WITH_PARSERS = {
    "subfinder", "amass", "dnsx", "naabu", "nmap", "httpx", "whatweb",
    "wafw00f", "sslscan", "testssl", "katana", "hakrawler", "gau",
    "waybackurls", "arjun", "paramspider", "nuclei", "nikto", "ffuf",
    "gobuster", "feroxbuster", "dirsearch", "sqlmap", "dalfox", "wapiti",
    "subjack", "curl-headers", "shodan-cli", "theharvester", "h8mail",
    "trufflehog", "gitleaks", "semgrep", "bandit", "trivy",
}


def build_tool_health_matrix(*, force: bool = False, include_unprofiled: bool = False) -> dict[str, Any]:
    matrix = build_kali_tool_matrix(include_unprofiled=include_unprofiled, force=force)
    rows = [_health_from_catalog_row(row).to_dict() for row in list(matrix.get("tools") or [])]
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    required_broken = [
        row for row in rows
        if row.get("status") not in {"ready", "experimental"}
        and str(row.get("detail", {}).get("requiredness") or "required") == "required"
    ]
    return {
        "runner_reachable": bool(matrix.get("runner_reachable")),
        "runner_error": matrix.get("runner_error") or "",
        "coverage_ratio": matrix.get("coverage_ratio"),
        "counts": counts,
        "ready": counts.get("ready", 0),
        "broken_required": len(required_broken),
        "tools": rows,
        "unprofiled_summary": matrix.get("unprofiled_summary") or {},
        "unprofiled_tools": matrix.get("unprofiled_tools") or [],
    }


def persist_tool_health_snapshot(db: Session, *, force: bool = False) -> dict[str, Any]:
    matrix = build_tool_health_matrix(force=force)
    checked_at = datetime.now()
    for row in matrix.get("tools") or []:
        snapshot = ToolHealthSnapshot(
            tool_name=str(row.get("tool_name") or ""),
            profile=str(row.get("profile") or "") or None,
            binary=str(row.get("binary") or "") or None,
            phase=str(row.get("phase") or "") or None,
            skill_id=",".join(row.get("skills") or [])[:120] or None,
            worker_group=str(row.get("worker_group") or "") or None,
            status=str(row.get("status") or "unknown"),
            parser_status=str(row.get("parser_status") or "unknown"),
            dry_run_status=str(row.get("dry_run_status") or "not_run"),
            timeout=row.get("timeout") if isinstance(row.get("timeout"), int) else None,
            resource_class=str(row.get("resource_class") or "") or None,
            detail=dict(row.get("detail") or {}),
            checked_at=checked_at,
        )
        db.add(snapshot)
    db.flush()
    return matrix


def latest_tool_health(db: Session, limit: int = 500) -> dict[str, Any]:
    rows = (
        db.query(ToolHealthSnapshot)
        .order_by(ToolHealthSnapshot.checked_at.desc(), ToolHealthSnapshot.id.desc())
        .limit(max(1, min(limit, 2000)))
        .all()
    )
    by_tool: dict[str, ToolHealthSnapshot] = {}
    for row in rows:
        by_tool.setdefault(str(row.tool_name), row)
    serialized = [_serialize_snapshot(row) for row in by_tool.values()]
    counts: dict[str, int] = {}
    for row in serialized:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {"total": len(serialized), "counts": counts, "tools": serialized}


def _health_from_catalog_row(row: dict[str, Any]) -> ToolHealthContract:
    available = bool(row.get("available"))
    catalog_status = str(row.get("status") or "unknown")
    tool_name = str(row.get("name") or "")
    parser_status = "available" if tool_name.lower() in TOOLS_WITH_PARSERS else "fallback"
    status = "ready"
    detail: dict[str, Any] = {
        "catalog_status": catalog_status,
        "source": row.get("source"),
        "need": row.get("need") or "",
        "functionality": row.get("functionality") or "",
        "skills": row.get("skills") or [],
        "mission_phases": row.get("mission_phases") or [],
        "requiredness": "required",
    }
    if not available:
        if catalog_status in {"missing_profile_mapping", "profile_not_loaded"}:
            status = "missing_profile"
        elif catalog_status == "missing_kali_binary":
            status = "missing_binary"
        elif catalog_status == "runner_unreachable":
            status = "runner_unreachable"
        else:
            status = "unknown"
    elif parser_status == "fallback":
        status = "ready"
        detail["parser_warning"] = "no dedicated parser registered; report will use generic output"
    if row.get("source") == "backend_local":
        status = "ready"
        parser_status = "available"
    return ToolHealthContract(
        tool_name=tool_name,
        status=status,  # type: ignore[arg-type]
        profile=str(row.get("profile") or ""),
        binary=str(row.get("executable") or ""),
        phase=str(row.get("phase") or ""),
        skill_id=",".join(row.get("skills") or [])[:120],
        worker_group=str(row.get("worker_group") or ""),
        parser_status=parser_status,
        dry_run_status="not_run",
        timeout=row.get("timeout") if isinstance(row.get("timeout"), int) else None,
        resource_class=str(row.get("resource_class") or ""),
        detail=detail,
    )


def _serialize_snapshot(row: ToolHealthSnapshot) -> dict[str, Any]:
    return {
        "tool_name": row.tool_name,
        "profile": row.profile,
        "binary": row.binary,
        "phase": row.phase,
        "skill_id": row.skill_id,
        "worker_group": row.worker_group,
        "status": row.status,
        "parser_status": row.parser_status,
        "dry_run_status": row.dry_run_status,
        "timeout": row.timeout,
        "resource_class": row.resource_class,
        "detail": row.detail or {},
        "checked_at": row.checked_at.isoformat() if row.checked_at else None,
    }
