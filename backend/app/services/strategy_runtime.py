"""Runtime guardrails, timeline and learning loop for autonomous pentest scans."""
from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.models import ScanAuthorization, ScanAuditLog
from app.services.scan_scope import is_host_in_scope


def normalize_target_host(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    return raw.split("/")[0].split(":")[0].strip().strip(".")


def parse_scope_targets(target_query: str) -> list[str]:
    pieces = str(target_query or "").replace(",", "\n").replace(";", "\n").splitlines()
    hosts = [normalize_target_host(piece) for piece in pieces]
    return list(dict.fromkeys([host for host in hosts if host]))


def is_local_test_target(host: str) -> bool:
    host = normalize_target_host(host)
    if not host:
        return False
    if host in {"localhost", "0.0.0.0"} or host.endswith((".localhost", ".test", ".local", ".internal")):
        return True
    try:
        ip = ip_address(host)
        return bool(ip.is_loopback or ip.is_private or ip.is_link_local)
    except ValueError:
        return False


def authorization_scope_roots(authorization: ScanAuthorization | None) -> list[str]:
    if not authorization:
        return []
    return parse_scope_targets(str(authorization.target_query or ""))


def evaluate_scan_authorization(
    db: Session,
    *,
    owner_id: int,
    target_query: str,
    authorization_code: str | None = None,
    authorization_attested: bool = False,
    enforce_public_targets: bool = True,
) -> dict[str, Any]:
    targets = parse_scope_targets(target_query)
    public_targets = [target for target in targets if not is_local_test_target(target)]
    if not enforce_public_targets or not public_targets:
        return {
            "approved": True,
            "mode": "local_or_policy_exempt",
            "targets": targets,
            "public_targets": public_targets,
            "authorized_scope": targets,
            "authorization_id": None,
            "authorization_code": authorization_code,
            "authorization_attested": bool(authorization_attested),
            "reason": "local/test targets do not require external authorization gate",
        }

    if authorization_attested:
        return {
            "approved": True,
            "mode": "operator_attestation",
            "targets": targets,
            "public_targets": public_targets,
            "authorized_scope": public_targets,
            "authorization_id": None,
            "authorization_code": authorization_code,
            "authorization_attested": True,
            "reason": "operator explicitly attested authorization for every public target in scope",
        }

    query = db.query(ScanAuthorization).filter(
        ScanAuthorization.status == "approved",
        ScanAuthorization.requester_id == owner_id,
    )
    if authorization_code:
        query = query.filter(ScanAuthorization.authorization_code == authorization_code)

    now = datetime.now()
    candidates = [
        row for row in query.order_by(ScanAuthorization.created_at.desc()).all()
        if not row.expires_at or row.expires_at >= now
    ]
    for candidate in candidates:
        roots = authorization_scope_roots(candidate)
        if roots and all(is_host_in_scope(target, roots) for target in public_targets):
            return {
                "approved": True,
                "mode": "approved_authorization",
                "targets": targets,
                "public_targets": public_targets,
                "authorized_scope": roots,
                "authorization_id": candidate.id,
                "authorization_code": candidate.authorization_code,
                "authorization_attested": bool(authorization_attested),
                "reason": "approved authorization covers every public target",
            }

    return {
        "approved": False,
        "mode": "blocked_missing_authorization",
        "targets": targets,
        "public_targets": public_targets,
        "authorized_scope": [],
        "authorization_id": None,
        "authorization_code": authorization_code,
        "authorization_attested": False,
        "reason": "public target requires explicit operator authorization attestation",
    }


def append_runtime_event(state: dict[str, Any], event_type: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    event = {
        "type": event_type,
        "ts": datetime.now().isoformat(),
        **dict(payload or {}),
    }
    timeline = list(state.get("strategy_runtime_timeline") or [])
    timeline.append(event)
    state["strategy_runtime_timeline"] = timeline[-240:]
    return event


def build_reasoning_feedback(
    *,
    state: dict[str, Any],
    capability: str,
    skill_id: str,
    selected_tools: list[str],
    execution_results: list[dict[str, Any]],
    findings_added: int,
) -> dict[str, Any]:
    tool_successes = sum(1 for item in execution_results if str(item.get("target") or "").strip())
    status = "productive" if findings_added > 0 else ("executed_no_findings" if tool_successes else "not_executed")
    feedback = {
        "capability": capability,
        "skill_id": skill_id,
        "tools": selected_tools,
        "status": status,
        "findings_added": int(findings_added),
        "targets_executed": len(execution_results),
        "created_at": datetime.now().isoformat(),
        "next_reasoning_hint": (
            "prioritize validation/proof pack" if findings_added > 0
            else "try alternate technique or gather stronger context before repeating"
        ),
    }
    history = list(state.get("llm_reasoning_feedback") or [])
    history.append(feedback)
    state["llm_reasoning_feedback"] = history[-120:]
    append_runtime_event(state, "reasoning_feedback", feedback)
    return feedback


def persist_operational_memory(db: Session, scan_id: int, state: dict[str, Any], limit: int = 8) -> None:
    feedback = list(state.get("llm_reasoning_feedback") or [])[-limit:]
    for idx, item in enumerate(feedback):
        db.add(
            ScanAuditLog(
                scan_job_id=scan_id,
                iteration=int(state.get("loop_iteration", 0) or 0),
                node_name="strategy_runtime",
                entry_type="reasoning_feedback",
                content=(
                    f"{item.get('status')} | capability={item.get('capability')} "
                    f"skill={item.get('skill_id')} findings={item.get('findings_added')} "
                    f"targets={item.get('targets_executed')}"
                ),
            )
        )


def build_strategy_timeline(scan_job: Any, audit_logs: list[Any] | None = None) -> list[dict[str, Any]]:
    state = dict(getattr(scan_job, "state_data", None) or {})
    strategy = dict(state.get("operational_strategy") or {})
    timeline: list[dict[str, Any]] = []
    for event in list(strategy.get("events") or []):
        timeline.append({"source": "strategy", **dict(event or {})})
    for event in list(state.get("strategy_runtime_timeline") or []):
        timeline.append({"source": "runtime", **dict(event or {})})
    for item in list(state.get("llm_reasoning") or [])[-30:]:
        timeline.append({
            "source": "llm",
            "type": "llm_decision",
            "ts": item.get("created_at") or item.get("ts") or "",
            "skill_id": item.get("skill_id"),
            "phase": item.get("phase"),
            "decision": (item.get("decision") or {}).get("execution_decision") or (item.get("decision") or {}).get("notes"),
        })
    for item in list(state.get("mcp_adapter_contracts") or [])[-30:]:
        timeline.append({
            "source": "mcp",
            "type": "mcp_contract",
            "ts": item.get("created_at") or "",
            "skill_id": item.get("skill_id"),
            "capability": item.get("capability"),
            "tools": item.get("tools") or [],
        })
    for log in list(audit_logs or [])[-40:]:
        timeline.append({
            "source": "memory",
            "type": getattr(log, "entry_type", "audit"),
            "ts": getattr(log, "created_at", None).isoformat() if getattr(log, "created_at", None) else "",
            "node": getattr(log, "node_name", ""),
            "message": getattr(log, "content", ""),
        })
    return sorted(timeline, key=lambda item: str(item.get("ts") or ""))[-160:]
