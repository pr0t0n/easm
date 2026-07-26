from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.models import Finding, ScanJob, ScanLog, ScanWorkItem


AUTHORITATIVE_GATE_TOOLS = {
    "P02": {"naabu", "nmap"},
    "P06": {"httpx"},
}
ACTIVE_ITEM_STATUSES = {"queued", "retry", "dispatched", "running", "submitted"}
TERMINAL_ITEM_STATUSES = {"completed", "done", "failed", "timeout", "skipped"}


def emit_recon_event(
    db: Session,
    scan_id: int,
    event: str,
    *,
    level: str = "INFO",
    **payload: Any,
) -> None:
    """Persist one machine-readable orchestration event in the normal scan log."""
    body = {
        "event": str(event),
        "at": datetime.now().isoformat(),
        **payload,
    }
    db.add(
        ScanLog(
            scan_job_id=scan_id,
            source="recon-observability",
            level=level,
            message=json.dumps(body, ensure_ascii=False, sort_keys=True, default=str),
        )
    )


def emit_recon_event_standalone(
    scan_id: int,
    event: str,
    *,
    level: str = "INFO",
    **payload: Any,
) -> None:
    """Best-effort event writer for code paths that do not own a DB session."""
    db = None
    try:
        from app.db.session import SessionLocal

        db = SessionLocal()
        emit_recon_event(db, scan_id, event, level=level, **payload)
        db.commit()
    except Exception:
        if db is not None:
            db.rollback()
    finally:
        if db is not None:
            db.close()


def _status_counts(items: list[ScanWorkItem]) -> dict[str, int]:
    return dict(Counter(str(item.status or "unknown") for item in items))


def _profile_summary(state: dict[str, Any]) -> dict[str, Any]:
    profiles = dict(((state.get("preflight") or {}).get("targets") or {}))
    values = [dict(profile or {}) for profile in profiles.values()]
    return {
        "profiles_total": len(values),
        "dns_resolved": sum(bool(profile.get("dns_resolves")) for profile in values),
        "dns_inconclusive": sum(
            str(profile.get("status") or "") in {"dns_inconclusive", "p02_inconclusive"}
            for profile in values
        ),
        "p02_input_covered": sum(bool(profile.get("p02_input_covered")) for profile in values),
        "p02_complete": sum(bool(profile.get("p02_complete")) for profile in values),
        "targets_with_open_ports": sum(bool(profile.get("open_ports")) for profile in values),
        "open_ports_observed": sum(len(profile.get("open_ports") or []) for profile in values),
        "p06_input_covered": sum(bool(profile.get("p06_input_covered")) for profile in values),
        "p06_complete": sum(bool(profile.get("p06_complete")) for profile in values),
        "http_live": sum(bool(profile.get("p06_http_live")) for profile in values),
        "runner_connectivity_blocked": sum(
            str(profile.get("status") or "") == "runner_connectivity_blocked"
            for profile in values
        ),
        "no_http_response": sum(
            bool(profile.get("p06_complete"))
            and not bool(profile.get("p06_http_live"))
            and str(profile.get("status") or "") != "runner_connectivity_blocked"
            for profile in values
        ),
    }


def _gate_snapshot(
    phase_id: str,
    items: list[ScanWorkItem],
    profiles: dict[str, Any],
    downstream_blocked: int,
    contract_version: int,
    scan_status: str = "",
) -> dict[str, Any]:
    tools = AUTHORITATIVE_GATE_TOOLS[phase_id]
    authoritative = [
        item for item in items
        if str(item.phase_id or "") == phase_id
        and str(item.tool_name or "").lower() in tools
    ]
    statuses = _status_counts(authoritative)
    active = sum(statuses.get(status, 0) for status in ACTIVE_ITEM_STATUSES)
    terminal = sum(statuses.get(status, 0) for status in TERMINAL_ITEM_STATUSES)
    batch_items = [item for item in authoritative if str(item.target or "") == "__batch__"]
    manifested = [
        item for item in batch_items
        if bool((item.result or {}).get("batch_targets"))
        and bool((item.result or {}).get("batch_target_file_sha256"))
    ]
    manifest_targets = {
        str(target)
        for item in manifested
        for target in (item.result or {}).get("batch_targets") or []
        if str(target or "")
    }
    if phase_id == "P02":
        qualified = int(profiles.get("p02_complete") or 0)
        covered = int(profiles.get("p02_input_covered") or 0)
    else:
        qualified = int(profiles.get("http_live") or 0)
        covered = int(profiles.get("p06_input_covered") or 0)

    scan_terminal = str(scan_status or "").lower() in {"completed", "completed_with_gaps"}
    if scan_terminal and active > 0:
        state_name = "terminal_inconsistent"
        normal = False
        reason = "Scan terminal ainda possui item autoritativo ativo neste gate."
    elif contract_version < 3:
        state_name = "legacy_unverifiable"
        normal = False
        reason = "Scan anterior ao contrato de cobertura por alvo; status global não comprova o lote."
    elif active > 0:
        state_name = "running"
        normal = True
        reason = "Gate em execução; dependentes bloqueados são espera normal."
    elif authoritative and terminal < len(authoritative):
        state_name = "waiting"
        normal = True
        reason = "Gate aguardando itens autoritativos alcançarem estado terminal."
    elif qualified > 0:
        state_name = "open"
        normal = True
        reason = f"Gate possui evidência por alvo e qualificou {qualified} alvo(s)."
    elif authoritative and terminal == len(authoritative):
        state_name = "closed_no_qualified_targets"
        normal = downstream_blocked > 0
        reason = (
            "Gate terminou sem alvo qualificado; dependentes devem permanecer bloqueados "
            "e finalizar como lacuna explícita."
        )
    else:
        state_name = "not_started"
        normal = True
        reason = "Gate ainda não possui item autoritativo."

    return {
        "phase_id": phase_id,
        "state": state_name,
        "normal_wait": normal,
        "reason": reason,
        "authoritative_tools": sorted(tools),
        "items": len(authoritative),
        "status_counts": statuses,
        "active_items": active,
        "terminal_items": terminal,
        "batch_items": len(batch_items),
        "manifested_batches": len(manifested),
        "manifest_targets": len(manifest_targets),
        "covered_targets": covered,
        "qualified_targets": qualified,
        "downstream_blocked": int(downstream_blocked),
    }


def _lock_snapshot(scan_id: int, scan_status: str) -> dict[str, Any]:
    rows = []
    try:
        from app.services.scan_work_queue import _redis_client

        redis = _redis_client()
        for lock_type, key in (
            ("scan_chain", f"scan_chain_lock:{scan_id}"),
            ("dispatcher", f"dispatch_lock:{scan_id}"),
        ):
            held = bool(redis.exists(key))
            ttl = int(redis.ttl(key) or -1) if held else -1
            rows.append({
                "type": lock_type,
                "held": held,
                "ttl_seconds": ttl,
                "interpretation": (
                    "normal: impede duas cadeias do mesmo scan"
                    if lock_type == "scan_chain" and held
                    else "normal e transitório: serializa o dispatcher"
                    if lock_type == "dispatcher" and held
                    else "livre"
                ),
            })
    except Exception as exc:
        return {
            "observable": False,
            "error": str(exc)[:200],
            "locks": [],
        }
    return {
        "observable": True,
        "scan_status": scan_status,
        "locks": rows,
    }


def _capacity_snapshot(db: Session, scan_id: int) -> list[dict[str, Any]]:
    try:
        from app.services.scan_work_queue import capacity_limits, kali_inflight_get

        caps = capacity_limits()
    except Exception:
        return []
    rows = (
        db.query(
            ScanWorkItem.resource_class,
            ScanWorkItem.status,
            func.count(ScanWorkItem.id),
        )
        .filter(ScanWorkItem.scan_job_id == scan_id)
        .group_by(ScanWorkItem.resource_class, ScanWorkItem.status)
        .all()
    )
    output = []
    for resource_class, cap in caps.items():
        queued = sum(
            count
            for rc, status, count in rows
            if str(rc) == resource_class and str(status) in {"queued", "retry"}
        )
        active = sum(
            count
            for rc, status, count in rows
            if str(rc) == resource_class and str(status) in {"dispatched", "running", "submitted"}
        )
        output.append({
            "resource_class": resource_class,
            "capacity": int(cap),
            "global_inflight": int(kali_inflight_get(resource_class)),
            "scan_active": int(active),
            "scan_queued": int(queued),
        })
    return output


def _scan_depth(db: Session, scan: ScanJob) -> dict[str, Any]:
    state = dict(scan.state_data or {})
    items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == scan.id).all()
    findings = db.query(Finding).filter(Finding.scan_job_id == scan.id).all()
    successful = [item for item in items if str(item.status or "") in {"completed", "done"}]
    failed = [item for item in items if str(item.status or "") in {"failed", "timeout"}]
    blocked = [item for item in items if str(item.status or "") == "blocked"]
    active = [item for item in items if str(item.status or "") in ACTIVE_ITEM_STATUSES]
    def _item_skills(item: ScanWorkItem) -> set[str]:
        metadata = dict(item.item_metadata or {})
        values = list(metadata.get("skill_ids") or [])
        if metadata.get("skill_id"):
            values.append(metadata["skill_id"])
        return {str(value) for value in values if str(value or "")}

    attributed_skills = set().union(*(_item_skills(item) for item in items)) if items else set()
    executed_skills = (
        set().union(*(_item_skills(item) for item in successful))
        if successful
        else set()
    )
    depth = {
        "scan_id": scan.id,
        "status": scan.status,
        "qualification_contract_version": int(state.get("qualification_contract_version") or 0),
        "targets_selected": len(state.get("target_set") or []),
        "targets_dead": len(state.get("dead_targets") or []),
        "work_items": len(items),
        "successful_items": len(successful),
        "failed_items": len(failed),
        "blocked_items": len(blocked),
        "active_items": len(active),
        "phases_with_success": len({str(item.phase_id) for item in successful}),
        "tools_with_success": len({str(item.tool_name) for item in successful}),
        "skills_attributed": len(attributed_skills),
        "skills_executed": len(executed_skills),
        "findings": len(findings),
        "confirmed_findings": sum(
            str(finding.verification_status or "").lower() == "confirmed"
            for finding in findings
        ),
    }
    depth["assessment"] = _scan_assessment(depth)
    return depth


def _scan_assessment(depth: dict[str, Any]) -> dict[str, Any]:
    """Explain whether shallow output represents the target or the platform."""
    status = str(depth.get("status") or "").lower()
    active = int(depth.get("active_items") or 0)
    blocked = int(depth.get("blocked_items") or 0)
    successful = int(depth.get("successful_items") or 0)
    failed = int(depth.get("failed_items") or 0)
    skills_attributed = int(depth.get("skills_attributed") or 0)
    skills_executed = int(depth.get("skills_executed") or 0)
    phases = int(depth.get("phases_with_success") or 0)

    if status in {"paused", "stopped", "cancelled", "canceled"}:
        return {
            "category": "interrupted",
            "label": "Execução interrompida",
            "reliable_negative": False,
            "evidence": [
                f"status={status}",
                f"{active} itens ativos e {blocked} bloqueados permanecem no histórico",
            ],
        }
    if status in {"completed", "completed_with_gaps"} and (
        active > 0
        or (
            blocked > 0
            and int(depth.get("qualification_contract_version") or 0) < 3
        )
    ):
        return {
            "category": "platform_orchestration_failure",
            "label": "Falha de orquestração",
            "reliable_negative": False,
            "evidence": [
                "scan foi declarado terminal com trabalho ainda ativo/bloqueado",
                f"{successful} itens concluídos; {active} ativos; {blocked} bloqueados",
                (
                    f"{skills_attributed} skills atribuídas, mas somente "
                    f"{skills_executed} aparecem em itens concluídos"
                ),
            ],
        }
    if failed > successful and failed > 0:
        return {
            "category": "tool_execution_failure",
            "label": "Falhas de tools/skills",
            "reliable_negative": False,
            "evidence": [
                f"{failed} itens falharam contra {successful} concluídos",
                "ausência de finding não é evidência negativa confiável",
            ],
        }
    if status in {"completed", "completed_with_gaps"} and successful > 0 and phases >= 3:
        return {
            "category": "executed",
            "label": "Profundidade executada",
            "reliable_negative": True,
            "evidence": [
                f"{successful} itens concluídos em {phases} fases",
                f"{skills_executed}/{skills_attributed} skills atribuídas aparecem em execuções concluídas",
            ],
        }
    return {
        "category": "incomplete_or_unverifiable",
        "label": "Execução inconclusiva",
        "reliable_negative": False,
        "evidence": [
            f"status={status or 'desconhecido'}",
            f"{successful} itens concluídos em {phases} fases",
        ],
    }


def build_recon_observability(db: Session, scan: ScanJob) -> dict[str, Any]:
    state = dict(scan.state_data or {})
    items = db.query(ScanWorkItem).filter(ScanWorkItem.scan_job_id == scan.id).all()
    contract_version = int(state.get("qualification_contract_version") or 0)
    profiles = _profile_summary(state)
    p02_downstream = sum(
        1 for item in items
        if str(item.status or "") == "blocked"
        and str((item.item_metadata or {}).get("gate_reason") or item.last_error or "").find("P02") >= 0
    )
    p06_downstream = sum(
        1 for item in items
        if str(item.status or "") == "blocked"
        and (
            str((item.item_metadata or {}).get("gate_reason") or item.last_error or "").find("P06") >= 0
            or str(item.phase_id or "") in {"P03", "P04", "P05", "P07", "P08", "P09", "P16"}
        )
    )
    reason_counts = Counter(
        str((item.item_metadata or {}).get("gate_reason") or item.last_error or "waiting_for_gate")
        for item in items
        if str(item.status or "") == "blocked"
    )
    event_rows = (
        db.query(ScanLog)
        .filter(
            ScanLog.scan_job_id == scan.id,
            ScanLog.source == "recon-observability",
        )
        .order_by(ScanLog.id.desc())
        .limit(30)
        .all()
    )
    events = []
    for row in reversed(event_rows):
        try:
            payload = dict(json.loads(str(row.message or "{}")))
        except Exception:
            payload = {"event": "unparsed", "message": str(row.message or "")}
        payload.update({
            "level": row.level,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        })
        events.append(payload)

    current = _scan_depth(db, scan)
    previous = (
        db.query(ScanJob)
        .filter(
            ScanJob.target_query == scan.target_query,
            ScanJob.id < scan.id,
        )
        .order_by(ScanJob.id.desc())
        .first()
    )
    previous_depth = _scan_depth(db, previous) if previous else None
    history_scans = (
        db.query(ScanJob)
        .filter(ScanJob.target_query == scan.target_query)
        .order_by(ScanJob.id.desc())
        .limit(10)
        .all()
    )
    history = [_scan_depth(db, row) for row in reversed(history_scans)]
    comparison_reasons: list[str] = []
    comparable = bool(previous_depth)
    if previous_depth:
        if current["qualification_contract_version"] != previous_depth["qualification_contract_version"]:
            comparable = False
            comparison_reasons.append("contratos de qualificação diferentes")
        if current["targets_selected"] != previous_depth["targets_selected"]:
            comparison_reasons.append(
                f"inventário diferente: {previous_depth['targets_selected']} → {current['targets_selected']} alvos"
            )
        if current["phases_with_success"] != previous_depth["phases_with_success"]:
            comparison_reasons.append(
                f"profundidade diferente: {previous_depth['phases_with_success']} → "
                f"{current['phases_with_success']} fases com sucesso"
            )
        if current["blocked_items"] or previous_depth["blocked_items"]:
            comparison_reasons.append(
                f"bloqueios diferentes: {previous_depth['blocked_items']} → {current['blocked_items']} itens"
            )
        if (
            str(scan.status or "") in {"completed", "completed_with_gaps"}
            and (current["blocked_items"] or current["active_items"])
        ):
            comparable = False
            comparison_reasons.append("scan terminal ainda possui trabalho bloqueado/ativo")

    return {
        "contract_version": contract_version,
        "inventory": {
            "expanded_targets": len(state.get("expanded_targets") or []),
            "selected_targets": len(state.get("target_set") or []),
            "dead_targets": len(state.get("dead_targets") or []),
            "dns_inconclusive_targets": len(state.get("dns_inconclusive_targets") or []),
            "producer_stage": state.get("work_producer_stage"),
            "producers_sealed": state.get("work_producers_sealed"),
        },
        "qualification": profiles,
        "gates": [
            _gate_snapshot(
                "P02", items, profiles, p02_downstream, contract_version, str(scan.status or "")
            ),
            _gate_snapshot(
                "P06", items, profiles, p06_downstream, contract_version, str(scan.status or "")
            ),
        ],
        "blocked_reasons": [
            {"reason": reason, "count": count}
            for reason, count in reason_counts.most_common(10)
        ],
        "locks": _lock_snapshot(scan.id, str(scan.status or "")),
        "capacity": _capacity_snapshot(db, scan.id),
        "events": events,
        "comparison": {
            "comparable": comparable,
            "reasons": comparison_reasons,
            "current": current,
            "previous": previous_depth,
            "history": history,
        },
    }
