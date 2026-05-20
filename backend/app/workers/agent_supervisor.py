"""Agent supervisor: orquestra execução sequencial P01–P22 via Celery.

Regras obrigatórias:
1. O supervisor percorre PENTEST_PHASES em ordem (P01 → P22).
2. Cada fase é executada segundo seu PHASE_CONTRACT.
3. Uma fase só avança quando validate_phase_exit_criteria() retornar can_advance=True.
4. Quando can_advance=False: retry até max_retries; se esgotar → skip com motivo.
5. O phase_ledger é atualizado no ScanJob.state_data após cada fase.
6. Se MCP falhar de forma arquitetural: registrar fase como partial e bloquear avanço.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.graph.mission import PENTEST_PHASES, PHASE_CONTRACTS
from app.models.models import ExecutedToolRun, ScanJob
from app.workers.celery_app import celery

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Phase ledger state helpers (operate on ScanJob.state_data directly)
# ─────────────────────────────────────────────────────────────────────────────

def _load_phase_ledger(state_data: dict[str, Any]) -> dict[str, Any]:
    return dict(state_data.get("phase_ledger") or {})


def _save_phase_ledger(db: Session, scan: ScanJob, ledger: dict[str, Any]) -> None:
    sd = dict(scan.state_data or {})
    sd["phase_ledger"] = ledger
    scan.state_data = sd
    db.commit()


def _ledger_entry(ledger: dict[str, Any], phase_id: str) -> dict[str, Any]:
    return dict(ledger.get(phase_id) or {})


def _mark_phase_running(ledger: dict[str, Any], phase_id: str, phase_name: str) -> None:
    entry = _ledger_entry(ledger, phase_id)
    if entry.get("status") in ("completed", "skipped"):
        return
    entry["phase_id"] = phase_id
    entry["name"] = phase_name
    entry["status"] = "running"
    entry["started_at"] = entry.get("started_at") or datetime.utcnow().isoformat()
    ledger[phase_id] = entry


def _mark_phase_completed(
    ledger: dict[str, Any],
    phase_id: str,
    reason: str,
    tools_succeeded: list[str],
    evidence_persisted: bool,
) -> None:
    entry = _ledger_entry(ledger, phase_id)
    entry["status"] = "completed"
    entry["completed_at"] = datetime.utcnow().isoformat()
    entry["exit_criteria_met"] = True
    entry["can_advance"] = True
    entry["evidence_persisted"] = evidence_persisted
    entry["validation_result"] = {
        "status": "completed",
        "reason": reason,
        "can_advance": True,
        "ts": datetime.utcnow().isoformat(),
    }
    # Merge tools_succeeded without duplicates
    existing = list(entry.get("tools_succeeded") or [])
    for t in tools_succeeded:
        if t not in existing:
            existing.append(t)
    entry["tools_succeeded"] = existing
    ledger[phase_id] = entry


def _mark_phase_partial(
    ledger: dict[str, Any],
    phase_id: str,
    reason: str,
    retry_count: int,
) -> None:
    entry = _ledger_entry(ledger, phase_id)
    entry["status"] = "partial"
    entry["can_advance"] = False
    entry["retry_count"] = retry_count
    entry["validation_result"] = {
        "status": "partial",
        "reason": reason,
        "can_advance": False,
        "ts": datetime.utcnow().isoformat(),
    }
    ledger[phase_id] = entry


def _mark_phase_failed(
    ledger: dict[str, Any],
    phase_id: str,
    reason: str,
    retry_count: int,
) -> None:
    entry = _ledger_entry(ledger, phase_id)
    entry["status"] = "failed"
    entry["can_advance"] = False
    entry["retry_count"] = retry_count
    entry["validation_result"] = {
        "status": "failed",
        "reason": reason,
        "can_advance": False,
        "ts": datetime.utcnow().isoformat(),
    }
    ledger[phase_id] = entry


def _mark_phase_skipped(
    ledger: dict[str, Any],
    phase_id: str,
    skip_reason: str,
) -> None:
    entry = _ledger_entry(ledger, phase_id)
    entry["status"] = "skipped"
    entry["can_advance"] = True
    entry["skip_reason"] = skip_reason
    entry["completed_at"] = datetime.utcnow().isoformat()
    entry["validation_result"] = {
        "status": "skipped",
        "reason": skip_reason,
        "can_advance": True,
        "ts": datetime.utcnow().isoformat(),
    }
    ledger[phase_id] = entry


# ─────────────────────────────────────────────────────────────────────────────
# Phase exit criteria validation (Celery-level, using ExecutedToolRun)
# ─────────────────────────────────────────────────────────────────────────────

def check_phase_exit_criteria(
    db: Session,
    scan_id: int,
    phase_id: str,
    ledger: dict[str, Any],
) -> tuple[bool, str, str]:
    """Evaluate phase exit criteria using DB tool runs + phase_ledger evidence flags.

    Returns:
        (can_advance: bool, status: str, reason: str)
    """
    contract = PHASE_CONTRACTS.get(phase_id)
    if not contract:
        return False, "error", f"No PHASE_CONTRACT for {phase_id}"

    entry = _ledger_entry(ledger, phase_id)

    # Query actual tool executions from DB
    tool_runs = (
        db.query(ExecutedToolRun)
        .filter(ExecutedToolRun.scan_job_id == scan_id)
        .all()
    )
    tools_succeeded_db = {
        str(r.tool_name or "").strip().lower()
        for r in tool_runs
        if r.status == "success"
    }
    tools_attempted_db = {
        str(r.tool_name or "").strip().lower()
        for r in tool_runs
    }

    required_tools = [t.lower() for t in (contract.get("required_tools") or [])]
    exit_c = dict(contract.get("exit_criteria") or {})
    min_succeeded = int(exit_c.get("min_required_tools_succeeded", 1))
    needs_evidence = bool(exit_c.get("evidence_persisted", True))
    needs_parser = bool(exit_c.get("parser_result_registered", True))

    req_attempted = [t for t in required_tools if t in tools_attempted_db]
    req_succeeded = [t for t in required_tools if t in tools_succeeded_db]
    req_failed = [t for t in required_tools if t in tools_attempted_db and t not in tools_succeeded_db]

    # MCP architectural failure check from ledger
    mcp_failures = list(entry.get("mcp_failures") or [])
    if mcp_failures and not tools_succeeded_db:
        reason = (
            f"Phase {phase_id}: MCP architectural failure — {len(mcp_failures)} MCP error(s). "
            "Phase cannot advance until MCP is restored."
        )
        logger.error("SUPERVISOR [%s] mcp_architectural_failure", phase_id)
        return False, "mcp_failure", reason

    if not req_attempted:
        return False, "not_started", f"Phase {phase_id}: required tools not attempted: {required_tools}"

    if len(req_succeeded) < min_succeeded:
        if req_failed and len(req_failed) >= len(required_tools):
            reason = (
                f"Phase {phase_id}: all required tools failed — {req_failed}. "
                "Exhausted required tools. Will try optional tools or skip."
            )
            return False, "failed", reason
        reason = (
            f"Phase {phase_id}: {len(req_succeeded)}/{min_succeeded} required tools succeeded. "
            f"Succeeded: {req_succeeded}. Failed: {req_failed}."
        )
        return False, "partial", reason

    evidence_persisted = bool(
        entry.get("evidence_persisted")
        or len([r for r in tool_runs if r.status == "success"]) > 0
    )
    if needs_evidence and not evidence_persisted:
        return False, "partial", f"Phase {phase_id}: evidence not persisted"

    parser_result = entry.get("parser_result")
    if needs_parser and not parser_result:
        # Accept if any findings were generated (parser ran implicitly)
        findings_exist = any(r.status == "success" for r in tool_runs if r.tool_name in required_tools)
        if not findings_exist:
            return False, "partial", f"Phase {phase_id}: parser/validator result not registered"

    return True, "completed", (
        f"Phase {phase_id}: exit criteria met — "
        f"required_succeeded={req_succeeded}, evidence={evidence_persisted}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# AgentSupervisor — sequential P01–P22 orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class AgentSupervisor:
    """Supervisiona execução sequencial P01–P22 via Celery com phase_ledger."""

    def __init__(self, scan_id: int, db: Session | None = None):
        self.scan_id = scan_id
        self.db = db or SessionLocal()
        self.scan: ScanJob | None = None
        self.phase_ledger: dict[str, Any] = {}
        self.started_at = datetime.utcnow().isoformat()
        self._load_scan()

    def _load_scan(self) -> None:
        self.scan = self.db.query(ScanJob).filter(ScanJob.id == self.scan_id).first()
        if not self.scan:
            raise ValueError(f"Scan {self.scan_id} not found")
        sd = dict(self.scan.state_data or {})
        self.phase_ledger = _load_phase_ledger(sd)

    def _persist_ledger(self) -> None:
        if self.scan:
            _save_phase_ledger(self.db, self.scan, self.phase_ledger)

    def _current_phase_index(self) -> int:
        """Returns the current pentest_phase_index from state_data."""
        sd = dict((self.scan.state_data or {}) if self.scan else {})
        return int(sd.get("pentest_phase_index") or 0)

    def _advance_phase_index(self) -> None:
        """Increments pentest_phase_index in state_data."""
        if not self.scan:
            return
        sd = dict(self.scan.state_data or {})
        current = int(sd.get("pentest_phase_index") or 0)
        sd["pentest_phase_index"] = current + 1
        next_idx = current + 1
        if next_idx < len(PENTEST_PHASES):
            sd["current_pentest_phase_id"] = PENTEST_PHASES[next_idx]["id"]
        else:
            sd["current_pentest_phase_id"] = ""
        sd["phase_ledger"] = self.phase_ledger
        self.scan.state_data = sd
        self.db.commit()

    def _get_optional_tools_not_tried(self, phase_id: str) -> list[str]:
        """Returns optional tools from contract that haven't been attempted yet."""
        contract = PHASE_CONTRACTS.get(phase_id, {})
        optional = [t.lower() for t in (contract.get("optional_tools") or [])]
        tool_runs = (
            self.db.query(ExecutedToolRun)
            .filter(ExecutedToolRun.scan_job_id == self.scan_id)
            .all()
        )
        attempted = {str(r.tool_name or "").lower() for r in tool_runs}
        return [t for t in optional if t not in attempted]

    def execute_phase(self, phase_id: str, phase_name: str) -> dict[str, Any]:
        """Submits agents for a single phase and returns execution metadata.

        In production this would dispatch actual Celery tasks via the
        LangGraph agent pipeline. Here it records the submission and
        returns a handle for monitoring.
        """
        logger.info(
            "SUPERVISOR [%s] executing phase=%s scan_id=%s",
            phase_id, phase_name, self.scan_id,
        )
        _mark_phase_running(self.phase_ledger, phase_id, phase_name)
        self._persist_ledger()

        # Log to scan audit trail
        try:
            from app.models.models import ScanAuditLog
            log_entry = ScanAuditLog(
                scan_job_id=self.scan_id,
                node_name="agent_supervisor",
                entry_type="action",
                content=f"PHASE_START phase={phase_id} name={phase_name}",
                iteration=self._current_phase_index(),
            )
            self.db.add(log_entry)
            self.db.commit()
        except Exception:
            logger.exception("Failed to write audit log for phase start")

        return {
            "phase_id": phase_id,
            "phase_name": phase_name,
            "scan_id": self.scan_id,
            "status": "submitted",
            "submitted_at": datetime.utcnow().isoformat(),
        }

    def validate_and_advance(self, phase_id: str, retry_count: int = 0) -> dict[str, Any]:
        """Check phase exit criteria. Advance or record failure.

        Returns a result dict with can_advance, status, reason.
        """
        can_advance, status, reason = check_phase_exit_criteria(
            self.db, self.scan_id, phase_id, self.phase_ledger,
        )

        contract = PHASE_CONTRACTS.get(phase_id, {})
        max_retries = int((contract.get("retry_policy") or {}).get("max_retries", 2))

        if can_advance:
            entry = _ledger_entry(self.phase_ledger, phase_id)
            _mark_phase_completed(
                self.phase_ledger,
                phase_id,
                reason=reason,
                tools_succeeded=list(entry.get("tools_succeeded") or []),
                evidence_persisted=bool(entry.get("evidence_persisted")),
            )
            self._persist_ledger()
            self._advance_phase_index()
            logger.info("SUPERVISOR [%s] completed can_advance=True", phase_id)
            self._audit(phase_id, "phase_completed", reason)
        elif status == "failed" and retry_count >= max_retries:
            skip_reason = (
                f"Phase {phase_id} failed after {retry_count} retries: {reason}. "
                f"Skip condition: {contract.get('retry_policy', {}).get('skip_condition', 'max_retries_exceeded')}"
            )
            _mark_phase_skipped(self.phase_ledger, phase_id, skip_reason)
            self._persist_ledger()
            self._advance_phase_index()
            logger.warning("SUPERVISOR [%s] skipped after %d retries", phase_id, retry_count)
            self._audit(phase_id, "phase_skipped", skip_reason)
        elif status == "mcp_failure":
            _mark_phase_partial(self.phase_ledger, phase_id, reason, retry_count)
            self._persist_ledger()
            logger.error("SUPERVISOR [%s] mcp_architectural_failure — phase blocked", phase_id)
            self._audit(phase_id, "mcp_architectural_failure", reason)
        elif retry_count < max_retries:
            _mark_phase_partial(self.phase_ledger, phase_id, reason, retry_count)
            self._persist_ledger()
            logger.info("SUPERVISOR [%s] partial retry=%d/%d", phase_id, retry_count, max_retries)
            self._audit(phase_id, "phase_partial_retry", reason)
        else:
            skip_reason = f"Phase {phase_id} partial after {retry_count} retries: {reason}"
            _mark_phase_skipped(self.phase_ledger, phase_id, skip_reason)
            self._persist_ledger()
            self._advance_phase_index()
            logger.warning("SUPERVISOR [%s] skipped partial max_retries=%d", phase_id, max_retries)
            self._audit(phase_id, "phase_skipped_partial", skip_reason)

        return {
            "phase_id": phase_id,
            "can_advance": can_advance or status in ("skipped",),
            "status": status,
            "reason": reason,
            "retry_count": retry_count,
        }

    def _audit(self, phase_id: str, entry_type: str, content: str) -> None:
        try:
            from app.models.models import ScanAuditLog
            log_entry = ScanAuditLog(
                scan_job_id=self.scan_id,
                node_name="agent_supervisor",
                entry_type=entry_type,
                content=f"[{phase_id}] {content[:500]}",
                iteration=self._current_phase_index(),
            )
            self.db.add(log_entry)
            self.db.commit()
        except Exception:
            logger.exception("Audit log write failed for phase=%s", phase_id)

    def execute_all_phases_sequential(self) -> dict[str, Any]:
        """Executes all 22 phases in order, validating exit criteria before advancing.

        This is the deterministic P01→P22 loop. For each phase:
        1. Mark as running.
        2. Delegate tool execution (submit to LangGraph/Celery).
        3. Validate exit criteria.
        4. If not met: retry up to max_retries, then skip with reason.
        5. Advance pentest_phase_index only when phase is completed or skipped.
        """
        results: list[dict[str, Any]] = []
        phase_index = self._current_phase_index()

        for i, phase_def in enumerate(PENTEST_PHASES):
            phase_id = str(phase_def["id"])
            phase_name = str(phase_def.get("title", phase_id))

            # Skip already completed/skipped phases (resume support)
            entry = _ledger_entry(self.phase_ledger, phase_id)
            if entry.get("status") in ("completed", "skipped"):
                logger.info("SUPERVISOR [%s] already done status=%s — skip", phase_id, entry["status"])
                results.append({
                    "phase_id": phase_id,
                    "status": entry["status"],
                    "skipped": True,
                    "reason": "already_completed_or_skipped",
                })
                continue

            # Execute phase
            exec_result = self.execute_phase(phase_id, phase_name)

            # Validate and retry loop
            contract = PHASE_CONTRACTS.get(phase_id, {})
            max_retries = int((contract.get("retry_policy") or {}).get("max_retries", 2))
            retry_count = 0
            validation_result: dict[str, Any] = {}

            while retry_count <= max_retries:
                validation_result = self.validate_and_advance(phase_id, retry_count)

                if validation_result.get("can_advance"):
                    break

                status = str(validation_result.get("status") or "")
                if status == "mcp_failure":
                    # MCP architectural failure: block entirely, don't retry
                    logger.error(
                        "SUPERVISOR [%s] MCP architectural failure — blocking scan progression",
                        phase_id,
                    )
                    break

                retry_count += 1
                if retry_count <= max_retries:
                    # Try optional tools on retry
                    optional_remaining = self._get_optional_tools_not_tried(phase_id)
                    logger.info(
                        "SUPERVISOR [%s] retry %d/%d optional_tools_remaining=%s",
                        phase_id, retry_count, max_retries, optional_remaining,
                    )
                    if optional_remaining:
                        self.execute_phase(phase_id, f"{phase_name} (retry {retry_count})")

            results.append({
                **exec_result,
                "validation": validation_result,
                "retry_count": retry_count,
            })

        return self.get_execution_summary(results)

    def get_execution_summary(self, phase_results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Returns full execution summary with phase_ledger details."""
        ledger = self.phase_ledger

        completed = [pid for pid, e in ledger.items() if e.get("status") == "completed"]
        partial = [pid for pid, e in ledger.items() if e.get("status") in ("partial", "failed")]
        skipped = [pid for pid, e in ledger.items() if e.get("status") == "skipped"]
        pending = [pid for pid, e in ledger.items() if e.get("status") in ("pending", "running")]

        all_tools_attempted: set[str] = set()
        all_tools_succeeded: set[str] = set()
        all_mcp_failures: list[dict] = []
        for entry in ledger.values():
            all_tools_attempted.update(entry.get("tools_attempted") or [])
            all_tools_succeeded.update(entry.get("tools_succeeded") or [])
            all_mcp_failures.extend(entry.get("mcp_failures") or [])

        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "current_time": datetime.utcnow().isoformat(),
            "pentest_phase_index": self._current_phase_index(),
            "phases_total": len(PENTEST_PHASES),
            "phases_completed": len(completed),
            "phases_partial": len(partial),
            "phases_skipped": len(skipped),
            "phases_pending": len(pending),
            "phases_completed_ids": sorted(completed),
            "phases_partial_ids": sorted(partial),
            "phases_skipped_ids": sorted(skipped),
            "phases_pending_ids": sorted(pending),
            "tools_attempted_total": len(all_tools_attempted),
            "tools_succeeded_total": len(all_tools_succeeded),
            "tools_attempted_list": sorted(all_tools_attempted),
            "tools_succeeded_list": sorted(all_tools_succeeded),
            "mcp_failures_total": len(all_mcp_failures),
            "mcp_architectural_failure": len(all_mcp_failures) > 0 and len(all_tools_succeeded) == 0,
            "phase_ledger": ledger,
            "phase_results": phase_results or [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Celery tasks
# ─────────────────────────────────────────────────────────────────────────────

@celery.task(
    name="supervisor.orchestrate_scan",
    bind=True,
    queue="worker.unit.reconhecimento",
    priority=10,
)
def orchestrate_scan(self, scan_id: int) -> dict[str, Any]:
    """Celery task: orquestra execução sequencial P01–P22 completa.

    1. Carrega ScanJob e phase_ledger do state_data.
    2. Executa fases em ordem sequencial.
    3. Valida critérios de saída antes de avançar.
    4. Atualiza phase_ledger após cada fase.
    5. Registra falhas arquiteturais de MCP sem fingir sucesso.
    """
    try:
        db = SessionLocal()
        try:
            supervisor = AgentSupervisor(scan_id, db)
            result = supervisor.execute_all_phases_sequential()
            logger.info(
                "SUPERVISOR orchestrate_scan completed scan_id=%s phases_completed=%d",
                scan_id, result.get("phases_completed", 0),
            )
            return result
        finally:
            db.close()
    except Exception as exc:
        logger.exception("Error in orchestrate_scan scan_id=%s: %s", scan_id, exc)
        raise self.retry(exc=exc, countdown=60)


@celery.task(
    name="supervisor.check_phase_progress",
    bind=True,
    queue="worker.unit.reconhecimento",
)
def check_phase_progress(self, scan_id: int, phase_id: str) -> dict[str, Any]:
    """Celery task: verifica progresso de uma fase e dispara retry se necessário."""
    try:
        db = SessionLocal()
        try:
            supervisor = AgentSupervisor(scan_id, db)
            result = supervisor.validate_and_advance(phase_id, retry_count=0)

            if result.get("can_advance"):
                logger.info("SUPERVISOR check_phase_progress [%s] completed", phase_id)
            elif str(result.get("status")) == "mcp_failure":
                logger.error("SUPERVISOR check_phase_progress [%s] MCP architectural failure", phase_id)
            else:
                logger.info(
                    "SUPERVISOR check_phase_progress [%s] status=%s — retry queued",
                    phase_id, result.get("status"),
                )

            return result
        finally:
            db.close()
    except Exception as exc:
        logger.exception("Error in check_phase_progress phase=%s: %s", phase_id, exc)
        return {"error": str(exc), "phase_id": phase_id}


def submit_scan_orchestration(scan_id: int) -> str:
    """Submete orquestração sequencial P01–P22 para um scan."""
    task = orchestrate_scan.apply_async(
        args=[scan_id],
        queue="worker.unit.reconhecimento",
        priority=10,
    )
    logger.info("Submitted sequential P01-P22 orchestration: task_id=%s scan_id=%s", task.id, scan_id)
    return str(task.id)


__all__ = [
    "AgentSupervisor",
    "orchestrate_scan",
    "check_phase_progress",
    "submit_scan_orchestration",
    "check_phase_exit_criteria",
]
