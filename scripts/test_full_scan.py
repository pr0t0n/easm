#!/usr/bin/env python3
"""
Full P01-P22 offensive scan test against example.com.
Runs synchronously inside the backend container so every phase
decision is visible in real-time.

Usage (inside container):
    python /app/scripts/test_full_scan.py
"""
from __future__ import annotations

import sys
import time
import json
from datetime import datetime

sys.path.insert(0, "/app")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import ScanJob, ScanLog, User
from app.services.offensive_operator_runner import run_offensive_operator_scan
from app.services.offensive_operator_core import PHASE_ORDER, PHASE_CONTRACTS


TARGET = "example.com"
ADMIN_EMAIL = "admin@example.com"

# ── helpers ────────────────────────────────────────────────────────────────────

def _hr(char="─", width=72):
    print(char * width)

def _now():
    return datetime.now().strftime("%H:%M:%S")

def _print_phase_header(phase_id: str):
    contract = PHASE_CONTRACTS.get(phase_id, {})
    name = contract.get("name", "")
    _hr("═")
    print(f"[{_now()}]  FASE {phase_id}  {name}")
    _hr("═")

def _tail_logs(db: Session, job_id: int, after_id: int) -> int:
    rows = (
        db.query(ScanLog)
        .filter(ScanLog.scan_job_id == job_id, ScanLog.id > after_id)
        .order_by(ScanLog.id)
        .all()
    )
    for row in rows:
        prefix = f"  [{row.level:7}] [{row.source}]"
        print(f"{prefix}  {row.message[:220]}")
    return rows[-1].id if rows else after_id


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    engine = create_engine(settings.database_url)
    SessionMaker = lambda: Session(engine)  # noqa: E731

    db = SessionMaker()

    owner = db.query(User).filter(User.email == ADMIN_EMAIL).first()
    if not owner:
        print(f"ERROR: user {ADMIN_EMAIL} not found")
        sys.exit(1)

    # Create a fresh ScanJob
    job = ScanJob(
        owner_id=owner.id,
        target_query=TARGET,
        mode="unit",
        status="queued",
        compliance_status="approved",
        current_step="test runner",
        state_data={
            "execution_mode": "controlled_pentest",
            "offensive_operator_enabled": True,
        },
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    _hr("━")
    print(f"  TESTE COMPLETO P01→P22  |  alvo={TARGET}  |  job_id={job.id}")
    print(f"  Fases previstas: {len(PHASE_ORDER)}  ({', '.join(PHASE_ORDER)})")
    _hr("━")

    last_log_id = 0
    phase_results = []
    t0 = time.time()

    # Monkey-patch run_phase to print phase headers in real time
    from app.services import offensive_operator_core as core_mod

    original_run_phase = None

    class MonitoredRuntime(core_mod.OffensiveSkillRuntime):
        def run_phase(self, phase_id, *args, **kwargs):
            _print_phase_header(phase_id)
            t_phase = time.time()
            result = super().run_phase(phase_id, *args, **kwargs)
            elapsed = time.time() - t_phase
            status = result["phase_ledger"].get("status", "?")
            reason = result["validator_decision"].get("reason", "")
            can_adv = result["validator_decision"].get("can_advance", False)
            tools_ok = result["phase_ledger"].get("tools_success", [])
            tools_fail = result["phase_ledger"].get("tools_failed", [])
            tools_att = result["phase_ledger"].get("tools_attempted", [])
            print(f"\n  ▶  status={status}  can_advance={can_adv}  reason={reason}")
            print(f"     tools_attempted={tools_att}")
            print(f"     tools_success={tools_ok}  tools_failed={tools_fail}")
            print(f"     elapsed={elapsed:.1f}s")
            phase_results.append({
                "phase_id": phase_id,
                "status": status,
                "reason": reason,
                "can_advance": can_adv,
                "elapsed_s": round(elapsed, 1),
                "tools_attempted": tools_att,
                "tools_success": tools_ok,
                "tools_failed": tools_fail,
            })
            # flush DB logs since last check
            db2 = SessionMaker()
            nonlocal last_log_id
            last_log_id = _tail_logs(db2, job.id, last_log_id)
            db2.close()
            return result

    # Inject monitored runtime into the runner module
    import app.services.offensive_operator_runner as runner_mod
    from app.services.offensive_operator_core import MCPToolExecutor
    from app.services.offensive_operator_runner import _mcp_available, _call_mcp_execution

    mcp_available = _mcp_available() if settings.mcp_execute_tools_via_mcp else False
    print(f"  MCP disponível: {mcp_available}")
    print()

    # Patch OffensiveSkillRuntime inside runner_mod to use MonitoredRuntime
    original_cls = runner_mod.OffensiveSkillRuntime
    runner_mod.OffensiveSkillRuntime = MonitoredRuntime  # type: ignore[attr-defined]

    try:
        campaign = run_offensive_operator_scan(db, job, scan_mode="unit")
    except Exception as exc:
        print(f"\n[ERRO FATAL] {exc}")
        import traceback; traceback.print_exc()
        campaign = {}
    finally:
        runner_mod.OffensiveSkillRuntime = original_cls

    total_elapsed = time.time() - t0

    # ── Summary ────────────────────────────────────────────────────────────────
    _hr("═")
    print(f"  RESUMO FINAL  |  job_id={job.id}  |  status={job.status}  |  total={total_elapsed:.0f}s")
    _hr("═")
    completed = [p for p in phase_results if p["status"] == "completed"]
    partial   = [p for p in phase_results if p["status"] == "partial"]
    blocked   = [p for p in phase_results if p["status"] == "blocked"]
    skipped   = [p for p in phase_results if p["status"] not in {"completed", "partial", "blocked"}]

    print(f"  Fases executadas : {len(phase_results)}/{len(PHASE_ORDER)}")
    print(f"  ✓ completed      : {len(completed)}  → {[p['phase_id'] for p in completed]}")
    print(f"  ~ partial        : {len(partial)}   → {[p['phase_id'] for p in partial]}")
    print(f"  ✗ blocked        : {len(blocked)}   → {[p['phase_id'] for p in blocked]}")
    if skipped:
        print(f"  ? outros         : {skipped}")

    print()
    print("  DETALHES POR FASE:")
    for p in phase_results:
        icon = "✓" if p["status"] == "completed" else ("~" if p["status"] == "partial" else "✗")
        print(f"  {icon} {p['phase_id']:4}  {p['status']:10}  {p['elapsed_s']:5.1f}s  {p['reason']}")

    print()
    print(f"  mission_progress = {job.mission_progress}%")
    if campaign:
        report = campaign.get("campaign_report", {})
        if report:
            print(f"  campaign_report keys: {list(report.keys())}")

    db.close()
    print()
    _hr("━")
    print("  Teste concluido.")
    _hr("━")


if __name__ == "__main__":
    main()
