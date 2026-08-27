"""BAS schedule firing + periodic tick (celery beat), mirroring
workers/tasks.py::scheduler_tick()'s ScheduledScan -> ScanJob shape, but for
BasSchedule -> BasJob (dispatched through bas_dispatcher, never through the
generic ScanWorkItem/execute_scan_work_item queue)."""
from __future__ import annotations

import logging
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import BasAgent, BasJob, BasSchedule, Finding, ScanJob
from app.services.bas_dispatcher import dispatch_bas_technique
from app.services.bas_guardrail_policy import check_bas_authorization
from app.services.bas_technique_catalog import get_technique

logger = logging.getLogger(__name__)


def _create_shadow_scan_job(db: Session, schedule: BasSchedule, agent: BasAgent) -> ScanJob:
    # target_query must be the REAL target_hint, not a synthetic label --
    # kali_runner requires a non-empty authorized_scope on every dispatch
    # (SEC-001), and resolve_authorized_scope_for_dispatch derives that scope
    # from this ScanJob's target_query via authorized_scope_from_target_query.
    # A label like "bas:schedule#1" parses to no valid root at all, so every
    # dispatch through this shadow job would fail closed with 400. When
    # target_hint is blank (range-only schedule), fall back to the agent's
    # own self-reported network -- same value fire_schedule below will use
    # as the actual per-technique target -- so authorized_scope agrees with
    # what's really being dispatched instead of a meaningless placeholder.
    target_query = (
        schedule.target_hint
        or agent.local_network_cidr
        or f"bas-unset-target-schedule-{schedule.id}"
    )
    shadow = ScanJob(
        owner_id=schedule.owner_id,
        access_group_id=schedule.access_group_id,
        target_query=target_query,
        mode="bas",
        status="running",
    )
    db.add(shadow)
    db.flush()
    return shadow


def _split_targets(target_hint: str, fallback: str) -> list[str]:
    """Same split regex as scan_scope.authorized_scope_from_target_query, so
    the per-target dispatch loop below and the shadow ScanJob's derived
    authorized_scope always agree on the same set of targets. A schedule's
    target_hint can now be a single target (unchanged behavior) or a
    comma/semicolon/newline-separated list -- one BasJob per (technique,
    target) pair either way."""
    pieces = [p.strip() for p in re.split(r"[,;\n]+", str(target_hint or "")) if p.strip()]
    return pieces or [fallback]


_MAX_HOST_FANOUT = 256


def _cidr_hosts(value: str) -> tuple[list[str] | None, str | None]:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None, None
    if network.num_addresses <= 1:
        return [str(network.network_address)], None
    if network.num_addresses > _MAX_HOST_FANOUT:
        return None, f"network_fanout_too_large:{network.num_addresses}_hosts_max_{_MAX_HOST_FANOUT}"
    return [str(ip) for ip in network.hosts()], None


def _targets_for_technique(base_target: str, technique: dict[str, Any], *, target_was_defaulted: bool) -> tuple[list[str], str | None]:
    if technique.get("accepts_range"):
        return [base_target], None
    target_format = str(technique.get("target_format") or "host")
    if target_format not in {"host", "host_port"}:
        if target_was_defaulted:
            return [], f"target_format_requires_explicit_target:{target_format}"
        return [base_target], None
    hosts, error = _cidr_hosts(base_target)
    if error:
        return [], error
    if hosts:
        return hosts, None
    return [base_target], None


def _extract_key_findings(technique_key: str, category: str, result: dict[str, Any]) -> list[str]:
    """Pulls the actually meaningful lines out of a real tool's raw stdout
    instead of leaving the report to show just a title/status -- this is
    what "mostrar as vulnerabilidades" needs: what the tool actually
    observed, not that it merely ran. Deliberately conservative/best-effort
    per output shape; falls back to a short, honest "no signal" message
    rather than guessing when a tool's output doesn't match any known
    pattern here."""
    if technique_key in ("port_service_scan", "firewall_segmentation_test"):
        open_ports = result.get("open_ports") or []
        if isinstance(open_ports, list) and open_ports:
            findings = []
            for item in open_ports[:50]:
                if not isinstance(item, dict):
                    continue
                host = str(item.get("host") or item.get("ip") or item.get("target") or "").strip()
                port = str(item.get("port") or "").strip()
                protocol = str(item.get("protocol") or "tcp").strip()
                service = str(item.get("service") or item.get("name") or "").strip()
                if host and port:
                    findings.append(f"{host}: {port}/{protocol} open {service}".strip())
            if findings:
                return findings
        summary = result.get("nmap_summary") or {}
        if isinstance(summary, dict) and summary:
            scanned = summary.get("ip_addresses") or summary.get("reported_hosts") or 0
            hosts_up = summary.get("hosts_up") or summary.get("reported_hosts") or 0
            return [f"Nmap concluiu sem portas abertas: {scanned} IP(s) varrido(s), {hosts_up} host(s) tratado(s) como ativo(s)."]

    stdout = str(result.get("stdout") or "")
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return []

    if technique_key == "owasp_web_app_scan":
        return [ln for ln in lines if ln.startswith("+ [")][:15]
    if technique_key == "smb_enum_cme":
        return [ln for ln in lines if ln.startswith("SMB") and ("(signing:False)" in ln or "(SMBv1:True)" in ln)][:50]
    if technique_key in ("port_service_scan", "firewall_segmentation_test"):
        # These two accept_range techniques run nmap against a whole CIDR in
        # one invocation -- its stdout only prints "Nmap scan report for
        # <host>" once per host, then a bare PORT/STATE/SERVICE table with no
        # host repeated per line. Filtering on "open" alone (the old
        # single-host-only behavior) would flatten a multi-host result into
        # an indistinguishable list of ports with no idea which host each
        # belongs to -- track the most recent host header and prefix it in.
        current_host = ""
        findings: list[str] = []
        for ln in lines:
            if ln.lower().startswith("nmap scan report for"):
                current_host = ln[len("Nmap scan report for "):].strip()
                continue
            if "open" in ln.lower() and "/tcp" in ln:
                findings.append(f"{current_host}: {ln}" if current_host else ln)
        return findings[:50]
    if technique_key == "network_share_discovery":
        return [ln for ln in lines if "open" in ln.lower() and "share" in ln.lower()][:15]
    if technique_key in ("pipeline_secrets_harvesting", "source_code_secrets_scan"):
        hits = [ln for ln in lines if not ln.upper().startswith("EXIT_CODE") and "no leaks found" not in ln.lower()]
        return hits[:15]
    if technique_key == "netlogon_zerologon_check":
        return [ln for ln in lines if "vulnerable" in ln.lower()][:5]
    # Generic fallback: last few non-boilerplate lines, so the report never
    # shows literally nothing for a technique with no dedicated extractor.
    return [ln for ln in lines if not ln.upper().startswith("EXIT_CODE")][-5:]


def _derive_severity(technique_key: str, key_findings: list[str]) -> str:
    """Real content in, real severity out -- never a blanket "info" once
    there's an actual positive signal in what the tool observed. Stays
    "info" (no issue found / nothing to escalate) when key_findings is
    empty or the technique has no severity-worthy signal defined here."""
    if not key_findings:
        return "info"
    if technique_key == "netlogon_zerologon_check":
        return "critical"  # a real, unauthenticated domain-controller takeover primitive
    if technique_key == "smb_enum_cme":
        if any("(SMBv1:True)" in ln for ln in key_findings):
            return "high"
        if any("(signing:False)" in ln for ln in key_findings):
            return "medium"
        return "low"
    if technique_key in ("pipeline_secrets_harvesting", "source_code_secrets_scan"):
        return "high"  # a real exposed credential/token
    if technique_key == "owasp_web_app_scan":
        return "medium"  # real misconfiguration-class findings (headers, CORS, etc.)
    if technique_key in ("port_service_scan", "firewall_segmentation_test", "network_share_discovery"):
        if all(str(ln).startswith("Nmap concluiu sem portas abertas") for ln in key_findings):
            return "info"
        return "low"  # real reachability/exposure, not itself a vulnerability
    return "info"


def _finding_from_job_result(
    db: Session, job: BasJob, schedule: BasSchedule, technique: dict[str, Any], agent: BasAgent,
) -> Finding | None:
    """`simulated` (and everything that follows from it -- score/attack-path
    counting, bas_exclusion.py's aggregation filter, the UI's "SIMULADO"
    badge) is keyed off `agent.kind`, never a blanket constant: a stub-kind
    agent (bas_agent_stub) always fabricates its tunnel's response content,
    but a real-kind agent (cryptographically proven via its CA-signed mTLS
    cert -- see bas_ca.py) actually relayed to a real destination, so its
    result is real and counts like any other Finding."""
    result = job.result or {}
    is_stub = agent.kind != "real"
    # Real content in, real severity/findings out -- a stub dispatch never
    # had real content to begin with, so it never gets to claim a real
    # vulnerability was observed regardless of what its canned text says.
    key_findings = [] if is_stub else _extract_key_findings(technique["technique_key"], technique["category"], result)
    severity = "info" if is_stub else _derive_severity(technique["technique_key"], key_findings)
    finding = Finding(
        scan_job_id=job.scan_job_id,
        title=f"BAS: {technique['display_name']}" + (" (simulado)" if is_stub else ""),
        severity=severity,
        tool="bas-agent",
        verification_status="hypothesis",
        confidence_score=min(20, 20),
        details={
            "source_module": "bas",
            "simulated": is_stub,
            "counts_towards_score": not is_stub,
            "counts_towards_attack_path": not is_stub,
            "bas_job_id": job.id,
            "bas_schedule_id": schedule.id,
            "target": job.target,
            "bas_agent_id": agent.id,
            "bas_agent_kind": agent.kind,
            "technique_key": technique["technique_key"],
            "category": technique["category"],
            "mode": technique["mode"],
            "risk_tier": technique["risk_tier"],
            "mitre_refs": technique.get("mitre_refs", []),
            "recommendation": technique.get("recommendation", ""),
            "key_findings": key_findings,
            "phase": "phase_1_stub" if is_stub else "real_agent",
            "command": result.get("command"),
            "status": result.get("status"),
        },
    )
    db.add(finding)
    db.flush()
    return finding


def fire_schedule(db: Session, schedule: BasSchedule) -> dict[str, Any]:
    """Runs every technique in a schedule right now: creates a shadow
    ScanJob, dispatches each authorized technique through bas_dispatcher,
    persists the (stub) result as a Finding, and updates last_run_at."""
    agent = db.query(BasAgent).filter(BasAgent.id == schedule.agent_id).first()
    if not agent:
        return {"error": "agent_not_found"}

    job_ids: list[int] = []
    skipped: list[dict[str, str]] = []

    target_was_defaulted = not bool(schedule.target_hint and schedule.target_hint.strip())
    if not target_was_defaulted:
        targets = _split_targets(schedule.target_hint, agent.hostname or "internal-target")
    elif agent.local_network_cidr:
        targets = [agent.local_network_cidr]
    else:
        # Agent has never reported its network (binary predates this
        # capability, or hasn't sent a heartbeat yet) -- never guess or fall
        # back to a meaningless placeholder; skip every technique with a
        # clear, actionable reason instead of a silent/garbled dispatch.
        for technique_key in schedule.technique_keys:
            skipped.append({
                "technique_key": technique_key, "target": "",
                "reason": "agent_network_unknown_send_a_heartbeat_first",
            })
        schedule.last_run_at = datetime.now()
        db.commit()
        return {"scan_job_id": None, "job_ids": [], "skipped": skipped}

    shadow = _create_shadow_scan_job(db, schedule, agent)
    # Commit (not just flush) before any dispatch: resolve_authorized_scope_
    # for_dispatch opens its OWN SessionLocal() to read this ScanJob by id --
    # a separate connection can't see a row this transaction has only
    # flushed, so every dispatch would fail closed with "authorized_scope is
    # required" until this row is actually committed.
    db.commit()

    for target in targets:
        run_targets = [target]
        selected_techniques = [get_technique(key) for key in schedule.technique_keys]
        all_host_based = bool(selected_techniques) and all(
            technique is not None
            and not technique.get("accepts_range")
            and str(technique.get("target_format") or "host") in {"host", "host_port"}
            for technique in selected_techniques
        )
        if target_was_defaulted and all_host_based:
            hosts, target_error = _cidr_hosts(target)
            if target_error:
                for technique_key in schedule.technique_keys:
                    skipped.append({"technique_key": technique_key, "target": target, "reason": target_error})
                continue
            if hosts:
                run_targets = hosts

        for run_target in run_targets:
            for technique_key in schedule.technique_keys:
                technique = get_technique(technique_key)
                if technique is None:
                    skipped.append({"technique_key": technique_key, "target": run_target, "reason": "unknown_technique"})
                    continue
                decision = check_bas_authorization(schedule, technique_key)
                if not decision["allowed"]:
                    skipped.append({"technique_key": technique_key, "target": run_target, "reason": decision["reason"]})
                    logger.info(
                        "bas_scheduler: skipped technique=%s target=%s reason=%s schedule=%s",
                        technique_key, run_target, decision["reason"], schedule.id,
                    )
                    continue

                dispatch_targets, target_error = _targets_for_technique(
                    run_target, technique, target_was_defaulted=target_was_defaulted,
                )
                if target_error:
                    skipped.append({"technique_key": technique_key, "target": run_target, "reason": target_error})
                    continue

                stop_current_target = False
                for dispatch_target in dispatch_targets:
                    job = BasJob(
                        schedule_id=schedule.id,
                        agent_id=agent.id,
                        owner_id=schedule.owner_id,
                        access_group_id=schedule.access_group_id,
                        scan_job_id=shadow.id,
                        technique_key=technique_key,
                        target=dispatch_target,
                        risk_tier=technique["risk_tier"],
                        status="dispatched_to_kali",
                        dispatched_at=datetime.now(),
                    )
                    db.add(job)
                    db.commit()

                    outcome = dispatch_bas_technique(
                        technique_key=technique_key,
                        target_hint=dispatch_target,
                        bas_agent=agent,
                        scan_id=shadow.id,
                        schedule=schedule,
                    )
                    if not outcome["dispatched"]:
                        job.status = "skipped"
                        job.last_error = outcome["reason"]
                        job.finished_at = datetime.now()
                        db.commit()
                        skipped.append({"technique_key": technique_key, "target": dispatch_target, "reason": outcome["reason"]})
                        continue

                    result = outcome["result"]
                    job.kali_job_id = str(result.get("dispatch_task_id") or "")
                    job.result = result
                    job.status = "completed" if result.get("status") == "executed" else "failed"
                    job.last_error = None if job.status == "completed" else str(result.get("stderr") or result.get("error") or "")[:2000]
                    job.finished_at = datetime.now()
                    db.flush()

                    finding = _finding_from_job_result(db, job, schedule, technique, agent)
                    if finding:
                        job.finding_id = finding.id
                    job_ids.append(job.id)
                    db.commit()

                    if schedule.stop_on_failure and job.status == "failed":
                        remaining = schedule.technique_keys[schedule.technique_keys.index(technique_key) + 1:]
                        for remaining_key in remaining:
                            skipped.append({"technique_key": remaining_key, "target": dispatch_target, "reason": "chain_stopped_after_failure"})
                        logger.info(
                            "bas_scheduler: chain stopped after technique=%s failed for target=%s, skipping %d remaining step(s) for this target, schedule=%s",
                            technique_key, dispatch_target, len(remaining), schedule.id,
                        )
                        stop_current_target = True
                        break
                if stop_current_target:
                    break

    shadow.status = "completed"
    schedule.last_run_at = datetime.now()
    db.commit()

    return {"scan_job_id": shadow.id, "job_ids": job_ids, "skipped": skipped}


_FREQUENCY_MINUTES = {
    "every_3_hours": 180,
    "every_6_hours": 360,
    "every_12_hours": 720,
}


def _is_due(schedule: BasSchedule, now: datetime) -> bool:
    if schedule.frequency in _FREQUENCY_MINUTES:
        if not schedule.last_run_at:
            return True
        return now >= schedule.last_run_at + timedelta(minutes=_FREQUENCY_MINUTES[schedule.frequency])

    try:
        run_hour, run_minute = (int(part) for part in str(schedule.run_time or "00:00").split(":", 1))
    except ValueError:
        run_hour, run_minute = 0, 0
    if now.hour != run_hour or now.minute != run_minute:
        return False
    if schedule.last_run_at and schedule.last_run_at.date() == now.date():
        return False  # already fired this slot today

    if schedule.frequency == "daily":
        return True
    if schedule.frequency == "weekly":
        return str(schedule.day_of_week or "").lower() == now.strftime("%A").lower()
    if schedule.frequency == "monthly":
        return schedule.day_of_month == now.day
    return False


def bas_scheduler_tick(db: Session) -> dict[str, Any]:
    """Celery-beat entry point (registered as task "bas_scheduler.tick" in
    workers/tasks.py). Mirrors scheduler_tick()'s due-check/idempotency
    logic 1:1 against BasSchedule instead of ScheduledScan."""
    now = datetime.now()
    fired = 0
    for schedule in db.query(BasSchedule).filter(BasSchedule.enabled.is_(True)).all():
        if not _is_due(schedule, now):
            continue
        fire_schedule(db, schedule)
        fired += 1
    return {"ok": True, "fired": fired, "checked_at": now.isoformat()}


_HEARTBEAT_STALE_MINUTES = 5
_JOB_STUCK_MINUTES = 15


def bas_watchdog_tick(db: Session) -> dict[str, Any]:
    """Mirrors the existing kali watchdog's recovery pattern: mark stale
    agents offline, and fail BasJob rows stuck past a reasonable timeout
    instead of leaving them silently hung forever."""
    now = datetime.now()
    stale_cutoff = now - timedelta(minutes=_HEARTBEAT_STALE_MINUTES)
    marked_offline = (
        db.query(BasAgent)
        .filter(BasAgent.status == "online", BasAgent.last_heartbeat_at < stale_cutoff)
        .update({"status": "offline"}, synchronize_session=False)
    )

    stuck_cutoff = now - timedelta(minutes=_JOB_STUCK_MINUTES)
    stuck_jobs = (
        db.query(BasJob)
        .filter(BasJob.status.in_(["queued", "dispatched_to_kali", "running"]), BasJob.created_at < stuck_cutoff)
        .all()
    )
    for job in stuck_jobs:
        job.status = "failed"
        job.last_error = "tunnel_timeout"
        job.finished_at = now
    db.commit()

    return {"ok": True, "agents_marked_offline": marked_offline, "jobs_failed": len(stuck_jobs)}
