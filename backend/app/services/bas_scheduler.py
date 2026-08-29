"""BAS schedule firing + periodic tick (celery beat), mirroring
workers/tasks.py::scheduler_tick()'s ScheduledScan -> ScanJob shape, but for
BasSchedule -> BasJob (dispatched through bas_dispatcher, never through the
generic ScanWorkItem/execute_scan_work_item queue)."""
from __future__ import annotations

import logging
import re
import ipaddress
import shlex
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.models import BasAgent, BasJob, BasSchedule, Finding, ScanJob
from app.services.bas_dispatcher import dispatch_bas_technique
from app.services.bas_guardrail_policy import check_bas_authorization
from app.services.bas_proof import build_bas_proof
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


def _cidr_hosts(value: str) -> tuple[list[str] | None, str | None]:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None, None
    if network.num_addresses <= 1:
        return [str(network.network_address)], None
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


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")

_FAILURE_ONLY_MARKERS = (
    "could not", "timed out", "timeout", "aborting", "connection refused",
    "no route to host", "connection reset", "unreachable", "failed to connect",
    "no answer", "host is down", "network is unreachable", "socket error",
)


def _is_failure_only_output(lines: list[str]) -> bool:
    """True when every substantive line is just the tool reporting it
    couldn't reach/observe anything (a timeout, a refused connection, an
    aborted probe) -- never real content about the target. A tool's own
    "nothing here" banner (e.g. enum4linux-ng's "Could not get NetBIOS
    names... timed out" / "Aborting remainder of tests since neither SMB
    nor LDAP are accessible") is not a finding, even though it's the only
    output the tool produced."""
    if not lines:
        return True
    return all(any(marker in ln.lower() for marker in _FAILURE_ONLY_MARKERS) for ln in lines)


def _extract_nmap_command_ports(command: str) -> str:
    try:
        parts = shlex.split(str(command or ""))
    except ValueError:
        parts = str(command or "").split()
    for idx, part in enumerate(parts):
        if part == "-p" and idx + 1 < len(parts):
            return parts[idx + 1].strip()
        if part.startswith("-p") and len(part) > 2:
            return part[2:].strip()
    return ""


def _extract_nmap_done_line(stdout: str) -> str:
    for line in str(stdout or "").splitlines():
        clean = line.strip()
        if clean.startswith("Nmap done:"):
            return clean
    return ""


def _extract_proxychains_summary(stderr: str) -> str:
    attempts = 0
    samples: list[str] = []
    for line in str(stderr or "").splitlines():
        if "Dynamic chain" not in line:
            continue
        endpoints = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}:\d+", line)
        if not endpoints:
            continue
        attempts += 1
        endpoint = endpoints[-1]
        if endpoint not in samples and len(samples) < 8:
            samples.append(endpoint)
    if not attempts:
        return ""
    sample_text = f"; amostras: {', '.join(samples)}" if samples else ""
    return f"Túnel BAS/proxychains: {attempts} tentativa(s) TCP via relay{sample_text}."


def _port_scan_observation_lines(result: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    target = str(result.get("target") or "").strip()
    command = str(result.get("command") or "").strip()
    if target:
        findings.append(f"Alvo varrido: {target}")
    ports = _extract_nmap_command_ports(command)
    if ports:
        findings.append(f"Portas TCP testadas: {ports}")
    summary = result.get("nmap_summary") or {}
    if isinstance(summary, dict) and summary:
        scanned = summary.get("ip_addresses") or summary.get("reported_hosts") or 0
        hosts_up = summary.get("hosts_up") or summary.get("reported_hosts") or 0
        duration = summary.get("duration_seconds")
        duration_text = f", duração {duration}s" if duration not in (None, "") else ""
        findings.append(f"Resumo nmap: {scanned} IP(s) varrido(s), {hosts_up} host(s) tratados como ativos pelo -Pn{duration_text}.")
    open_ports = result.get("open_ports") or []
    if isinstance(open_ports, list) and open_ports:
        for item in open_ports[:50]:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or item.get("ip") or item.get("target") or "").strip()
            port = str(item.get("port") or "").strip()
            protocol = str(item.get("protocol") or "tcp").strip()
            service = str(item.get("service") or item.get("name") or "").strip()
            if host and port:
                findings.append(f"{host}: {port}/{protocol} open {service}".strip())
    elif summary:
        findings.append("Nenhuma das portas TCP BAS foi observada aberta no alvo.")
    done_line = _extract_nmap_done_line(str(result.get("stdout") or ""))
    if done_line:
        findings.append(f"Saída nmap: {done_line}")
    proxy_summary = _extract_proxychains_summary(str(result.get("stderr") or ""))
    if proxy_summary:
        findings.append(proxy_summary)
    if command:
        findings.append(f"Comando executado: {command}")
    return findings[:60]


def _is_port_scan_no_open_observation(key_findings: list[str]) -> bool:
    return bool(key_findings) and any(
        str(ln).startswith("Nenhuma das portas TCP BAS foi observada aberta")
        or str(ln).startswith("Nmap concluiu sem portas abertas")
        for ln in key_findings
    )


def _extract_key_findings(technique_key: str, category: str, result: dict[str, Any]) -> list[str]:
    """Pulls the actually meaningful lines out of a real tool's raw stdout
    instead of leaving the report to show just a title/status -- this is
    what "mostrar as vulnerabilidades" needs: what the tool actually
    observed, not that it merely ran. Deliberately conservative/best-effort
    per output shape; falls back to a short, honest "no signal" message
    rather than guessing when a tool's output doesn't match any known
    pattern here."""
    if technique_key in ("port_service_scan", "firewall_segmentation_test"):
        findings = _port_scan_observation_lines(result)
        if findings:
            return findings

    stdout = str(result.get("stdout") or "")
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    if not lines:
        return []

    if technique_key in ("owasp_web_app_scan", "controlled_exploit_validation"):
        return [ln for ln in lines if ln.startswith("+ [")][:15]
    if technique_key in ("smb_enum_cme", "safe_credential_checks"):
        return [ln for ln in lines if ln.startswith("SMB") and ("(signing:False)" in ln or "(SMBv1:True)" in ln)][:50]
    if technique_key in ("port_service_scan", "firewall_segmentation_test", "lateral_movement_simulation_safe"):
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
    if technique_key == "smb_enum_enum4linux":
        # enum4linux-ng marks every line it prints with a colored [+]
        # (something was actually retrieved), [-] (that specific probe
        # failed), or [!] (a warning/abort) -- only [+] lines are a real
        # observation about the target. Without this, an unreachable host's
        # "[-] Could not get NetBIOS names... [!] Aborting remainder of
        # tests since neither SMB nor LDAP are accessible" banner (the ONLY
        # output for the overwhelming majority of hosts in a network sweep)
        # fell through to the generic fallback below and was surfaced as a
        # "confirmed" finding for every single one of them (live 2026-08-28).
        clean_lines = [_ANSI_ESCAPE_RE.sub("", ln) for ln in lines]
        return [ln for ln in clean_lines if ln.startswith("[+]")][:20]
    if technique_key in ("pipeline_secrets_harvesting", "source_code_secrets_scan"):
        hits = [ln for ln in lines if not ln.upper().startswith("EXIT_CODE") and "no leaks found" not in ln.lower()]
        return hits[:15]
    if technique_key == "netlogon_zerologon_check":
        return [ln for ln in lines if "vulnerable" in ln.lower()][:5]
    if technique_key in ("cloud_directory_scouting", "azure_entra_id_discovery", "m365_tenant_exposure_check"):
        cloud_hits = [ln for ln in lines if any(token in ln.lower() for token in ("tenant", "federation", "managed", "namespace", "cloud", "microsoft", "azure", "entra"))][:15]
        if cloud_hits:
            return cloud_hits
        fallback_tail = [ln for ln in lines if not ln.upper().startswith("EXIT_CODE")][:5]
        return [] if _is_failure_only_output(fallback_tail) else fallback_tail
    # Generic fallback: last few non-boilerplate lines, so the report never
    # shows literally nothing for a technique with no dedicated extractor --
    # but never when those lines are just the tool reporting it couldn't
    # reach/observe anything at all (a timeout/refused/aborted probe is not
    # itself a finding about the target -- before this check it was
    # surfaced as one for every unreachable host in a network-wide sweep,
    # live 2026-08-28).
    tail = [ln for ln in lines if not ln.upper().startswith("EXIT_CODE")][-5:]
    return [] if _is_failure_only_output(tail) else tail


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
    if technique_key in ("port_service_scan", "firewall_segmentation_test", "network_share_discovery", "lateral_movement_simulation_safe"):
        if _is_port_scan_no_open_observation(key_findings):
            return "info"
        return "low"  # real reachability/exposure, not itself a vulnerability
    if technique_key == "safe_credential_checks":
        return "medium"
    if technique_key == "smb_enum_enum4linux":
        return "medium"  # anonymous/null-session SMB or AD enumeration actually succeeded
    if technique_key == "controlled_exploit_validation":
        return "medium"
    if technique_key in ("cloud_directory_scouting", "azure_entra_id_discovery", "m365_tenant_exposure_check"):
        return "info"
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
    proof = build_bas_proof(
        technique=technique, job=job, agent=agent, result=result, key_findings=key_findings, severity=severity,
    )
    counts = bool(proof.get("valid"))
    job_result = dict(result)
    job_result["bas_proof"] = proof
    job.result = job_result
    if not key_findings:
        # No real content in, no Finding out. Before this gate, EVERY
        # dispatch materialized a "BAS: <technique>" Finding regardless of
        # whether anything was observed -- a host-based technique fanned out
        # over a large network turned that into hundreds of info-severity
        # rows for plain connection failures/timeouts (key_findings always
        # empty for those), drowning out the real signal in the
        # Vulnerabilidades tab and reading like a scan execution log rather
        # than actual findings (user report, 2026-08-28). A stub agent's
        # key_findings is always [] by construction (never allowed to claim
        # a real observation), so this also means stub dispatches no longer
        # produce placeholder Findings -- the BasJob row remains the
        # execution record either way; only real, non-empty signal
        # (open ports found, secrets found, vulnerable state confirmed, etc.)
        # becomes a Finding now.
        return None
    finding = Finding(
        scan_job_id=job.scan_job_id,
        title=f"BAS: {technique['display_name']}" + (" (simulado)" if is_stub else ""),
        severity=severity,
        tool="bas-agent",
        verification_status="confirmed" if counts else "hypothesis",
        confidence_score=90 if counts else 20,
        details={
            "source_module": "bas",
            "simulated": is_stub,
            "counts_towards_score": counts,
            "counts_towards_attack_path": counts,
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
            "proof": proof,
            "proof_status": proof.get("status"),
        },
    )
    db.add(finding)
    db.flush()
    return finding


def _resolve_run_targets(schedule: BasSchedule, agent: BasAgent) -> dict[str, Any]:
    """Target-resolution logic shared by a fresh run (prepare_schedule_run)
    and a resumed one (resume_schedule_run) -- deterministic from the
    schedule's target_hint / the agent's self-reported network, so there's
    nothing to persist for a resume to recover; recomputing it is enough."""
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
        return {"targets": None, "target_was_defaulted": target_was_defaulted, "skipped": skipped}
    return {"targets": targets, "target_was_defaulted": target_was_defaulted, "skipped": skipped}


def prepare_schedule_run(db: Session, schedule: BasSchedule) -> dict[str, Any]:
    """First (fast, synchronous) half of firing a schedule: resolves targets
    and creates+commits the shadow ScanJob, so an HTTP caller (run-now) gets
    a scan_job_id back immediately instead of blocking on the actual
    dispatch loop below, which can take minutes (real Kali tools over the
    tunnel, one technique at a time). execute_schedule_run does the rest,
    off the request thread."""
    agent = db.query(BasAgent).filter(BasAgent.id == schedule.agent_id).first()
    if not agent:
        return {"error": "agent_not_found"}

    resolved = _resolve_run_targets(schedule, agent)
    if resolved["targets"] is None:
        schedule.last_run_at = datetime.now()
        db.commit()
        return {"scan_job_id": None, "job_ids": [], "skipped": resolved["skipped"], "queued": False}

    shadow = _create_shadow_scan_job(db, schedule, agent)
    shadow.current_step = "Preparando execução"
    shadow.state_data = {
        **dict(shadow.state_data or {}),
        "bas_schedule_id": schedule.id,
        "bas_agent_id": agent.id,
        "bas_chain_key": getattr(schedule, "chain_key", None),
        "bas_technique_keys": list(schedule.technique_keys or []),
    }
    # Commit (not just flush) before any dispatch: resolve_authorized_scope_
    # for_dispatch opens its OWN SessionLocal() to read this ScanJob by id --
    # a separate connection can't see a row this transaction has only
    # flushed, so every dispatch would fail closed with "authorized_scope is
    # required" until this row is actually committed.
    db.commit()

    return {
        "scan_job_id": shadow.id,
        "targets": resolved["targets"],
        "target_was_defaulted": resolved["target_was_defaulted"],
        "skipped": resolved["skipped"],
        "queued": True,
    }


def resume_schedule_run(db: Session, schedule: BasSchedule, scan_job_id: int) -> dict[str, Any]:
    """Resumes a stopped run instead of starting a new one: reuses the SAME
    shadow ScanJob (its BasJob history stays attached to one scan_job_id --
    a resume is the same test continuing, not a new one) and flips it back
    to "running". execute_schedule_run's own per-dispatch idempotency check
    (skip a (technique, target) pair that already has a terminal BasJob for
    this scan_job_id) is what actually avoids redoing work already done;
    this only re-arms the shadow job and re-resolves targets."""
    agent = db.query(BasAgent).filter(BasAgent.id == schedule.agent_id).first()
    shadow = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
    if not agent or not shadow:
        return {"error": "agent_or_shadow_not_found"}
    if str(shadow.status or "").lower() != "stopped":
        return {"error": "not_stopped"}

    resolved = _resolve_run_targets(schedule, agent)
    if resolved["targets"] is None:
        return {"error": "agent_network_unknown", "skipped": resolved["skipped"]}

    shadow.status = "running"
    shadow.current_step = "Retomando execução…"
    db.commit()

    return {
        "scan_job_id": shadow.id,
        "targets": resolved["targets"],
        "target_was_defaulted": resolved["target_was_defaulted"],
        "skipped": resolved["skipped"],
        "queued": True,
    }


_PORT_SCAN_CHUNK_HOSTS = 16


def _all_chunk_addresses(chunk: str) -> list[str]:
    """Every address in a port-scan chunk, including its own network/
    broadcast addresses -- unlike _cidr_hosts (which excludes those as
    "not independently usable hosts"), a chunk's network/broadcast address
    can be an ordinary mid-range host of the LARGER CIDR it was split from
    (e.g. 10.10.0.255 is just a normal host in 10.10.0.0/23, even though
    it's chunk 10.10.0.0/24's own broadcast address) -- known_hosts must
    match the same host list the per-technique fanout (_cidr_hosts on the
    ORIGINAL, unchunked target) will actually dispatch against."""
    try:
        return [str(ip) for ip in ipaddress.ip_network(str(chunk or "").strip(), strict=False)]
    except ValueError:
        return [chunk]


def _port_scan_chunks(target: str) -> list[str]:
    """Splits a large CIDR into fixed-size /28-equivalent chunks (16
    addresses each) so the mandatory port-scan pre-req reports back --
    and the shadow ScanJob's progress/CMDB -- incrementally, chunk by
    chunk, instead of the whole run sitting at 0% with nothing to show
    until one monolithic scan of the entire range finishes (confirmed
    live 2026-08-28: a /20 in a single dispatch left the CMDB view empty
    with zero visible progress for over 30 minutes). A single host or an
    already-small range is returned unchanged -- one "chunk"."""
    try:
        network = ipaddress.ip_network(str(target or "").strip(), strict=False)
    except ValueError:
        return [target]
    if network.num_addresses <= _PORT_SCAN_CHUNK_HOSTS:
        return [target]
    new_prefix = 32 - (_PORT_SCAN_CHUNK_HOSTS - 1).bit_length()
    try:
        return [str(sub) for sub in network.subnets(new_prefix=new_prefix)]
    except ValueError:
        return [target]


def _port_scan_max_wait(target: str) -> int:
    """How long to let the mandatory port_service_scan pre-req run before
    giving up. execute_via_kali's own default (1800s) is what a single
    proxychains-tunneled nmap invocation was silently capped to regardless
    of the profile's own declared timeout -- fine for a single host, but a
    real /20 (~4094 hosts) was still under 10% done at that mark (confirmed
    live 2026-08-28). Scales with the target's host count instead of
    assuming one size fits every network mask; capped so a genuinely dead
    dispatch doesn't hang forever."""
    try:
        network = ipaddress.ip_network(str(target or "").strip(), strict=False)
    except ValueError:
        return 60
    return max(60, min(300, network.num_addresses * 4))


def _open_ports_by_host(result: dict[str, Any]) -> dict[str, set[int]]:
    """Builds a host -> {open TCP ports} map from a port_service_scan
    dispatch's result -- the CMDB signal later host-based techniques gate
    on (technique['required_ports']) instead of blindly enumerating LDAP/
    SMB/AD state on every address in a network mask regardless of whether
    anything is even listening there."""
    by_host: dict[str, set[int]] = {}
    for entry in result.get("open_ports") or []:
        if not isinstance(entry, dict):
            continue
        host = str(entry.get("host") or "").strip()
        port = entry.get("port")
        if not host or port is None:
            continue
        try:
            by_host.setdefault(host, set()).add(int(port))
        except (TypeError, ValueError):
            continue
    return by_host


def _run_was_stopped(db: Session, scan_job_id: int) -> bool:
    """Cooperative-cancellation check for execute_schedule_run's dispatch
    loop. A raw scalar read against the row -- not the already-loaded
    `shadow` ORM object -- so an UPDATE committed by the stop endpoint's own
    request/session is seen immediately instead of sitting behind
    SQLAlchemy's identity map for this long-lived session."""
    row = db.execute(text("SELECT status FROM scan_jobs WHERE id = :id"), {"id": scan_job_id}).first()
    return bool(row) and str(row[0]) == "stopped"


def execute_schedule_run(
    db: Session,
    schedule: BasSchedule,
    scan_job_id: int,
    targets: list[str],
    target_was_defaulted: bool,
    skipped: list[dict[str, str]],
) -> dict[str, Any]:
    """Second half of firing a schedule: dispatches each authorized technique
    through bas_dispatcher against the shadow ScanJob `scan_job_id` already
    created by prepare_schedule_run, persists the (stub) result as a
    Finding, and updates last_run_at. Runs off the request thread (celery)
    when triggered from run-now, so it also keeps `scan_job_id`'s
    current_step/mission_progress current as it goes -- the same fields
    GET /api/scans/{id}/status already exposes for regular pentest scans --
    so a poller can show which technique/target is running right now and
    roughly how far along the run is."""
    agent = db.query(BasAgent).filter(BasAgent.id == schedule.agent_id).first()
    shadow = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
    if not agent or not shadow:
        return {"error": "agent_or_shadow_not_found"}

    # port_service_scan is a mandatory pre-req now, not an optional pick --
    # it always runs first for every target regardless of what's in
    # technique_keys (explicit user decision, 2026-08-28: don't test every
    # host in a network mask for LDAP/SMB/AD without first confirming via
    # CMDB/port scan that the relevant port is even open there). Filter it
    # out of the iterated list so an older schedule that still has it saved
    # explicitly doesn't dispatch it twice.
    effective_technique_keys = [k for k in schedule.technique_keys if k != "port_service_scan"]

    # Chunked upfront so progress/CMDB fills in incrementally chunk-by-chunk
    # instead of the whole run sitting at 0% with nothing to show until one
    # monolithic scan of an entire large network finishes (confirmed live
    # 2026-08-28: a /20 in a single dispatch left the CMDB view empty, no
    # visible progress, for 30+ minutes). Computed once here so total_units
    # below can count each chunk as its own unit.
    port_scan_chunks_by_target = {t: _port_scan_chunks(t) for t in targets}

    job_ids: list[int] = []
    total_units = max(
        1,
        sum(len(port_scan_chunks_by_target[t]) for t in targets) + len(targets) * len(effective_technique_keys),
    )
    completed_units = 0
    cancelled = False

    for target in targets:
        if cancelled:
            break

        # known_hosts: hosts whose chunk's port scan genuinely completed --
        # gated techniques below trust an absence from open_ports_by_host for
        # these (really means "nothing open"). A host NOT in known_hosts
        # (its chunk failed/timed out/was skipped) is unknown, not confirmed
        # closed -- gating falls back to testing it, per host, rather than
        # silently skipping real testing because ONE chunk out of many never
        # got an answer.
        open_ports_by_host: dict[str, set[int]] = {}
        known_hosts: set[str] = set()
        port_scan_technique = get_technique("port_service_scan")
        chunks = port_scan_chunks_by_target[target]

        for chunk in chunks:
            if _run_was_stopped(db, shadow.id):
                cancelled = True
                break

            existing_port_scan_job = (
                db.query(BasJob)
                .filter(
                    BasJob.scan_job_id == shadow.id,
                    BasJob.technique_key == "port_service_scan",
                    BasJob.target == chunk,
                    BasJob.status.in_(("completed", "failed", "skipped")),
                )
                .order_by(BasJob.id.desc())
                .first()
            )
            if existing_port_scan_job is not None:
                # Resume: this chunk already ran in an earlier (stopped)
                # attempt on this same shadow job -- reuse what it found
                # instead of re-scanning it.
                if existing_port_scan_job.status == "completed":
                    open_ports_by_host.update(_open_ports_by_host(existing_port_scan_job.result or {}))
                    known_hosts.update(_all_chunk_addresses(chunk))
            else:
                shadow.current_step = f"{port_scan_technique['display_name']} (pré-requisito CMDB) → {chunk}"
                shadow.mission_progress = min(99, int(round(completed_units / total_units * 100)))
                db.commit()

                port_job = BasJob(
                    schedule_id=schedule.id, agent_id=agent.id, owner_id=schedule.owner_id,
                    access_group_id=schedule.access_group_id, scan_job_id=shadow.id,
                    technique_key="port_service_scan", target=chunk,
                    risk_tier=port_scan_technique["risk_tier"], status="dispatched_to_kali",
                    dispatched_at=datetime.now(),
                )
                db.add(port_job)
                db.commit()

                outcome = dispatch_bas_technique(
                    technique_key="port_service_scan", target_hint=chunk,
                    bas_agent=agent, scan_id=shadow.id, schedule=schedule,
                    max_wait=_port_scan_max_wait(chunk),
                )
                if not outcome["dispatched"]:
                    port_job.status = "skipped"
                    port_job.last_error = outcome["reason"]
                    port_job.finished_at = datetime.now()
                    db.commit()
                    skipped.append({"technique_key": "port_service_scan", "target": chunk, "reason": outcome["reason"]})
                else:
                    result = outcome["result"]
                    port_job.kali_job_id = str(result.get("dispatch_task_id") or "")
                    port_job.result = result
                    port_job.status = "completed" if result.get("status") == "executed" else "failed"
                    port_job.last_error = None if port_job.status == "completed" else str(result.get("stderr") or result.get("error") or result.get("dispatch_error") or "")[:2000]
                    port_job.finished_at = datetime.now()
                    db.flush()

                    port_finding = _finding_from_job_result(db, port_job, schedule, port_scan_technique, agent)
                    if port_finding:
                        port_job.finding_id = port_finding.id
                    job_ids.append(port_job.id)
                    db.commit()

                    # A failed/errored chunk means the CMDB signal is simply
                    # unknown for its hosts -- NOT "nothing is open" for
                    # them. Not adding them to known_hosts makes gating fall
                    # back to testing them individually below, instead of
                    # silently skipping real testing because this one chunk
                    # never got an answer.
                    if port_job.status == "completed":
                        open_ports_by_host.update(_open_ports_by_host(result))
                        known_hosts.update(_all_chunk_addresses(chunk))
            completed_units += 1
        if cancelled:
            break

        run_targets = [target]
        selected_techniques = [get_technique(key) for key in effective_technique_keys]
        all_host_based = bool(selected_techniques) and all(
            technique is not None
            and not technique.get("accepts_range")
            and str(technique.get("target_format") or "host") in {"host", "host_port"}
            for technique in selected_techniques
        )
        if target_was_defaulted and all_host_based:
            hosts, target_error = _cidr_hosts(target)
            if target_error:
                for technique_key in effective_technique_keys:
                    skipped.append({"technique_key": technique_key, "target": target, "reason": target_error})
                completed_units += len(effective_technique_keys)
                continue
            if hosts:
                run_targets = hosts

        for run_target in run_targets:
            if cancelled:
                break
            for technique_key in effective_technique_keys:
                if _run_was_stopped(db, shadow.id):
                    cancelled = True
                    break
                technique = get_technique(technique_key)
                shadow.current_step = f"{technique['display_name'] if technique else technique_key} → {run_target}"
                shadow.mission_progress = min(99, int(round(completed_units / total_units * 100)))
                db.commit()

                if technique is None:
                    skipped.append({"technique_key": technique_key, "target": run_target, "reason": "unknown_technique"})
                    completed_units += 1
                    continue
                decision = check_bas_authorization(schedule, technique_key)
                if not decision["allowed"]:
                    skipped.append({"technique_key": technique_key, "target": run_target, "reason": decision["reason"]})
                    logger.info(
                        "bas_scheduler: skipped technique=%s target=%s reason=%s schedule=%s",
                        technique_key, run_target, decision["reason"], schedule.id,
                    )
                    completed_units += 1
                    continue

                dispatch_targets, target_error = _targets_for_technique(
                    run_target, technique, target_was_defaulted=target_was_defaulted,
                )
                if target_error:
                    skipped.append({"technique_key": technique_key, "target": run_target, "reason": target_error})
                    completed_units += 1
                    continue

                required_ports = technique.get("required_ports")
                if required_ports:
                    # CMDB gate: a host whose port-scan chunk genuinely
                    # completed (known_hosts) only gets tested when one of
                    # the required ports actually showed up open there. A
                    # host whose chunk failed/timed out (not in known_hosts)
                    # is unknown, not confirmed closed -- falls back to
                    # being tested anyway, same as before this gate existed.
                    gated_targets = [
                        h for h in dispatch_targets
                        if h not in known_hosts or (open_ports_by_host.get(h) and any(p in open_ports_by_host[h] for p in required_ports))
                    ]
                    for h in dispatch_targets:
                        if h not in gated_targets:
                            skipped.append({
                                "technique_key": technique_key, "target": h,
                                "reason": f"port_not_open_per_port_scan:{required_ports}",
                            })
                    dispatch_targets = gated_targets

                stop_current_target = False
                for dispatch_target in dispatch_targets:
                    if _run_was_stopped(db, shadow.id):
                        cancelled = True
                        break
                    # Resume idempotency: a resumed run recomputes the same
                    # (technique, host) sequence from scratch (nothing about
                    # it is persisted beyond the BasJob rows already
                    # created), so anything with a terminal BasJob already
                    # on this exact scan_job_id was already dispatched --
                    # skip it instead of doing it twice.
                    already_done = db.query(BasJob.id).filter(
                        BasJob.scan_job_id == shadow.id,
                        BasJob.technique_key == technique_key,
                        BasJob.target == dispatch_target,
                        BasJob.status.in_(("completed", "failed", "skipped")),
                    ).first()
                    if already_done:
                        continue
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
                    job.last_error = None if job.status == "completed" else str(result.get("stderr") or result.get("error") or result.get("dispatch_error") or "")[:2000]
                    job.finished_at = datetime.now()
                    db.flush()

                    finding = _finding_from_job_result(db, job, schedule, technique, agent)
                    if finding:
                        job.finding_id = finding.id
                    job_ids.append(job.id)
                    db.commit()

                    if schedule.stop_on_failure and job.status == "failed":
                        remaining = effective_technique_keys[effective_technique_keys.index(technique_key) + 1:]
                        for remaining_key in remaining:
                            skipped.append({"technique_key": remaining_key, "target": dispatch_target, "reason": "chain_stopped_after_failure"})
                        logger.info(
                            "bas_scheduler: chain stopped after technique=%s failed for target=%s, skipping %d remaining step(s) for this target, schedule=%s",
                            technique_key, dispatch_target, len(remaining), schedule.id,
                        )
                        stop_current_target = True
                        break
                completed_units += 1
                if stop_current_target or cancelled:
                    break
            if cancelled:
                break

    if cancelled:
        # Deliberately doesn't overwrite shadow.status: the stop endpoint
        # (routes_bas.py) already set it to "stopped" -- that's the signal
        # this loop reacted to, and it stays the terminal status here so a
        # cancelled run is never confused with a completed one.
        shadow.current_step = "Interrompido pelo usuário"
        schedule.last_run_at = datetime.now()
        db.commit()
        return {"scan_job_id": shadow.id, "job_ids": job_ids, "skipped": skipped, "cancelled": True}

    shadow.status = "completed"
    shadow.mission_progress = 100
    shadow.current_step = "Concluído"
    schedule.last_run_at = datetime.now()
    db.commit()

    return {"scan_job_id": shadow.id, "job_ids": job_ids, "skipped": skipped}


def fire_schedule(db: Session, schedule: BasSchedule) -> dict[str, Any]:
    """Synchronous convenience wrapper: prepares and executes a run in one
    call. Used by the celery-beat periodic tick (bas_scheduler_tick), which
    already runs off any HTTP request thread, so there's no need to split it
    into prepare/execute like run-now (routes_bas.py) does."""
    prepared = prepare_schedule_run(db, schedule)
    if prepared.get("error") or not prepared.get("queued"):
        return prepared
    return execute_schedule_run(
        db, schedule, prepared["scan_job_id"], prepared["targets"],
        prepared["target_was_defaulted"], prepared["skipped"],
    )


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
