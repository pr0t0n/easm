"""Persistent P01-P22 offensive operator execution.

This is the integration layer that binds the dependency-light contracts in
`offensive_operator_core` to ScanJob.state_data. It is intentionally explicit:
phase progress is only persisted from Skill -> Tool Plan -> MCP -> Evidence ->
Validator output.
"""
from __future__ import annotations

import re
import threading
from typing import Any

import requests

from app.core.config import settings
from app.models.models import Finding, ScanJob, ScanLog
from app.services.offensive_operator_core import (
    BACKEND_LOCAL_TOOL_NAMES,
    MCPToolExecutor,
    PHASE_CONTRACTS,
    PHASE_ORDER,
    ReportBuilder,
    Scope,
    OffensiveSkillRuntime,
    create_operation_event,
    create_offensive_state,
    stable_id,
)
from app.services.capability_runtime import mark_capability
from app.services.scan_intelligence import (
    expand_targets_after_p01,
    detect_tech_stack,
    tools_to_inject_for_tech,
    wordlist_for_tech,
    validate_critical_findings,
    evasion_profile_for,
    enrich_finding_with_mappings,
    auth_headers_from_state,
    has_auth,
    phases_for_scan_level,
    extract_learning_signals,
    analyze_waf_behavior,
    apply_waf_confidence_adjustment,
    refine_target_set,
    NETWORK_PHASES,
    classify_target_preflight,
    preflight_skip_reason,
    detect_rate_limit_signals,
    dedup_findings_by_signature,
    derive_cvss,
    build_executive_narrative,
    diff_against_previous,
    chain_findings,
    load_fp_blocklist,
    apply_fp_blocklist,
    llm_phase_reasoning,
    build_asset_dag,
    detect_incremental_changes,
    emit_partial_report,
)


# Phase → capability mapping: which capabilities each phase contributes evidence for
PHASE_TO_CAPABILITIES: dict[str, list[str]] = {
    "P01": ["strategic_planning", "asset_discovery"],
    "P02": ["asset_discovery", "threat_intel"],
    "P03": ["asset_discovery", "adversarial_hypothesis"],
    "P04": ["adversarial_hypothesis"],
    "P05": ["asset_discovery"],
    "P06": ["asset_discovery", "threat_intel"],
    "P07": ["threat_intel"],
    "P08": ["adversarial_hypothesis"],
    "P09": ["risk_assessment", "threat_intel"],
    "P10": ["risk_assessment"],
    "P11": ["risk_assessment"],
    "P12": ["risk_assessment"],
    "P13": ["risk_assessment"],
    "P14": ["risk_assessment"],
    "P15": ["risk_assessment", "evidence_adjudication"],
    "P16": ["adversarial_hypothesis"],
    "P17": ["risk_assessment", "evidence_adjudication"],
    "P18": ["threat_intel", "evidence_adjudication"],
    "P19": ["risk_assessment"],
    "P20": ["evidence_adjudication"],
    "P21": ["evidence_adjudication", "governance"],
    "P22": ["governance", "executive_analyst"],
}


def _scan_mode_value(scan_mode: str) -> str:
    return "scheduled" if str(scan_mode or "").strip().lower() == "scheduled" else "unit"


def _next_pending_phase_target(
    all_targets: list[str],
    completed_work: set[str],
    input_target_count: int,
    allowed_phases: set[str] | None,
    delegated_targets: set[str] | None = None,
) -> tuple[str, str] | None:
    delegated_targets = delegated_targets or set()
    for target_index, target in enumerate(all_targets):
        if not target or target in delegated_targets:
            continue
        for phase_id in PHASE_ORDER:
            if allowed_phases is not None and phase_id not in allowed_phases:
                continue
            if phase_id == "P01" and target_index >= input_target_count:
                continue
            if phase_id == "P01" and not _should_run_subdomain_enumeration(target):
                continue
            if f"{phase_id}:{target}" not in completed_work:
                return phase_id, target
    return None


def _enqueue_operator_continuation(
    db,
    job: ScanJob,
    scan_mode: str,
    next_phase_id: str,
    *,
    countdown: int = 0,
    reason: str = "phase_checkpoint",
) -> dict[str, Any]:
    from app.workers.tasks import run_scan_job_scheduled, run_scan_job_unit
    from app.workers.worker_groups import group_for_phase, phase_queue

    mode = _scan_mode_value(scan_mode)
    task = run_scan_job_scheduled if mode == "scheduled" else run_scan_job_unit
    group = group_for_phase(next_phase_id)
    queue = phase_queue(next_phase_id, mode=mode)  # type: ignore[arg-type]
    # ── Idempotent continuation dedup (defense-in-depth atop the chain lock) ──
    # Key on the next phase-UNIT (scan:mode:phase:target), NOT on `reason`, so two
    # independent code paths that compute the same next-unit dedupe against each
    # other. The TTL is wide enough to absorb concurrent bursts (duplicate chains,
    # broker redeliveries) but far below the ~50min checkpoint cadence, so a
    # legitimate checkpoint-resume of the same unit is never suppressed.
    _next_target = str((job.state_data or {}).get("current_pentest_target") or "")
    import os as _os
    dedupe_ttl = max(int(_os.getenv("OPERATOR_CONTINUATION_DEDUP_TTL", "90")), int(countdown or 0) + 30)
    dedupe_key = f"operator_continuation:{job.id}:{mode}:{next_phase_id}:{_next_target}"
    try:
        from app.services.scan_work_queue import _redis_client

        if not _redis_client().set(dedupe_key, "1", nx=True, ex=dedupe_ttl):
            db.add(ScanLog(
                scan_job_id=job.id,
                source="offensive-operator",
                level="INFO",
                message=(
                    f"phase_queue_enqueue_suppressed reason={reason} next_phase={next_phase_id} "
                    f"target={_next_target} group={group} queue={queue} ttl={dedupe_ttl}"
                ),
            ))
            return {"task_id": "", "queue": queue, "group": group, "next_phase_id": next_phase_id, "deduped": True}
    except Exception:
        pass
    async_result = task.apply_async(args=[job.id], countdown=max(0, int(countdown or 0)), queue=queue)
    db.add(ScanLog(
        scan_job_id=job.id,
        source="offensive-operator",
        level="INFO",
        message=(
            f"phase_queue_enqueue reason={reason} next_phase={next_phase_id} "
            f"group={group} queue={queue} countdown={max(0, int(countdown or 0))} task_id={async_result.id}"
        ),
    ))
    return {"task_id": async_result.id, "queue": queue, "group": group, "next_phase_id": next_phase_id}


def _parse_targets_from_query(target_query: str) -> list[str]:
    raw = str(target_query or "")
    tokens = [token.strip() for token in re.split(r"[;,\n]", raw) if str(token or "").strip()]
    return tokens


def _is_absolute_http_url(target: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(str(target or "").strip())
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _should_run_subdomain_enumeration(target: str) -> bool:
    """P01 is domain enumeration. Full URLs are explicit app targets."""
    return not _is_absolute_http_url(target)


def _normalize_asset_host(target: str) -> str:
    """Chave canônica de asset = host puro (sem esquema/porta/path/barra).
    Sem isto, o MESMO alvo virava 2 assets: 'http://x/' e 'x' (bug recorrente)."""
    from urllib.parse import urlparse
    raw = str(target or "").strip()
    if "://" in raw:
        host = urlparse(raw).hostname or raw
    else:
        host = raw.split("/")[0].split("?")[0].split(":")[0]
    return host.rstrip(".").lower()[:255]


def _scope_from_job(job: ScanJob, target: str, execution_mode: str = "controlled_pentest") -> Scope:
    state = dict(job.state_data or {})
    raw_scope = state.get("scope") if isinstance(state.get("scope"), dict) else {}
    allowed_domains = list(raw_scope.get("allowed_domains") or [])
    allowed_subdomains = list(raw_scope.get("allowed_subdomains") or [])
    allowed_ips = list(raw_scope.get("allowed_ips") or [])
    if not (allowed_domains or allowed_subdomains or allowed_ips):
        from urllib.parse import urlparse

        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        allowed_domains = [host]
    return Scope(
        scope_id=str(raw_scope.get("scope_id") or f"scan-{job.id}"),
        allowed_domains=allowed_domains,
        allowed_subdomains=allowed_subdomains,
        allowed_ips=allowed_ips,
        allowed_ports=list(raw_scope.get("allowed_ports") or []),
        allowed_protocols=list(raw_scope.get("allowed_protocols") or ["http", "https"]),
        disallowed_targets=list(raw_scope.get("disallowed_targets") or []),
        allowed_techniques=list(raw_scope.get("allowed_techniques") or []),
        disallowed_techniques=list(raw_scope.get("disallowed_techniques") or []),
        max_noise_level=str(
            raw_scope.get("max_noise_level")
            or ("high" if execution_mode in {"controlled_pentest", "full_authorized_pentest"} else "medium")
        ),
        allow_authenticated_testing=bool(raw_scope.get("allow_authenticated_testing", True)),
        allow_post_exploitation=bool(raw_scope.get("allow_post_exploitation", False)),
        allow_credential_testing=bool(raw_scope.get("allow_credential_testing", False)),
        allow_data_access_validation=bool(raw_scope.get("allow_data_access_validation", False)),
        execution_windows=list(raw_scope.get("execution_windows") or []),
    )


def _mcp_available() -> bool:
    try:
        response = requests.get(f"{settings.mcp_server_url.rstrip('/')}/health", timeout=3)
        payload = response.json() if response.ok else {}
        return response.ok and bool(payload.get("kali_connected", True))
    except Exception:
        return False


# ── Target reachability gate (SYN) ───────────────────────────────────────────
# Se o alvo ficar inacessível via SYN por _TARGET_UNREACHABLE_GRACE segundos,
# o alvo é marcado morto e PULADO — todas as suas fases restantes são registradas
# como skipped. Sem isto, cada ferramenta (ffuf/sqlmap/bl-test/...) trava esperando
# conexão que nunca completa, parando o scan inteiro (caso real do #8).
import os as _os_env
_TARGET_UNREACHABLE_GRACE = max(30, int(_os_env.getenv("TARGET_UNREACHABLE_GRACE_SECONDS", "300")))
_TARGET_SYN_TIMEOUT = 5.0
_TARGET_SYN_PROBE_INTERVAL = 20.0


def _tcp_syn_reachable(target: str, timeout: float = _TARGET_SYN_TIMEOUT) -> bool:
    """SYN connect ao alvo — usado pelo gate de alcançabilidade.

    CRÍTICO: isto roda no DRIVER (scope worker), cuja resolução DNS é
    NÃO-confiável por design — a rede real do scan é feita pelo kali_runner.
    Portanto:
      • Falha de DNS (gaierror) = problema do driver, NÃO do alvo → fail-open
        (True). Nunca marcar um alvo como morto só porque o driver não resolveu;
        senão um hiccup do Docker DNS mataria todos os scans como "Timeout
        Destination".
      • Só conclui inacessível (False) quando o DNS RESOLVE mas nenhuma porta
        candidata aceita conexão (alvo genuinamente fora do ar).
      • Testa 80 e 443 (alvo HTTPS-only não pode virar falso-negativo)."""
    import socket
    from urllib.parse import urlparse
    raw = target if "://" in str(target) else f"http://{target}"
    p = urlparse(raw)
    host = p.hostname
    if not host:
        return True  # não dá pra concluir → fail-open
    try:
        socket.gethostbyname(host)
    except Exception:
        return True  # DNS do driver falhou → inconclusivo → fail-open
    ports = [int(p.port)] if p.port else ([443] if p.scheme == "https" else [80, 443])
    for port in ports:
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            return True
        except OSError:
            continue
    return False


def _reachability_gate(db, job: ScanJob, target: str, completed_work: set, phases: list[str]) -> bool:
    """Portão de alcançabilidade por alvo. Retorna True (prosseguir) ou False
    (alvo morto → pular). Quando o alvo fica inacessível via SYN por
    _TARGET_UNREACHABLE_GRACE s, marca dead_targets, registra TODAS as fases
    restantes do alvo como skipped (p/ o scan poder finalizar) e devolve False."""
    import time as _t
    state = dict(job.state_data or {})
    dead = set(state.get("dead_targets") or [])
    if target in dead:
        return False
    if _tcp_syn_reachable(target):
        since = dict(state.get("target_unreachable_since") or {})
        if since.pop(target, None) is not None:
            state["target_unreachable_since"] = since
            job.state_data = state
            db.commit()
        return True

    # Inacessível → janela de tolerância (persistida p/ sobreviver a checkpoints).
    since = dict(state.get("target_unreachable_since") or {})
    first = since.get(target)
    now_wall = _t.time()
    if first is None:
        since[target] = now_wall
        state["target_unreachable_since"] = since
        job.state_data = state
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                       message=(f"target_unreachable target={target} — sem resposta SYN; "
                                f"sondando por até {_TARGET_UNREACHABLE_GRACE}s antes de pular")))
        db.commit()
        first = now_wall
    started = _t.monotonic()
    while True:
        try:
            db.refresh(job)
            if _scan_halted(job):
                return False
        except Exception:
            pass
        elapsed_total = (now_wall - float(first)) + (_t.monotonic() - started)
        if _tcp_syn_reachable(target):
            since = dict((job.state_data or {}).get("target_unreachable_since") or {})
            since.pop(target, None)
            st = dict(job.state_data or {}); st["target_unreachable_since"] = since
            job.state_data = st
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                           message=f"target_recovered target={target} respondeu SYN após {int(elapsed_total)}s"))
            db.commit()
            return True
        if elapsed_total >= _TARGET_UNREACHABLE_GRACE:
            st = dict(job.state_data or {})
            dead = set(st.get("dead_targets") or []); dead.add(target)
            st["dead_targets"] = sorted(dead)
            since = dict(st.get("target_unreachable_since") or {}); since.pop(target, None)
            st["target_unreachable_since"] = since
            # registra todas as fases restantes do alvo como skipped p/ finalizar
            for ph in phases:
                completed_work.add(f"{ph}:{target}")
            st["completed_work"] = sorted(completed_work)
            job.state_data = st
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="ERROR",
                           message=(f"target_timeout_destination target={target} inacessível via SYN "
                                    f">{_TARGET_UNREACHABLE_GRACE}s — pulando alvo (fases restantes = skipped)")))
            db.commit()
            return False
        _t.sleep(min(_TARGET_SYN_PROBE_INTERVAL, max(1.0, _TARGET_UNREACHABLE_GRACE - elapsed_total)))


_MCP_STDOUT_STATE_CAP = 5_000  # bytes kept per mcp_result entry in state_data
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
_URL_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.:-]{0,79})=")
_BARE_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,79}$")
_HALTED_SCAN_STATUSES = {"paused", "stopped"}


def _scan_halted(job: ScanJob) -> bool:
    return str(job.status or "").lower() in _HALTED_SCAN_STATUSES


def _clean_tool_text(value: Any) -> str:
    text = str(value or "")
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r", "\n")
    return "\n".join(line.rstrip() for line in text.splitlines()).strip()


def _clean_lines(value: Any) -> list[str]:
    return [line.strip() for line in _clean_tool_text(value).splitlines() if line.strip()]


def _is_noise_line(line: str) -> bool:
    lowered = line.lower()
    if not line or len(line) > 500:
        return True
    return any(
        marker in lowered
        for marker in (
            "[inf]",
            "[err]",
            "[wrn]",
            "[debug]",
            "stable version",
            "projectdiscovery",
            "starting scan",
            "probing",
            "target:",
            "usage:",
            "elapsed",
            "requests",
            "rate-limit",
        )
    )


def _is_banner_line(line: str) -> bool:
    """Detecta arte ASCII / banner de ferramenta (figlet, box-drawing) que NÃO é
    achado. Os scanners (wapiti, sqlmap, etc.) imprimem um logo na inicialização
    que era capturado como título/summary de vulnerabilidade. Ver backlog item 1."""
    s = (line or "").strip()
    if not s:
        return True
    # Caracteres de box-drawing / blocos (banner do wapiti, sqlmap, dalfox, etc.)
    if any(ch in s for ch in "█▄▀▒░╗║╔╝╚╠╣╦╩╬│┌┐└┘├┤┬┴┼"):
        return True
    # Linha dominada por não-alfanuméricos (figlet com _ / \ | ( ) . ')
    alnum = sum(c.isalnum() for c in s)
    if len(s) >= 6 and alnum / max(len(s), 1) < 0.4:
        return True
    return False


def _extract_domains_from_output(stdout: str) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for line in _clean_lines(stdout):
        if _is_noise_line(line):
            continue
        for match in _DOMAIN_RE.findall(line):
            domain = match.strip(".,;:()[]{}<>").lower()
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
    return domains


def _extract_parameters_from_output(stdout: str, parsed: Any) -> list[str]:
    params: list[str] = []
    seen: set[str] = set()

    def add_param(raw: Any) -> None:
        param = str(raw or "").strip().strip("[]'\",;")
        # "_" é cache-buster do jQuery (artefato, não parâmetro real). Backlog item 5.
        if not param or param.lower() in {"none", "null", "true", "false", "target", "found", "stable", "_"}:
            return
        if not _BARE_PARAM_RE.match(param):
            return
        if param.lower() in seen:
            return
        seen.add(param.lower())
        params.append(param)

    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                for key in ("param", "parameter", "name"):
                    if item.get(key):
                        add_param(item.get(key))
                url = item.get("url") or item.get("matched") or item.get("endpoint")
                if url:
                    for match in _URL_PARAM_RE.findall(str(url)):
                        add_param(match)
            else:
                raw = str(item or "")
                for match in _URL_PARAM_RE.findall(raw):
                    add_param(match)
                add_param(raw)

    for line in _clean_lines(stdout):
        if _is_noise_line(line):
            continue
        for match in _URL_PARAM_RE.findall(line):
            add_param(match)
        if len(line) <= 100 and " " not in line and "?" not in line and "/" not in line:
            add_param(line)

    return params[:200]


def _trim_mcp_stdout(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a shallow copy of each result with stdout/stderr capped for DB storage.

    Full stdout is already written to the kali-runner workspace file; keeping
    500KB blobs per tool in Postgres state_data causes multi-MB commits per phase.
    """
    trimmed = []
    for r in results:
        if not isinstance(r, dict):
            trimmed.append(r)
            continue
        entry = dict(r)
        if "stdout" in entry and isinstance(entry["stdout"], str) and len(entry["stdout"]) > _MCP_STDOUT_STATE_CAP:
            entry["stdout"] = entry["stdout"][-_MCP_STDOUT_STATE_CAP:]
        if "stderr" in entry and isinstance(entry["stderr"], str) and len(entry["stderr"]) > _MCP_STDOUT_STATE_CAP:
            entry["stderr"] = entry["stderr"][-_MCP_STDOUT_STATE_CAP:]
        trimmed.append(entry)
    return trimmed


# Thread-local auth header storage — safe for both prefork and --pool=threads workers.
# Each OS thread / Celery task gets its own isolated copy; concurrent subtasks for
# different scans running in the same process cannot overwrite each other's creds.
_AUTH_LOCAL = threading.local()

# Serialises the read-modify-write on ScanJob.state_data for parallel subtasks
# that share the same worker_parallel process (--pool=threads).  Each subtask
# holds this lock only for the brief Python dict-merge + SQLAlchemy write, so
# contention is negligible compared to the minutes-long MCP tool executions.
_SUBTASK_STATE_LOCK = threading.Lock()


def _get_auth_headers() -> dict[str, str]:
    return dict(getattr(_AUTH_LOCAL, "headers", {}))


def _set_auth_headers(headers: dict[str, str]) -> None:
    _AUTH_LOCAL.headers = dict(headers)


def _get_discovered_urls() -> list[str]:
    """Thread-local list of P03-discovered parameterized URLs, for bl-test."""
    return list(getattr(_AUTH_LOCAL, "discovered_urls", []))


def _set_discovered_urls(urls: list[str]) -> None:
    _AUTH_LOCAL.discovered_urls = list(urls or [])


def _preflight_profile_for(state: dict[str, Any], target: str) -> tuple[dict[str, Any], bool]:
    """Return cached Tier 1 preflight profile; compute it when absent."""
    preflight = dict(state.get("preflight") or {})
    targets = dict(preflight.get("targets") or {})
    cached = targets.get(target)
    if isinstance(cached, dict) and cached.get("status"):
        return cached, False

    ports = state.get("preflight_ports")
    if not isinstance(ports, list) or not ports:
        ports = None
    profile = classify_target_preflight(target, ports=ports)
    targets[target] = profile
    preflight.update(
        {
            "enabled": True,
            "version": 1,
            "mode": "dns_tcp_http",
            "targets": targets,
        }
    )
    state["preflight"] = preflight
    return profile, True


def _record_preflight_skip(
    db,
    job: ScanJob,
    phase_ledgers: list[dict[str, Any]],
    completed_work: set[str],
    phase_id: str,
    target: str,
    reason: str,
) -> None:
    """Persist a skipped phase-target as completed work for resumability."""
    work_key = f"{phase_id}:{target}"
    if work_key in completed_work:
        return
    ledger = {
        "phase_id": phase_id,
        "phase_name": PHASE_CONTRACTS.get(phase_id, {}).get("name", phase_id),
        "target": target,
        "status": "skipped",
        "skip_reason": reason,
        "tools_attempted": [],
        "tools_success": [],
        "mcp_results": [],
        "tier": "tier1_preflight",
    }
    phase_ledgers.append(ledger)
    completed_work.add(work_key)
    with _SUBTASK_STATE_LOCK:
        try:
            db.refresh(job)
        except Exception:  # noqa: BLE001
            pass
        state = dict(job.state_data or {})
        skipped_work = list(state.get("skipped_work") or [])
        skipped_work.append({"phase_id": phase_id, "target": target, "reason": reason, "tier": "tier1_preflight"})
        state["skipped_work"] = skipped_work[-2000:]
        state["completed_work"] = sorted(set(state.get("completed_work") or []) | completed_work)
        state["phase_ledger_v2"] = _merge_phase_ledgers(list(state.get("phase_ledger_v2") or []), [ledger])
        job.state_data = state
        db.add(ScanLog(
            scan_job_id=job.id,
            source="scan-intelligence",
            level="INFO",
            message=f"tier1_preflight_skip phase={phase_id} target={target} reason={reason}",
        ))
        db.commit()


def _record_direct_url_p01_skip(
    db,
    job: ScanJob,
    phase_ledgers: list[dict[str, Any]],
    completed_work: set[str],
    target: str,
    all_targets: list[str],
) -> None:
    _record_preflight_skip(
        db,
        job,
        phase_ledgers,
        completed_work,
        "P01",
        target,
        "direct_url_target_no_subdomain_enumeration",
    )
    state = dict(job.state_data or {})
    modes = dict(state.get("target_input_modes") or {})
    modes[target] = "direct_url"
    state["target_input_modes"] = modes
    state["direct_url_targets"] = sorted(set(list(state.get("direct_url_targets") or []) + [target]))
    state["target_set"] = list(all_targets)
    job.state_data = state
    db.commit()


def _phase_ids_for_target_subset(allowed_phases: set[str] | None) -> list[str]:
    return [
        phase_id for phase_id in PHASE_ORDER
        if phase_id != "P01" and (allowed_phases is None or phase_id in allowed_phases)
    ]


def _pending_parallel_targets(state: dict[str, Any], completed_work: set[str], allowed_phases: set[str] | None) -> list[str]:
    phase_ids = _phase_ids_for_target_subset(allowed_phases)
    delegated = [str(target) for target in (state.get("parallel_delegated_targets") or []) if str(target or "").strip()]
    pending: list[str] = []
    for target in delegated:
        if not all(f"{phase_id}:{target}" in completed_work for phase_id in phase_ids):
            pending.append(target)
    return pending


def _slim_ledger(ledger: dict[str, Any]) -> dict[str, Any]:
    """Enxuga campos BRUTOS pesados (stdout/output) de um ledger já processado.
    Backlog item 19: phase_ledger_v2 acumulava o ledger completo (com stdout
    bruto de mcp_results/tool_evidence) de TODOS os ~2600 phase-targets em
    state_data (80MB), reescrito a cada checkpoint = write amplification brutal.
    Os achados já foram persistidos (Finding) e o output bruto já está em
    executed_tool_runs — aqui mantém só a estrutura necessária ao resume."""
    slim = dict(ledger)
    mr = slim.get("mcp_results")
    if isinstance(mr, list):
        slim["mcp_results"] = [
            {k: v for k, v in m.items()
             if k not in ("stdout", "raw_output", "output", "stdout_preview", "output_lines")}
            for m in mr if isinstance(m, dict)
        ]
    for fld in ("evidence", "tool_evidence"):
        ev = slim.get(fld)
        if isinstance(ev, list):
            slim[fld] = [
                {k: v for k, v in e.items()
                 if k not in ("output", "raw_output", "raw_output_preview", "stdout", "output_lines")}
                for e in ev if isinstance(e, dict)
            ]
    return slim


def _merge_phase_ledgers(existing: list[dict[str, Any]], additions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    # Ledgers já existentes (de checkpoints anteriores) entram ENXUTOS — seus
    # achados já foram persistidos. Apenas os `additions` (frescos) mantêm o
    # output bruto, necessário para _persist_offensive_findings desta rodada.
    _existing_terminal = {"completed", "partial", "skipped", "failed", "blocked"}
    for ledger in [
        (_slim_ledger(l) if isinstance(l, dict) and str(l.get("status") or "").lower() in _existing_terminal else l)
        for l in list(existing or [])
    ] + list(additions or []):
        if not isinstance(ledger, dict):
            continue
        key = (
            str(ledger.get("phase_id") or ""),
            str(ledger.get("target") or ""),
            str(ledger.get("status") or ""),
            str(ledger.get("skip_reason") or ledger.get("parallel_subtask") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(ledger)
    return merged


# Tools que rodam NO BACKEND (não no kali via MCP). O operator roda no processo
# backend/celery, então pode chamá-las direto — não há profile kali p/ elas.
_BACKEND_LOCAL_TOOLS = BACKEND_LOCAL_TOOL_NAMES


def _run_backend_local_tool(execution: dict[str, Any]) -> dict[str, Any]:
    """Executa uma tool backend-local in-process e devolve um contrato compatível
    com o que _run_one_tool/_extract_evidence esperam (status/stdout/parsed_result)."""
    tool = str(execution.get("tool_name") or "").strip().lower()
    target = execution["target"]
    try:
        if tool == "bl-test":
            from app.services.business_logic_test import run_as_tool as _run
            # Pass P03-discovered parameterized URLs so bl-test tests the real
            # endpoint surface (Comments.aspx?id=, ReadNews.aspx?NewsAd=) instead
            # of only re-discovering via chromium+wordlist.
            _disc = _get_discovered_urls()
            try:
                r = _run(target, extra_urls=_disc) if _disc else _run(target)
            except TypeError:
                # run_as_tool signature without extra_urls — fall back
                r = _run(target)
            findings = r.get("findings_extracted") or []
            parsed = r.get("parsed") or {}
            parsed = {**parsed, "findings": findings}
            status = r.get("status") or "done"
            return {
                "status": "success" if status in {"done", "success"} else status,
                "exit_code": r.get("return_code", 0),
                "stdout": (r.get("stdout") or "")[:10_000],
                "stderr": r.get("stderr") or "",
                "parsed": parsed,
                "command": r.get("command") or f"{tool} {target}",
                "duration_seconds": r.get("duration_seconds"),
            }
        elif tool == "code-analyzer":
            from app.services.code_analyzer import run_as_tool as _run
        elif tool == "semgrep":
            from app.services.semgrep_local import run_as_tool as _run
        else:
            return {"status": "blocked", "error": f"unknown_backend_local:{tool}", "exit_code": None}
        r = _run(target)
        findings = r.get("findings_extracted") or []
        parsed = r.get("parsed") or {}
        parsed = {**parsed, "findings": findings}
        status = r.get("status") or "done"
        return {
            "status": "success" if status in {"done", "success"} else status,
            "exit_code": r.get("return_code", 0),
            "stdout": (r.get("stdout") or "")[:10_000],
            "stderr": r.get("stderr") or "",
            "parsed": parsed,
            "command": r.get("command") or f"{tool} {target}",
            "duration_seconds": r.get("duration_seconds"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}", "exit_code": None}


def _call_mcp_execution(execution: dict[str, Any]) -> dict[str, Any]:
    """Submit a tool to MCP and poll until completion — async submit+poll.

    Uses /mcp/submit (fire-and-forget) then polls /mcp/jobs/{id} until
    the job reaches a terminal state. This avoids blocking a worker thread
    for the entire tool duration (was /mcp/execute which held the thread
    for up to `timeout` seconds, causing platform-wide timeouts for nikto,
    wapiti, sqlmap etc. that run for 30+ minutes).
    """
    import time as _time
    if str(execution.get("tool_name") or "").strip().lower() in _BACKEND_LOCAL_TOOLS:
        return _run_backend_local_tool(execution)
    arguments: dict[str, Any] = dict(execution.get("arguments") or {})
    arguments.setdefault("target", execution["target"])
    arguments.setdefault("scan_id", execution.get("scan_id"))
    # Never pass a timeout from the backend — the Kali runner's profile timeout
    # is the authoritative limit. Passing a low value (e.g. 300) from the catalog
    # kills long-running tools (nikto, sqlmap, wapiti) before they finish.
    arguments.pop("timeout", None)
    _auth = _get_auth_headers()
    if _auth:
        arguments["auth_headers"] = _auth
    # Forward API keys from environment to kali runner via arguments
    import os as _os
    for _env_key in ("SHODAN_API_KEY", "HIBP_API_KEY", "GITHUB_TOKEN"):
        _env_val = _os.environ.get(_env_key, "").strip()
        if _env_val:
            arguments[_env_key] = _env_val
    request = {
        "mcp_request_id": execution.get("mcp_request_id"),
        "phase_id": execution["phase_id"],
        "skill_id": execution["skill_id"],
        "tool_name": execution["tool_name"],
        "profile": execution["profile"],
        "target": execution["target"],
        "targets": list(execution.get("targets") or []),
        "arguments": arguments,
        "expected_evidence": ["stdout", "raw_tool_output", "parsed_result"],
    }
    base = settings.mcp_server_url.rstrip("/")

    # ── Step 1: submit (non-blocking) ────────────────────────────────────────
    submit_resp = requests.post(f"{base}/mcp/submit", json=request, timeout=30)
    submit_resp.raise_for_status()
    submit_data = dict(submit_resp.json())

    # If the job already has a terminal status (cached/skipped), return immediately
    _TERMINAL = {"done", "completed", "success", "failed", "timeout", "skipped", "error"}
    if str(submit_data.get("status") or "").lower() in _TERMINAL:
        return submit_data

    job_id = str(submit_data.get("kali_job_id") or submit_data.get("dispatch_task_id") or submit_data.get("job_id") or "")
    if not job_id:
        # No job_id means MCP handled it synchronously (e.g. backend-local fallback)
        return submit_data

    # ── Step 2: poll until terminal ───────────────────────────────────────────
    # Adaptive backoff: 3s for first 30s, grows 2s per minute, cap at 20s.
    # No hard platform timeout — the tool runs as long as it needs.
    _start = _time.monotonic()
    while True:
        _elapsed = _time.monotonic() - _start
        _sleep = min(3 + int(_elapsed // 30) * 2, 20)
        _time.sleep(_sleep)
        try:
            status_resp = requests.get(f"{base}/mcp/jobs/{job_id}", timeout=10)
            status_resp.raise_for_status()
            status_data = dict(status_resp.json())
        except Exception:
            continue
        _st = str(status_data.get("status") or "").lower()
        if _st in _TERMINAL:
            break

    # ── Step 3: fetch result ──────────────────────────────────────────────────
    try:
        result_resp = requests.get(f"{base}/mcp/jobs/{job_id}/result", timeout=120)
        result_resp.raise_for_status()
        result = dict(result_resp.json())
    except Exception:
        result = dict(status_data)

    # ── Normalise to /mcp/execute response shape ─────────────────────────────
    # /mcp/execute returned: status="success"/"failed"/"timeout", exit_code,
    #   stdout (text), stdout_path, parsed_result, execution_key, execution_backend
    # /mcp/jobs/{id}/result returns: status="done"/"failed"/"timeout",
    #   return_code, workdir, stdout (text), stderr, parsed (not parsed_result)
    raw_st = str(result.get("status") or status_data.get("status") or "done").lower()
    result["status"] = "success" if raw_st in {"done", "success"} and (result.get("return_code") or 0) == 0 else raw_st
    # exit_code / return_code unification
    if "exit_code" not in result:
        result["exit_code"] = result.get("return_code")
    # stdout_path from workdir (for evidence logging compatibility)
    if "stdout_path" not in result:
        result["stdout_path"] = result.get("workdir") or ""
    # parsed_result from parsed
    if "parsed_result" not in result and "parsed" in result:
        result["parsed_result"] = result.get("parsed")
    # execution_key (deterministic id for de-dup)
    if "execution_key" not in result:
        result["execution_key"] = str(job_id)
    # execution_backend
    result.setdefault("execution_backend", "mcp")
    result.setdefault("tool_name", execution.get("tool_name"))
    result.setdefault("phase_id", execution.get("phase_id"))
    result.setdefault("target", execution.get("target"))
    return result


def _call_operator_tool(mcp_available: bool):
    """Fábrica do call_tool do executor. Tools BACKEND-LOCAL (bl-test, code-analyzer)
    rodam SEMPRE (não dependem de MCP/kali); tools remotas são bloqueadas quando o
    MCP está indisponível. Assim o executor é criado com available=True e o gate de
    MCP fica AQUI — senão o core bloquearia tudo (inclusive backend-local) antes."""
    def _call(execution: dict[str, Any]) -> dict[str, Any]:
        tool = str(execution.get("tool_name") or "").strip().lower()
        if tool in _BACKEND_LOCAL_TOOLS:
            return _run_backend_local_tool(execution)
        if not mcp_available:
            return {"status": "blocked", "error": "mcp_unavailable", "exit_code": None,
                    "stdout": "", "stderr": ""}
        return _call_mcp_execution(execution)
    return _call


# ─── Tier 3: Batch phase profiles ───────────────────────────────────────────
# When ≥2 live targets exist for a phase, one batch job replaces N individual
# jobs.  Tool startup overhead (nuclei: ~15s, naabu: ~3s, nmap: ~5s) is paid
# once for all targets instead of once per target.
_BATCH_PHASE_PROFILES: dict[str, str] = {
    "P02": "naabu_top1000_batch",      # naabu -list targets.txt
    "P06": "httpx_probe_batch",         # httpx -l targets.txt (status, tech, headers)
}
# Minimum number of targets to justify a batch call over N single calls.
_BATCH_MIN_TARGETS = 2


def _extract_host_from_target(target: str) -> str:
    from urllib.parse import urlparse as _up
    raw = str(target or "").strip()
    try:
        p = _up(raw if "://" in raw else f"http://{raw}")
        return (p.hostname or raw).split(":")[0]
    except Exception:  # noqa: BLE001
        return raw


def _dispatch_batch_phase(
    db,
    job: ScanJob,
    phase_id: str,
    targets: list[str],
    phase_ledgers: list[dict[str, Any]],
    completed_work: set[str],
    profile_override: str | None = None,
) -> bool:
    """Dispatch ONE batch kali job for phase_id across all targets.

    Returns True when the batch ran successfully and all (phase_id, target)
    pairs have been added to completed_work.  Returns False on any error so
    callers fall back to sequential single-target dispatch.
    """
    batch_profile = profile_override or _BATCH_PHASE_PROFILES.get(phase_id)
    if not batch_profile or len(targets) < _BATCH_MIN_TARGETS:
        return False

    # For port-scan phases, pass bare hosts; for URL phases pass full URLs.
    if phase_id in {"P02"}:
        batch_list = [_extract_host_from_target(t) for t in targets]
    else:
        batch_list = list(targets)
    batch_list = [t for t in batch_list if t]
    if not batch_list:
        return False

    primary = targets[0]
    contract = PHASE_CONTRACTS.get(phase_id, {})
    execution: dict[str, Any] = {
        "mcp_execution_id": stable_id("MCP", {"batch": phase_id, "targets_hash": hash(tuple(sorted(batch_list)))}),
        "mcp_request_id": stable_id("mcp", {"batch": phase_id, "targets_hash": hash(tuple(sorted(batch_list)))}),
        "tool_plan_id": f"batch-{phase_id}-{job.id}",
        "phase_id": phase_id,
        "skill_id": contract.get("required_skills", [phase_id])[0] if contract.get("required_skills") else phase_id,
        "tool_name": batch_profile,
        "profile": batch_profile,
        "target": primary,
        "targets": batch_list,
        "timeout": 1200,
        "scan_id": job.id,
        "arguments": {"scan_id": job.id, "targets": batch_list, "timeout": 1200},
    }
    try:
        result = _call_mcp_execution(execution)
        status = result.get("status", "failed")
        ledger_status = "completed" if status in {"success", "done"} else "partial"

        for t in targets:
            completed_work.add(f"{phase_id}:{t}")
            phase_ledgers.append({
                "phase_id": phase_id,
                "phase_name": contract.get("name", phase_id),
                "target": t,
                "status": ledger_status,
                "tools_attempted": [batch_profile],
                "tools_success": [batch_profile] if ledger_status == "completed" else [],
                "tools_failed": [] if ledger_status == "completed" else [batch_profile],
                "mcp_results": [result],
                "batch_mode": True,
                "batch_size": len(batch_list),
            })

        db.add(ScanLog(
            scan_job_id=job.id,
            source="offensive-operator",
            level="INFO",
            message=(
                f"batch_phase phase_id={phase_id} profile={batch_profile} "
                f"targets={len(batch_list)} status={ledger_status}"
            ),
        ))
        db.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        db.add(ScanLog(
            scan_job_id=job.id,
            source="offensive-operator",
            level="WARNING",
            message=f"batch_phase_failed phase_id={phase_id} error={exc!s} — falling back to sequential",
        ))
        db.commit()
        return False


def run_offensive_operator_scan(
    db,
    job: ScanJob,
    scan_mode: str = "unit",
    *,
    phase_queue_enabled: bool = False,
    phase_task_budget: int | None = None,
) -> dict[str, Any]:
    """Run deterministic Skill-based P01-P22 campaign and persist every phase."""
    targets = _parse_targets_from_query(str(job.target_query or ""))
    if not targets:
        targets = [""]
    execution_mode = str((job.state_data or {}).get("execution_mode") or "controlled_pentest")
    offensive_state = dict((job.state_data or {}).get("offensive_state") or create_offensive_state(targets[0], campaign_id=f"scan-{job.id}"))
    phase_ledgers: list[dict[str, Any]] = list((job.state_data or {}).get("phase_ledger_v2") or [])
    events: list[dict[str, Any]] = list((job.state_data or {}).get("operation_events") or [])
    mcp_available = _mcp_available() if settings.mcp_execute_tools_via_mcp else False
    if not mcp_available:
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                       message="mcp_server unreachable — tools will be skipped; phases will be marked partial"))
        db.commit()
    runtime = OffensiveSkillRuntime(executor=MCPToolExecutor(call_tool=_call_operator_tool(mcp_available), available=True))

    # Read EASM scan-level (asm/full) from state_data; default = full.
    initial_state = dict(job.state_data or {})
    scan_level = str(initial_state.get("scan_level") or "full").lower()
    allowed_phases = phases_for_scan_level(scan_level)
    if allowed_phases is not None:
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                       message=f"scan_level={scan_level} — limiting to phases: {sorted(allowed_phases)}"))
        db.commit()

    # Set thread-local auth headers so _call_mcp_execution propagates them to kali.
    _set_auth_headers(auth_headers_from_state(initial_state))
    _auth_now = _get_auth_headers()
    if _auth_now:
        masked = {k: (v[:10] + "***" if v else "") for k, v in _auth_now.items()}
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                       message=f"auth_engaged headers={masked} — tools will inject these into requests"))
        db.commit()

    # ─── Checkpoint Engine: resumable work queue across root + subdomains ────
    import time as _time
    _checkpoint_start = _time.monotonic()
    _CHECKPOINT_SECONDS = int(initial_state.get("checkpoint_seconds") or 3000)
    # Per-phase-unit wall-clock budget. Bounds a SINGLE (phase,target) so a phase
    # whose internal fan-out is large (e.g. P10/P12 multi-URL: up to 8 tools ×
    # 3600s = 8h) can't monopolize a worker thread. When exceeded mid-phase we
    # stop launching further tools and let the normal checkpoint advance the queue.
    _PHASE_UNIT_DEADLINE = max(120, int(initial_state.get("phase_unit_deadline_seconds") or 1500))
    _phase_unit_start = _time.monotonic()
    completed_work: set[str] = set(initial_state.get("completed_work") or [])
    # all_targets starts as the input targets; after P01 it grows with every
    # discovered subdomain so each phase P02-P22 runs against the full set.
    all_targets: list[str] = list(initial_state.get("target_set") or targets)
    _input_target_count = len(targets)
    _phases_for_level = [p for p in PHASE_ORDER if allowed_phases is None or p in allowed_phases]
    # host → resolved IP, for IP-grouped network phases (populated after P01)
    host_ip_map: dict[str, str] = dict(initial_state.get("host_ip_map") or {})
    _target_idx = 0
    _phase_queue_enabled = bool(initial_state.get("offensive_operator_phase_queue_enabled", phase_queue_enabled))
    _phase_task_budget = max(1, int(initial_state.get("offensive_operator_phase_task_budget") or phase_task_budget or 1))
    _phase_units_this_task = 0

    for _input_target in all_targets[:_input_target_count]:
        if _input_target and not _should_run_subdomain_enumeration(_input_target):
            _record_direct_url_p01_skip(db, job, phase_ledgers, completed_work, _input_target, all_targets)

    if _phase_queue_enabled and not initial_state.get("_operator_phase_queue_started"):
        _delegated_targets = set(initial_state.get("parallel_delegated_targets") or [])
        _next_unit = _next_pending_phase_target(
            all_targets,
            completed_work,
            _input_target_count,
            allowed_phases,
            _delegated_targets,
        )
        if _next_unit:
            _next_phase, _next_target = _next_unit
            state = dict(job.state_data or {})
            state["offensive_operator_phase_queue_enabled"] = True
            state["offensive_operator_phase_task_budget"] = _phase_task_budget
            state["_operator_phase_queue_started"] = True
            state["current_pentest_phase_id"] = _next_phase
            state["current_pentest_target"] = _next_target
            job.state_data = state
            job.current_step = f"queued {_next_phase} {PHASE_CONTRACTS[_next_phase]['name']} ({_next_target})"
            queued = _enqueue_operator_continuation(
                db,
                job,
                scan_mode,
                _next_phase,
                reason="phase_queue_start",
            )
            db.commit()
            return {
                "checkpointed": True,
                "phase_queue_started": True,
                "next_phase_id": _next_phase,
                "next_target": _next_target,
                **queued,
            }

    while _target_idx < len(all_targets):
        target = all_targets[_target_idx]
        if not target:
            _target_idx += 1
            continue
        # RACE-FIX: refresh completed_work + target_set from DB at every target
        # iteration so updates from parallel subtasks are visible to the main
        # task (and vice-versa). Without this, parallel subtasks' progress is
        # invisible and the main task re-executes phases they already finished.
        try:
            db.refresh(job)
            if _scan_halted(job):
                db.add(
                    ScanLog(
                        scan_job_id=job.id,
                        source="offensive-operator",
                        level="WARNING",
                        message=f"pause_guard target={target} status={job.status}; saindo sem persistir nova fase",
                    )
                )
                db.commit()
                return {"ok": False, "scan_id": job.id, "halted": job.status}
            _live_state = job.state_data or {}
            for _k in (_live_state.get("completed_work") or []):
                completed_work.add(_k)
            for _t in (_live_state.get("target_set") or []):
                if _t and _t not in all_targets:
                    all_targets.append(_t)
            for _h, _ip in (_live_state.get("host_ip_map") or {}).items():
                host_ip_map.setdefault(_h, _ip)
        except Exception:  # noqa: BLE001
            pass
        _delegated_targets = set((job.state_data or {}).get("parallel_delegated_targets") or [])
        if target in _delegated_targets:
            _target_idx += 1
            continue
        # ── Portão de alcançabilidade (SYN): pula alvo morto p/ não travar o chain ──
        if not _reachability_gate(db, job, target, completed_work, _phases_for_level):
            _target_idx += 1
            continue
        scope = _scope_from_job(job, target, execution_mode)
        offensive_state["target"] = target
        offensive_state["campaign_id"] = offensive_state.get("campaign_id") or f"scan-{job.id}"

        for phase_id in PHASE_ORDER:
            # Skip phases outside the configured scan_level (asm = recon only).
            if allowed_phases is not None and phase_id not in allowed_phases:
                continue
            # P01 (subdomain enumeration) only runs on root/input targets — a
            # discovered subdomain does not get re-enumerated for subdomains.
            if phase_id == "P01" and _target_idx >= _input_target_count:
                continue
            # RESUME: skip work already completed in a prior checkpoint segment.
            _work_key = f"{phase_id}:{target}"
            if _work_key in completed_work:
                continue
            if phase_id == "P01" and not _should_run_subdomain_enumeration(target):
                _record_direct_url_p01_skip(db, job, phase_ledgers, completed_work, target, all_targets)
                continue
            if phase_id != "P01":
                _pf_state = dict(job.state_data or {})
                _profile, _created = _preflight_profile_for(_pf_state, target)
                # ── Stale-cache rescue: batch phases (P02 naabu, P06 httpx) run via
                # the Kali runner which has reliable external DNS. If a batch phase
                # already completed for this target, the host IS reachable — a
                # stale dns_dead/tcp_closed preflight from a transient backend DNS
                # failure must not cascade into skipping all downstream phases.
                _batch_confirmed = (
                    f"P06:{target}" in completed_work
                    or f"P02:{target}" in completed_work
                )
                if _profile.get("status") in {"dns_dead", "tcp_closed", "invalid"} and _batch_confirmed:
                    _profile = {
                        **_profile,
                        "status": "http_live",
                        "reason": "http_confirmed_by_p06_batch",
                        "dns_resolves": True,
                        "stale_cache_rescued": True,
                    }
                    _created = True
                if _created:
                    _current_state = dict(job.state_data or {})
                    _pf_state["preflight"] = dict(_pf_state.get("preflight") or {})
                    _pf_state["preflight"].setdefault("targets", {})[target] = _profile
                    _current_state["preflight"] = _pf_state.get("preflight") or {}
                    job.state_data = _current_state
                    db.add(ScanLog(
                        scan_job_id=job.id,
                        source="scan-intelligence",
                        level="INFO",
                        message=(
                            f"tier1_preflight target={target} status={_profile.get('status')} "
                            f"ip={_profile.get('ip') or '-'} ports={_profile.get('open_ports') or []} "
                            f"http={len(_profile.get('http') or [])} reason={_profile.get('reason')}"
                        ),
                    ))
                    db.commit()
                _skip_reason = preflight_skip_reason(phase_id, _profile)
                if _skip_reason:
                    _record_preflight_skip(db, job, phase_ledgers, completed_work, phase_id, target, _skip_reason)
                    continue
            # IP-GROUPING: a network phase (port scan) is bound to the host's
            # IP. If a sibling hostname on the same IP already ran it, reuse —
            # don't re-scan the same WAF/CDN edge (and trigger 429s).
            if phase_id in NETWORK_PHASES:
                _host_ip = host_ip_map.get(target)
                if _host_ip and f"{phase_id}:ip:{_host_ip}" in completed_work:
                    completed_work.add(_work_key)
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                                   message=f"ip_dedup phase={phase_id} target={target} — IP {_host_ip} already scanned, reused"))
                    db.commit()
                    continue
            # ── P10/P12/P13 target upgrade: prefer parameterized URLs from P03 ──
            # sqlmap (P10) and dalfox (P12) need a URL with parameters.
            # If P03 crawlers discovered parameterized URLs, use the best one.
            _effective_target = target
            if phase_id in {"P10", "P12", "P13"}:
                _p03_urls = list(dict(job.state_data or {}).get("discovered_parameterized_urls") or [])
                if _p03_urls:
                    # P10 (sqlmap): prefer URLs with `id=` or numeric params (SQLi-likely)
                    # P12 (dalfox): prefer URLs with text/string params (XSS-likely)
                    if phase_id == "P10":
                        _sqli_candidate = next(
                            (u for u in _p03_urls if "id=" in u.lower() or "news" in u.lower()),
                            _p03_urls[0]
                        )
                        _effective_target = _sqli_candidate
                    elif phase_id == "P12":
                        _xss_candidate = next(
                            (u for u in _p03_urls if any(p in u.lower() for p in ["name=", "q=", "search=", "query=", "newsad="])),
                            _p03_urls[0]
                        )
                        _effective_target = _xss_candidate
                    else:
                        _effective_target = _p03_urls[0]
                    if _effective_target != target:
                        db.add(ScanLog(
                            scan_job_id=job.id, source="scan-intelligence", level="INFO",
                            message=f"target_upgrade phase={phase_id} original={target} → parameterized={_effective_target}",
                        ))
                # P13 (bl-test): expose the full discovered URL list via thread-local
                # so business logic testing covers every parameterized endpoint.
                if phase_id == "P13":
                    _set_discovered_urls(_p03_urls)

            job.current_step = f"{phase_id} {PHASE_CONTRACTS[phase_id]['name']} ({_effective_target})"
            state = dict(job.state_data or {})
            state.update(
                {
                    "execution_mode": execution_mode,
                    "current_pentest_phase_id": phase_id,
                    "current_pentest_target": _effective_target,
                    "offensive_operator_phase_queue_enabled": _phase_queue_enabled,
                    "offensive_operator_phase_task_budget": _phase_task_budget,
                    "offensive_state": offensive_state,
                    "phase_ledger_v2": phase_ledgers,
                    "operation_events": events,
                }
            )
            job.state_data = state
            db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO", message=f"dispatch phase_id={phase_id} tool=kali target={_effective_target}"))
            db.commit()

            events.append(create_operation_event("phase_started", offensive_state["campaign_id"], str(job.id), phase_id, status="running"))
            _phase_unit_start = _time.monotonic()
            result = runtime.run_phase(phase_id, _effective_target, scope, execution_mode, offensive_state)
            try:
                db.refresh(job)
                if _scan_halted(job):
                    db.add(
                        ScanLog(
                            scan_job_id=job.id,
                            source="offensive-operator",
                            level="WARNING",
                            message=(
                                f"pause_guard phase_id={phase_id} target={target} status={job.status}; "
                                "resultado em andamento descartado antes da persistencia"
                            ),
                        )
                    )
                    db.commit()
                    return {"ok": False, "scan_id": job.id, "halted": job.status, "phase_id": phase_id, "target": target}
            except Exception:
                pass
            offensive_state = result["offensive_state"]
            phase_ledger = result["phase_ledger"]
            phase_ledger["target"] = target

            # ── Multi-URL attack: run the primary attack tool against EVERY
            # discovered parameterized URL, not just the one _effective_target.
            # testaspnet has Comments.aspx?id=, ReadNews.aspx?id=, ReadNews.aspx?NewsAd=
            # — sqlmap/dalfox must hit ALL of them, not the first match only.
            if phase_id in {"P10", "P12"}:
                try:
                    from urllib.parse import urlparse as _up, parse_qs as _pqs
                    _all_param_urls = list(dict(job.state_data or {}).get("discovered_parameterized_urls") or [])
                    if phase_id == "P10":
                        _primary_tool, _primary_profile, _primary_skill = "sqlmap", "sqlmap_basic", "skill.vuln.sql_injection"
                    else:
                        _primary_tool, _primary_profile, _primary_skill = "dalfox", "dalfox_xss", "skill.vuln.xss"
                    # Dedupe by injection point = path + sorted param NAMES (ignore values).
                    # Comments.aspx?id=2 and Comments.aspx?id=1337 are the SAME injection
                    # point — test it once, not 8 times. Prefer clean (non-payload) values.
                    _by_point: dict[str, str] = {}
                    for _u in _all_param_urls:
                        if "=" not in _u:
                            continue
                        try:
                            _pp = _up(_u)
                            _pnames = ",".join(sorted(_pqs(_pp.query).keys()))
                            _point = f"{_pp.path}?{_pnames}"
                        except Exception:
                            _point = _u
                        # Prefer the URL with the shortest query (cleanest values, no injected payloads)
                        if _point not in _by_point or len(_u) < len(_by_point[_point]):
                            _by_point[_point] = _u
                    _attack_urls = [u for u in _by_point.values() if u != _effective_target][:8]
                    _supp_results: list[dict[str, Any]] = []
                    _skipped_urls = 0
                    for _au in _attack_urls:
                        # Per-phase-unit deadline: stop launching further multi-URL
                        # tools once the budget is spent (each can take up to 3600s).
                        if _time.monotonic() - _phase_unit_start > _PHASE_UNIT_DEADLINE:
                            _skipped_urls = len(_attack_urls) - len(_supp_results)
                            db.add(ScanLog(
                                scan_job_id=job.id, source="offensive-operator", level="WARNING",
                                message=(
                                    f"multiurl_deadline phase={phase_id} tool={_primary_tool} "
                                    f"budget={_PHASE_UNIT_DEADLINE}s exceeded — {_skipped_urls} URL(s) "
                                    f"not attacked this pass (will retry on a later phase-unit)"
                                ),
                            ))
                            db.commit()
                            break
                        _supp_exec = {
                            "mcp_request_id": f"multiurl-{phase_id}-{abs(hash(_au)) % 10**8}",
                            "phase_id": phase_id,
                            "skill_id": _primary_skill,
                            "tool_name": _primary_tool,
                            "profile": _primary_profile,
                            "target": _au,
                            "arguments": {"target": _au, "scan_id": job.id, "timeout": 3600},
                            "timeout": 3600,
                            "expected_evidence": ["stdout", "raw_tool_output", "parsed_result"],
                        }
                        try:
                            _supp_results.append(_call_mcp_execution(_supp_exec))
                        except Exception:
                            continue
                    if _supp_results:
                        result["mcp_results"] = list(result.get("mcp_results") or []) + _supp_results
                        db.add(ScanLog(
                            scan_job_id=job.id, source="offensive-operator", level="INFO",
                            message=(
                                f"multiurl_attack phase={phase_id} tool={_primary_tool} "
                                f"extra_urls={len(_attack_urls)} (alvos: "
                                + ", ".join(u.split('/')[-1][:40] for u in _attack_urls[:3]) + ")"
                            ),
                        ))
                        db.commit()
                except Exception as _mu_err:
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                                   message=f"multiurl_attack_failed phase={phase_id} error={_mu_err!s}"))
                    db.commit()

            # Embed mcp_results in the ledger so _persist_offensive_findings can extract evidence.
            # Trim stdout/stderr to _MCP_STDOUT_STATE_CAP before storing in state_data.
            phase_ledger["mcp_results"] = _trim_mcp_stdout(result.get("mcp_results") or [])
            phase_ledgers.append(phase_ledger)

            # Emit per-tool command log lines so WorkerLogsPage CommandFeed picks them up
            mcp_results = result.get("mcp_results") or []
            for mcp_res in mcp_results:
                tool_name = mcp_res.get("tool_name", "unknown")
                status_v = mcp_res.get("status", "unknown")
                backend_v = str(mcp_res.get("execution_backend") or "mcp")
                skill_v = str(mcp_res.get("skill_id") or "")
                profile_v = str(mcp_res.get("profile") or "")
                key_v = str(mcp_res.get("execution_key") or "")
                stdout_v = str(mcp_res.get("stdout_path") or mcp_res.get("stdout") or "")[:500]
                stderr_v = str(mcp_res.get("stderr_path") or mcp_res.get("stderr") or "")[:200]
                rc = mcp_res.get("exit_code") if mcp_res.get("exit_code") is not None else mcp_res.get("return_code")
                log_msg = (
                    f"{backend_v} tool={tool_name} profile={profile_v} phase={phase_id} skill={skill_v} status={status_v}"
                    f" execution_key={key_v}"
                    f" return_code={rc}"
                    f" stdout={stdout_v!r}"
                    + (f" stderr={stderr_v!r}" if stderr_v else "")
                )
                source_v = "backend-local" if backend_v == "backend_local" else "kali-runner"
                db.add(ScanLog(scan_job_id=job.id, source=source_v, level="INFO", message=log_msg))

            phase_status = phase_ledger.get("status", "")
            validator_reason = result["validator_decision"].get("reason", "")
            db.add(ScanLog(
                scan_job_id=job.id,
                source="offensive-operator",
                level="INFO" if phase_status in {"completed", "partial"} else "WARNING",
                message=(
                    f"phase_result phase_id={phase_id} status={phase_status}"
                    f" tools_attempted={phase_ledger.get('tools_attempted', [])} tools_success={phase_ledger.get('tools_success', [])}"
                    f" reason={validator_reason}"
                ),
            ))

            events.append(
                create_operation_event(
                    "phase_completed" if result["validator_decision"].get("can_advance") else "phase_blocked",
                    offensive_state["campaign_id"],
                    str(job.id),
                    phase_id,
                    skill_id=",".join((result.get("skill_plan") or {}).get("selected_skills") or []),
                    status=result["phase_ledger"].get("status", ""),
                    details={
                        "reason": result["validator_decision"].get("reason"),
                        "skill_ids": (result.get("skill_plan") or {}).get("selected_skills") or [],
                        "skill_coverage": result["phase_ledger"].get("skill_coverage") or {},
                    },
                )
            )
            state = dict(job.state_data or {})
            state.update(
                {
                    "offensive_operator_enabled": True,
                    "execution_mode": execution_mode,
                    "current_pentest_phase_id": phase_id,
                    "current_pentest_target": target,
                    "offensive_operator_phase_queue_enabled": _phase_queue_enabled,
                    "offensive_operator_phase_task_budget": _phase_task_budget,
                    "offensive_state": offensive_state,
                    "phase_ledger_v2": phase_ledgers,
                    "operation_events": events,
                    "last_skill_plan": result.get("skill_plan"),
                    "last_tool_plan": result.get("tool_plan"),
                    "last_mcp_results": _trim_mcp_stdout(result.get("mcp_results") or []),
                    "last_evidence": result.get("evidence"),
                }
            )

            # ─ Populate runtime evidence so capability ledger inference works ─
            # strategic_planning needs: supervisor_route, selected_skill, operation_plan, pentest_strategy
            selected_skill_ids = (result.get("skill_plan") or {}).get("selected_skills") or []
            if selected_skill_ids:
                state["selected_skill"] = selected_skill_ids[0]  # legacy compatibility
                state["selected_skills"] = selected_skill_ids
            _emit_skill_runtime_telemetry(db, job, phase_id, target, result)
            skill_coverage_state = dict(state.get("skill_coverage") or {})
            skill_coverage_state[f"{phase_id}:{target}"] = result["phase_ledger"].get("skill_coverage") or {}
            state["skill_coverage"] = skill_coverage_state
            state["supervisor_route"] = state.get("supervisor_route") or list(state.get("phase_ledger_v2") and [phase_id] or [phase_id])
            state["operation_plan"] = state.get("operation_plan") or {
                "campaign_id": offensive_state.get("campaign_id"),
                "target": target,
                "phases": PHASE_ORDER,
                "execution_mode": execution_mode,
            }
            state["pentest_strategy"] = state.get("pentest_strategy") or {
                "campaign_id": offensive_state.get("campaign_id"),
                "phases_planned": PHASE_ORDER,
                "current_phase": phase_id,
            }
            # asset_discovery needs: recon_graph, executed_tool_runs, discovered_ports, lista_ativos
            mcp_list = result.get("mcp_results") or []
            existing_runs = list(state.get("executed_tool_runs") or [])
            existing_runs.extend([{
                "execution_key": m.get("execution_key"),
                "execution_backend": m.get("execution_backend"),
                "tool": m.get("tool_name"),
                "profile": m.get("profile"),
                "phase": phase_id,
                "skill_id": m.get("skill_id"),
                "target": m.get("target") or target,
                "status": m.get("status"),
                "arguments_hash": m.get("arguments_hash"),
                "started_at": m.get("started_at"),
                "finished_at": m.get("finished_at"),
                "exit_code": m.get("exit_code"),
            } for m in mcp_list if isinstance(m, dict)])
            state["executed_tool_runs"] = existing_runs[-500:]
            if phase_id == "P01":
                lista = list(state.get("lista_ativos") or [])
                for m in mcp_list:
                    stdout = str((m or {}).get("stdout") or "")
                    for line in stdout.splitlines():
                        host = line.strip().split()[0] if line.strip() else ""
                        if host and "." in host and host not in lista:
                            lista.append(host)
                state["lista_ativos"] = lista
                state["recon_graph"] = {"root": target, "assets": lista}
            if phase_id == "P02":
                ports: list[int] = list(state.get("discovered_ports") or [])
                for m in mcp_list:
                    stdout = str((m or {}).get("stdout") or "")
                    for line in stdout.splitlines():
                        if ":" in line:
                            part = line.split(":")[-1].strip()
                            if part.isdigit():
                                p = int(part)
                                if p not in ports and 1 <= p <= 65535:
                                    ports.append(p)
                state["discovered_ports"] = ports[:500]
                # Tier 1 feedback: P02 tells us which ports are actually open.
                # Update preflight_ports so future _preflight_profile_for calls
                # have accurate data, and correct any tcp_closed profile to
                # tcp_open so P03+ phases aren't skipped for live hosts.
                if ports:
                    state["preflight_ports"] = ports[:500]
                    _pf = dict(state.get("preflight") or {})
                    _pf_tgts = dict(_pf.get("targets") or {})
                    if target in _pf_tgts:
                        _old_pf = dict(_pf_tgts[target])
                        if _old_pf.get("status") in ("tcp_closed", "unknown") or not _old_pf.get("open_ports"):
                            _old_pf["status"] = "tcp_open"
                            _old_pf["open_ports"] = sorted(set((_old_pf.get("open_ports") or []) + ports))
                            _old_pf["reason"] = f"P02 scan discovered {len(ports)} open port(s)"
                            _pf_tgts[target] = _old_pf
                            _pf["targets"] = _pf_tgts
                            state["preflight"] = _pf
                    # Tier 4: detect new ports and record the incremental change
                    _p02_prev_ports = list(state.get("discovered_ports_snapshot") or [])
                    _p02_ic = detect_incremental_changes(
                        prev_targets=[], curr_targets=[],
                        prev_ports=_p02_prev_ports, curr_ports=ports,
                        prev_tech=[], curr_tech=[],
                        source_phase="P02",
                    )
                    if _p02_ic["has_changes"]:
                        _p02_changes = list(state.get("incremental_changes") or [])
                        _p02_changes.append(_p02_ic)
                        state["incremental_changes"] = _p02_changes[-100:]
                    state["discovered_ports_snapshot"] = ports[:500]

            # ─── Scan Intelligence hooks ───────────────────────────────────
            # 1. Multi-target propagation: after P01, expand to discovered subdomains
            if phase_id == "P01":
                expanded = expand_targets_after_p01(state, target, mcp_list)
                if len(expanded) > 1:
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=f"target_expansion phase=P01 root={target} expanded_to={len(expanded)} hosts (first 5: {expanded[1:6]})"))
            # 2. Tech-stack detection: every phase contributes signals
            tech_stack = detect_tech_stack(state, mcp_list)
            if tech_stack.get("detected") and phase_id in {"P06", "P07"}:
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                               message=f"tech_detected phase={phase_id} stack={tech_stack['detected']} cms={tech_stack.get('cms')} waf={tech_stack.get('waf')}"))
            # 3. Evasion profile: adapt rate-limits when WAF detected
            evasion = evasion_profile_for(tech_stack)
            state["evasion_profile"] = evasion
            if tech_stack.get("waf") and not state.get("_evasion_logged"):
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                               message=f"evasion_engaged {evasion['rationale']} rate={evasion['rate_limit']}/s threads={evasion['threads']}"))
                state["_evasion_logged"] = True
            # 3b. WAF deception analysis — learn the environment, flag fake ports/429
            env_profile = analyze_waf_behavior(state, mcp_list)
            if env_profile.get("waf_present") and not state.get("_waf_analysis_logged"):
                behaviors = env_profile.get("observed_behaviors") or []
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                               message=(f"waf_environment_learned vendors={env_profile.get('waf_vendors')} "
                                        f"behaviors={behaviors} confidence_penalty={env_profile.get('finding_confidence_penalty')}%")))
                state["_waf_analysis_logged"] = True
            # 4. Evidence validation: re-probe critical findings via MCP curl
            try:
                def _call_curl(url: str) -> dict:
                    import requests as _r
                    headers = {"User-Agent": evasion.get("user_agents", ["Mozilla/5.0"])[0], **auth_headers_from_state(state)}
                    r = _r.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
                    return {"status_code": r.status_code, "body": r.text[:500]}
                # 429 detection + ADAPTIVE RETRY. If the WAF throttled tools,
                # wait the back-off window and re-run the phase with the
                # reduced-rate evasion profile already engaged. Cap at 1 retry
                # per (phase,target) so we never loop indefinitely.
                _rl = detect_rate_limit_signals(mcp_list)
                _retry_key = f"_rl_retried_{_work_key}"
                if _rl.get("hit") and not state.get(_retry_key):
                    state[_retry_key] = True
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                   message=(f"rate_limit_detected phase={phase_id} target={target} "
                                            f"tools_throttled={_rl['tools_throttled']} — backing off 30s "
                                            f"and re-running with reduced-rate evasion profile")))
                    state["rate_limited_phases"] = list(set((state.get("rate_limited_phases") or []) + [phase_id]))
                    job.state_data = state
                    db.commit()
                    _time.sleep(30)
                    # Re-run the phase with the slow profile already in state
                    try:
                        _retry_result = runtime.run_phase(phase_id, target, scope, execution_mode, offensive_state)
                        _retry_ledger = _retry_result["phase_ledger"]
                        _retry_ledger["target"] = target
                        _retry_ledger["mcp_results"] = _retry_result.get("mcp_results") or []
                        _retry_ledger["rate_limit_retry"] = True
                        phase_ledgers.append(_retry_ledger)
                        offensive_state = _retry_result["offensive_state"]
                        # Replace mcp_list with retry data for downstream hooks
                        mcp_list = _retry_result.get("mcp_results") or []
                        result = _retry_result
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                       message=f"rate_limit_retry_completed phase={phase_id} target={target} status={_retry_ledger.get('status')}"))
                    except Exception as _re_exc:  # noqa: BLE001
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                       message=f"rate_limit_retry_failed phase={phase_id} error={_re_exc!s}"))
                validations = validate_critical_findings(state, mcp_list, call_curl=_call_curl)
                # LLM reasoning between phases — only after high-signal phases
                try:
                    _tool_evs_for_llm = []
                    for m in mcp_list:
                        if isinstance(m, dict) and m.get("status") in ("success", "done"):
                            _tool_evs_for_llm.append(_extract_evidence(phase_id, m.get("tool_name", ""), m))
                    _reasoning = llm_phase_reasoning(state, phase_id, target, _tool_evs_for_llm, tech_stack, env_profile)
                    if _reasoning:
                        state["llm_reasoning"] = (state.get("llm_reasoning") or []) + [_reasoning]
                        # Merge injected_tools into per-phase plans
                        merged = state.get("llm_injected_tools") or {}
                        for ph, tools in (_reasoning.get("injected_tools") or {}).items():
                            merged.setdefault(ph, [])
                            for t in tools:
                                if t not in merged[ph]:
                                    merged[ph].append(t)
                        state["llm_injected_tools"] = merged
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                       message=(f"llm_reasoning after={phase_id} "
                                                f"suggested_phases={list((_reasoning.get('injected_tools') or {}).keys())} "
                                                f"reason=\"{_reasoning.get('reasoning','')[:120]}\"")))
                except Exception:  # noqa: BLE001
                    pass
                if validations:
                    _vc = {}
                    for _v in validations:
                        _s = _v.get("validation_status", "?")
                        _vc[_s] = _vc.get(_s, 0) + 1
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=(f"finding_validation phase={phase_id} validated={len(validations)} "
                                            f"confirmed={_vc.get('confirmed', 0)} false_positive={_vc.get('false_positive', 0)} "
                                            f"waf_blocked={_vc.get('waf_blocked', 0)} unconfirmed={_vc.get('unconfirmed', 0)}")))
            except Exception as exc:  # noqa: BLE001
                pass
            # adversarial_hypothesis needs: pentest_hypotheses, skill_invocation, tool_selection_contract
            hypotheses = list(state.get("pentest_hypotheses") or [])
            for h in offensive_state.get("open_hypotheses", [])[-5:]:
                if h not in hypotheses:
                    hypotheses.append(h)
            state["pentest_hypotheses"] = hypotheses[-200:]
            invocations = list(state.get("skill_invocation") or [])
            if selected_skill_ids:
                for _sid in selected_skill_ids:
                    invocations.append({"phase_id": phase_id, "skill_id": _sid, "target": target})
            state["skill_invocation"] = invocations[-200:]
            state["tool_selection_contract"] = {
                "phase_id": phase_id,
                "tools": [t.get("tool_name") for t in (result.get("tool_plan") or {}).get("tools", [])],
            }
            # risk_assessment needs: tool_execution_results, vulnerabilidades_encontradas
            state["tool_execution_results"] = _trim_mcp_stdout(mcp_list)
            vulns = list(state.get("vulnerabilidades_encontradas") or [])
            for ev in (result.get("evidence") or []):
                if isinstance(ev, dict) and ev.get("evidence_strength") in {"medium", "strong", "conclusive"}:
                    vulns.append({"phase_id": phase_id, "evidence_id": ev.get("evidence_id"), "type": ev.get("vulnerability_class")})
            state["vulnerabilidades_encontradas"] = vulns[-500:]
            # evidence_adjudication needs: validation_backlog
            state["validation_backlog"] = state.get("validation_backlog") or []
            # node_history: append capability nodes touched
            node_history = list(state.get("node_history") or [])
            for cap in PHASE_TO_CAPABILITIES.get(phase_id, []):
                if cap not in node_history:
                    node_history.append(cap)
            state["node_history"] = node_history
            # completed_capabilities for fully-completed phase
            if result["phase_ledger"].get("status") == "completed":
                completed_caps = list(state.get("completed_capabilities") or [])
                for cap in PHASE_TO_CAPABILITIES.get(phase_id, []):
                    if cap not in completed_caps:
                        completed_caps.append(cap)
                        # Also mark in capability_ledger directly
                        mark_capability(
                            state,
                            cap,
                            source=f"phase_{phase_id}",
                            status="completed",
                            evidence={
                                "phase_id": phase_id,
                                "skill_id": selected_skill_ids[0] if selected_skill_ids else "",
                                "skill_ids": selected_skill_ids,
                            },
                        )
                state["completed_capabilities"] = completed_caps

            job.state_data = state
            # REAL-TIME PERSISTENCE: update progress + persist findings after each phase
            # so partial results survive worker crashes / scan interruption.
            completed_so_far = len([l for l in phase_ledgers if l.get("status") == "completed"])
            partial_so_far = len([l for l in phase_ledgers if l.get("status") == "partial"])
            job.mission_progress = min(100, int(round((len(phase_ledgers) / max(1, len(PHASE_ORDER))) * 100)))
            db.commit()
            try:
                _persist_offensive_findings(db, job, phase_ledgers, targets)
                db.commit()
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                               message=f"finding_persist_partial_failure phase={phase_id} error={exc!s}"))
                db.commit()
            # Only abort on blocked if no skill was resolved at all (hard blocker).
            # Tool-level blocks (e.g. missing optional OOB tool) are logged and skipped.
            _hard_blocked = False
            if result["phase_ledger"].get("status") == "blocked":
                blocking_reason = result["phase_ledger"].get("blocking_reason", "")
                if blocking_reason in {"no_approved_skill_resolved"}:
                    _hard_blocked = True
                # Otherwise continue to the next phase — record as covered/partial.

            # ─── Checkpoint Engine: mark work done, expand targets, re-dispatch ──
            completed_work.add(_work_key)
            # Record the IP-level key for network phases so sibling hostnames
            # on the same IP skip the redundant re-scan.
            if phase_id in NETWORK_PHASES:
                _done_ip = host_ip_map.get(target)
                if _done_ip:
                    completed_work.add(f"{phase_id}:ip:{_done_ip}")
            _cp_state = dict(job.state_data or {})
            _cp_state["completed_work"] = sorted(completed_work)
            # After P01 on a root target, expand the work set with every
            # discovered subdomain. Liveness-filter (drop hosts that don't
            # resolve) and IP-group (so network phases run once per IP).
            # NO CAP by default — every alive subdomain enters the queue.
            # Set subdomain_propagation_cap explicitly to limit if needed.
            if phase_id == "P01":
                _cap_raw = _cp_state.get("subdomain_propagation_cap")
                _cap = int(_cap_raw) if _cap_raw not in (None, "", 0, "0") else None
                _subs = [s for s in (_cp_state.get("expanded_targets") or []) if s and s != target]
                _refined = refine_target_set(target, _subs, cap=_cap)
                for _live in _refined["live_targets"]:
                    if _live and _live not in all_targets:
                        all_targets.append(_live)
                _cp_state["target_set"] = list(all_targets)
                _cp_state["host_ip_map"] = _refined["host_ip"]
                _cp_state["dead_targets"] = _refined["dead_targets"]
                _cp_state["ip_groups"] = _refined["ip_groups"]
                host_ip_map = _refined["host_ip"]
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                               message=(f"target_set refined — {len(_refined['live_targets'])} live, "
                                        f"{len(_refined['dead_targets'])} dead, "
                                        f"{len(_refined['ip_groups'])} unique IP(s); full P02-P22 per live target")))
                # ─ Superfície de ataque: inventaria TODOS os subdomínios vivos como
                # assets (não só o domínio raiz). Antes, um host só virava asset se
                # gerasse uma vuln acionável (linha ~3640), então a superfície
                # mostrava apenas o alvo do scan. O inventário é independente de
                # achados — é o mapa do que existe e responde.
                try:
                    from app.graph.workflow import _persist_discovered_assets_to_db
                    _inv_hosts = []
                    _seen_inv = set()
                    for _h in [target] + list(_refined.get("live_targets") or []):
                        _hn = _normalize_asset_host(str(_h or ""))
                        if _hn and _hn not in _seen_inv:
                            _seen_inv.add(_hn)
                            _inv_hosts.append(_hn)
                    _inv_added = _persist_discovered_assets_to_db(job.id, job.owner_id, _inv_hosts, source_tool="subdomain_enum")
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                                   message=(f"attack_surface inventory — {len(_inv_hosts)} host(s) vivo(s) persistido(s) "
                                            f"como asset ({_inv_added} novo(s))")))
                except Exception as _inv_err:
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                                   message=f"attack_surface inventory falhou: {str(_inv_err)[:120]}"))
                # ─ Tier 4: Asset DAG init + incremental change detection ────
                _cp_state["asset_dag"] = build_asset_dag(_cp_state, all_targets, PHASE_ORDER)
                _ic_prev_targets = list(state.get("expanded_targets_snapshot") or [target])
                _ic_change = detect_incremental_changes(
                    prev_targets=_ic_prev_targets,
                    curr_targets=all_targets,
                    prev_ports=[],
                    curr_ports=[],
                    prev_tech=[],
                    curr_tech=list((state.get("tech_stack") or {}).get("detected") or []),
                    source_phase="P01",
                )
                if _ic_change["has_changes"]:
                    _changes = list(_cp_state.get("incremental_changes") or [])
                    _changes.append(_ic_change)
                    _cp_state["incremental_changes"] = _changes[-100:]
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=(f"tier4_incremental P01 new_targets={len(_ic_change['new_targets'])} "
                                            f"triggered={_ic_change['triggered_phases']}")))
                _cp_state["expanded_targets_snapshot"] = list(all_targets)
                # Emit first partial report after P01 target expansion
                _pr = emit_partial_report(_cp_state, phase_ledgers, all_targets, PHASE_ORDER)
                _reports = list(_cp_state.get("scan_reports") or [])
                _reports.append(_pr)
                _cp_state["scan_reports"] = _reports[-50:]
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                               message=(f"tier4_partial_report coverage={_pr['coverage_pct']}% "
                                        f"targets={_pr['targets_total']} findings={_pr['findings']}")))
                # ─ Tier 3 Batch dispatch: run P02/P06 once for all targets ──
                # Instead of N sequential jobs (one per subdomain), dispatch a
                # single batch job that passes all hosts in one targets.txt.
                # Marked as done in completed_work so the per-target loop skips them.
                _all_live = [t for t in _refined["live_targets"] if t]
                if len(_all_live) >= _BATCH_MIN_TARGETS:
                    _batch_targets_for_phase = [target] + [t for t in _all_live if t != target]
                    for _bp_id in list(_BATCH_PHASE_PROFILES):
                        if allowed_phases is not None and _bp_id not in allowed_phases:
                            continue
                        if all(f"{_bp_id}:{t}" in completed_work for t in _batch_targets_for_phase):
                            continue  # Already done (e.g., resumed scan)
                        _batch_targets_todo = [
                            t for t in _batch_targets_for_phase
                            if f"{_bp_id}:{t}" not in completed_work
                        ]
                        if len(_batch_targets_todo) >= _BATCH_MIN_TARGETS:
                            _dispatch_batch_phase(
                                db, job, _bp_id, _batch_targets_todo,
                                phase_ledgers, completed_work,
                            )
                    # Persist batch completions before subtasks are dispatched so
                    # each subtask reads the updated completed_work from DB and
                    # skips P02/P06 that were already handled in batch.
                    _cp_state["completed_work"] = sorted(completed_work)
                    _cp_state["phase_ledger_v2"] = _merge_phase_ledgers(
                        list(_cp_state.get("phase_ledger_v2") or []), phase_ledgers
                    )
                    job.state_data = _cp_state
                    db.commit()

                # ─ Parallel fan-out: dispatch a subtask per non-root target ─
                # ── L1: OSINT Phase Zero — passive recon before active scanning ──
                # Run once per scan (guarded by osint_phase_zero_done in state_data)
                if not _cp_state.get("osint_phase_zero_done"):
                    try:
                        from app.services.osint_phase_zero import run_osint_phase_zero as _osint0
                        _root_domain = str(target or "").strip()
                        _osint0_result = _osint0(db, job, _root_domain)
                        _cp_state["osint_phase_zero_done"] = True
                        _cp_state["osint_phase_zero_result"] = _osint0_result
                    except Exception as _osint_err:
                        import logging as _olog
                        _olog.getLogger(__name__).debug("osint_phase_zero failed: %s", _osint_err)
                        _cp_state["osint_phase_zero_done"] = True  # Don't retry on failure

                if _cp_state.get("parallelize"):
                    try:
                        _already_delegated = set(_cp_state.get("parallel_delegated_targets") or [])
                        _to_dispatch = [
                            _t for _t in _refined["live_targets"]
                            if _t and _t not in _already_delegated
                        ]
                        _dispatched = 0
                        if settings.scan_work_queue_enabled:
                            from app.services.scan_work_queue import enqueue_scan_work_items, work_queue_counts
                            from app.workers.tasks import dispatch_scan_work_items as _dispatch_wq

                            _seed = enqueue_scan_work_items(db, job, _to_dispatch, source="p01_parallel")
                            _dispatched = int(_seed.get("created") or 0)
                            _already_delegated.update(_to_dispatch)
                            _cp_state["parallel_engine"] = "capacity_work_queue"
                            _cp_state["work_queue_counts"] = work_queue_counts(db, job.id)
                            _dispatch_wq.delay(job.id)
                        else:
                            from app.workers.tasks import run_scan_target_subset as _rsts
                            for _t in _to_dispatch:
                                _rsts.delay(job.id, _t)
                                _already_delegated.add(_t)
                                _dispatched += 1
                            _cp_state["parallel_engine"] = "target_subset"
                        _cp_state["parallel_delegated_targets"] = sorted(_already_delegated)
                        _cp_state["parallel_pending_targets"] = sorted(_to_dispatch if not settings.scan_work_queue_enabled else [])
                        _cp_state["parallel_batch_size"] = len(_to_dispatch)
                        _cp_state["_parallel_checkpoint_after_p01"] = bool(_dispatched)
                        if _dispatched:
                            db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                                           message=(
                                               f"parallel_fanout engine={_cp_state.get('parallel_engine')} "
                                               f"dispatched={_dispatched} delegated_total={len(_already_delegated)}"
                                           )))
                    except Exception as _pfe:  # noqa: BLE001
                        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                                       message=f"parallel_fanout_failed error={_pfe!s}"))
                # ─ Domain Takeover: check dead targets for dangling DNS ────────
                # Subdomains that don't resolve may still have CNAME records
                # pointing to unclaimed services (GitHub Pages, S3, Heroku, etc.).
                try:
                    _dead = [t for t in (_refined.get("dead_targets") or []) if t and t != target]
                    if _dead and not _cp_state.get("_domain_takeover_dispatched"):
                        _all_for_takeover = [target] + list(_refined.get("live_targets") or []) + _dead
                        _all_for_takeover = sorted(set(_all_for_takeover))
                        _dispatch_batch_phase(
                            db, job, "P01",  # runs under P01 bucket, distinct profile
                            _all_for_takeover, phase_ledgers, completed_work,
                            profile_override="domain_takeover_batch",
                        )
                        _cp_state["_domain_takeover_dispatched"] = True
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                       message=(
                                           f"domain_takeover_batch dispatched for {len(_dead)} dead + "
                                           f"{len(_refined.get('live_targets') or [])} live targets"
                                       )))
                except Exception as _dte:  # noqa: BLE001
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                                   message=f"domain_takeover_dispatch_failed error={_dte!s}"))
                # ─ WAF Origin Discovery — hunt the real server behind the WAF ─
                try:
                    from app.services.waf_origin import discover_origin_candidates as _disc_origin
                    _origin = _disc_origin(target, _refined["host_ip"], result.get("mcp_results") or [])
                    _cp_state["origin_discovery"] = _origin
                    _cands = _origin.get("candidate_origins") or []
                    if _cands:
                        _top = _cands[0]
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                       message=(f"waf_origin_discovery {_origin['summary']} — "
                                                f"top candidate {_top['ip']} (confidence={_top['confidence']}, "
                                                f"hosts={_top['hosts'][:3]})")))
                        _persist_origin_finding(db, job, target, _origin)
                    else:
                        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                       message=f"waf_origin_discovery {_origin['summary']}"))
                except Exception as _oexc:  # noqa: BLE001
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                                   message=f"waf_origin_discovery_failed error={_oexc!s}"))
            # ─ P03 post-processing: extract parameterized URLs for attack phases ─
            # Crawlers (katana, gau, waybackurls) discover URLs with parameters
            # like Comments.aspx?id=3 and ReadNews.aspx?id=3&NewsAd=...
            # These are stored in state["discovered_parameterized_urls"] so
            # P10 (sqlmap) and P12 (dalfox) can target them instead of only
            # the initial entry URL.
            if phase_id == "P03" and not _cp_state.get("_p03_url_expansion_done"):
                try:
                    _crawler_tools = {"katana", "katana-js", "gospider", "hakrawler", "gau", "waybackurls"}
                    _param_urls: list[str] = list(_cp_state.get("discovered_parameterized_urls") or [])
                    _param_seen: set[str] = set(_param_urls)
                    for _ev in result.get("tool_evidences") or []:
                        if not isinstance(_ev, dict):
                            continue
                        if str(_ev.get("tool") or "").lower() not in _crawler_tools:
                            continue
                        for _u in (_ev.get("parameterized_urls") or []):
                            if _u and _u not in _param_seen:
                                _param_seen.add(_u)
                                _param_urls.append(_u)
                    # Also scan mcp_results for stdout lines from crawlers
                    for _res in (result.get("mcp_results") or []):
                        if not isinstance(_res, dict):
                            continue
                        if str(_res.get("tool_name") or "").lower() not in _crawler_tools:
                            continue
                        for _line in str(_res.get("stdout") or "").splitlines():
                            _u = _line.strip()
                            if _u.startswith("http") and "?" in _u and "=" in _u and _u not in _param_seen:
                                _param_seen.add(_u)
                                _param_urls.append(_u)
                    if _param_urls:
                        _cp_state["discovered_parameterized_urls"] = _param_urls[:100]
                        _cp_state["_p03_url_expansion_done"] = True
                        db.add(ScanLog(
                            scan_job_id=job.id, source="scan-intelligence", level="INFO",
                            message=(
                                f"p03_url_expansion: {len(_param_urls)} parameterized URLs discovered "
                                f"— feeding P10/P12. Sample: "
                                + ", ".join(u.split("?")[0].split("/")[-1] + "?" + u.split("?")[1][:30]
                                            for u in _param_urls[:3])
                            ),
                        ))
                except Exception as _p3e:
                    pass

            # Progress across the whole job (every target × every phase).
            _total_units = max(1, len(all_targets) * max(1, len(_phases_for_level)))
            job.mission_progress = min(100, int(round(len(completed_work) / _total_units * 100)))
            # ─ Tier 4: per-phase DAG update + periodic partial report ─────────
            # Update only this target's entry in the DAG (cheap: one target).
            try:
                _dag_patch = build_asset_dag(_cp_state, [target], PHASE_ORDER)
                _cur_dag = dict(_cp_state.get("asset_dag") or {})
                _cur_dag.update(_dag_patch)
                _cp_state["asset_dag"] = _cur_dag
            except Exception:  # noqa: BLE001
                pass
            # Emit a partial report every 5 completed phases.
            _pr_counter = int(_cp_state.get("_partial_report_counter") or 0) + 1
            _cp_state["_partial_report_counter"] = _pr_counter
            if _pr_counter % 5 == 0:
                try:
                    _pr = emit_partial_report(_cp_state, phase_ledgers, all_targets, PHASE_ORDER)
                    _scan_reports = list(_cp_state.get("scan_reports") or [])
                    _scan_reports.append(_pr)
                    _cp_state["scan_reports"] = _scan_reports[-50:]
                    db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                                   message=(f"tier4_partial_report coverage={_pr['coverage_pct']}% "
                                            f"targets_active={_pr['targets_active']}/{_pr['targets_total']} "
                                            f"findings={_pr['findings']}")))
                except Exception:  # noqa: BLE001
                    pass
            _parallel_checkpoint_after_p01 = bool(_cp_state.pop("_parallel_checkpoint_after_p01", False))
            job.state_data = _cp_state
            db.commit()
            if phase_id == "P01" and _parallel_checkpoint_after_p01:
                _pending_parallel = _pending_parallel_targets(_cp_state, completed_work, allowed_phases)
                _wait_seconds = max(15, int(_cp_state.get("parallel_wait_seconds") or settings.scan_parallel_wait_seconds or 60))
                job.current_step = f"parallel: {len(_pending_parallel)} target(s) delegados"
                db.add(ScanLog(
                    scan_job_id=job.id,
                    source="offensive-operator",
                    level="INFO",
                    message=(
                        f"parallel_checkpoint_after_p01 delegated={len(_pending_parallel)} "
                        f"redispatch_in={_wait_seconds}s"
                    ),
                ))
                db.commit()
                _delegated_targets = set((job.state_data or {}).get("parallel_delegated_targets") or [])
                _next_unit = _next_pending_phase_target(all_targets, completed_work, _input_target_count, allowed_phases, _delegated_targets)
                _next_phase = (_next_unit or ("P02", target))[0]
                queued = _enqueue_operator_continuation(
                    db,
                    job,
                    scan_mode,
                    _next_phase,
                    countdown=_wait_seconds,
                    reason="parallel_checkpoint_after_p01",
                )
                db.commit()
                return {"checkpointed": True, "parallel_delegated_targets": len(_pending_parallel), **queued}
            _phase_units_this_task += 1
            if _phase_queue_enabled and _phase_units_this_task >= _phase_task_budget and not _hard_blocked:
                _delegated_targets = set((job.state_data or {}).get("parallel_delegated_targets") or [])
                _next_unit = _next_pending_phase_target(all_targets, completed_work, _input_target_count, allowed_phases, _delegated_targets)
                if _next_unit:
                    _next_phase, _next_target = _next_unit
                    job.current_step = f"checkpoint: next {_next_phase} {PHASE_CONTRACTS[_next_phase]['name']} ({_next_target})"
                    queued = _enqueue_operator_continuation(
                        db,
                        job,
                        scan_mode,
                        _next_phase,
                        reason=f"phase_task_budget_{_phase_task_budget}",
                    )
                    db.commit()
                    return {
                        "checkpointed": True,
                        "phase_queue": True,
                        "completed_phase_targets": len(completed_work),
                        "next_phase_id": _next_phase,
                        "next_target": _next_target,
                        **queued,
                    }
            # Re-dispatch before the Celery time limit so deep multi-target
            # scans run effectively unbounded — each (phase,target) is a
            # durable checkpoint, so a continuation resumes exactly here.
            if _time.monotonic() - _checkpoint_start > _CHECKPOINT_SECONDS:
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                               message=(f"checkpoint — {len(completed_work)} phase-targets done; "
                                        f"re-dispatching scan to continue")))
                job.current_step = f"checkpoint: {len(completed_work)} concluídos — continuando"
                _delegated_targets = set((job.state_data or {}).get("parallel_delegated_targets") or [])
                _next_unit = _next_pending_phase_target(all_targets, completed_work, _input_target_count, allowed_phases, _delegated_targets)
                if _next_unit:
                    queued = _enqueue_operator_continuation(
                        db,
                        job,
                        scan_mode,
                        _next_unit[0],
                        reason="time_checkpoint",
                    )
                    db.commit()
                    return {"checkpointed": True, "completed_phase_targets": len(completed_work), **queued}
                db.commit()
            if _hard_blocked:
                break
        _target_idx += 1

    try:
        db.refresh(job)
        _final_state_snapshot = dict(job.state_data or {})
        completed_work = set(_final_state_snapshot.get("completed_work") or completed_work)
        phase_ledgers = list(_final_state_snapshot.get("phase_ledger_v2") or phase_ledgers)
        _wq_engine = _final_state_snapshot.get("parallel_engine") == "capacity_work_queue"
        _wq_all_done = False
        if _wq_engine:
            from app.services.scan_work_queue import has_pending_work, work_queue_counts
            if has_pending_work(db, job.id):
                _wait_seconds = max(15, int(_final_state_snapshot.get("parallel_wait_seconds") or settings.scan_parallel_wait_seconds or 60))
                _final_state_snapshot["work_queue_counts"] = work_queue_counts(db, job.id)
                job.state_data = _final_state_snapshot
                job.current_step = f"fila: aguardando work items {dict(_final_state_snapshot['work_queue_counts'])}"
                db.add(ScanLog(
                    scan_job_id=job.id,
                    source="work-queue",
                    level="INFO",
                    message=f"work_queue_wait counts={_final_state_snapshot['work_queue_counts']} redispatch_in={_wait_seconds}s",
                ))
                db.commit()
                from app.workers.tasks import dispatch_scan_work_items as _dispatch_wq
                _dispatch_wq.delay(job.id)
                _final_targets = list(_final_state_snapshot.get("target_set") or all_targets)
                _delegated_targets = set(_final_state_snapshot.get("parallel_delegated_targets") or [])
                _next_unit = _next_pending_phase_target(_final_targets, completed_work, _input_target_count, allowed_phases, _delegated_targets)
                queued = _enqueue_operator_continuation(
                    db,
                    job,
                    scan_mode,
                    _next_unit[0] if _next_unit else "P22",
                    countdown=_wait_seconds,
                    reason="work_queue_wait",
                )
                db.commit()
                return {"checkpointed": True, "work_queue_counts": _final_state_snapshot["work_queue_counts"], **queued}
            else:
                # work_queue tem itens mas nenhum está ativo → tudo terminal, prosseguir para conclusão
                _wq_all_done = True
                db.add(ScanLog(
                    scan_job_id=job.id,
                    source="work-queue",
                    level="INFO",
                    message="work_queue_complete — todos os items terminais, finalizando scan",
                ))
                db.commit()
        # Skip _pending_parallel check when work_queue handled everything
        _pending_parallel = [] if _wq_all_done else _pending_parallel_targets(_final_state_snapshot, completed_work, allowed_phases)
        if _pending_parallel:
            _wait_seconds = max(15, int(_final_state_snapshot.get("parallel_wait_seconds") or settings.scan_parallel_wait_seconds or 60))
            _final_state_snapshot["parallel_pending_targets"] = _pending_parallel
            job.state_data = _final_state_snapshot
            job.current_step = f"parallel: aguardando {len(_pending_parallel)} target(s) delegados"
            db.add(ScanLog(
                scan_job_id=job.id,
                source="offensive-operator",
                level="INFO",
                message=(
                    f"parallel_wait pending={len(_pending_parallel)} "
                    f"completed_work={len(completed_work)} redispatch_in={_wait_seconds}s"
                ),
            ))
            db.commit()
            _final_targets = list(_final_state_snapshot.get("target_set") or all_targets)
            _delegated_targets = set(_final_state_snapshot.get("parallel_delegated_targets") or [])
            _next_unit = _next_pending_phase_target(_final_targets, completed_work, _input_target_count, allowed_phases, _delegated_targets)
            queued = _enqueue_operator_continuation(
                db,
                job,
                scan_mode,
                _next_unit[0] if _next_unit else "P22",
                countdown=_wait_seconds,
                reason="parallel_wait",
            )
            db.commit()
            return {"checkpointed": True, "parallel_pending_targets": len(_pending_parallel), **queued}
        if _final_state_snapshot.get("parallel_delegated_targets"):
            _final_state_snapshot["parallel_pending_targets"] = []
            job.state_data = _final_state_snapshot
            db.commit()
    except Exception as _pwait_exc:  # noqa: BLE001
        db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                       message=f"parallel_wait_check_failed error={_pwait_exc!s}"))
        db.commit()

    campaign = {
        "target": targets[0] if targets else "",
        "targets": targets,
        "execution_mode": execution_mode,
        "phase_ledger": phase_ledgers,
        "offensive_state": offensive_state,
        "operation_events": events,
    }
    report = ReportBuilder().build(campaign)
    state = dict(job.state_data or {})
    state["campaign_report"] = report
    state["report_v2"] = {**dict(state.get("report_v2") or {}), "campaign_report": report}

    # ─── Tier 3/4 post-processing: dedup, CVSS, narrative, diff vs previous ───
    try:
        all_findings = db.query(Finding).filter(Finding.scan_job_id == job.id).all()
        finding_dicts = [{
            "id": f.id, "title": f.title, "severity": f.severity,
            "domain": f.domain, "details": f.details or {},
            "recommendation": f.recommendation,
        } for f in all_findings]
        env_snap = state.get("environment_profile") or {}
        for f, fd in zip(all_findings, finding_dicts):
            _signal = ""
            te = (fd["details"] or {}).get("tool_evidence") or []
            for e in te:
                if e.get("nuclei_findings"): _signal = "nuclei_finding"; break
                if e.get("secrets_found"): _signal = "secret_exposed"; break
                if e.get("open_ports"): _signal = "ports_open"
                elif e.get("discovered_paths"): _signal = "sensitive_path"
            cvss = derive_cvss(f.severity, _signal, bool(env_snap.get("waf_present")))
            f.cvss = cvss
            (f.details or {})["cvss_calculated"] = cvss
        db.commit()
        # FP blocklist — downgrade findings matching past analyst FP markings
        try:
            blocklist = load_fp_blocklist(db, owner_id=job.owner_id)
            if blocklist:
                downgraded = 0
                for f, fd in zip(all_findings, finding_dicts):
                    if apply_fp_blocklist(fd, blocklist):
                        f.severity = "info"
                        d = f.details or {}
                        d["fp_downgraded"] = True
                        f.details = d
                        downgraded += 1
                if downgraded:
                    db.commit()
                    db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                                   message=f"fp_blocklist_applied downgraded={downgraded} finding(s) matching known FP signatures"))
                    db.commit()
        except Exception as _fpe:  # noqa: BLE001
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                           message=f"fp_blocklist_failed error={_fpe!s}"))
        deduped = dedup_findings_by_signature(finding_dicts)
        state["unique_findings"] = [{
            "title": d["title"], "severity": d["severity"],
            "instance_count": d.get("instance_count", 1),
            "instances": d.get("instances", []),
        } for d in deduped]
        # Attack-path chaining — correlate findings into kill chains
        chains = chain_findings(finding_dicts)
        state["attack_chains"] = chains
        if chains:
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                           message=(f"attack_chains_identified count={len(chains)} "
                                    f"top=\"{chains[0]['name']}\" severity={chains[0]['severity']}")))
        primary = targets[0] if targets else ""
        narrative = build_executive_narrative(
            job.id, primary, finding_dicts,
            env_profile=env_snap,
            origin=state.get("origin_discovery"),
        )
        state["executive_summary"] = narrative
        from app.models.models import ScanJob as _SJ
        prev_scan = (
            db.query(_SJ)
            .filter(_SJ.target_query == job.target_query, _SJ.id != job.id, _SJ.status == "completed")
            .order_by(_SJ.created_at.desc())
            .first()
        )
        if prev_scan:
            prev_findings = db.query(Finding).filter(Finding.scan_job_id == prev_scan.id).all()
            prev_dicts = [{"id": pf.id, "title": pf.title, "severity": pf.severity,
                           "domain": pf.domain, "details": pf.details or {}} for pf in prev_findings]
            diff = diff_against_previous(finding_dicts, prev_dicts)
            state["regression_diff"] = {
                "previous_scan_id": prev_scan.id,
                "previous_scan_date": prev_scan.created_at.isoformat() if prev_scan.created_at else None,
                "new_count": diff["new_count"],
                "fixed_count": diff["fixed_count"],
                "persistent_count": diff["persistent_count"],
                "new_titles": [f.get("title") for f in diff["new_findings"]][:10],
                "fixed_titles": [f.get("title") for f in diff["fixed_findings"]][:10],
            }
            db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                           message=(f"regression_diff vs scan #{prev_scan.id}: "
                                    f"new={diff['new_count']} fixed={diff['fixed_count']} "
                                    f"persistent={diff['persistent_count']}")))
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                       message=(f"post_processing dedup_unique={len(deduped)} from {len(finding_dicts)} raw, "
                                f"headline=\"{narrative['headline']}\"")))
    except Exception as _ppe:  # noqa: BLE001
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                       message=f"post_processing_failed error={_ppe!s}"))
    db.commit()

    completed_count = len([l for l in phase_ledgers if l.get("status") == "completed"])
    partial_count = len([l for l in phase_ledgers if l.get("status") == "partial"])
    blocked_count = len([l for l in phase_ledgers if l.get("status") == "blocked"])

    # ─ Finalize capability ledger: governance + executive_analyst from campaign report ─
    completed_phases = [l.get("phase_id") for l in phase_ledgers if l.get("status") == "completed"]
    state["easm_rating"] = {
        "campaign_id": offensive_state.get("campaign_id"),
        "phases_completed": completed_phases,
        "phase_count": len(completed_phases),
        "total_phases": len(PHASE_ORDER),
        "coverage_percent": round((len(completed_phases) / max(1, len(PHASE_ORDER))) * 100),
    }
    state["fair_decomposition"] = state.get("fair_decomposition") or {
        "loss_event_frequency": "low",
        "loss_magnitude": "medium",
        "evidence_phases": completed_phases,
    }
    state["executive_summary"] = state.get("executive_summary") or {
        "target": targets[0] if targets else "",
        "phases_executed": len(phase_ledgers),
        "phases_completed": len(completed_phases),
        "campaign_status": "completed" if (completed_count + partial_count) > 0 else "failed",
    }
    mark_capability(state, "governance", source="report_builder", status="completed",
                    evidence={"easm_rating": state["easm_rating"]})
    mark_capability(state, "executive_analyst", source="report_builder", status="completed",
                    evidence={"summary": state["executive_summary"]})

    try:
        db.refresh(job)
        if _scan_halted(job):
            db.add(
                ScanLog(
                    scan_job_id=job.id,
                    source="offensive-operator",
                    level="WARNING",
                    message=f"pause_guard finalizacao status={job.status}; relatorio/finalizacao nao persistidos",
                )
            )
            db.commit()
            return {"ok": False, "scan_id": job.id, "halted": job.status}
    except Exception:
        pass

    # ─── Learning loop: extract VulnerabilityLearning seeds from scan results ───
    try:
        learning_signals = extract_learning_signals(state, phase_ledgers)
        if learning_signals:
            from app.models.models import VulnerabilityLearning
            from datetime import datetime as _dt
            persisted = 0
            for sig in learning_signals[:30]:  # cap to 30 per scan
                exists = db.query(VulnerabilityLearning).filter(
                    VulnerabilityLearning.title == (sig.get("title") or "")[:255],
                    VulnerabilityLearning.vulnerability_type == (sig.get("template") or "nuclei")[:120],
                ).first()
                if exists:
                    continue
                row = VulnerabilityLearning(
                    title=(sig.get("title") or sig.get("template") or "scan-derived")[:255],
                    vulnerability_type=(sig.get("template") or "nuclei")[:120],
                    summary=sig.get("description") or "",
                    impact=f"Tech stack: {', '.join(sig.get('tech_stack', [])) or 'unknown'}. Severity: {sig.get('severity')}",
                    remediation="Review nuclei template guidance and apply patch/configuration changes.",
                    evidence_signals=[sig.get("template"), sig.get("cve")],
                    safe_validation_steps=[f"curl {sig.get('evidence_url')}", "Verify with nuclei -id " + str(sig.get("template"))],
                    affected_phases=[sig.get("phase_id")],
                    affected_skills=[],
                    recommended_tools=["nuclei", "curl"],
                    technique_count=1,
                    status="pending_review",
                    source="scan_extraction",
                    source_kind="scan_finding",
                    model="scan_intelligence_extractor",
                    owner_id=job.owner_id,
                    created_at=_dt.utcnow(),
                    updated_at=_dt.utcnow(),
                )
                db.add(row)
                persisted += 1
            if persisted:
                db.commit()
                db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="INFO",
                               message=f"learning_loop persisted={persisted} new_signals_from_scan"))
                db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="WARNING",
                       message=f"learning_loop_failed error={exc!s}"))
        db.commit()

    job.state_data = state
    job.mission_progress = min(100, int(round((len(phase_ledgers) / max(1, len(PHASE_ORDER))) * 100)))
    # A scan is "completed" if at least one phase ran (completed or partial).
    # It is "failed" only when zero phases produced any result at all.
    _dead_targets = list((state or {}).get("dead_targets") or [])
    if _dead_targets:
        # Alvo(s) ficaram inacessíveis via SYN > grace. FINALIZA entregando os
        # achados já coletados, com marcador final "Timeout Destination".
        job.status = "completed"
        job.current_step = "Timeout Destination"
        state["timeout_destination"] = {
            "dead_targets": _dead_targets,
            "grace_seconds": _TARGET_UNREACHABLE_GRACE,
            "reason": "alvo inacessível via SYN além do limite — fases restantes puladas",
        }
        job.state_data = state
        db.add(ScanLog(scan_job_id=job.id, source="scan-intelligence", level="ERROR",
                       message=(f"scan_finalizado=Timeout Destination dead_targets={_dead_targets} "
                                f"findings_preservados=sim phases_completed={completed_count} partial={partial_count}")))
    else:
        job.status = "completed" if (completed_count + partial_count) > 0 else "failed"
        job.current_step = "P22 Campaign Report"
    db.commit()

    # ── Persist findings from phase evidence into the Finding table ────────
    _persist_offensive_findings(db, job, phase_ledgers, targets)

    db.commit()
    return campaign


def _extract_evidence(phase_id: str, tool_name: str, mcp_res: dict[str, Any]) -> dict[str, Any]:
    """Parse tool stdout/parsed_result into structured evidence for RedTeam reporting."""
    import json as _json
    stdout = _clean_tool_text(mcp_res.get("stdout") or "")
    parsed = mcp_res.get("parsed_result")
    command = str(mcp_res.get("command") or "")
    duration = mcp_res.get("duration_seconds")
    workdir = str(mcp_res.get("stdout_path") or "")

    evidence: dict[str, Any] = {
        "tool": tool_name,
        "command": command,
        "duration_seconds": duration,
        "workdir": workdir,
        "raw_output_preview": stdout[:3000] if stdout else None,
    }

    tool_lower = tool_name.lower()

    # --- subfinder / amass: subdomains list ---
    if tool_lower in {
        "subfinder",
        "amass",
        "amass-brute",
        "amass-intel",
        "assetfinder",
        "dnsx",
        "dnsrecon",
        "dnsrecon-brt",
        "dnsenum",
        "findomain",
        "sublist3r",
        "ghdb-public-indexes",
    }:
        domains = _extract_domains_from_output(stdout)
        evidence["discovered_subdomains"] = domains[:200]
        evidence["subdomain_count"] = len(domains)
        evidence["finding_summary"] = (
            f"{len(domains)} subdomains discovered via {tool_name}: "
            + (", ".join(domains[:5]) + ("…" if len(domains) > 5 else ""))
            if domains else f"No subdomains found via {tool_name}"
        )

    # --- theHarvester: emails, hosts, IPs from OSINT ---
    elif tool_lower in {"theharvester"}:
        emails = [l.strip() for l in _clean_lines(stdout) if "@" in l and "." in l]
        hosts = _extract_domains_from_output(stdout)
        evidence["emails_found"] = emails[:50]
        evidence["hosts_found"] = hosts[:50]
        evidence["finding_summary"] = (
            f"OSINT harvest: {len(emails)} email(s), {len(hosts)} host(s). "
            + ("Emails: " + ", ".join(emails[:3]) if emails else "")
        )

    # --- naabu / nmap: open ports ---
    elif tool_lower in {"naabu", "nmap", "masscan"}:
        port_lines = [l.strip() for l in _clean_lines(stdout) if ":" in l or re.search(r"\b\d{1,5}/tcp\b", l)]
        parsed_ports = []
        if isinstance(parsed, list):
            parsed_ports = parsed
        elif port_lines:
            parsed_ports = port_lines[:50]
        evidence["open_ports"] = parsed_ports[:50]
        evidence["port_count"] = len(parsed_ports)
        evidence["finding_summary"] = (
            f"{len(parsed_ports)} open port(s) found: "
            + ", ".join(str(p) for p in parsed_ports[:10])
            if parsed_ports else "No open ports found"
        )

    # --- shodan: service banners and exposed services (JSON output from Python API) ---
    elif tool_lower in {"shodan-cli", "shodan"}:
        evidence["shodan_raw"] = stdout[:2000]
        shodan_data: dict[str, Any] = {}
        try:
            shodan_data = _json.loads(stdout) if stdout.strip().startswith("{") else {}
        except Exception:
            shodan_data = {}
        if shodan_data:
            ports = shodan_data.get("ports") or []
            org = shodan_data.get("org") or ""
            hostnames = shodan_data.get("hostnames") or []
            vulns = shodan_data.get("vulns") or []
            banners = shodan_data.get("banners") or []
            evidence["open_ports"] = ports
            evidence["organization"] = org
            evidence["hostnames"] = hostnames
            evidence["cve_ids"] = vulns
            evidence["service_banners"] = banners[:10]
            vuln_str = f", CVEs: {', '.join(vulns[:3])}" if vulns else ""
            evidence["finding_summary"] = (
                f"Shodan [{org}]: {len(ports)} port(s) open — {', '.join(str(p) for p in ports[:8])}"
                + (f", hostnames: {', '.join(hostnames[:3])}" if hostnames else "")
                + vuln_str
            )
        else:
            interesting = [l.strip() for l in _clean_lines(stdout)
                           if any(k in l.lower() for k in ["ip:", "port:", "os:", "org:", "cpe:", "vuln", "banner"])]
            evidence["service_intel"] = interesting[:30]
            evidence["finding_summary"] = (
                f"Shodan OSINT: " + "; ".join(interesting[:5])
                if interesting else "Shodan: no enrichment data"
            )

    # --- ffuf / gobuster: discovered paths ---
    elif tool_lower in {"ffuf", "gobuster", "feroxbuster", "dirsearch", "wfuzz"}:
        if isinstance(parsed, list) and parsed:
            paths = [str(p.get("url") or p.get("path") or p) if isinstance(p, dict) else str(p) for p in parsed[:100]]
        else:
            paths = [l.strip() for l in _clean_lines(stdout) if "/" in l and not _is_noise_line(l)][:100]
        evidence["discovered_paths"] = paths[:100]
        evidence["path_count"] = len(paths)
        evidence["finding_summary"] = (
            f"{len(paths)} path(s) discovered: "
            + ", ".join(paths[:5]) + ("…" if len(paths) > 5 else "")
            if paths else "No paths discovered"
        )

    # --- nuclei: CVEs, vulnerabilities, misconfigurations ---
    elif tool_lower == "nuclei" or tool_lower.startswith("nuclei-"):
        findings = []
        if isinstance(parsed, list):
            for item in parsed[:50]:
                if isinstance(item, dict):
                    findings.append({
                        "template": item.get("template-id") or item.get("template"),
                        "name": item.get("info", {}).get("name") or item.get("name"),
                        "severity": item.get("info", {}).get("severity") or item.get("severity"),
                        "url": item.get("matched-at") or item.get("url"),
                        "description": item.get("info", {}).get("description") or "",
                        "cve": item.get("info", {}).get("classification", {}).get("cve-id") if isinstance(item.get("info"), dict) else None,
                    })
        else:
            # Try parsing JSONL from stdout
            for line in _clean_lines(stdout):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = _json.loads(line)
                    findings.append({
                        "template": item.get("template-id"),
                        "name": (item.get("info") or {}).get("name"),
                        "severity": (item.get("info") or {}).get("severity"),
                        "url": item.get("matched-at"),
                        "description": (item.get("info") or {}).get("description", ""),
                        "cve": ((item.get("info") or {}).get("classification") or {}).get("cve-id"),
                    })
                except Exception:
                    pass
        evidence["nuclei_findings"] = findings
        evidence["vulnerability_count"] = len(findings)
        crits = [f for f in findings if str(f.get("severity") or "").lower() in {"critical", "high"}]
        evidence["finding_summary"] = (
            f"Nuclei: {len(findings)} finding(s) — "
            + (f"{len(crits)} critical/high: " + ", ".join(f.get("name","?") for f in crits[:3]) if crits
               else "no critical/high findings" if findings else "no vulnerabilities detected")
        )

    # --- bl-test: business logic (valor/IDOR-BOLA/mass-assignment/dados sensíveis) ---
    elif tool_lower == "bl-test":
        bl = parsed.get("findings") if isinstance(parsed, dict) else None
        bl = bl if isinstance(bl, list) else []
        norm = []
        for f in bl:
            det = (f.get("details") or {}) if isinstance(f, dict) else {}
            norm.append({
                "title": f.get("title") if isinstance(f, dict) else str(f),
                "severity": f.get("severity") if isinstance(f, dict) else "info",
                "vuln_family": det.get("vuln_family") or "business_logic",
                "url": det.get("asset") or det.get("matched_at"),
                "evidence": det.get("evidence"),
                "payload": det.get("payload"),
                "verification_status": det.get("verification_status"),
            })
        confirmed = [f for f in norm if f.get("verification_status") == "confirmed"]
        evidence["business_logic_findings"] = norm
        evidence["vulnerability_count"] = len(norm)
        evidence["confirmed_count"] = len(confirmed)
        evidence["finding_summary"] = (
            f"Business Logic: {len(confirmed)} confirmada(s) de {len(norm)} — "
            + (", ".join(f.get("title", "?").split("] ", 1)[-1][:50] for f in confirmed[:3]) if confirmed
               else "nenhuma confirmada" if norm else "nenhuma vulnerabilidade de BL detectada")
        )

    # --- gitleaks / trufflehog: secrets and credentials ---
    elif tool_lower in {"gitleaks", "trufflehog", "trufflehog-filesystem"}:
        secrets = []
        if isinstance(parsed, list):
            for item in parsed[:20]:
                if isinstance(item, dict):
                    secrets.append({
                        "type": item.get("RuleID") or item.get("rule_id") or item.get("DetectorName") or "secret",
                        "file": item.get("File") or item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file") or "unknown",
                        "line": item.get("StartLine") or item.get("line"),
                        "secret_preview": str(item.get("Secret") or item.get("Raw") or "")[:20] + "***",
                        "description": item.get("Description") or item.get("RuleDescription") or "",
                    })
        else:
            for line in _clean_lines(stdout):
                try:
                    item = _json.loads(line)
                    secrets.append({
                        "type": item.get("RuleID") or item.get("DetectorName") or "secret",
                        "file": item.get("File") or "unknown",
                        "line": item.get("StartLine"),
                        "secret_preview": str(item.get("Secret") or item.get("Raw") or "")[:20] + "***",
                    })
                except Exception:
                    pass
        evidence["secrets_found"] = secrets
        evidence["secret_count"] = len(secrets)
        evidence["finding_summary"] = (
            f"Credential scan: {len(secrets)} secret(s) found — "
            + "; ".join(f"{s['type']} in {s['file']}:{s.get('line','?')}" for s in secrets[:3])
            if secrets else "No credentials or secrets found"
        )

    # --- curl / curl-headers: HTTP response evidence ---
    elif tool_lower in {"curl", "curl-headers", "httpx", "httpx-headers"}:
        headers = {}
        status_line = ""
        for line in _clean_lines(stdout):
            if line.startswith("HTTP/"):
                status_line = line.strip()
            elif ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        security_headers = {
            k: v for k, v in headers.items()
            if k in {"server", "x-powered-by", "x-frame-options", "content-security-policy",
                     "strict-transport-security", "x-content-type-options", "set-cookie",
                     "www-authenticate", "cf-ray", "x-amz-request-id", "x-aspnet-version"}
        }
        missing_security = [
            h for h in ["x-frame-options", "content-security-policy", "strict-transport-security",
                        "x-content-type-options"]
            if h not in headers
        ]
        tech_hints = []
        if "server" in headers:
            tech_hints.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            tech_hints.append(f"X-Powered-By: {headers['x-powered-by']}")
        if "x-aspnet-version" in headers:
            tech_hints.append(f"ASP.NET: {headers['x-aspnet-version']}")
        evidence["http_status"] = status_line
        evidence["security_headers"] = security_headers
        evidence["missing_security_headers"] = missing_security
        evidence["technology_hints"] = tech_hints
        evidence["finding_summary"] = (
            f"HTTP {status_line}. "
            + (f"Tech: {'; '.join(tech_hints)}. " if tech_hints else "")
            + (f"Missing headers: {', '.join(missing_security)}" if missing_security else "All security headers present")
        )

    # --- arjun: discovered parameters ---
    elif tool_lower in {"arjun", "paramspider"}:
        params = _extract_parameters_from_output(stdout, parsed)
        evidence["discovered_parameters"] = params
        evidence["parameter_count"] = len(params)
        evidence["finding_summary"] = (
            f"{len(params)} parameter(s) discovered: " + ", ".join(params[:10])
            if params else "No parameters discovered"
        )

    # --- sqlmap: injection points ---
    elif tool_lower in {"sqlmap"}:
        # CONFIRMAÇÃO real de injeção — não as linhas "[INFO] testing 'X technique'"
        # nem "parameter ... does NOT appear to be injectable" (que CONTÊM
        # 'injectable'/'parameter'/'technique'). Só conta quando o sqlmap declara
        # a injeção. Ver backlog itens 1 e 15.
        _low = (stdout or "").lower()
        _negative = (
            "do not appear to be injectable" in _low
            or "does not seem to be injectable" in _low
            or "all tested parameters do not" in _low
        )
        _confirmed = (
            "sqlmap identified the following injection point" in _low
            or "is vulnerable" in _low
            or "back-end dbms:" in _low
        )
        injections: list[str] = []
        if _confirmed and not _negative:
            injections = [
                l.strip() for l in _clean_lines(stdout)
                if any(k in l.lower() for k in ["parameter:", "type:", "title:", "payload:", "back-end dbms"])
                and "[info]" not in l.lower() and "[warning]" not in l.lower()
            ]
            if injections:
                evidence["injection_evidence"] = injections[:20]
        evidence["finding_summary"] = (
            "SQLMap: injeção CONFIRMADA — " + "; ".join(injections[:3])
            if injections else ("SQLMap: parâmetros NÃO injetáveis" if _negative else "Nenhuma injeção SQL confirmada")
        )

    elif tool_lower in {"katana", "katana-js", "gospider", "hakrawler", "gau", "waybackurls"}:
        # Crawlers: extract URLs with query parameters — these seed P10/P12 attack phases.
        import re as _re
        _param_re = _re.compile(r"https?://[^\s\"'<>]+\?[^\s\"'<>]+")
        _all_urls: list[str] = []
        _param_urls: list[str] = []
        _seen: set[str] = set()
        for line in (stdout or "").splitlines():
            url = line.strip()
            if not url.startswith("http"):
                continue
            if url not in _seen:
                _seen.add(url)
                _all_urls.append(url)
                if "?" in url and "=" in url:
                    _param_urls.append(url)
        evidence["discovered_urls"] = _all_urls[:200]
        evidence["parameterized_urls"] = _param_urls[:50]
        evidence["url_count"] = len(_all_urls)
        evidence["param_url_count"] = len(_param_urls)
        evidence["finding_summary"] = (
            f"Crawler {tool_name}: {len(_all_urls)} URLs, {len(_param_urls)} with parameters"
            + (f" — {', '.join(u.split('?')[0].split('/')[-1] for u in _param_urls[:3])}" if _param_urls else "")
        )

    else:
        # Generic: return first meaningful output lines — descarta banner ASCII
        # da ferramenta (figlet/box-drawing), que virava título de "vuln". Item 1.
        lines = [l.strip() for l in _clean_lines(stdout) if not _is_noise_line(l) and not _is_banner_line(l)][:20]
        evidence["output_lines"] = lines
        evidence["finding_summary"] = lines[0] if lines else f"{tool_name} executado (sem saída estruturada)"

    return evidence


def _generate_recommendation(phase_id: str, tool_evidences: list[dict[str, Any]]) -> str:
    """Generate specific, actionable recommendation from phase evidence."""
    recs: list[str] = []

    for ev in tool_evidences:
        tool = str(ev.get("tool") or "").lower()

        if tool in {"subfinder", "amass", "amass-brute", "assetfinder"}:
            count = ev.get("subdomain_count", 0)
            subs = ev.get("discovered_subdomains") or []
            if count:
                recs.append(
                    f"Foram encontrados {count} subdomínio(s) ({', '.join(subs[:3])}{'…' if count > 3 else ''}). "
                    "Revise cada subdomínio para verificar se está ativo, se contém serviços expostos indevidamente "
                    "e aplique política de subdomain takeover monitoring."
                )

        elif tool == "theharvester":
            emails = ev.get("emails_found") or []
            if emails:
                recs.append(
                    f"OSINT revelou {len(emails)} e-mail(s) corporativo(s) ({', '.join(emails[:3])}). "
                    "Implemente monitoramento de data leaks (HaveIBeenPwned, DarkWeb), "
                    "habilite MFA em todas as contas e remova endereços expostos de páginas públicas."
                )

        elif tool in {"naabu", "nmap", "masscan"}:
            ports = ev.get("open_ports") or []
            if ports:
                recs.append(
                    f"Portas abertas identificadas: {', '.join(str(p) for p in ports[:10])}. "
                    "Feche portas desnecessárias via firewall, aplique segmentação de rede e "
                    "garanta que serviços expostos estão na versão mais recente com patches de segurança."
                )

        elif tool in {"shodan-cli", "shodan"}:
            cves = ev.get("cve_ids") or []
            banners = ev.get("service_banners") or []
            if cves:
                recs.append(
                    f"Shodan identificou {len(cves)} CVE(s) associado(s) ao alvo: {', '.join(cves[:5])}. "
                    "Aplique os patches correspondentes imediatamente e revise banners de serviços que expõem versões."
                )
            elif banners:
                recs.append(
                    "Shodan indexou banners de serviços deste alvo. "
                    "Remova headers/banners que expõem versão de servidor e habilite regras de firewall para bloquear crawlers."
                )

        elif tool in {"ffuf", "gobuster", "feroxbuster"}:
            paths = ev.get("discovered_paths") or []
            if paths:
                sensitive = [p for p in paths if any(k in p.lower() for k in
                    ["admin", "backup", ".git", "config", "env", "secret", "api", "swagger", "debug", "test"])]
                recs.append(
                    f"Content discovery encontrou {len(paths)} caminho(s)"
                    + (f", incluindo caminhos sensíveis: {', '.join(sensitive[:5])}" if sensitive else "")
                    + ". Restrinja acesso a endpoints administrativos via autenticação, "
                    "remova arquivos de backup/config expostos e configure WAF para bloquear path traversal."
                )

        elif tool == "nuclei":
            findings = ev.get("nuclei_findings") or []
            crits = [f for f in findings if str(f.get("severity") or "").lower() in {"critical", "high"}]
            if crits:
                crit_names = ", ".join(f.get("name", f.get("template", "?")) for f in crits[:3])
                recs.append(
                    f"Nuclei detectou {len(crits)} vulnerabilidade(s) crítica(s)/alta(s): {crit_names}. "
                    "Aplique patches imediatamente, revise configurações de servidor e implemente "
                    "controles de segurança conforme as recomendações de cada template Nuclei."
                )
            elif findings:
                recs.append(
                    f"Nuclei identificou {len(findings)} finding(s) de média/baixa severidade. "
                    "Revise e corrija configurações de segurança, headers HTTP e versões de componentes."
                )

        elif tool in {"gitleaks", "trufflehog", "trufflehog-filesystem"}:
            secrets = ev.get("secrets_found") or []
            if secrets:
                types = list({s.get("type", "secret") for s in secrets[:5]})
                recs.append(
                    f"CRITICAL: {len(secrets)} credencial(is) exposta(s) via {tool}: {', '.join(types)}. "
                    "Revogue e rotacione IMEDIATAMENTE todas as credenciais expostas, "
                    "remova do repositório usando git-filter-branch/BFG, "
                    "implemente pre-commit hooks (git-secrets, detect-secrets) e "
                    "use gerenciador de segredos (HashiCorp Vault, AWS Secrets Manager)."
                )

        elif tool in {"curl", "curl-headers"}:
            missing = ev.get("missing_security_headers") or []
            tech = ev.get("technology_hints") or []
            if missing:
                recs.append(
                    f"Headers de segurança ausentes: {', '.join(missing)}. "
                    "Configure Content-Security-Policy, X-Frame-Options (SAMEORIGIN), "
                    "Strict-Transport-Security (HSTS) e X-Content-Type-Options (nosniff) no servidor web."
                )
            if tech:
                recs.append(
                    f"Stack tecnológica identificada via headers: {'; '.join(tech)}. "
                    "Remova ou ofusque headers que expõem versões de servidor (Server, X-Powered-By) "
                    "para dificultar fingerprinting."
                )

        elif tool in {"arjun", "paramspider"}:
            params = ev.get("discovered_parameters") or []
            if params:
                recs.append(
                    f"{len(params)} parâmetro(s) descoberto(s): {', '.join(params[:8])}. "
                    "Valide e sanitize todos os parâmetros de entrada, implemente rate limiting, "
                    "e revise se parâmetros expostos podem ser vetores de injection ou IDOR."
                )

    if not recs:
        # Phase-level fallback
        phase_fallbacks = {
            "P01": "Implemente monitoramento contínuo de surface de ataque e política de DNS naming convention.",
            "P02": "Minimize a superfície de ataque fechando portas não essenciais e aplicando firewall.",
            "P09": "Execute scans regulares de vulnerabilidade com Nuclei e mantenha templates atualizados.",
            "P17": "Aplique patches de segurança imediatamente para CVEs identificados.",
            "P18": "Implemente DLP (Data Loss Prevention) e monitore vazamentos de credenciais em Dark Web.",
            "P22": "Implemente ciclo de revisão de segurança contínuo baseado nos findings deste relatório.",
        }
        return phase_fallbacks.get(phase_id, "Revise os resultados deste fase e aplique controles de segurança adequados.")

    return " | ".join(recs)


def _has_real_evidence(tool_evidences: list[dict[str, Any]]) -> tuple[bool, str]:
    """Inspect tool evidence and decide whether an actual security-relevant
    finding exists. Returns (has_evidence, strongest_signal).

    A finding is only "real" when a tool produced concrete output:
    discovered ports/paths/subdomains/params, nuclei findings, secrets,
    missing security headers, etc. Phases that ran but found nothing must
    NOT be reported as high/critical vulnerabilities.
    """
    strongest = ""
    for ev in tool_evidences:
        if ev.get("nuclei_findings"):
            crits = [f for f in ev["nuclei_findings"] if str(f.get("severity") or "").lower() in {"critical", "high"}]
            if crits:
                return True, "nuclei_critical"
            strongest = "nuclei_finding"
        if ev.get("secrets_found"):
            return True, "secret_exposed"
        if ev.get("confirmed_count", 0) > 0:        # bl-test: BL confirmada (read-back/baseline)
            return True, "business_logic_confirmed"
        if ev.get("business_logic_findings"):
            strongest = strongest or "business_logic"
        if ev.get("cve_ids"):
            return True, "cve_identified"
        if ev.get("vulnerability_count", 0) > 0:
            strongest = strongest or "vulnerability"
        if ev.get("discovered_paths"):
            sensitive = [p for p in ev["discovered_paths"] if any(
                k in str(p).lower() for k in ["admin", "backup", ".git", "config", ".env", "secret", "debug", "swagger"])]
            if sensitive:
                strongest = "sensitive_path"
            else:
                strongest = strongest or "path_discovered"
        if ev.get("open_ports"):
            strongest = strongest or "ports_open"
        if ev.get("discovered_subdomains"):
            strongest = strongest or "subdomains_found"
        if ev.get("discovered_parameters"):
            strongest = strongest or "params_found"
        if ev.get("missing_security_headers"):
            strongest = strongest or "missing_headers"
        if ev.get("injection_evidence"):
            return True, "injection_confirmed"
        if ev.get("parameterized_urls"):
            strongest = strongest or "parameterized_urls_found"
        if ev.get("url_count", 0) > 0:
            strongest = strongest or "urls_discovered"
    return (bool(strongest), strongest)


def _assess_evidence_severity(phase_id: str, status: str, tool_evidences: list[dict[str, Any]],
                              phase_severity_map: dict[str, str]) -> tuple[str, int]:
    """Derive severity + confidence from ACTUAL evidence — not just the phase.

    Previously every P11 (SSRF) finding was 'high' even with zero evidence,
    producing false positives. Now:
      - no evidence at all   → 'info', low confidence
      - weak recon evidence  → 'info'/'low'
      - confirmed vuln/secret/CVE → phase severity
    """
    has_evidence, signal = _has_real_evidence(tool_evidences)
    phase_sev = phase_severity_map.get(phase_id, "info")

    if not has_evidence:
        # Phase ran but produced nothing actionable — informational only.
        return "info", (25 if status == "completed" else 15)

    # Strong, confirmed signals → escalate to the phase's intended severity.
    if signal in {"nuclei_critical", "secret_exposed", "cve_identified", "injection_confirmed"}:
        return phase_sev if phase_sev != "info" else "high", 90

    # Business logic CONFIRMADA (read-back/baseline via navegador real) — risco
    # REAL que antes caía no default 'info' por falta de branch (backlog item 17).
    # Ex.: token/JWT em localStorage confirmado pelo chromium-capture.
    if signal == "business_logic_confirmed":
        return (phase_sev if phase_sev in {"high", "critical"} else "medium"), 85

    # Sensitive path / nuclei medium finding → at least medium.
    if signal in {"sensitive_path", "nuclei_finding", "vulnerability"}:
        escalated = phase_sev if phase_sev in {"high", "critical", "medium"} else "medium"
        return escalated, 70

    # Recon-level evidence (ports, subdomains, params) → low/info, never high.
    if signal in {"ports_open", "subdomains_found", "path_discovered", "params_found"}:
        return "low", 55
    if signal in {"missing_headers"}:
        return "medium", 60

    return "info", 40


def _build_redteam_title(phase_id: str, phase_name: str, status: str, evidence_list: list[dict[str, Any]]) -> str:
    """Build a descriptive finding title that reflects what was actually found.

    Titles must not imply a vulnerability when no evidence exists. A phase that
    ran but found nothing is labelled 'Sem achados' (coverage only).
    """
    has_evidence, signal = _has_real_evidence(evidence_list)
    # Pick the most informative non-empty summary that isn't a "nothing found" line
    # nem um banner ASCII de ferramenta (item 1).
    meaningful = [
        e.get("finding_summary", "") for e in evidence_list
        if e.get("finding_summary")
        and not str(e.get("finding_summary")).lower().startswith(("no ", "nenhum", "sem ", "nenhuma"))
        and not _is_banner_line(str(e.get("finding_summary")))
    ]
    if has_evidence and meaningful:
        return f"{phase_name}: {meaningful[0][:120]}"
    # Crawler summary: report URL count + parameterized URL count
    _total_urls = sum(int(e.get("url_count") or 0) for e in evidence_list)
    _param_urls = sum(len(e.get("parameterized_urls") or []) for e in evidence_list)
    if _total_urls > 0:
        return (
            f"{phase_name}: {_total_urls} URLs descobertos"
            + (f", {_param_urls} com parâmetros" if _param_urls else "")
        )
    if has_evidence:
        return f"{phase_name}: evidência de superfície coletada"
    # No real evidence — coverage record only, not a vulnerability.
    return f"{phase_name} — Sem achados (cobertura executada)"


def _build_reproduction(phase_id: str, target: str, tool_evidences: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a complete reproduction package for a finding.

    Every finding must be independently verifiable. This returns:
      - discovery_method: how the issue was found (tool + technique)
      - commands: exact CLI commands that produced the evidence (copy-paste ready)
      - payloads: any attack payloads used (SQLi/XSS/SSRF strings, fuzz inputs)
      - proof: raw tool output snippets that constitute the evidence
      - steps: numbered reproduction steps an analyst can follow
    """
    commands: list[dict[str, str]] = []
    payloads: list[str] = []
    proof: list[dict[str, str]] = []

    for ev in tool_evidences:
        tool = str(ev.get("tool") or "")
        cmd = str(ev.get("command") or "")
        if cmd and not any(c["command"] == cmd for c in commands):
            commands.append({"tool": tool, "command": cmd})
        # Raw output proof — first meaningful slice of stdout
        raw = ev.get("raw_output_preview") or ""
        summary = ev.get("finding_summary") or ""
        if raw and summary and not summary.lower().startswith(("no ", "nenhum", "sem ")):
            proof.append({"tool": tool, "output": str(raw)[:1200], "summary": summary})
        # Tool-specific payloads
        if tool == "nuclei":
            for nf in (ev.get("nuclei_findings") or [])[:5]:
                tid = nf.get("template") or ""
                url = nf.get("url") or ""
                if tid:
                    payloads.append(f"nuclei -id {tid} -u {url or target} -v")
        if tool in {"sqlmap"}:
            for inj in (ev.get("injection_evidence") or [])[:3]:
                payloads.append(str(inj))
        if tool in {"ffuf", "gobuster", "feroxbuster", "dirsearch"}:
            for p in (ev.get("discovered_paths") or [])[:8]:
                payloads.append(f"curl -sk -i {p}")
        if tool in {"dalfox"}:
            for x in (ev.get("xss_payloads") or [])[:3]:
                payloads.append(str(x))
        if tool in {"arjun", "paramspider"}:
            for prm in (ev.get("discovered_parameters") or [])[:8]:
                payloads.append(f"# parameter to fuzz: {prm}")

    # Discovery method narrative
    tools_used = sorted({str(ev.get("tool") or "") for ev in tool_evidences if ev.get("tool")})
    discovery_method = (
        f"Fase {phase_id}: descoberto via {', '.join(tools_used)}"
        if tools_used else f"Fase {phase_id}: nenhuma ferramenta produziu evidência"
    )

    # Numbered reproduction steps
    steps: list[str] = []
    if commands:
        steps.append(f"1. Garanta que as ferramentas estejam instaladas: {', '.join(tools_used)}")
        for idx, c in enumerate(commands[:6], start=2):
            steps.append(f"{idx}. Execute: {c['command']}")
        if payloads:
            steps.append(f"{len(steps) + 1}. Valide manualmente com os payloads listados em 'payloads'")
        steps.append(f"{len(steps) + 1}. Compare a saída obtida com a evidência em 'proof'")

    return {
        "discovery_method": discovery_method,
        "commands": commands,
        "payloads": payloads[:20],
        "proof": proof[:8],
        "steps": steps,
        "target": target,
        "verifiable": bool(commands and proof),
    }


def _severity_to_cvss(severity: str) -> float:
    return {
        "critical": 9.2,
        "high": 8.1,
        "medium": 5.6,
        "low": 3.1,
        "info": 0.0,
    }.get(str(severity or "").lower(), 0.0)


def _build_redteam_impact(phase_id: str, severity: str, target: str, tool_evidences: list[dict[str, Any]]) -> str:
    _, signal = _has_real_evidence(tool_evidences)
    if signal == "secret_exposed":
        return (
            f"Credenciais ou segredos expostos em {target} podem permitir acesso nao autorizado, "
            "movimento lateral, abuso de APIs e persistencia fora do perimetro monitorado."
        )
    if signal in {"nuclei_critical", "cve_identified", "vulnerability", "nuclei_finding"}:
        return (
            f"Existe evidencia reproduzivel de vulnerabilidade em {target}. Um operador pode usar "
            "a falha para ampliar acesso, contornar controles ou impactar confidencialidade, "
            "integridade e disponibilidade conforme o componente afetado."
        )
    if signal == "injection_confirmed":
        return (
            f"O alvo {target} apresentou evidencia de injecao. O impacto potencial inclui leitura "
            "ou alteracao de dados, bypass de autenticacao e execucao de consultas nao autorizadas."
        )
    if signal == "business_logic_confirmed":
        return (
            f"Falha de logica de negocio CONFIRMADA em {target} (read-back/baseline via navegador real). "
            "Ex.: token/JWT de sessao acessivel via JavaScript (localStorage/sessionStorage) e roubavel "
            "por XSS, ou autorizacao quebrada (IDOR/BOLA) permitindo acesso a dados de outro usuario."
        )
    if signal == "sensitive_path":
        return (
            f"Caminhos sensiveis expostos em {target} aumentam a chance de acesso a paineis, backups, "
            "arquivos de configuracao ou endpoints administrativos."
        )
    if signal == "missing_headers":
        return (
            f"{target} responde sem controles HTTP defensivos esperados. Isso nao prova exploracao "
            "sozinho, mas amplia risco de clickjacking, XSS exploravel e downgrade de transporte."
        )
    if signal == "ports_open":
        return (
            f"Servicos expostos em {target} ampliam a superficie de ataque e devem ser priorizados "
            "para enumeracao de versao, autenticacao e hardening."
        )
    return (
        f"A fase {phase_id} coletou evidencia de superficie em {target}. O impacto deve ser tratado "
        f"como {severity} ate que a validacao manual confirme explorabilidade."
    )


def _framework_mapping_for_finding(phase_id: str, tool_evidences: list[dict[str, Any]]) -> dict[str, Any]:
    _, signal = _has_real_evidence(tool_evidences)
    pci = ["PCI DSS 11.3 - External and internal penetration testing"]
    cis = ["CIS Control 7 - Continuous Vulnerability Management"]
    iso = ["ISO 27001 A.8.8 - Management of technical vulnerabilities"]
    mitre = [{"id": "T1595", "name": "Active Scanning"}]

    if signal in {"secret_exposed"}:
        pci.append("PCI DSS 8.3 - Strong authentication and credential protection")
        cis.append("CIS Control 6 - Access Control Management")
        iso.append("ISO 27001 A.5.17 - Authentication information")
        mitre.append({"id": "T1552", "name": "Unsecured Credentials"})
    elif signal in {"nuclei_critical", "cve_identified", "vulnerability", "nuclei_finding"}:
        pci.append("PCI DSS 6.3 - Security vulnerabilities are identified and addressed")
        cis.append("CIS Control 18 - Penetration Testing")
        iso.append("ISO 27001 A.8.20 - Network security")
        mitre.append({"id": "T1190", "name": "Exploit Public-Facing Application"})
    elif signal == "missing_headers":
        pci.append("PCI DSS 6.4 - Public-facing web applications are protected")
        cis.append("CIS Control 16 - Application Software Security")
        iso.append("ISO 27001 A.8.26 - Application security requirements")
        mitre.append({"id": "T1189", "name": "Drive-by Compromise"})

    return {
        "mitre_attack": mitre,
        "pci_dss": pci,
        "cis_controls": cis,
        "iso27001": iso,
    }


def _is_actionable_vulnerability(severity: str, tool_evidences: list[dict[str, Any]], reproduction: dict[str, Any]) -> bool:
    if str(severity or "").lower() not in {"medium", "high", "critical"}:
        return False
    has_evidence, signal = _has_real_evidence(tool_evidences)
    if not has_evidence:
        return False
    if signal in {"subdomains_found", "ports_open", "path_discovered", "params_found"}:
        return False
    if signal in {"missing_headers"}:
        return bool(reproduction.get("commands") and reproduction.get("proof"))
    return bool(reproduction.get("verifiable"))


def _emit_skill_runtime_telemetry(
    db,
    job: ScanJob,
    phase_id: str,
    target: str,
    result: dict[str, Any],
) -> None:
    """Persist supervisor-visible skill consultation/result telemetry.

    The work queue has explicit skill-consultation events; direct operator
    phases (notably P01) must emit the same model so the platform can measure
    consultation + usage + positive result consistently.
    """
    from datetime import datetime as _dt
    from app.models.models import AgentTraceEvent, SkillScore

    ledger = result.get("phase_ledger") or {}
    skill_plan = result.get("skill_plan") or {}
    selected_skill_ids = list(
        dict.fromkeys(
            [str(s) for s in (
                skill_plan.get("selected_skills")
                or ledger.get("selected_skills")
                or []
            ) if str(s)]
        )
    )
    if not selected_skill_ids:
        selected_skill_ids = [str(s) for s in (PHASE_CONTRACTS.get(phase_id, {}).get("required_skills") or []) if str(s)]
    if not selected_skill_ids:
        return

    mcp_results = [m for m in (result.get("mcp_results") or []) if isinstance(m, dict)]
    evidence = [e for e in (result.get("evidence") or []) if isinstance(e, dict)]
    tool_names = list(dict.fromkeys(str(m.get("tool_name") or "") for m in mcp_results if m.get("tool_name")))
    positive = any(
        str(ev.get("evidence_strength") or "").lower() in {"medium", "strong", "conclusive"}
        for ev in evidence
    ) or any(str(m.get("status") or "").lower() in {"success", "done", "completed"} for m in mcp_results)
    now = _dt.utcnow()

    for skill_id in selected_skill_ids:
        base_payload = {
            "phase_id": phase_id,
            "target": target,
            "skill_id": skill_id,
            "tool_names": tool_names,
            "skill_coverage": (ledger.get("skill_coverage") or {}).get(skill_id) or {},
            "result_status": ledger.get("status"),
            "positive_result": bool(positive),
            "evidence_count": len(evidence),
            "source": "offensive_operator",
            "decision_source": "supervisor_skill_contract+accepted_learning",
        }
        for event_type, status in (
            ("skill_consulted", "selected"),
            ("skill_execution_result", "positive" if positive else str(ledger.get("status") or "attempted")),
        ):
            existing = (
                db.query(AgentTraceEvent.id)
                .filter(
                    AgentTraceEvent.scan_id == job.id,
                    AgentTraceEvent.event_type == event_type,
                    AgentTraceEvent.skill_id == skill_id[:120],
                    AgentTraceEvent.capability == phase_id[:100],
                )
                .first()
            )
            if not existing:
                db.add(AgentTraceEvent(
                    scan_id=job.id,
                    event_type=event_type,
                    from_node="supervisor",
                    to_node="offensive_operator",
                    skill_id=skill_id[:120],
                    tool_name=",".join(tool_names)[:100] or None,
                    capability=phase_id[:100],
                    status=status[:50],
                    payload=base_payload,
                    created_at=now,
                ))

        # Atribuição POR-SKILL (backlog item 7): antes carimbava o AGREGADO da
        # fase (len(mcp_results)) em CADA skill — todas as ~15 skills de uma fase
        # ficavam com números idênticos. Agora usa o skill_coverage por skill.
        _cov = (ledger.get("skill_coverage") or {}).get(skill_id) or {}
        _has_cov = bool(_cov)
        _sk_attempts = len(_cov.get("tools_attempted") or _cov.get("tool_execution_keys_attempted") or [])
        _sk_success = len(_cov.get("tools_success") or _cov.get("tool_execution_keys_success") or [])
        _sk_failed = len(_cov.get("tools_failed") or _cov.get("tool_execution_keys_failed") or [])
        _sk_evidence = len(_cov.get("evidence_ids") or [])
        _sk_positive = str(_cov.get("status") or "").lower() in {"completed", "success"} if _has_cov else positive
        # Fallback ao agregado da fase só quando NÃO há cobertura por skill.
        n_attempts = _sk_attempts if _has_cov else len(mcp_results)
        n_success = _sk_success if _has_cov else len([m for m in mcp_results if str(m.get("status") or "").lower() in {"success", "done", "completed"}])
        n_failed = _sk_failed if _has_cov else max(0, len(mcp_results) - n_success)
        n_evidence = _sk_evidence if _has_cov else len(evidence)
        # library_hits HONESTO (item 8): conta learnings de fato consultados para
        # esta skill (registrados no coverage), não o hardcoded "max(,1)".
        n_library = len(_cov.get("learning_refs") or _cov.get("rag_matches") or [])

        existing_score = (
            db.query(SkillScore)
            .filter(
                SkillScore.scan_id == job.id,
                SkillScore.skill_id == skill_id[:120],
                SkillScore.capability == phase_id[:60],
            )
            .first()
        )
        if not existing_score:
            existing_score = SkillScore(
                scan_id=job.id,
                skill_id=skill_id[:120],
                capability=phase_id[:60],
                created_at=now,
            )
            db.add(existing_score)
        existing_score.library_hits = max(int(existing_score.library_hits or 0), n_library)
        existing_score.tool_attempts = max(int(existing_score.tool_attempts or 0), n_attempts)
        existing_score.tool_successes = max(int(existing_score.tool_successes or 0), n_success)
        existing_score.tool_failures = max(int(existing_score.tool_failures or 0), n_failed)
        existing_score.findings_raw = max(int(existing_score.findings_raw or 0), n_evidence)
        existing_score.findings_promoted = max(int(existing_score.findings_promoted or 0), 1 if _sk_positive else 0)
        existing_score.efficiency_score = round(n_success / max(1, n_attempts), 4)
        existing_score.productivity_score = round((n_evidence + (1 if _sk_positive else 0)) / max(1, n_attempts), 4)


def _persist_executed_tool_runs(db, job: ScanJob, ledger: dict[str, Any], mcp_results: list[dict[str, Any]]) -> None:
    from datetime import datetime as _dt
    from app.models.models import ExecutedToolRun

    target = str(ledger.get("target") or job.target_query or "")[:500]
    local_seen: set[tuple[int, str]] = set()
    for mcp_res in mcp_results:
        if not isinstance(mcp_res, dict):
            continue
        tool_name = str(mcp_res.get("tool_name") or "").strip().lower()
        if not tool_name:
            continue
        execution_key = str(
            mcp_res.get("execution_key")
            or stable_id(
                "TR",
                {
                    "phase_id": ledger.get("phase_id") or mcp_res.get("phase_id"),
                    "skill_id": mcp_res.get("skill_id"),
                    "tool_name": tool_name,
                    "profile": mcp_res.get("profile"),
                    "arguments_hash": mcp_res.get("arguments_hash"),
                    "target": mcp_res.get("target") or target,
                },
            )
        )[:160]
        key = (int(job.id), execution_key)
        if key in local_seen:
            continue
        local_seen.add(key)
        raw_status = str(mcp_res.get("status") or ledger.get("status") or "unknown").strip().lower()
        status = "success" if raw_status in {"success", "done", "completed", "executed"} else raw_status
        if status not in {"success", "failed", "timeout", "skipped", "blocked"}:
            status = "failed" if raw_status in {"error", "exception"} else status
        run = (
            db.query(ExecutedToolRun)
            .filter(
                ExecutedToolRun.scan_job_id == job.id,
                ExecutedToolRun.execution_key == execution_key,
            )
            .first()
        )
        if not run:
            run = ExecutedToolRun(
                scan_job_id=job.id,
                phase_id=str(ledger.get("phase_id") or mcp_res.get("phase_id") or "")[:10] or None,
                skill_id=str(mcp_res.get("skill_id") or "")[:120] or None,
                tool_name=tool_name[:100],
                profile=str(mcp_res.get("profile") or "")[:120] or None,
                target=target,
                execution_key=execution_key,
                arguments_hash=str(mcp_res.get("arguments_hash") or "")[:80] or None,
                status=status[:50],
                created_at=_dt.utcnow(),
            )
            db.add(run)
            db.flush()
        run.phase_id = str(ledger.get("phase_id") or mcp_res.get("phase_id") or "")[:10] or None
        run.skill_id = str(mcp_res.get("skill_id") or "")[:120] or None
        run.profile = str(mcp_res.get("profile") or "")[:120] or None
        run.execution_key = execution_key
        run.arguments_hash = str(mcp_res.get("arguments_hash") or "")[:80] or None
        run.status = status[:50]
        run.error_message = str(mcp_res.get("stderr") or mcp_res.get("error") or "")[:2000] or None
        try:
            run.execution_time_seconds = float(mcp_res.get("duration_seconds")) if mcp_res.get("duration_seconds") is not None else None
        except Exception:
            run.execution_time_seconds = None
        db.flush()


def _run_target_phases_subset(db, job: ScanJob, target: str) -> dict[str, Any]:
    """Run P02-P22 for a single target. Used by the parallel fan-out task.

    Each phase result is persisted via the same idempotent _persist_offensive_findings
    flow used by the main scan, so concurrent subtasks writing different (phase,
    target) pairs do not collide.
    """
    state = dict(job.state_data or {})
    execution_mode = str(state.get("execution_mode") or "controlled_pentest")
    allowed_phases = phases_for_scan_level(state.get("scan_level"))
    scope = _scope_from_job(job, target, execution_mode)
    offensive_state = dict(state.get("offensive_state") or create_offensive_state(target, campaign_id=f"scan-{job.id}"))
    offensive_state["target"] = target

    # Auth headers stored in thread-local so concurrent subtasks in the same
    # process (--pool=threads) don't overwrite each other's credentials.
    _set_auth_headers(auth_headers_from_state(state))

    mcp_available = _mcp_available() if settings.mcp_execute_tools_via_mcp else False
    runtime = OffensiveSkillRuntime(executor=MCPToolExecutor(call_tool=_call_operator_tool(mcp_available), available=True))

    completed_work: set[str] = set(state.get("completed_work") or [])
    host_ip_map: dict[str, str] = dict(state.get("host_ip_map") or {})
    phase_ledgers: list[dict[str, Any]] = list(state.get("phase_ledger_v2") or [])
    processed = 0
    skipped = 0
    for phase_id in PHASE_ORDER:
        if phase_id == "P01":
            continue
        if allowed_phases is not None and phase_id not in allowed_phases:
            continue
        wk = f"{phase_id}:{target}"
        if wk in completed_work:
            skipped += 1
            continue
        pf_state = dict(job.state_data or {})
        profile, created = _preflight_profile_for(pf_state, target)
        if created:
            try:
                db.refresh(job)
            except Exception:  # noqa: BLE001
                pass
            cur_state = dict(job.state_data or {})
            cur_preflight = dict(cur_state.get("preflight") or {})
            cur_targets = dict(cur_preflight.get("targets") or {})
            cur_targets[target] = profile
            cur_preflight.update(pf_state.get("preflight") or {})
            cur_preflight["targets"] = cur_targets
            cur_state["preflight"] = cur_preflight
            job.state_data = cur_state
            db.add(ScanLog(
                scan_job_id=job.id,
                source="scan-intelligence",
                level="INFO",
                message=(
                    f"tier1_preflight target={target} status={profile.get('status')} "
                    f"ip={profile.get('ip') or '-'} ports={profile.get('open_ports') or []} "
                    f"http={len(profile.get('http') or [])} reason={profile.get('reason')} (parallel)"
                ),
            ))
            db.commit()
        reason = preflight_skip_reason(phase_id, profile)
        if reason:
            _record_preflight_skip(db, job, phase_ledgers, completed_work, phase_id, target, reason)
            skipped += 1
            continue
        # IP dedup
        if phase_id in NETWORK_PHASES:
            _ip = host_ip_map.get(target)
            if _ip and f"{phase_id}:ip:{_ip}" in completed_work:
                completed_work.add(wk)
                skipped += 1
                continue
        try:
            result = runtime.run_phase(phase_id, target, scope, execution_mode, offensive_state)
            offensive_state = result["offensive_state"]
            ledger = result["phase_ledger"]
            ledger["target"] = target
            ledger["mcp_results"] = result.get("mcp_results") or []
            ledger["parallel_subtask"] = True
            phase_ledgers.append(ledger)
            completed_work.add(wk)
            if phase_id in NETWORK_PHASES:
                ip = host_ip_map.get(target)
                if ip:
                    completed_work.add(f"{phase_id}:ip:{ip}")
            # Persist incremental state — locked to prevent concurrent subtasks
            # from clobbering each other's completed_work / phase_ledger updates.
            with _SUBTASK_STATE_LOCK:
                try:
                    db.refresh(job)
                except Exception:  # noqa: BLE001
                    pass
                cur = dict(job.state_data or {})
                cur["completed_work"] = sorted(set((cur.get("completed_work") or [])) | completed_work)
                cur["phase_ledger_v2"] = _merge_phase_ledgers(list(cur.get("phase_ledger_v2") or []), [ledger])
                selected_skill_ids = list(ledger.get("selected_skills") or [])
                if selected_skill_ids:
                    cur["selected_skill"] = selected_skill_ids[0]
                    cur["selected_skills"] = selected_skill_ids
                _emit_skill_runtime_telemetry(db, job, phase_id, target, result)
                skill_coverage_state = dict(cur.get("skill_coverage") or {})
                skill_coverage_state[f"{phase_id}:{target}"] = ledger.get("skill_coverage") or {}
                cur["skill_coverage"] = skill_coverage_state
                existing_runs = list(cur.get("executed_tool_runs") or [])
                existing_runs.extend([
                    {
                        "execution_key": m.get("execution_key"),
                        "execution_backend": m.get("execution_backend"),
                        "tool": m.get("tool_name"),
                        "profile": m.get("profile"),
                        "phase": phase_id,
                        "skill_id": m.get("skill_id"),
                        "target": m.get("target") or target,
                        "status": m.get("status"),
                        "arguments_hash": m.get("arguments_hash"),
                        "started_at": m.get("started_at"),
                        "finished_at": m.get("finished_at"),
                        "exit_code": m.get("exit_code"),
                    }
                    for m in (result.get("mcp_results") or [])
                    if isinstance(m, dict)
                ])
                cur["executed_tool_runs"] = existing_runs[-500:]
                job.state_data = cur
                phase_ledgers = _merge_phase_ledgers(phase_ledgers, [ledger])
                db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="INFO",
                               message=(
                                   f"phase_result phase_id={phase_id} status={ledger.get('status')} target={target} "
                                   f"skills={selected_skill_ids} (parallel)"
                               )))
                db.commit()
            try:
                _persist_offensive_findings(db, job, phase_ledgers, [target])
                db.commit()
            except Exception:  # noqa: BLE001
                db.rollback()
            processed += 1
        except Exception as exc:  # noqa: BLE001
            db.add(ScanLog(scan_job_id=job.id, source="offensive-operator", level="WARNING",
                           message=f"parallel_phase_failed phase={phase_id} target={target} error={exc!s}"))
            db.commit()
    with _SUBTASK_STATE_LOCK:
        try:
            db.refresh(job)
            cur = dict(job.state_data or {})
            final_completed = set(cur.get("completed_work") or [])
            pending = _pending_parallel_targets(cur, final_completed, allowed_phases)
            cur["parallel_pending_targets"] = pending
            job.state_data = cur
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
    return {"target": target, "processed": processed, "skipped": skipped}


def _persist_origin_finding(db, job: ScanJob, target: str, origin: dict[str, Any]) -> None:
    """Persist a Finding for WAF origin discovery — the real server behind the edge.

    This is one of the highest-value RedTeam findings: if the origin is
    reachable directly, every WAF protection is bypassable.
    """
    candidates = origin.get("candidate_origins") or []
    if not candidates:
        return
    # Idempotent — one origin-discovery finding per (scan, target)
    existing = (
        db.query(Finding)
        .filter(Finding.scan_job_id == job.id, Finding.domain == str(target)[:255])
        .all()
    )
    for f in existing:
        if (f.details or {}).get("finding_kind") == "waf_origin_discovery":
            return

    top = candidates[0]
    high_conf = [c for c in candidates if c.get("confidence") == "high"]
    severity = "high" if high_conf else "medium"
    confidence = 80 if high_conf else 55

    title = (f"[WAF-BYPASS] Origem potencial exposta atrás do WAF — "
             f"{len(candidates)} IP(s) candidato(s), top {top['ip']}")
    recommendation = (
        "Confirme o IP de origem com requisição Host-header direta; se a origem "
        "responder a aplicação real, TODA proteção do WAF é contornável. "
        "Mitigação: bloqueie no firewall da origem todo tráfego que não venha "
        "dos ranges do WAF, e rotacione o IP de origem após exposição."
    )
    repro_commands = [{"tool": "curl", "command": c["verify"]} for c in candidates[:6]]
    steps = [
        "1. Para cada IP candidato, envie uma requisição com o Host header do alvo",
        "2. Compare o corpo da resposta com a resposta servida pelo WAF",
        "3. Resposta idêntica à aplicação real = origem confirmada (WAF bypassável)",
        "4. Documente o IP de origem e o vetor de acesso direto",
    ]
    details: dict[str, Any] = {
        "finding_kind": "waf_origin_discovery",
        "phase_id": "P01",
        "phase_name": "WAF Origin Discovery",
        "target": target,
        "apex_behind_waf": origin.get("apex_behind_waf"),
        "waf_edge_ips": origin.get("waf_edge_ips") or [],
        "candidate_origins": candidates,
        "summary": origin.get("summary"),
        "reproduction": {
            "discovery_method": "Análise de divergência de IP entre subdomínios + mineração de registros DNS (SPF/MX)",
            "commands": repro_commands,
            "payloads": [c["verify"] for c in candidates[:10]],
            "proof": [{"tool": "dns", "summary": f"{c['ip']} via {c['source']} (hosts: {', '.join(c['hosts'][:3]) or 'DNS record'})", "output": c["verify"]} for c in candidates[:6]],
            "steps": steps,
            "verifiable": True,
        },
        "mitre_attack": [{"id": "T1590.005", "name": "Gather Victim Network Info: IP Addresses"},
                         {"id": "T1133", "name": "External Remote Services"}],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "kill_chain_stage": "Reconnaissance",
    }
    # WAF origin discovery is a network-fact finding (IP divergence + DNS mining),
    # but it is NOT an actively-confirmed exploit — the origin still needs a
    # Host-header verification request. Route it through the gated path as a
    # 'candidate' so HIGH severity triggers a P21 validation (curl Host-header
    # check) before it appears as confirmed in the report.
    details["asset"] = str(target)
    details["tool"] = "waf_origin_discovery"
    details["recommendation"] = recommendation
    details["verification_status"] = "candidate"
    _waf_raw = [{
        "title": title[:255],
        "severity": severity,
        "risk_score": max(1, confidence // 10),
        "details": details,
    }]
    try:
        from app.services.findings_extractor import persist_finding_dicts
        persist_finding_dicts(
            db, job, _waf_raw,
            default_tool="waf_origin_discovery", default_target=str(target), source_item=None,
        )
    except Exception:
        # Fallback to direct persist if gated path unavailable
        db.add(Finding(
            scan_job_id=job.id, title=title[:255], severity=severity,
            domain=str(target)[:255], tool="waf_origin_discovery",
            recommendation=recommendation, confidence_score=confidence,
            risk_score=max(1, confidence // 10), details=details,
            verification_status="candidate",
        ))
        db.commit()


def _persist_offensive_findings(db, job: ScanJob, phase_ledgers: list[dict[str, Any]], targets: list[str]) -> None:
    """Convert phase ledger + MCP tool output into rich Finding rows with real evidence.

    Idempotent: pre-loads existing (phase_id, target) pairs from DB so re-running
    after each phase only adds new findings, never duplicates.
    """
    from app.models.models import Asset, Vulnerability

    # Pre-seed `seen` with (phase_id, target) keys already persisted for this scan
    # so this function is safe to call multiple times during a single scan execution.
    existing_findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == job.id)
        .all()
    )
    seen: set[tuple[str, str]] = set()
    for f in existing_findings:
        d = f.details or {}
        pid = str(d.get("phase_id") or "")
        tgt = str(d.get("target") or f.domain or "")
        if pid:
            seen.add((pid, tgt))
    primary_target = targets[0] if targets else str(job.target_query or "")

    PHASE_SEVERITY: dict[str, str] = {
        "P09": "medium",    # nuclei vuln templates
        "P10": "high",      # injection
        "P11": "high",      # ssrf
        "P12": "medium",    # xss
        "P13": "high",      # idor
        "P14": "high",      # auth bypass
        "P15": "medium",    # file handling
        "P17": "critical",  # exploit validation
        "P18": "critical",  # credential exposure
    }

    # Build index of mcp_results per phase from state_data
    state = dict(job.state_data or {})
    # phase_ledger_v2 and last_mcp_results are the sources; build a map phase→mcp_results
    phase_mcp_map: dict[str, list[dict[str, Any]]] = {}
    for ledger in phase_ledgers:
        pid = ledger.get("phase_id", "")
        if pid and ledger.get("mcp_results"):
            phase_mcp_map[pid] = list(ledger["mcp_results"])

    for ledger in phase_ledgers:
        phase_id = ledger.get("phase_id", "")
        phase_name = ledger.get("phase_name", phase_id)
        status = ledger.get("status", "")
        target = ledger.get("target") or primary_target

        tools_success = ledger.get("tools_success", [])
        tools_attempted = ledger.get("tools_attempted", [])
        if not tools_attempted:
            continue

        # Extract per-tool evidence from MCP results stored in the ledger.
        # Prefer the ledger's own mcp_results (correct for multi-target
        # propagation where many ledgers share the same phase_id).
        mcp_results = ledger.get("mcp_results") or phase_mcp_map.get(phase_id) or []
        _persist_executed_tool_runs(db, job, ledger, mcp_results)

        key = (phase_id, str(target))
        if key in seen:
            continue
        seen.add(key)

        tool_evidences: list[dict[str, Any]] = []
        for mcp_res in mcp_results:
            if not isinstance(mcp_res, dict):
                continue
            tool_name = str(mcp_res.get("tool_name") or "")
            if mcp_res.get("status") in {"success", "done"} and tool_name:
                ev = _extract_evidence(phase_id, tool_name, mcp_res)
                tool_evidences.append(ev)

        # Severity + confidence are derived from ACTUAL evidence, not the phase.
        # A phase that ran with no findings → 'info', never 'high'.
        severity, confidence = _assess_evidence_severity(phase_id, status, tool_evidences, PHASE_SEVERITY)

        # Coverage-only records (fase rodou mas SEM evidência real) NÃO são
        # vulnerabilidades — não persistir como Finding (eram o ruído "[Pxx] …
        # Sem achados"). A cobertura da fase já fica registrada no phase_ledger.
        _has_ev_persist, _ = _has_real_evidence(tool_evidences)
        if not _has_ev_persist:
            continue

        # State-derived context for MITRE/OWASP enrichment + tech_stack snapshot
        state_snap = dict(job.state_data or {})
        tech_snap = state_snap.get("tech_stack") or {}
        env_snap = state_snap.get("environment_profile") or {}

        # WAF deception adjustment — discount findings the WAF likely faked.
        waf_caveat = None
        if env_snap.get("waf_present"):
            _, signal = _has_real_evidence(tool_evidences)
            severity, confidence, waf_caveat = apply_waf_confidence_adjustment(
                env_snap, severity, confidence, phase_id, signal)

        title = _build_redteam_title(phase_id, phase_name, status, tool_evidences)
        recommendation = _generate_recommendation(phase_id, tool_evidences)
        if waf_caveat:
            recommendation = f"[WAF] {waf_caveat} | {recommendation}"

        reproduction = _build_reproduction(phase_id, str(target), tool_evidences)
        impact_analysis = _build_redteam_impact(phase_id, severity, str(target), tool_evidences)
        framework_mapping = _framework_mapping_for_finding(phase_id, tool_evidences)

        details: dict[str, Any] = {
            "phase_id": phase_id,
            "phase_name": phase_name,
            "phase_status": status,
            "tools_attempted": tools_attempted,
            "tools_success": tools_success,
            "tools_failed": ledger.get("tools_failed", []),
            "selected_skills": ledger.get("selected_skills", []),
            "skills_success": ledger.get("skills_success", []),
            "skills_partial": ledger.get("skills_partial", []),
            "skills_blocked": ledger.get("skills_blocked", []),
            "skill_coverage": ledger.get("skill_coverage", {}),
            "tool_execution_keys_attempted": ledger.get("tool_execution_keys_attempted", []),
            "tool_execution_keys_success": ledger.get("tool_execution_keys_success", []),
            "tool_execution_keys_failed": ledger.get("tool_execution_keys_failed", []),
            "evidence_ids": ledger.get("evidence_ids", []),
            "hypotheses_created": ledger.get("hypotheses_created", []),
            "attack_paths_updated": ledger.get("attack_paths_updated", []),
            "blocking_reason": ledger.get("blocking_reason"),
            "target": target,
            "scan_mode": "offensive_operator",
            "source_worker": "offensive_operator",
            # RedTeam evidence — one entry per tool that ran
            "tool_evidence": tool_evidences,
            # Complete reproduction package: discovery method, commands,
            # payloads, raw proof and numbered steps so the finding is
            # independently verifiable by an analyst.
            "reproduction": reproduction,
            "impact_analysis": impact_analysis,
            "framework_mapping": framework_mapping,
            "cvss_estimate": _severity_to_cvss(severity),
            # Tech stack snapshot at time of finding
            "tech_stack": tech_snap.get("detected") or [],
            "cms_detected": tech_snap.get("cms") or [],
            "waf_detected": tech_snap.get("waf") or [],
            # Learned environment profile — WAF behaviour, deception flags,
            # and how to interpret results for this target.
            "environment_profile": {
                "waf_present": env_snap.get("waf_present", False),
                "waf_vendors": env_snap.get("waf_vendors") or [],
                "observed_behaviors": env_snap.get("observed_behaviors") or [],
                "interpretation_notes": env_snap.get("interpretation_notes") or [],
                "finding_confidence_penalty": env_snap.get("finding_confidence_penalty", 0),
            },
            "waf_caveat": waf_caveat,
        }
        _selected_skills = [str(s) for s in ledger.get("selected_skills", []) if str(s)]
        details.setdefault("skill_context", {
            "skill_ids": _selected_skills,
            "skill_id": _selected_skills[0] if _selected_skills else "",
            "skill_attribution": "offensive_operator_phase_ledger",
            "phase_id": phase_id,
            "skill_coverage": ledger.get("skill_coverage", {}),
        })
        details.setdefault("supervisor_validation", {
            "status": "validated" if tool_evidences and reproduction.get("verifiable") else "needs_review",
            "reason": "direct_operator_finding_evidence_review",
            "has_url_or_target": bool(target),
            "has_tool": bool(tools_success or tools_attempted),
            "has_recommendation": bool(recommendation),
            "has_reproduction": bool(reproduction),
            "evidence_count": len(tool_evidences),
            "phase_id": phase_id,
        })
        details = enrich_finding_with_mappings(phase_id, details)

        finding = Finding(
            scan_job_id=job.id,
            title=title[:255],
            severity=severity,
            cve=None,
            cvss=_severity_to_cvss(severity),
            domain=str(target)[:255],
            tool=", ".join(tools_success or tools_attempted)[:100] or None,
            recommendation=recommendation or None,
            confidence_score=confidence,
            risk_score=max(1, confidence // 10),
            details=details,
        )
        db.add(finding)
        db.flush()

        # Item 17 — emite cada finding de BUSINESS LOGIC CONFIRMADO como Finding
        # PRÓPRIO (antes ficavam aninhados em tool_evidence do wrapper, invisíveis).
        # Ex.: token/JWT em localStorage confirmado via navegador real.
        try:
            _seen_bl: set[str] = set()
            for _ev in tool_evidences:
                for _bl in (_ev.get("business_logic_findings") or []):
                    if not isinstance(_bl, dict):
                        continue
                    if str(_bl.get("verification_status") or "").lower() != "confirmed":
                        continue
                    _bl_title = str(_bl.get("title") or "").strip()[:255]
                    if not _bl_title or _bl_title in _seen_bl:
                        continue
                    _seen_bl.add(_bl_title)
                    _bl_url = str(_bl.get("url") or target)
                    _bl_dup = (
                        db.query(Finding.id)
                        .filter(Finding.scan_job_id == job.id, Finding.title == _bl_title,
                                Finding.domain == str(target)[:255])
                        .first()
                    )
                    if _bl_dup:
                        continue
                    db.add(Finding(
                        scan_job_id=job.id,
                        title=_bl_title,
                        severity=severity if severity in {"high", "critical", "medium"} else "medium",
                        cve=None,
                        cvss=_severity_to_cvss(severity if severity != "info" else "medium"),
                        domain=str(target)[:255],
                        tool=", ".join(tools_success or ["bl-test"])[:100] or None,
                        recommendation="Não armazene tokens/segredos de sessão em localStorage/sessionStorage (use cookie HttpOnly+Secure+SameSite); valide autorização por objeto (IDOR/BOLA).",
                        confidence_score=max(confidence, 85),
                        risk_score=max(1, max(confidence, 85) // 10),
                        details={
                            "phase_id": phase_id,
                            "phase_name": phase_name,
                            "target": target,
                            "finding_class": "business_logic_confirmed",
                            "verification_status": "confirmed",
                            "scan_mode": "offensive_operator",
                            "source_worker": "offensive_operator",
                            "business_logic_detail": _bl,
                            "url": _bl_url,
                            "evidence": str(_bl.get("title") or "")[:1000],
                        },
                        verification_status="confirmed",
                    ))
            db.flush()
        except Exception:
            pass

        # Persist asset + vulnerability only for actionable, reproducible risk.
        if (
            status in {"completed", "partial"}
            and target
            and _is_actionable_vulnerability(severity, tool_evidences, reproduction)
        ):
            try:
                _akey = _normalize_asset_host(target)
                asset = db.query(Asset).filter(
                    Asset.owner_id == job.owner_id,
                    Asset.domain_or_ip == _akey,
                ).first()
                if not asset:
                    from datetime import datetime as _dt
                    _now = _dt.utcnow()
                    asset = Asset(
                        owner_id=job.owner_id,
                        domain_or_ip=_akey,
                        asset_type="domain",
                        first_seen=_now,
                        last_seen=_now,
                        last_scan_id=job.id,
                    )
                    db.add(asset)
                    db.flush()
                existing_vuln = db.query(Vulnerability).filter(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.title == title[:255],
                ).first()
                if not existing_vuln:
                    from datetime import datetime as _dt
                    _now = _dt.utcnow()
                    vuln = Vulnerability(
                        asset_id=asset.id,
                        finding_id=finding.id,
                        title=title[:255],
                        severity=severity,
                        cvss_score=_severity_to_cvss(severity),
                        description=impact_analysis,
                        tool_source=", ".join(tools_success or tools_attempted)[:100] or "offensive_operator",
                        first_detected=_now,
                        last_detected=_now,
                        remediation_notes=recommendation or None,
                        ra_score=round(float(_severity_to_cvss(severity)) * (confidence / 100.0), 2),
                        vulnerability_metadata={
                            "scan_id": job.id,
                            "phase_id": phase_id,
                            "target": str(target),
                            "evidence": tool_evidences,
                            "reproduction": reproduction,
                            "impact_analysis": impact_analysis,
                            "framework_mapping": framework_mapping,
                            "confidence_score": confidence,
                        },
                    )
                    db.add(vuln)
            except Exception:
                pass

        # ── Per-tool findings: call individual parsers for tools that produce
        # structured evidence (nikto, wapiti, dalfox, sqlmap, nuclei, testssl…).
        # The aggregate phase finding above captures the RedTeam narrative;
        # these produce the granular technical findings (missing headers, XSS
        # vectors, SQLi parameters, CVEs) visible in the Vulnerabilities page.
        try:
            from app.services.findings_extractor import (
                extract_findings_from_work_item,
                persist_finding_dicts,
            )
            # Tools whose per-tool output yields actionable individual findings.
            _PER_TOOL_PARSEABLE = {
                "nikto", "wapiti", "dalfox", "sqlmap", "testssl",
                "whatweb", "whatweb-basic", "wafw00f", "curl-headers",
                "gitleaks", "trufflehog", "nuclei",
            } | {f"nuclei-{v}" for v in (
                "xss", "sqli", "ssrf", "lfi", "ssti", "xxe", "cors", "crlf",
                "redirect", "idor", "csrf", "race", "rce", "auth", "jwt",
                "exposure", "cloud", "deserialization", "clickjacking",
                "headers", "spoofing", "takeover", "graphql",
            )}
            _tool_seen: set[str] = set()
            for _mcp_res in mcp_results:
                if not isinstance(_mcp_res, dict):
                    continue
                _tname = str(_mcp_res.get("tool_name") or "").strip().lower()
                if not _tname or _tname in _tool_seen:
                    continue
                if _mcp_res.get("status") not in {"success", "done"}:
                    continue
                if _tname not in _PER_TOOL_PARSEABLE:
                    continue
                _tool_seen.add(_tname)

                # Prefer full stdout; fall back to truncated state copy
                _stdout = str(_mcp_res.get("stdout") or _mcp_res.get("stdout_preview") or "")
                _parsed = _mcp_res.get("parsed_result")
                if not _stdout.strip() and not _parsed:
                    continue

                _tool_findings = extract_findings_from_work_item(
                    _tname,
                    str(target),
                    str(phase_id),
                    {"stdout_preview": _stdout, "stdout_full": _stdout, "parsed_result": _parsed},
                )
                if _tool_findings:
                    persist_finding_dicts(
                        db, job, _tool_findings,
                        default_tool=_tname,
                        default_target=str(target),
                    )
        except Exception:
            pass
