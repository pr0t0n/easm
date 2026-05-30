from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import ScanJob, ScanLog, ScanWorkItem


# ── Global Redis semaphore — garante cap TOTAL cross-scans ───────────────────
# Dois scans simultâneos não devem despachar 2×100=200 tarefas para 100 workers.
# Usamos INCR/DECR atômico no Redis por resource_class como semáforo leve.
# Se Redis estiver indisponível (timeout/conexão), fail-open — despacha normalmente.

def _redis_client():
    """Lazy Redis client. Reconecta se necessário."""
    import redis
    return redis.from_url(settings.redis_url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2)


def kali_inflight_get(rc: str) -> int:
    """Retorna contagem atual de tarefas em voo para a resource class."""
    try:
        val = _redis_client().get(f"kali:inflight:{rc}")
        return max(0, int(val or 0))
    except Exception:
        return 0


def kali_inflight_claim(rc: str, count: int, cap: int) -> bool:
    """Tenta reservar `count` slots para `rc`. Retorna True se dentro do cap.

    Usa INCR atômico: se o novo valor exceder o cap, faz rollback com DECR.
    Fail-open: se Redis estiver indisponível, permite o despacho.
    """
    if count <= 0:
        return True
    try:
        r = _redis_client()
        key = f"kali:inflight:{rc}"
        new_val = r.incrby(key, count)
        r.expire(key, max(3600, int(settings.scan_work_queue_lease_seconds) * 2))
        if new_val > cap:
            r.decrby(key, count)
            return False
        return True
    except Exception:
        return True  # fail-open: Redis down → permite despacho


def kali_inflight_release(rc: str, count: int = 1) -> None:
    """Libera `count` slots ao completar/falhar uma tarefa."""
    if count <= 0:
        return
    try:
        r = _redis_client()
        key = f"kali:inflight:{rc}"
        new_val = r.decrby(key, count)
        if new_val < 0:
            r.set(key, 0)  # floor
    except Exception:
        pass
from app.services.offensive_operator_core import PHASE_CONTRACTS, ToolCatalog


HEAVY_TOOLS = {
    "amass",
    "amass-brute",
    "masscan",
    "nmap",
    "nmap-vuln",
    "nmap-vulscan",
    "nmap-http",
    "nmap-smb",
    "nmap-ssh",
    "nmap-ssl",
    "nmap-dns",
    "sqlmap",
    "nikto",
    "wpscan",
    "wapiti",
    "zap-active",   # ZAP active scan — full OWASP Top 10 fuzzing
    "zap-api",      # ZAP API scan — tests all OpenAPI/Swagger endpoints
}
MEDIUM_TOOLS = {
    "zap-baseline",  # ZAP passive scan + quick spider — low noise, fast
    "zap-ajax",      # ZAP AJAX spider for SPA/JS-heavy targets
    "nuclei",
    "nuclei-xss",
    "nuclei-sqli",
    "nuclei-ssrf",
    "nuclei-lfi",
    "nuclei-ssti",
    "nuclei-xxe",
    "nuclei-cors",
    "nuclei-redirect",
    "nuclei-idor",
    "nuclei-csrf",
    "nuclei-crlf",
    "nuclei-graphql",
    "nuclei-race",
    "nuclei-rce",
    "nuclei-auth",
    "nuclei-jwt",
    "nuclei-exposure",
    "nuclei-cloud",
    "nuclei-deserialization",
    "nuclei-clickjacking",
    "nuclei-headers",
    "nuclei-spoofing",
    "nuclei-takeover",
    "ffuf",
    "ffuf-params",
    "ffuf-content",
    "gobuster",
    "feroxbuster",
    "dirsearch",
    "wfuzz",
    "dalfox",
    "subjack",
}
OOB_TOOLS = {"interactsh", "interactsh-client"}
MANUAL_TOOLS = {"manual_review", "manual_correlation", "manual_http_probe", "report-builder", "manual_scope_review"}

# ─────────────────────────────────────────────────────────────────────────────
# High-risk subdomain keywords → prioridade elevada no scanner
# Estes targets expõem gestão de infra, dados sensíveis ou env de dev.
# ─────────────────────────────────────────────────────────────────────────────
HIGH_RISK_SUBDOMAIN_KEYWORDS = {
    # Gestão de infraestrutura (prioridade máxima)
    "portainer", "rancher", "k8s", "kubernetes", "consul", "vault",
    "jenkins", "gitlab", "grafana", "kibana", "elastic", "logstash",
    "prometheus", "alertmanager", "jaeger", "zipkin",
    # Message brokers e filas
    "rabbitmq", "kafka", "activemq", "celery", "flower", "worker",
    # Monitoramento
    "zabbix", "nagios", "icinga", "netdata", "datadog", "newrelic",
    # Serviços internos expostos
    "internal", "intranet", "private", "mgmt", "management", "admin",
    "backdoor", "debug", "staging", "homolog", "hml", "dev-",
    # Segurança / autenticação
    "auth", "sso", "oauth", "saml", "token", "secret", "credential",
    "key-manager", "kms", "hsm", "pki", "cert",
    # Dados sensíveis
    "crm", "erp", "bi-", "dashboard", "analytics", "report",
    "database", "db-", "redis", "mongo", "postgres", "mysql",
    # Comunicação
    "mail", "smtp", "imap", "exchange", "mattermost", "rocketchat",
    # IoT / telecom
    "scada", "iot", "telecom", "gateway", "vpn", "bastion",
}

# Boost de prioridade para subdomínios de alto risco (menor número = maior prioridade)
HIGH_RISK_PRIORITY_BOOST = -30   # sobe 30 posições na fila


def _high_risk_priority_boost(target: str) -> int:
    """Retorna boost negativo de prioridade se o target for de alto risco."""
    t = target.lower()
    # Extract subdomain prefix (before first dot)
    subdomain = t.split(".")[0] if "." in t else t
    full = t  # also check full string
    for kw in HIGH_RISK_SUBDOMAIN_KEYWORDS:
        if kw in subdomain or kw in full:
            return HIGH_RISK_PRIORITY_BOOST
    return 0


PHASE_PRIORITY = {
    "P02": 10,
    "P06": 15,
    "P07": 20,
    "P03": 25,
    "P04": 30,
    "P05": 35,
    "P09": 50,
    "P10": 60,
    "P11": 60,
    "P12": 60,
    "P13": 65,
    "P14": 70,
    "P15": 55,
    "P16": 45,
    "P17": 80,
    "P18": 55,
    "P19": 85,
    "P20": 90,
}


def resource_class_for_tool(tool_name: str) -> str:
    tool = str(tool_name or "").strip().lower()
    if tool in OOB_TOOLS:
        return "oob"
    if tool in HEAVY_TOOLS:
        return "heavy"
    if tool in MEDIUM_TOOLS or tool.startswith("nuclei-"):
        return "medium"
    return "light"


def capacity_limits() -> dict[str, int]:
    return {
        "light": max(1, int(settings.scan_work_queue_cap_light)),
        "medium": max(1, int(settings.scan_work_queue_cap_medium)),
        "heavy": max(1, int(settings.scan_work_queue_cap_heavy)),
        "oob": max(1, int(settings.scan_work_queue_cap_oob)),
    }


def _phase_tools(phase_id: str) -> list[str]:
    contract = PHASE_CONTRACTS.get(phase_id) or {}
    tools = list(contract.get("required_tools") or []) + list(contract.get("optional_tools") or [])
    out: list[str] = []
    seen: set[str] = set()
    for tool in tools:
        normalized = str(tool or "").strip()
        if not normalized or normalized in seen or normalized in MANUAL_TOOLS:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def _tool_profile(tool_name: str) -> str:
    entry = ToolCatalog().get(tool_name)
    return entry.profile if entry else tool_name


def _eligible_phases_for_target(target: str, state: dict[str, Any]) -> list[str]:
    preflight = ((state.get("preflight") or {}).get("targets") or {}).get(target) or {}
    has_http = bool(preflight.get("http"))
    status = str(preflight.get("status") or "").lower()
    if status in {"dead", "unresolved", "no_tcp"}:
        return ["P18"]
    # When preflight is not yet computed (empty dict), the target came through P01
    # live-target refinement — assume HTTP is available. The "no http" branch must
    # only fire when preflight was explicitly computed and HTTP was not found.
    # Without this guard, batch phases (P02/P06) run but don't write preflight,
    # so enqueue_scan_work_items seeds only P02/P06/P07/P18 and all web phases
    # (P03 ffuf, P04 arjun, P08 katana, P09-P20 vuln) are silently skipped.
    preflight_known = bool(status)
    if preflight_known and not has_http:
        return ["P02", "P06", "P07", "P18"]
    # Full web pentest phases — P08 (katana JS analysis) included alongside
    # the existing web phases so JS endpoints are always crawled.
    return [
        "P02", "P06", "P07", "P08",
        "P03", "P04", "P05", "P16",
        "P09", "P15", "P18",
        "P10", "P11", "P12", "P13",
        "P14", "P17", "P19", "P20",
    ]


# ── T4: Batch-capable tools — run once for ALL targets instead of N serial jobs ─
# Tools that support -l / --input-file / stdin list mode get ONE work item with
# target="__batch__" and item_metadata["batch_targets"]=[...].
# The MCP server writes a targets file and passes it to the tool natively.
#
# Nuclei: -l targets.txt  → 1 item replaces 50; runs templates against ALL targets in one process
# naabu:  -iL targets.txt → 1 port-scan job for all hosts
# httpx:  -l targets.txt  → 1 probe for all hosts
# whatweb: --input-file   → 1 fingerprint job for all hosts
# All nuclei-* variants share the same nuclei binary → all batch equally well
# ── Phase dependency gates — fases que devem aguardar prerequisito ────────────
# Fases criadas como status='blocked'; são desbloqueadas (→ 'queued') quando o
# prerequisito completa para aquele target via unblock_phase_items().
#
# Diagrama de dependência:
#   P02 (port scan)       → criada como queued — ponto de partida
#   P18 (OSINT)           → criada como queued — não depende de HTTP
#   P03-P07, P15          → blocked; desbloqueadas quando P02 completa
#   P08, P09, P16         → blocked; desbloqueadas quando P06 completa
#   P10-P14, P17, P19-P20 → blocked; desbloqueadas pós-triage de P09
#
PHASE_GATE: dict[str, str | None] = {
    "P02": None,   # queued imediatamente
    "P18": None,   # queued imediatamente (OSINT independente)
    "P03": "P02",  # crawl depende de saber que porta existe
    "P04": "P02",
    "P05": "P02",
    "P06": "P02",  # fingerprint depende de port scan
    "P07": "P02",
    "P15": "P02",  # waybackurls/gau não precisam de HTTP mas de resolução
    "P08": "P06",  # JS crawl depende de fingerprint HTTP
    "P09": "P06",  # nuclei depende de saber o serviço
    "P16": "P06",
    "P10": "P09",  # injeção ativa só após nuclei
    "P11": "P09",
    "P12": "P09",
    "P13": "P09",
    "P14": "P09",
    "P17": "P09",
    "P19": "P09",
    "P20": "P09",
}

# Fases que RECEBEM items como 'blocked' (aguardam gate)
_BLOCKED_AT_CREATE: frozenset[str] = frozenset(
    ph for ph, gate in PHASE_GATE.items() if gate is not None
)
# Invariant: phases with gate=None must NOT be in _BLOCKED_AT_CREATE.
# P02 and P18 start immediately — never created as 'blocked'.
# Violation would cause items to stall indefinitely (no gate fires to unblock them).
assert "P02" not in _BLOCKED_AT_CREATE, "P02 has gate=None but is in _BLOCKED_AT_CREATE"
assert "P18" not in _BLOCKED_AT_CREATE, "P18 has gate=None but is in _BLOCKED_AT_CREATE"

# Mapa inverso: qual fase ao completar deve desbloquear quais fases?
_GATE_UNLOCKS: dict[str, list[str]] = {}
for _ph, _gate in PHASE_GATE.items():
    if _gate:
        _GATE_UNLOCKS.setdefault(_gate, []).append(_ph)


def unblock_phase_items(
    db: Session,
    scan_id: int,
    targets: list[str],
    gate_phase: str,
) -> int:
    """
    Desbloqueia items de fases que dependem de gate_phase para os targets dados.
    Ex: gate_phase='P02' → desbloqueia P03/P04/P05/P06/P07/P15 para esses targets.
    Retorna quantos items foram desbloqueados.
    """
    phases_to_unlock = _GATE_UNLOCKS.get(gate_phase, [])
    if not phases_to_unlock or not targets:
        return 0

    now = datetime.utcnow()
    # Inclui batch items cujos batch_targets intersectam com os targets dados
    # Para batch: target='__batch__', batch_targets em item_metadata
    updated = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.phase_id.in_(phases_to_unlock),
            ScanWorkItem.status == "blocked",
            or_(
                ScanWorkItem.target.in_(targets),
                ScanWorkItem.target == "__batch__",
            ),
        )
        .update(
            {"status": "queued", "updated_at": now},
            synchronize_session=False,
        )
    )
    if updated:
        db.flush()
    return int(updated)


BATCH_CAPABLE_TOOLS: frozenset[str] = frozenset({
    # Core network tools (support -iL / --input-file host list)
    "naabu", "nmap", "nmap-vulscan", "nmap-ssl", "nmap-vuln", "nmap-http",
    "httpx", "dnsx", "subjack",
    # Crawlers (support -list / --sites / stdin)
    "katana", "katana-js", "hakrawler", "gospider",
    # Fingerprinting (support --input-file or equivalent)
    "whatweb", "whatweb-basic",
    # Passive recon (accept domain list)
    "gau", "waybackurls",
    # Nuclei + every variant — all use nuclei -l under the hood
    "nuclei",
    "nuclei-cves", "nuclei-headers", "nuclei-exposure", "nuclei-takeover",
    "nuclei-cors", "nuclei-crlf", "nuclei-redirect", "nuclei-spoofing",
    "nuclei-graphql", "nuclei-jwt", "nuclei-cloud",
    "nuclei-xss", "nuclei-sqli", "nuclei-ssrf", "nuclei-lfi",
    "nuclei-ssti", "nuclei-xxe", "nuclei-idor", "nuclei-csrf",
    "nuclei-race", "nuclei-rce", "nuclei-auth",
    "nuclei-deserialization", "nuclei-clickjacking",
})


def enqueue_scan_work_items(
    db: Session,
    job: ScanJob,
    targets: list[str],
    *,
    source: str = "p01",
    max_optional_per_phase: int = 4,
) -> dict[str, int]:
    state = dict(job.state_data or {})
    created = 0
    existing = 0
    skipped = 0

    # ── Pass 1: collect per-(phase, tool) target sets for batch collapsing ──────
    # batch_accumulator[(phase_id, tool)] → set of targets eligible for batching
    # single_items: (phase_id, tool, target) for non-batchable tools
    from collections import defaultdict
    batch_accumulator: dict[tuple[str, str], set[str]] = defaultdict(set)
    single_items: list[tuple[str, str, str]] = []

    clean_targets = [str(t).strip() for t in targets if str(t or "").strip()]

    for target in clean_targets:
        for phase_id in _eligible_phases_for_target(target, state):
            tools = _phase_tools(phase_id)
            if not tools:
                continue
            required = list((PHASE_CONTRACTS.get(phase_id) or {}).get("required_tools") or [])
            optional = [tool for tool in tools if tool not in set(required)]
            selected = list(dict.fromkeys(required + optional[:max_optional_per_phase]))
            for tool in selected:
                if tool in BATCH_CAPABLE_TOOLS:
                    batch_accumulator[(phase_id, tool)].add(target)
                else:
                    single_items.append((phase_id, tool, target))

    # ── Pass 2: create / update batch work items ─────────────────────────────
    for (phase_id, tool), tset in batch_accumulator.items():
        if not tset:
            continue
        sorted_targets = sorted(tset)

        # Check for existing batch item
        existing_batch = db.query(ScanWorkItem).filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.phase_id == phase_id,
            ScanWorkItem.tool_name == tool[:120],
            ScanWorkItem.target == "__batch__",
        ).first()

        if existing_batch:
            # If still queued/retry/blocked, merge in any new targets
            if existing_batch.status in ("queued", "retry", "blocked"):
                old_meta = dict(existing_batch.item_metadata or {})
                existing_tgts = set(old_meta.get("batch_targets") or [])
                merged = sorted(existing_tgts | tset)
                if merged != list(existing_tgts):
                    old_meta["batch_targets"] = merged
                    existing_batch.item_metadata = old_meta
                    existing_batch.updated_at = datetime.utcnow()
                    db.flush()
            existing += 1
            continue

        rc = resource_class_for_tool(tool)
        base_priority = PHASE_PRIORITY.get(phase_id, 100) + {"light": 0, "medium": 5, "heavy": 15, "oob": 20}.get(rc, 0)
        # Batch item gets best priority of all targets in the set
        best_boost = min(_high_risk_priority_boost(t) for t in sorted_targets) if sorted_targets else 0

        _batch_status = "blocked" if phase_id in _BLOCKED_AT_CREATE else "queued"
        item = ScanWorkItem(
            scan_job_id=job.id,
            phase_id=phase_id,
            target="__batch__",
            tool_name=tool[:120],
            profile=_tool_profile(tool)[:120],
            resource_class=rc,
            priority=max(1, base_priority + best_boost),
            status=_batch_status,
            max_attempts=2,
            item_metadata={
                "source": source,
                "engine": "capacity_work_queue",
                "batch_targets": sorted_targets,
                "batch_count": len(sorted_targets),
                "high_risk": best_boost < 0,
            },
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(item)
        try:
            db.flush()
            created += 1
        except Exception:
            db.rollback()
            skipped += 1

    # ── Slow tools that get adaptive timeout based on preflight port count ────
    # wapiti/sqlmap are heavy tools that scale linearly with open ports.
    # Port count 0–1 → 120s; 2–3 → 240s; 4–6 → 360s; 7+ → 600s (max).
    _ADAPTIVE_TIMEOUT_TOOLS = {"wapiti", "sqlmap", "nikto"}

    def _adaptive_timeout(tool: str, target: str) -> int | None:
        if tool not in _ADAPTIVE_TIMEOUT_TOOLS:
            return None
        target_preflight = ((state.get("preflight") or {}).get("targets") or {}).get(target) or {}
        _ports = target_preflight.get("ports") or target_preflight.get("open_ports") or []
        _port_count = len(_ports) if isinstance(_ports, (list, tuple)) else 0
        if _port_count <= 1:
            return 120
        if _port_count <= 3:
            return 240
        if _port_count <= 6:
            return 360
        return 600

    # ── Pass 3: create individual items for non-batch tools ───────────────────
    for (phase_id, tool, target) in single_items:
        already = db.query(ScanWorkItem.id).filter(
            ScanWorkItem.scan_job_id == job.id,
            ScanWorkItem.phase_id == phase_id,
            ScanWorkItem.tool_name == tool[:120],
            ScanWorkItem.target == target[:500],
        ).first()
        if already:
            existing += 1
            continue
        rc = resource_class_for_tool(tool)
        base_priority = PHASE_PRIORITY.get(phase_id, 100) + {"light": 0, "medium": 5, "heavy": 15, "oob": 20}.get(rc, 0)
        risk_boost = _high_risk_priority_boost(target)
        _item_meta: dict[str, Any] = {"source": source, "engine": "capacity_work_queue", "high_risk": risk_boost < 0}
        _to = _adaptive_timeout(tool, target)
        if _to is not None:
            _item_meta["timeout_override"] = _to
        _single_status = "blocked" if phase_id in _BLOCKED_AT_CREATE else "queued"
        item = ScanWorkItem(
            scan_job_id=job.id,
            phase_id=phase_id,
            target=target[:500],
            tool_name=tool[:120],
            profile=_tool_profile(tool)[:120],
            resource_class=rc,
            priority=max(1, base_priority + risk_boost),
            status=_single_status,
            max_attempts=2,
            item_metadata=_item_meta,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(item)
        try:
            db.flush()
            created += 1
        except Exception:
            db.rollback()
            skipped += 1

    db.add(ScanLog(
        scan_job_id=job.id,
        source="work-queue",
        level="INFO",
        message=f"work_queue_seed source={source} targets={len(targets)} created={created} existing={existing} skipped={skipped} batch_groups={len(batch_accumulator)}",
    ))
    db.commit()
    return {"created": created, "existing": existing, "skipped": skipped}


def work_queue_counts(db: Session, scan_id: int) -> dict[str, int]:
    rows = (
        db.query(ScanWorkItem.status, func.count(ScanWorkItem.id))
        .filter(ScanWorkItem.scan_job_id == scan_id)
        .group_by(ScanWorkItem.status)
        .all()
    )
    return {str(status): int(count) for status, count in rows}


def claim_work_items(db: Session, scan_id: int, *, limit: int | None = None) -> list[int]:
    now = datetime.utcnow()
    lease_until = now + timedelta(seconds=max(60, int(settings.scan_work_queue_lease_seconds)))
    dispatch_limit = max(1, int(limit or settings.scan_work_queue_dispatch_limit))
    caps = capacity_limits()
    claimed: list[int] = []
    lock_key = 917000 + int(scan_id)
    lock_acquired = bool(db.execute(text("select pg_try_advisory_lock(:key)"), {"key": lock_key}).scalar())
    if not lock_acquired:
        return []

    try:
        # ── Semaphore reconciliation ──────────────────────────────────────────
        # Lease expiry (bulk UPDATE below) changes dispatched/running/submitted →
        # retry/failed WITHOUT calling kali_inflight_release. Over time this
        # causes the Redis counter to drift above the real DB in-flight count.
        # Fix: compare DB reality vs Redis and correct the overshoot atomically.
        try:
            _r = _redis_client()
            for _rc in caps:
                _db_inflight = (
                    db.query(func.count(ScanWorkItem.id))
                    .filter(
                        ScanWorkItem.status.in_(["dispatched", "running", "submitted"]),
                        ScanWorkItem.resource_class == _rc,
                    )
                    .scalar() or 0
                )
                _redis_key = f"kali:inflight:{_rc}"
                _redis_val = max(0, int(_r.get(_redis_key) or 0))
                if _redis_val > _db_inflight:
                    _r.set(_redis_key, _db_inflight)
        except Exception:
            pass  # fail-open — reconciliation is best-effort

        db.query(ScanWorkItem).filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.status.in_(["running", "dispatched", "submitted"]),
            ScanWorkItem.lease_until.isnot(None),
            ScanWorkItem.lease_until <= now,
            ScanWorkItem.attempts < ScanWorkItem.max_attempts,
        ).update(
            {
                "status": "retry",
                "lease_until": None,
                "updated_at": now,
                "last_error": "lease_expired_requeued",
            },
            synchronize_session=False,
        )
        db.query(ScanWorkItem).filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.status.in_(["running", "dispatched", "submitted"]),
            ScanWorkItem.lease_until.isnot(None),
            ScanWorkItem.lease_until <= now,
            ScanWorkItem.attempts >= ScanWorkItem.max_attempts,
        ).update(
            {
                "status": "failed",
                "lease_until": None,
                "finished_at": now,
                "updated_at": now,
                "last_error": "lease_expired_max_attempts",
            },
            synchronize_session=False,
        )
        db.flush()

        # ── Zombie reaper: queued/retry items that exhausted attempts ─────────
        # CRITICAL stall fix: an item with status='queued'/'retry' but
        # attempts >= max_attempts can NEVER be claimed (the claim query requires
        # attempts < max_attempts). It sits forever as 'queued', so its phase
        # never reaches 100% terminal → the gate (P06→P08/P09 etc) never fires →
        # all downstream phases stay blocked → scan stalls. Mark them failed
        # (terminal) so the phase can complete and the gate opens.
        _reaped = db.query(ScanWorkItem).filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.status.in_(["queued", "retry"]),
            ScanWorkItem.attempts >= ScanWorkItem.max_attempts,
        ).update(
            {
                "status": "failed",
                "lease_until": None,
                "finished_at": now,
                "updated_at": now,
                "last_error": "max_attempts_exhausted_while_queued",
            },
            synchronize_session=False,
        )
        if _reaped:
            db.flush()

        # ── Fair-share: count how many active scans are competing for capacity ──
        # Prevent one scan from monopolizing all slots of a resource class when
        # other scans are also running. Each scan gets at most 75% of capacity.
        # With 2 active scans: each gets max 50%. With 1 scan: full capacity.
        try:
            _active_scan_count = (
                db.query(func.count(ScanJob.id))
                .filter(ScanJob.status.in_(["running", "queued", "retrying"]))
                .scalar() or 1
            )
        except Exception:
            _active_scan_count = 1

        for rc, cap in caps.items():
            # ── Global cap via Redis semaphore ────────────────────────────────
            # kali_inflight_get retorna quantas tarefas estão em voo globalmente
            # (todos os scans simultâneos), não só o scan atual.
            # Se Redis estiver down, fail-open (retorna 0).
            global_inflight = kali_inflight_get(rc)
            available = max(0, cap - global_inflight)
            if available <= 0:
                continue

            # ── Fair-share per scan ───────────────────────────────────────────
            # When multiple scans compete, limit this scan's share.
            # 1 scan  → can use up to 100% of remaining capacity
            # 2 scans → can use up to 60% each (ensures neither starves)
            # 3+ scans → can use up to 40% each
            if _active_scan_count >= 3:
                _share_pct = 0.40
            elif _active_scan_count == 2:
                _share_pct = 0.60
            else:
                _share_pct = 1.0
            _this_scan_inflight = (
                db.query(func.count(ScanWorkItem.id))
                .filter(
                    ScanWorkItem.scan_job_id == scan_id,
                    ScanWorkItem.resource_class == rc,
                    ScanWorkItem.status.in_(["dispatched", "running", "submitted"]),
                )
                .scalar() or 0
            )
            _fair_share_limit = max(1, int(cap * _share_pct))
            _this_scan_available = max(0, _fair_share_limit - _this_scan_inflight)
            available = min(available, _this_scan_available)
            if available <= 0:
                continue
            room = max(0, dispatch_limit - len(claimed))
            if room <= 0:
                break
            to_claim = min(available, room)
            rows = (
                db.query(ScanWorkItem)
                .filter(
                    ScanWorkItem.scan_job_id == scan_id,
                    ScanWorkItem.resource_class == rc,
                    ScanWorkItem.status.in_(["queued", "retry"]),
                    ScanWorkItem.attempts < ScanWorkItem.max_attempts,
                    or_(ScanWorkItem.lease_until.is_(None), ScanWorkItem.lease_until <= now),
                )
                .order_by(ScanWorkItem.priority.asc(), ScanWorkItem.created_at.asc(), ScanWorkItem.id.asc())
                .limit(to_claim)
                .with_for_update(skip_locked=True)
                .all()
            )
            if not rows:
                continue
            # Reserva os slots no semáforo Redis atomicamente.
            # Se a reserva falhar (outro scan chegou primeiro), não despacha.
            if not kali_inflight_claim(rc, len(rows), cap):
                continue
            for item in rows:
                item.status = "dispatched"
                item.lease_until = lease_until
                item.updated_at = now
                claimed.append(item.id)
        db.commit()
        return claimed
    finally:
        try:
            db.execute(text("select pg_advisory_unlock(:key)"), {"key": lock_key})
            db.commit()
        except Exception:
            db.rollback()


def triage_dead_target(db: Session, scan_id: int, target: str, reason: str = "no_http") -> int:
    """
    Chamada quando httpx/naabu confirma que um target está morto (sem HTTP, sem TCP).
    Cancela todos os work items queued/retry desse target, exceto P18 (relatório).
    Retorna quantidade de itens cancelados.
    """
    # Fases que ainda fazem sentido para targets mortos (relatório, exposição passiva)
    KEEP_PHASES = {"P18", "P01"}
    cancelled = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.target == target,
            ScanWorkItem.status.in_(["queued", "retry", "blocked"]),
            ~ScanWorkItem.phase_id.in_(list(KEEP_PHASES)),
        )
        .all()
    )
    count = 0
    for item in cancelled:
        item.status = "skipped"
        item.result = {"skipped_reason": f"target_triage:{reason}", "triage_at": datetime.utcnow().isoformat()}
        item.updated_at = datetime.utcnow()
        count += 1
    if count:
        db.commit()
    return count


def triage_post_p09_injection(db: Session, scan_id: int) -> dict[str, Any]:
    """Cancela P10/P12/P13 para targets SEM findings críticos/altos do nuclei (P09).

    Lógica: se o nuclei não encontrou nada interessante num target, rodar wapiti/sqlmap/dalfox
    nele é desperdício de 8–15 min/target. Mantemos apenas:
      - Targets com achados HIGH ou CRITICAL do nuclei/P09
      - Crown Jewels (independente de findings — merecem teste completo)
      - Batch items (target="__batch__") — deixa o executor decidir

    Chamada após qualquer item de P09 (nuclei batch) ser concluído.
    """
    from app.models.models import Finding

    _P09_TOOLS = {
        "nuclei", "nuclei-cves", "nuclei-sqli", "nuclei-ssrf", "nuclei-lfi",
        "nuclei-ssti", "nuclei-rce", "nuclei-exposure", "nuclei-idor", "nuclei-takeover",
        "nuclei-headers", "nuclei-cors", "nuclei-auth",
    }
    _HIGH_SEV = {"critical", "high", "medium"}
    _INJECTION_PHASES = {"P10", "P12", "P13"}
    _HIGH_COST_TOOLS = {"wapiti", "sqlmap", "dalfox", "nikto", "wpscan", "zap-active", "zap-api"}

    # 1. Subdomínios com achados medium/high/critical de ferramentas P09
    finding_rows = (
        db.query(Finding.subdomain, Finding.domain)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.severity.in_(list(_HIGH_SEV)),
            Finding.tool.in_(list(_P09_TOOLS)),
        )
        .distinct()
        .all()
    )
    targets_with_findings: set[str] = set()
    for row in finding_rows:
        if row.subdomain:
            targets_with_findings.add(str(row.subdomain))
        if row.domain:
            targets_with_findings.add(str(row.domain))

    # 2. Crown Jewels sempre mantidos — alto valor independe de findings
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if job:
        _cj_list = (dict(job.state_data or {})).get("crown_jewels") or []
        for cj in _cj_list:
            t = cj.get("target") or cj.get("subdomain") or ""
            if t:
                targets_with_findings.add(str(t))

    # 3. Cancela itens individuais (não-batch) de P10/P12/P13 sem evidência
    # Inclui "blocked" — items que ainda não foram desbloqueados também devem
    # ser cancelados se o target não possui findings suficientes do nuclei (P09).
    items_to_cancel = (
        db.query(ScanWorkItem)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.phase_id.in_(list(_INJECTION_PHASES)),
            ScanWorkItem.tool_name.in_(list(_HIGH_COST_TOOLS)),
            ScanWorkItem.status.in_(["queued", "retry", "blocked"]),
            ScanWorkItem.target != "__batch__",
            ~ScanWorkItem.target.in_(list(targets_with_findings)) if targets_with_findings else text("true"),
        )
        .all()
    )

    cancelled = 0
    now = datetime.utcnow()
    for wi in items_to_cancel:
        wi.status = "skipped"
        wi.result = {
            "skipped_reason": "triage_post_p09_no_p09_findings",
            "targets_with_findings_count": len(targets_with_findings),
            "triage_at": now.isoformat(),
        }
        wi.updated_at = now
        cancelled += 1

    if cancelled:
        db.add(ScanLog(
            scan_job_id=scan_id,
            source="work-queue",
            level="INFO",
            message=(
                f"triage_post_p09 scan={scan_id} "
                f"targets_with_findings={len(targets_with_findings)} "
                f"cancelled={cancelled}"
            ),
        ))
        db.commit()

    kept = (
        db.query(func.count(ScanWorkItem.id))
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.phase_id.in_(list(_INJECTION_PHASES)),
            ScanWorkItem.status.in_(["queued", "retry", "submitted", "running", "dispatched"]),
        )
        .scalar() or 0
    )

    return {
        "cancelled": cancelled,
        "kept": int(kept),
        "targets_with_findings": sorted(targets_with_findings),
    }


def has_pending_work(db: Session, scan_id: int) -> bool:
    """Return True if there is any work left to do — active OR blocked.

    'blocked' items are waiting for their gate phase to complete.
    They are NOT terminal — they will become 'queued' once their gate
    fires. Including them prevents premature scan completion when the
    active queue temporarily drains while blocked items wait.
    """
    now = datetime.utcnow()
    return db.query(ScanWorkItem.id).filter(
        ScanWorkItem.scan_job_id == scan_id,
        or_(
            ScanWorkItem.status.in_(["queued", "retry", "dispatched", "running", "submitted", "blocked"]),
            and_(ScanWorkItem.status.in_(["dispatched", "running", "submitted"]), ScanWorkItem.lease_until <= now),
        ),
    ).first() is not None
