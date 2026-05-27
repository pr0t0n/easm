from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.models import ScanJob, ScanLog, ScanWorkItem
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
    for target in [str(t).strip() for t in targets if str(t or "").strip()]:
        for phase_id in _eligible_phases_for_target(target, state):
            tools = _phase_tools(phase_id)
            if not tools:
                continue
            required = list((PHASE_CONTRACTS.get(phase_id) or {}).get("required_tools") or [])
            optional = [tool for tool in tools if tool not in set(required)]
            selected = list(dict.fromkeys(required + optional[:max_optional_per_phase]))
            for tool in selected:
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
                item = ScanWorkItem(
                    scan_job_id=job.id,
                    phase_id=phase_id,
                    target=target[:500],
                    tool_name=tool[:120],
                    profile=_tool_profile(tool)[:120],
                    resource_class=rc,
                    priority=max(1, base_priority + risk_boost),
                    status="queued",
                    max_attempts=2,
                    item_metadata={"source": source, "engine": "capacity_work_queue", "high_risk": risk_boost < 0},
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
        message=f"work_queue_seed source={source} targets={len(targets)} created={created} existing={existing} skipped={skipped}",
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

        running_rows = (
            db.query(ScanWorkItem.resource_class, func.count(ScanWorkItem.id))
            .filter(
                ScanWorkItem.scan_job_id == scan_id,
                ScanWorkItem.status.in_(["running", "dispatched", "submitted"]),
                or_(ScanWorkItem.lease_until.is_(None), ScanWorkItem.lease_until > now),
            )
            .group_by(ScanWorkItem.resource_class)
            .all()
        )
        running = {str(rc): int(count) for rc, count in running_rows}

        for rc, cap in caps.items():
            available = max(0, cap - running.get(rc, 0))
            if available <= 0:
                continue
            room = max(0, dispatch_limit - len(claimed))
            if room <= 0:
                break
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
                .limit(min(available, room))
                .with_for_update(skip_locked=True)
                .all()
            )
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
            ScanWorkItem.status.in_(["queued", "retry"]),
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


def has_pending_work(db: Session, scan_id: int) -> bool:
    now = datetime.utcnow()
    return db.query(ScanWorkItem.id).filter(
        ScanWorkItem.scan_job_id == scan_id,
        or_(
            ScanWorkItem.status.in_(["queued", "retry", "dispatched", "running", "submitted"]),
            and_(ScanWorkItem.status.in_(["dispatched", "running", "submitted"]), ScanWorkItem.lease_until <= now),
        ),
    ).first() is not None
