import os
import random
import re
import shutil
import subprocess
import threading
import time
import urllib.request
import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.graph.workflow import build_graph, initial_state
from app.models.models import AppSetting, Asset, ExecutedToolRun, Finding, ScanJob, ScanLog, ScheduledScan, Vulnerability, WorkerHeartbeat
from app.services.ai_recommendation_service import generate_portuguese_recommendations
from app.services.audit_service import log_audit
from app.services.cve_enrichment_service import enrichment_service
from app.services.llm_risk_service import parse_scan_llm_risk_config, run_llm_risk_assessment
from app.services.tool_adapters import run_tool_execution
from app.workers.celery_app import celery
from app.workers.worker_groups import (
    UNIT_WORKER_GROUPS,
    SCHEDULED_WORKER_GROUPS,
    SCAN_UNIT_QUEUE,
    SCAN_SCHEDULED_QUEUE,
    ScanMode,
    find_group_by_tool,
    group_queue,
)


SCHEDULE_TARGETS_PER_SCAN = max(1, min(200, int(os.getenv("SCHEDULE_TARGETS_PER_SCAN", "25"))))
BURP_GUARD_MAX_ATTEMPTS = max(1, min(10, int(os.getenv("BURP_GUARD_MAX_ATTEMPTS", "10"))))

# ── FAIR pillar mapping (duplicated from risk_service to avoid circular import) ───
_TOOL_FAIR_PILLAR: dict[str, str] = {
    "naabu": "perimeter_resilience", "nmap": "perimeter_resilience",
    "nmap-vulscan": "patching_hygiene", "nuclei": "patching_hygiene",
    "nikto": "patching_hygiene", "wapiti": "patching_hygiene",
    "sqlmap": "perimeter_resilience", "commix": "perimeter_resilience",
    "dalfox": "perimeter_resilience", "tplmap": "perimeter_resilience",
    "wafw00f": "perimeter_resilience", "sslscan": "patching_hygiene",
    "shcheck": "patching_hygiene", "curl-headers": "patching_hygiene",
    "burp-cli": "patching_hygiene", "theharvester": "osint_exposure",
    "h8mail": "osint_exposure", "shodan-cli": "osint_exposure",
    "subjack": "osint_exposure", "whatweb": "perimeter_resilience",
    "trufflehog": "osint_exposure",
}

_SEV_CVSS_FALLBACK: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5,
}


def _get_or_create_asset(
    db: Session, owner_id: int, domain_or_ip: str, scan_job_id: int,
    port: int | None = None, protocol: str = "http",
) -> Asset:
    """Upsert an Asset row keyed on (owner_id, domain_or_ip, port)."""
    now = datetime.utcnow()
    q = db.query(Asset).filter(
        Asset.owner_id == owner_id,
        Asset.domain_or_ip == domain_or_ip,
    )
    if port is not None:
        q = q.filter(Asset.port == port)
    else:
        q = q.filter(Asset.port.is_(None))
    asset = q.first()
    if asset:
        asset.last_seen = now
        asset.scan_count = (asset.scan_count or 0) + 1
        asset.last_scan_id = scan_job_id
        asset.status = "active"
    else:
        asset = Asset(
            owner_id=owner_id,
            domain_or_ip=domain_or_ip,
            port=port,
            protocol=protocol,
            first_seen=now,
            last_seen=now,
            scan_count=1,
            last_scan_id=scan_job_id,
        )
        db.add(asset)
        db.flush()
    return asset


def _upsert_vulnerability(
    db: Session, asset: Asset, finding: Finding,
    tool: str, cve_id: str | None, cvss: float | None,
    severity: str, title: str,
) -> None:
    """Create or update a Vulnerability row linked to the given asset/finding."""
    import math

    now = datetime.utcnow()
    fair_pillar = _TOOL_FAIR_PILLAR.get(tool, "patching_hygiene")
    cvss_score = cvss or _SEV_CVSS_FALLBACK.get(severity, 5.0)

    existing = db.query(Vulnerability).filter(
        Vulnerability.asset_id == asset.id,
        Vulnerability.tool_source == tool,
        Vulnerability.title == title[:255],
    ).first()

    if existing:
        existing.last_detected = now
        existing.detection_count = (existing.detection_count or 1) + 1
        existing.finding_id = finding.id
        existing.remediated_at = None
        days_open = max(0, (now - existing.first_detected).days)
        existing.age_factor = round(1 + math.log10(days_open + 1), 3)
        existing.ra_score = round(cvss_score * existing.age_factor, 2)
        if cve_id:
            existing.cve_id = cve_id
        if cvss is not None:
            existing.cvss_score = cvss
    else:
        db.add(Vulnerability(
            asset_id=asset.id,
            finding_id=finding.id,
            tool_source=tool[:100],
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            title=title[:255],
            first_detected=now,
            last_detected=now,
            fair_pillar=fair_pillar,
            age_factor=1.0,
            ra_score=round(cvss_score * 1.0, 2),
        ))

def _chunk_targets(targets: list[str], chunk_size: int) -> list[list[str]]:
    return [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]


def _get_scan_retry_policy(db: Session, owner_id: int) -> tuple[bool, int, int]:
    defaults = {
        "scan_retry_enabled": "true",
        "scan_retry_max_attempts": "3",
        "scan_retry_delay_seconds": "10",
    }

    rows = (
        db.query(AppSetting.key, AppSetting.value)
        .filter(
            AppSetting.owner_id == owner_id,
            AppSetting.key.in_(list(defaults.keys())),
        )
        .all()
    )
    values = {k: v for k, v in rows}

    def _as_int(raw: str, default: int, min_v: int, max_v: int) -> int:
        try:
            return max(min_v, min(max_v, int(raw)))
        except Exception:
            return default

    retry_enabled = str(values.get("scan_retry_enabled", defaults["scan_retry_enabled"]).strip()).lower() == "true"
    max_attempts = _as_int(str(values.get("scan_retry_max_attempts", defaults["scan_retry_max_attempts"])), 3, 1, 10)
    delay_seconds = _as_int(str(values.get("scan_retry_delay_seconds", defaults["scan_retry_delay_seconds"])), 10, 5, 3600)

    return retry_enabled, max_attempts, delay_seconds


def _get_burp_runtime_config(db: Session, owner_id: int) -> tuple[bool, str]:
    rows = (
        db.query(AppSetting.key, AppSetting.value)
        .filter(
            AppSetting.owner_id == owner_id,
            AppSetting.key.in_(["burp_enabled", "burp_license_key"]),
        )
        .all()
    )
    values = {k: v for k, v in rows}
    enabled = str(values.get("burp_enabled", "false")).strip().lower() == "true"
    license_key = str(values.get("burp_license_key", "")).strip()
    return enabled, license_key


def _progress_from_state(final_state: dict) -> tuple[int, dict]:
    mission_items = final_state.get("mission_items") or []
    total_steps = max(1, len(mission_items))
    metrics = final_state.get("mission_metrics") or {}
    steps_done = int(metrics.get("steps_done", 0) or 0)
    steps_success = int(metrics.get("steps_success", 0) or 0)
    tools_attempted = int(metrics.get("tools_attempted", 0) or 0)
    tools_success = int(metrics.get("tools_success", 0) or 0)

    step_ratio = min(1.0, steps_done / total_steps)
    quality_ratio = (tools_success / tools_attempted) if tools_attempted > 0 else 0.0
    progress = int(round((step_ratio * 0.85 + quality_ratio * 0.15) * 100))
    return progress, {
        "steps_done": steps_done,
        "steps_success": steps_success,
        "tools_attempted": tools_attempted,
        "tools_success": tools_success,
        "total_steps": total_steps,
    }


def _touch_worker_heartbeat(
    db: Session,
    *,
    scan_mode: ScanMode,
    status: str,
    scan_id: int | None = None,
    task_name: str | None = None,
) -> WorkerHeartbeat:
    worker_name = os.getenv("WORKER_NAME") or os.getenv("HOSTNAME") or "unknown-worker"
    hb = db.query(WorkerHeartbeat).filter(WorkerHeartbeat.worker_name == worker_name).first()
    if hb is None:
        hb = WorkerHeartbeat(worker_name=worker_name)

    hb.mode = scan_mode
    hb.status = status
    hb.current_scan_id = scan_id
    hb.last_task_name = task_name
    hb.last_seen_at = datetime.utcnow()
    db.add(hb)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        hb = db.query(WorkerHeartbeat).filter(WorkerHeartbeat.worker_name == worker_name).first()
        if hb is None:
            raise
        hb.mode = scan_mode
        hb.status = status
        hb.current_scan_id = scan_id
        hb.last_task_name = task_name
        hb.last_seen_at = datetime.utcnow()
        db.add(hb)
        db.flush()
    return hb


@celery.task(name="worker.heartbeat")
def worker_heartbeat() -> dict[str, Any]:
    """Heartbeat periódico de worker para health-check operacional."""
    db: Session = SessionLocal()
    try:
        hb = _touch_worker_heartbeat(db, scan_mode="unit", status="alive")
        db.commit()
        return {
            "ok": True,
            "worker_name": hb.worker_name,
            "status": hb.status,
            "last_seen_at": hb.last_seen_at.isoformat() if hb.last_seen_at else None,
        }
    except Exception as exc:
        db.rollback()
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


def _burp_api_host() -> str:
    host = str(os.getenv("BURP_API_HOST", "burp_rest")).strip() or "burp_rest"
    if host in {"0.0.0.0", "127.0.0.1", "localhost"} and os.path.exists("/.dockerenv"):
        return "burp_rest"
    return host


def _burp_api_port() -> str:
    return str(os.getenv("BURP_API_PORT", "1337")).strip() or "1337"


def _burp_cli_base_cmd() -> list[str]:
    cli = shutil.which("burp-api-cli") or shutil.which("burp-cli") or "burp-api-cli"
    return [cli, "-t", _burp_api_host(), "-p", _burp_api_port()]


def _run_burp_cli(args: list[str], timeout: int = 120) -> tuple[bool, str]:
    cmd = _burp_cli_base_cmd() + args
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as exc:
        return False, f"run_error={exc}"
    out = "\n".join(part for part in [proc.stdout or "", proc.stderr or ""] if part).strip()
    return proc.returncode == 0, out


def _burp_api_alive() -> bool:
    url = f"http://{_burp_api_host()}:{_burp_api_port()}/v0.1/"
    try:
        with urllib.request.urlopen(url, timeout=4) as resp:
            return int(resp.status) >= 200
    except Exception:
        return False


def _parse_burp_list_output(output: str) -> list[dict[str, str]]:
    scans: list[dict[str, str]] = []
    if not output:
        return scans

    line_re = re.compile(
        r"^\s*(?P<id>\d+)\s+(?P<url>\S+)\s+(?P<status>paused|auditing|running|succeeded|failed|cancelled)\b",
        re.IGNORECASE,
    )
    for raw in output.splitlines():
        line = str(raw or "").rstrip()
        m = line_re.match(line)
        if not m:
            continue
        scans.append(
            {
                "id": str(m.group("id") or "").strip(),
                "url": str(m.group("url") or "").strip(),
                "status": str(m.group("status") or "").strip().lower(),
            }
        )
    return scans


def _extract_scan_id_from_cli_output(output: str) -> str:
    for pattern in [r"\bID\s+(\d+)\b", r"/scan/(\d+)\b", r"\btask\s+(\d+)\b"]:
        m = re.search(pattern, output or "", re.IGNORECASE)
        if m:
            return str(m.group(1) or "").strip()
    return ""


def _scan_status(scan_id: str) -> str:
    ok, out = _run_burp_cli(["-S", scan_id, "-M"], timeout=90)
    if not out:
        return "unknown"
    m = re.search(r"Scan status\s+([a-zA-Z_]+)", out, re.IGNORECASE)
    if m:
        return str(m.group(1) or "").strip().lower()
    m2 = re.search(r'"scan_status"\s*:\s*"([^"]+)"', out, re.IGNORECASE)
    if m2:
        return str(m2.group(1) or "").strip().lower()
    return "unknown"


def _scan_metrics(scan_id: str) -> dict[str, Any]:
    if not scan_id:
        return {}
    url = f"http://{_burp_api_host()}:{_burp_api_port()}/v0.1/scan/{scan_id}"
    try:
        with urllib.request.urlopen(url, timeout=8) as resp:
            raw = (resp.read() or b"").decode("utf-8", "ignore").strip()
    except Exception:
        return {}

    try:
        payload = json.loads(raw) if raw else {}
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _resolve_scan_target(scan: dict[str, str]) -> str:
    scan_id = str(scan.get("id") or "").strip()
    listed_url = str(scan.get("url") or "").strip()
    if listed_url and not listed_url.startswith("scan_"):
        return listed_url

    metrics_payload = _scan_metrics(scan_id)
    scan_metrics = metrics_payload.get("scan_metrics") if isinstance(metrics_payload, dict) else {}
    if isinstance(scan_metrics, dict):
        current_url = str(scan_metrics.get("current_url") or "").strip()
        if current_url and current_url.startswith(("http://", "https://")):
            return current_url
        caption = str(scan_metrics.get("crawl_and_audit_caption") or "")
        match = re.search(r"https?://[^\s\"']+", caption, re.IGNORECASE)
        if match:
            return str(match.group(0) or "").strip()

    return ""


def _restart_paused_scan(url: str, max_attempts: int = 10) -> dict[str, Any]:
    if not url or url.startswith("scan_"):
        return {"ok": False, "attempts": 0, "reason": "target_url_indisponivel"}

    active_statuses = {"running", "auditing", "crawling", "succeeded"}
    attempts = 0
    last_status = "unknown"
    last_scan_id = ""

    for attempt in range(1, max_attempts + 1):
        attempts = attempt
        ok, out = _run_burp_cli(["-s", url], timeout=120)
        if not ok:
            continue
        scan_id = _extract_scan_id_from_cli_output(out)
        if not scan_id:
            continue
        last_scan_id = scan_id
        time.sleep(3)
        last_status = _scan_status(scan_id)
        if last_status in active_statuses:
            return {
                "ok": True,
                "attempts": attempts,
                "scan_id": scan_id,
                "status": last_status,
            }

    return {
        "ok": False,
        "attempts": attempts,
        "scan_id": last_scan_id,
        "status": last_status,
    }


@celery.task(name="burp.scan_guard", queue="worker.unit.analise_vulnerabilidade")
def burp_scan_guard() -> dict[str, Any]:
    """Beat de saude do Burp: detecta scans pausados e tenta reativar ate 10x."""
    if not _burp_api_alive():
        return {"ok": False, "api_alive": False, "fixed": 0, "paused": 0}

    ok, list_out = _run_burp_cli(["-L"], timeout=90)
    if not ok:
        return {"ok": False, "api_alive": True, "error": "list_scans_failed", "fixed": 0, "paused": 0}

    scans = _parse_burp_list_output(list_out)
    paused_scans = [s for s in scans if s.get("status") == "paused"]
    fixed = 0
    failed = 0
    skipped = 0
    actions: list[dict[str, Any]] = []

    for scan in paused_scans:
        target_url = _resolve_scan_target(scan)
        if not target_url:
            skipped += 1
            actions.append(
                {
                    "paused_scan_id": scan.get("id"),
                    "target": str(scan.get("url") or "").strip(),
                    "ok": False,
                    "attempts": 0,
                    "reason": "target_url_indisponivel",
                    "status": "skipped",
                }
            )
            continue

        result = _restart_paused_scan(target_url, max_attempts=BURP_GUARD_MAX_ATTEMPTS)
        actions.append(
            {
                "paused_scan_id": scan.get("id"),
                "target": target_url,
                **result,
            }
        )
        if result.get("ok"):
            fixed += 1
        else:
            failed += 1

    return {
        "ok": True,
        "api_alive": True,
        "total": len(scans),
        "paused": len(paused_scans),
        "skipped": skipped,
        "recoverable_paused": max(0, len(paused_scans) - skipped),
        "fixed": fixed,
        "failed": failed,
        "actions": actions,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Burp Async: execução desacoplada do pipeline principal
# ─────────────────────────────────────────────────────────────────────────────

def dispatch_burp_async(
    db: Session,
    parent_job: ScanJob,
    targets: list[str],
    scan_mode: str,
) -> list[str]:
    """Cria ScanJobs filhos (tool=burp) e dispara chord Celery.

    Chamado por ``_execute_scan`` após ``graph.invoke()`` retornar, quando
    ``state["burp_status"] == "scheduled"``.

    Retorna lista de Celery task IDs disparados.
    """
    from celery import chord as celery_chord, group as celery_group

    vuln_queue = group_queue("analise_vulnerabilidade", mode=scan_mode)

    task_signatures = []
    burp_job_ids: list[int] = []

    for target in targets:
        # Requisito 2: cria ScanJob no banco com tool="burp"
        burp_job = ScanJob(
            owner_id=parent_job.owner_id,
            access_group_id=parent_job.access_group_id,
            target_query=target,
            status="pending",
            mode=scan_mode,
            compliance_status="approved",
            current_step="Burp async (aguardando)",
            state_data={
                "parent_scan_job_id": parent_job.id,
                "tool": "burp",
                "target": target,
            },
        )
        db.add(burp_job)
        db.flush()
        burp_job_ids.append(burp_job.id)

        db.add(ScanLog(
            scan_job_id=burp_job.id,
            source="burp.dispatch",
            level="INFO",
            message=f"ScanJob criado para Burp async: target={target} parent={parent_job.id}",
        ))

        # Requisito 2: dispara run_burp_scan.delay(job_id)
        task_signatures.append(
            run_burp_scan.s(
                burp_job_id=burp_job.id,
                parent_job_id=parent_job.id,
                target=target,
                scan_mode=scan_mode,
            ).set(queue=vuln_queue)
        )

    db.add(ScanLog(
        scan_job_id=parent_job.id,
        source="burp.dispatch",
        level="INFO",
        message=f"Chord Burp disparado: {len(targets)} alvos, jobs={burp_job_ids}",
    ))
    log_audit(
        db,
        event_type="burp.dispatch",
        message=f"Burp async dispatched: {len(targets)} targets",
        scan_job_id=parent_job.id,
        metadata={"burp_job_ids": burp_job_ids, "targets": targets},
    )
    db.commit()

    # Dispara chord: group(run_burp_scan × N) → burp_post_process callback
    celery_chord(celery_group(task_signatures))(
        burp_post_process.s(parent_job_id=parent_job.id).set(queue=vuln_queue)
    )

    return [str(j) for j in burp_job_ids]


@celery.task(
    name="burp.run_scan",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    acks_late=True,
)
def run_burp_scan(
    self,
    burp_job_id: int,
    parent_job_id: int,
    target: str,
    scan_mode: str = "unit",
):
    """Executa scan Burp assíncrono para um único alvo.

    Requisito 4: controla completamente o ciclo de vida do Burp.
    - Atualiza ScanJob: PENDING → RUNNING → COMPLETED/FAILED
    - Salva findings no banco
    - Registra logs e heartbeat
    """
    from app.graph.workflow import _extract_burp_cli_findings

    db: Session = SessionLocal()
    try:
        burp_job = db.query(ScanJob).filter(ScanJob.id == burp_job_id).first()
        parent_job = db.query(ScanJob).filter(ScanJob.id == parent_job_id).first()
        if not burp_job or not parent_job:
            return {"ok": False, "error": "job_not_found", "target": target, "findings": []}

        # ── PENDING → RUNNING ─────────────────────────────────────────────────
        burp_job.status = "running"
        burp_job.current_step = f"Burp scanning: {target}"
        _touch_worker_heartbeat(
            db,
            scan_mode=scan_mode,
            status="busy",
            scan_id=burp_job.id,
            task_name="burp.run_scan",
        )
        db.add(ScanLog(
            scan_job_id=burp_job.id,
            source="burp.async",
            level="INFO",
            message=f"Burp scan RUNNING: {target}",
        ))
        db.add(ScanLog(
            scan_job_id=parent_job_id,
            source="burp.async",
            level="INFO",
            message=f"Burp async scan iniciado: {target} (job={burp_job_id})",
        ))
        db.commit()

        # Configura license key do Burp a partir do DB
        burp_enabled, burp_license_key = _get_burp_runtime_config(db, parent_job.owner_id)
        if burp_enabled and burp_license_key:
            os.environ["BURP_LICENSE_KEY"] = burp_license_key

        # ── Executa Burp ──────────────────────────────────────────────────────
        result = run_tool_execution("burp-cli", target, scan_mode=scan_mode)

        stdout = str(result.get("stdout") or result.get("output") or "")
        stderr = str(result.get("stderr") or "")
        command = str(result.get("command") or "")
        status_text = str(result.get("status") or "unknown").strip().lower()
        return_code = result.get("return_code")
        findings = _extract_burp_cli_findings(stdout, "risk_assessment", target)

        execution_blob_parts: list[str] = []
        if command:
            execution_blob_parts.append(f"command={command}")
        if return_code is not None:
            execution_blob_parts.append(f"return_code={return_code}")
        if stdout:
            execution_blob_parts.append(f"stdout:\n{stdout}")
        if stderr:
            execution_blob_parts.append(f"stderr:\n{stderr}")
        execution_blob = "\n\n".join(execution_blob_parts)

        db.add(
            ExecutedToolRun(
                scan_job_id=parent_job_id,
                tool_name="burp-cli",
                target=str(target or "").strip().lower(),
                status="success" if status_text == "executed" else status_text or "failed",
                error_message=(execution_blob[:12000] if execution_blob else None),
                execution_time_seconds=float(result.get("execution_time_seconds") or 0.0) or None,
            )
        )

        db.add(
            ScanLog(
                scan_job_id=parent_job_id,
                source="burp.async",
                level="INFO",
                message=f"tool=burp-cli status={status_text or 'unknown'} target={target} return_code={return_code}",
            )
        )
        if command:
            db.add(
                ScanLog(
                    scan_job_id=parent_job_id,
                    source="burp.async",
                    level="INFO",
                    message=f"tool=burp-cli cmd={command[:1200]}",
                )
            )
        if stdout:
            db.add(
                ScanLog(
                    scan_job_id=parent_job_id,
                    source="burp.async",
                    level="INFO",
                    message=f"tool=burp-cli stdout={stdout[:4000]}",
                )
            )
        if stderr:
            db.add(
                ScanLog(
                    scan_job_id=parent_job_id,
                    source="burp.async",
                    level="WARNING",
                    message=f"tool=burp-cli stderr={stderr[:2000]}",
                )
            )

        if not findings:
            db.add(ScanLog(
                scan_job_id=burp_job.id,
                source="burp.async",
                level="WARNING",
                message=(
                    "Burp executado sem findings parseados "
                    f"(rc={return_code}, stdout_len={len(stdout)}, stderr_len={len(stderr)})."
                ),
            ))

        # ── Persiste findings no banco (Requisito 4) ──────────────────────────
        known_patterns = [
            row[0]
            for row in db.query(Finding.title).filter(Finding.title.isnot(None)).distinct().limit(500).all()
            if row and row[0]
        ]
        new_count = 0
        for vuln in findings:
            details = dict(vuln)
            nested = details.get("details") if isinstance(details.get("details"), dict) else {}
            flattened = {**nested, **details}
            flattened.pop("details", None)
            flattened["source_worker"] = "burp_async"
            flattened["scan_mode"] = scan_mode

            title = str(vuln.get("title", "Burp finding")).strip()
            severity = str(vuln.get("severity", "medium")).strip().lower()

            try:
                recommendations = generate_portuguese_recommendations(vuln, known_patterns=known_patterns)
            except Exception:
                recommendations = {
                    "qwen_recomendacao_pt": '{"resumo":"Recomendacao indisponivel","impacto":"IA indisponivel","mitigacoes":["Hardening baseline"],"prioridade":"media","validacoes":["Reteste"]}',
                }
            flattened.update(recommendations)

            cve_id = enrichment_service.extract_cve(flattened, title=title)
            if cve_id:
                flattened.update(enrichment_service.enrich(cve_id))

            _cvss = None
            if flattened.get("cvss") is not None:
                try:
                    _cvss = float(flattened["cvss"])
                except (TypeError, ValueError):
                    pass

            _recommendation = str(
                flattened.get("qwen_recomendacao_pt") or flattened.get("cloudcode_recomendacao_pt") or ""
            ).strip() or None

            _domain = str(
                flattened.get("asset") or flattened.get("target") or target or ""
            ).strip()[:255] or None

            burp_finding = Finding(
                scan_job_id=parent_job_id,
                title=title,
                severity=severity,
                cve=cve_id,
                cvss=_cvss,
                domain=_domain,
                tool="burp-cli",
                recommendation=_recommendation,
                confidence_score=int(vuln.get("confidence_score", 50) or 50),
                risk_score=vuln.get("risk_score", 5),
                details=flattened,
            )
            db.add(burp_finding)

            # ── Persist Vulnerability + Asset (Burp async) ───────────────────
            if _domain:
                try:
                    asset_obj = _get_or_create_asset(
                        db, parent_job.owner_id, _domain, parent_job_id,
                        protocol="https",
                    )
                    db.flush()
                    _upsert_vulnerability(
                        db, asset_obj, burp_finding,
                        tool="burp-cli", cve_id=cve_id, cvss=_cvss,
                        severity=severity, title=title,
                    )
                except Exception:
                    pass
            new_count += 1

        # ── RUNNING → COMPLETED ───────────────────────────────────────────────
        burp_job.status = "completed"
        burp_job.current_step = "Burp concluído"
        burp_job.state_data = {
            **(burp_job.state_data or {}),
            "findings_count": new_count,
            "return_code": return_code,
            "completed_at": datetime.utcnow().isoformat(),
        }
        _touch_worker_heartbeat(
            db,
            scan_mode=scan_mode,
            status="idle",
            scan_id=None,
            task_name=None,
        )
        db.add(ScanLog(
            scan_job_id=burp_job.id,
            source="burp.async",
            level="INFO",
            message=f"Burp scan COMPLETED: {target} findings={new_count} rc={return_code}",
        ))
        db.add(ScanLog(
            scan_job_id=parent_job_id,
            source="burp.async",
            level="INFO",
            message=f"Burp async concluído: {target} findings={new_count} (job={burp_job_id})",
        ))
        db.commit()

        return {
            "ok": True,
            "burp_job_id": burp_job_id,
            "parent_job_id": parent_job_id,
            "target": target,
            "findings_count": new_count,
            "return_code": return_code,
        }
    except Exception as exc:
        db.rollback()
        try:
            # ── RUNNING → FAILED ──────────────────────────────────────────────
            burp_job = db.query(ScanJob).filter(ScanJob.id == burp_job_id).first()
            if burp_job:
                burp_job.status = "failed"
                burp_job.last_error = str(exc)
                burp_job.current_step = "Burp falhou"
            _touch_worker_heartbeat(
                db,
                scan_mode=scan_mode,
                status="error",
                scan_id=burp_job_id,
                task_name="burp.run_scan",
            )
            db.add(ScanLog(
                scan_job_id=burp_job_id,
                source="burp.async",
                level="ERROR",
                message=f"Burp scan FAILED: {target} error={exc}",
            ))
            db.add(ScanLog(
                scan_job_id=parent_job_id,
                source="burp.async",
                level="ERROR",
                message=f"Burp async falhou: {target} error={exc} (job={burp_job_id})",
            ))
            db.commit()
        except Exception:
            pass
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery.task(name="burp.post_process")
def burp_post_process(burp_results: list, parent_job_id: int):
    """Chord callback: recomputa Governance + Executive com findings completos.

    Requisito 5: após finalização do Burp, dispara reprocessamento parcial
    atualizando diretamente os dados consumidos pelos agentes posteriores.

    Requisito 6: pipeline suporta dois momentos:
    - execução inicial (sem Burp completo) — já feita pelo graph.invoke()
    - execução complementar (com Burp completo) — este callback
    """
    from app.graph.workflow import governance_node, executive_analyst_node
    from sqlalchemy.orm.attributes import flag_modified

    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == parent_job_id).first()
        if not job:
            return {"ok": False, "error": "job_not_found"}

        # ── 1. Contabiliza resultados do chord ────────────────────────────────
        successful_scans = 0
        failed_scans = 0
        total_findings = 0
        for result in (burp_results or []):
            if isinstance(result, dict) and result.get("ok"):
                successful_scans += 1
                total_findings += result.get("findings_count", 0)
            else:
                failed_scans += 1

        db.add(ScanLog(
            scan_job_id=parent_job_id,
            source="burp.post_process",
            level="INFO",
            message=(
                f"Burp post-process iniciado: {total_findings} findings "
                f"de {successful_scans} scans OK, {failed_scans} falhas"
            ),
        ))
        db.commit()

        # ── 2. Recomputa Governance + Executive com TODAS as findings ─────────
        # Findings do Burp já foram persistidas por cada run_burp_scan (Req 4)
        all_db_findings = db.query(Finding).filter(
            Finding.scan_job_id == parent_job_id
        ).all()

        vulns_for_governance = []
        for f in all_db_findings:
            vulns_for_governance.append({
                "title": f.title,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "source_worker": (f.details or {}).get("source_worker", "unknown"),
                "details": f.details or {},
            })

        state_data = dict(job.state_data or {})
        mini_state = {
            "scan_id": parent_job_id,
            "target": job.target_query or "",
            "scan_mode": job.mode or "unit",
            "easm_segment": state_data.get("easm_segment", "Digital Services"),
            "lista_ativos": state_data.get("lista_ativos") or [job.target_query or ""],
            "vulnerabilidades_encontradas": vulns_for_governance,
            "logs_terminais": [],
            "activity_metrics": [],
            "mission_index": 3,
            "mission_items": state_data.get("mission_items") or [],
            "mission_metrics": state_data.get("mission_metrics") or {},
            "asset_fingerprints": state_data.get("asset_fingerprints") or {},
            "fair_decomposition": {},
            "easm_rating": {},
            "executive_summary": "",
        }

        try:
            mini_state = governance_node(mini_state)
            mini_state = executive_analyst_node(mini_state)
        except Exception as gov_exc:
            db.add(ScanLog(
                scan_job_id=parent_job_id,
                source="burp.post_process",
                level="WARNING",
                message=f"Recompute governance/executive falhou: {gov_exc}",
            ))

        # ── 3. Atualiza state_data do ScanJob (Requisito 7: consistência) ─────
        state_data["easm_rating"] = mini_state.get("easm_rating") or state_data.get("easm_rating") or {}
        state_data["fair_decomposition"] = mini_state.get("fair_decomposition") or state_data.get("fair_decomposition") or {}
        state_data["executive_summary"] = mini_state.get("executive_summary") or state_data.get("executive_summary") or ""
        state_data["burp_status"] = "completed"
        state_data["burp_completed_at"] = datetime.utcnow().isoformat()
        state_data["burp_findings_count"] = total_findings

        report_v2 = state_data.get("report_v2") or {}
        report_v2.update({
            "easm_rating": state_data["easm_rating"],
            "fair_decomposition": state_data["fair_decomposition"],
            "executive_summary": state_data["executive_summary"],
        })
        state_data["report_v2"] = report_v2

        job.state_data = state_data
        flag_modified(job, "state_data")

        db.add(ScanLog(
            scan_job_id=parent_job_id,
            source="burp.post_process",
            level="INFO",
            message=(
                f"Burp post-process concluído: {total_findings} findings, "
                f"rating={state_data['easm_rating'].get('score', 'N/A')}/100 "
                f"(Grau {state_data['easm_rating'].get('grade', 'N/A')})"
            ),
        ))
        log_audit(
            db,
            event_type="burp.post_process_completed",
            message=f"Burp async concluído: {total_findings} findings, governance recomputada",
            scan_job_id=parent_job_id,
            metadata={
                "burp_findings": total_findings,
                "successful_scans": successful_scans,
                "failed_scans": failed_scans,
            },
        )
        db.commit()
        return {"ok": True, "findings_count": total_findings, "successful_scans": successful_scans}
    except Exception as exc:
        db.rollback()
        try:
            db.add(ScanLog(
                scan_job_id=parent_job_id,
                source="burp.post_process",
                level="ERROR",
                message=f"Burp post-process falhou: {exc}",
            ))
            state_data = dict(job.state_data or {}) if job else {}
            state_data["burp_status"] = "error"
            state_data["burp_error"] = str(exc)
            if job:
                job.state_data = state_data
                flag_modified(job, "state_data")
            db.commit()
        except Exception:
            pass
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()


# Executado a cada minuto pelo Celery Beat (já existente)
@celery.task(name="scheduler.tick", queue=SCAN_SCHEDULED_QUEUE)

def scheduler_tick():
    from zoneinfo import ZoneInfo

    tz = ZoneInfo("America/Sao_Paulo")
    now = datetime.now(tz)

    current_hhmm = now.strftime("%H:%M")
    current_dow = now.strftime("%A").lower()
    current_dom = now.day

    db: Session = SessionLocal()
    try:
        schedules = db.query(ScheduledScan).filter(ScheduledScan.enabled.is_(True)).all()
        fired = 0

        for sched in schedules:
            # horário
            if sched.run_time != current_hhmm:
                continue

            # frequência
            freq = (sched.frequency or "daily").lower()

            if freq == "weekly" and (sched.day_of_week or "").lower() != current_dow:
                continue

            if freq == "monthly" and sched.day_of_month != current_dom:
                continue

            # idempotência (não rodar 2x no mesmo minuto)
            if sched.last_run_at:
                from zoneinfo import ZoneInfo as _ZI
                slot_start = now.replace(second=0, microsecond=0)
                last_run_local = sched.last_run_at.replace(tzinfo=_ZI("UTC")).astimezone(tz)
                if last_run_local >= slot_start:
                    continue

            # targets
            raw_targets = [
                t.strip()
                for t in sched.targets_text.replace(",", ";").split(";")
                if t.strip()
            ]

            if not raw_targets:
                continue

            job_ids = []
            chunks = _chunk_targets(raw_targets, SCHEDULE_TARGETS_PER_SCAN)

            for index, chunk in enumerate(chunks, start=1):
                job = ScanJob(
                    owner_id=sched.owner_id,
                    access_group_id=sched.access_group_id,
                    target_query="; ".join(chunk),
                    status="pending",
                    mode="scheduled",
                    compliance_status="approved",
                    current_step="Aguardando worker",
                    state_data={},
                )

                db.add(job)
                db.flush()

                db.add(
                    ScanLog(
                        scan_job_id=job.id,
                        source="scheduler",
                        level="INFO",
                        message=(
                            f"Scan agendado disparado automaticamente | "
                            f"schedule_id={sched.id} | freq={freq} | "
                            f"batch={index}/{len(chunks)} | targets={len(chunk)}"
                        ),
                    )
                )

                job_ids.append(job.id)

            # marca execução
            sched.last_run_at = datetime.utcnow()
            db.add(sched)
            db.commit()

            # envia para fila
            for job_id in job_ids:
                celery.send_task(
                    "run_scan_job_scheduled",
                    kwargs={"scan_id": job_id},
                    queue=SCAN_SCHEDULED_QUEUE,
                )

            fired += len(job_ids)

        return {
            "ok": True,
            "checked": len(schedules),
            "fired": fired,
            "slot": current_hhmm,
        }

    finally:
        db.close()


# Scheduler separado
@celery.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(
        30.0,
        worker_heartbeat.s(),
        name="worker-heartbeat"
    )


def _format_mission_progress(state_data: dict, current_step: str) -> str:
    """
    Formata um resumo visual das missões mostrando quais foram completadas,
    qual está rodando e quais faltam.
    
    Retorna string formatada tipo:
      ✅ 1. Reconhecimento (2m 30s)
      ▶️ 2. Analise de Vulnerabilidade (1m 15s em andamento)
      ⏳ 3. OSINT
    """
    mission_items = state_data.get("mission_items", [
        "1. Reconhecimento",
        "2. OSINT",
        "3. Analise de Vulnerabilidade"
    ])
    mission_index = state_data.get("mission_index", 0)
    node_history = state_data.get("node_history", [])
    activity_metrics = state_data.get("activity_metrics", [])
    
    # Rastreia tempo de início de cada missão pelos logs de atividade
    mission_start_times = {}
    for metric in activity_metrics:
        if isinstance(metric, dict):
            node = metric.get("node", "")
            timestamp = metric.get("timestamp")
            # Identifica qual missão o nó pertence
            for idx, mission_name in enumerate(mission_items):
                mission_base = mission_name.split(". ")[1].lower() if ". " in mission_name else ""
                if mission_base and mission_base in node.lower():
                    if idx not in mission_start_times and timestamp:
                        mission_start_times[idx] = timestamp
                    break
    
    lines = []
    current_time = datetime.utcnow()
    
    for idx, mission_name in enumerate(mission_items):
        if idx < mission_index:
            # Missão já completada
            start_time = mission_start_times.get(idx)
            end_time = mission_start_times.get(idx + 1, current_time)
            
            if start_time and isinstance(start_time, (int, float)):
                duration_sec = int((end_time if isinstance(end_time, (int, float)) else time.time()) - start_time)
                duration_str = f"{duration_sec // 60}m {duration_sec % 60}s"
                lines.append(f"  ✅ {mission_name} ({duration_str})")
            else:
                lines.append(f"  ✅ {mission_name}")
                
        elif idx == mission_index:
            # Missão em execução
            start_time = mission_start_times.get(idx)
            if start_time and isinstance(start_time, (int, float)):
                elapsed_sec = int(time.time() - start_time)
                elapsed_str = f"{elapsed_sec // 60}m {elapsed_sec % 60}s"
                lines.append(f"  ▶️  {mission_name} ({elapsed_str} em andamento)")
            else:
                lines.append(f"  ▶️  {mission_name} (iniciando...)")
            lines.append(f"     └─ Etapa: {current_step}")
            
        else:
            # Missão ainda não iniciada
            lines.append(f"  ⏳ {mission_name}")
    
    return "\n".join(lines)


def _start_scan_progress_pulse(scan_id: int, scan_mode: ScanMode, interval_seconds: int = 20):
    """
    Emite logs periódicos durante execução longa para evitar sensação de travamento.
    Mostra progresso detalhado das missões (concluidas, em execução, pendentes).
    """
    stop_event = threading.Event()
    started_at = time.time()

    def _pulse_loop():
        last_state_data = {}
        
        while not stop_event.wait(interval_seconds):
            pulse_db: Session = SessionLocal()
            try:
                job = pulse_db.query(ScanJob).filter(ScanJob.id == scan_id).first()
                if not job:
                    break

                status = str(job.status or "").lower()
                if status in {"completed", "failed", "blocked", "stopped"}:
                    break

                elapsed = int(max(0, time.time() - started_at))
                current_step = str(job.current_step or "em execucao")
                state_data = job.state_data or {}

                # ── Propaga mission_index / current_step do state para o job ──
                mi = state_data.get("mission_index")
                mission_items = state_data.get("mission_items") or []
                if mi is not None and isinstance(mi, int) and mission_items:
                    step_label = mission_items[mi] if mi < len(mission_items) else mission_items[-1]
                    if job.current_step != step_label:
                        job.current_step = step_label
                        current_step = step_label
                    # Também atualiza mission_progress em tempo real
                    total = max(1, len(mission_items))
                    job.mission_progress = int(round(min(mi, total) / total * 100))
                
                # Emite log simples de progresso a cada pulse
                pulse_db.add(
                    ScanLog(
                        scan_job_id=scan_id,
                        source="worker.progress",
                        level="INFO",
                        message=(
                            f"Execucao [{scan_mode}] em andamento ({elapsed}s) | "
                            f"etapa atual: {current_step}"
                        ),
                    )
                )
                
                # A cada 60s (3 pulses), emite um resumo detalhado das missões
                if elapsed % 60 == 0 and elapsed > 0:
                    mission_summary = _format_mission_progress(state_data, current_step)
                    pulse_db.add(
                        ScanLog(
                            scan_job_id=scan_id,
                            source="worker.progress_detail",
                            level="INFO",
                            message=f"PROGRESSO DAS MISSOES (tempo total: {elapsed}s):\n{mission_summary}",
                        )
                    )
                
                pulse_db.commit()
                last_state_data = state_data
            except Exception as e:
                pulse_db.rollback()
            finally:
                pulse_db.close()

    thread = threading.Thread(target=_pulse_loop, name=f"scan-progress-{scan_id}", daemon=True)
    thread.start()

    def _stop():
        stop_event.set()
        thread.join(timeout=1.0)

    return _stop


# ──────────────────────────────────────────────────────────────────────────────
# Tasks de ferramentas — UNITARIOS (scan.unit / worker.unit.*)
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="worker.unit.reconhecimento.execute", queue="worker.unit.reconhecimento")
def unit_reconhecimento_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reconhecimento", tool, target, "unit", params)


@celery.task(name="worker.unit.analise_vulnerabilidade.execute", queue="worker.unit.analise_vulnerabilidade")
def unit_analise_vulnerabilidade_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("analise_vulnerabilidade", tool, target, "unit", params)


@celery.task(name="worker.unit.osint.execute", queue="worker.unit.osint")
def unit_osint_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("osint", tool, target, "unit", params)


@celery.task(name="worker.unit.dispatch", queue=SCAN_UNIT_QUEUE)
def unit_dispatch_tool(tool: str, target: str, params: dict | None = None):
    group = find_group_by_tool(tool, mode="unit")
    task_name = f"worker.unit.{group}.execute"
    return celery.send_task(task_name, kwargs={"tool": tool, "target": target, "params": params or {}}).id


# ──────────────────────────────────────────────────────────────────────────────
# Tasks de ferramentas — AGENDADOS (scan.scheduled / worker.scheduled.*)
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="worker.scheduled.reconhecimento.execute", queue="worker.scheduled.reconhecimento")
def scheduled_reconhecimento_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("reconhecimento", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.analise_vulnerabilidade.execute", queue="worker.scheduled.analise_vulnerabilidade")
def scheduled_analise_vulnerabilidade_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("analise_vulnerabilidade", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.osint.execute", queue="worker.scheduled.osint")
def scheduled_osint_execute(tool: str, target: str, params: dict | None = None):
    return _worker_result("osint", tool, target, "scheduled", params)


@celery.task(name="worker.scheduled.dispatch", queue=SCAN_SCHEDULED_QUEUE)
def scheduled_dispatch_tool(tool: str, target: str, params: dict | None = None):
    group = find_group_by_tool(tool, mode="scheduled")
    task_name = f"worker.scheduled.{group}.execute"
    return celery.send_task(task_name, kwargs={"tool": tool, "target": target, "params": params or {}}).id


# ──────────────────────────────────────────────────────────────────────────────
# Introspeccao
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(name="worker.unit.groups")
def list_unit_worker_groups():
    return UNIT_WORKER_GROUPS


@celery.task(name="worker.scheduled.groups")
def list_scheduled_worker_groups():
    return SCHEDULED_WORKER_GROUPS


# ──────────────────────────────────────────────────────────────────────────────
# Nucleo de execucao — compartilhado pelos dois modos
# ──────────────────────────────────────────────────────────────────────────────

def _execute_scan(scan_id: int, scan_mode: ScanMode) -> dict:
    """Logica central de execucao do scan, usada por ambas as tasks."""
    db: Session = SessionLocal()
    stop_pulse = None
    try:
        _touch_worker_heartbeat(db, scan_mode=scan_mode, status="alive")
        db.commit()

        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"ok": False, "error": "scan not found", "retryable": False}

        if job.status == "stopped":
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        job.status = "running"
        job.current_step = "Iniciando grafo"
        _touch_worker_heartbeat(
            db,
            scan_mode=scan_mode,
            status="busy",
            scan_id=job.id,
            task_name=f"run_scan_job_{scan_mode}",
        )
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker",
            level="INFO",
            message=f"Execucao [{scan_mode}] iniciada",
        ))
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker",
            level="INFO",
            message="Execucao em andamento: ferramentas como nuclei/nmap podem levar varios minutos por alvo.",
        ))
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker.plan",
            level="INFO",
            message=(
                "PLANO DE EXECUCAO:\n"
                "  1️⃣  Reconhecimento - Descoberta de hosts, portas, tecnologias e WAF\n"
                "  2️⃣  OSINT - Consultas OSINT, Shodan, certificados SSL\n"
                "  3️⃣  Analise de Vulnerabilidade - Burp, Nmap Vulscan, Nikto\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "Acompanhe o progresso nos logs abaixo com source=worker.progress_detail"
            ),
        ))
        log_audit(
            db,
            event_type="scan.execution_started",
            message=f"Execucao do scan [{scan_mode}] iniciada",
            scan_job_id=job.id,
            metadata={"scan_mode": scan_mode},
        )
        db.commit()

        stop_pulse = _start_scan_progress_pulse(scan_id=job.id, scan_mode=scan_mode, interval_seconds=20)

        burp_enabled, burp_license_key = _get_burp_runtime_config(db, job.owner_id)
        if burp_enabled and burp_license_key:
            os.environ["BURP_LICENSE_KEY"] = burp_license_key
        else:
            os.environ.pop("BURP_LICENSE_KEY", None)

        shodan_api_key = str(
            (
                db.query(AppSetting.value)
                .filter(AppSetting.owner_id == job.owner_id, AppSetting.key == "shodan_api_key")
                .scalar()
            ) or ""
        ).strip()
        if shodan_api_key:
            os.environ["SHODAN_API_KEY"] = shodan_api_key
        else:
            os.environ.pop("SHODAN_API_KEY", None)

        app = build_graph(mode=scan_mode)
        known_patterns = [
            row[0]
            for row in db.query(Finding.title).filter(Finding.title.isnot(None)).distinct().limit(500).all()
            if row and row[0]
        ]
        state = initial_state(
            scan_id=job.id,
            owner_id=job.owner_id,
            target=job.target_query,
            scan_mode=scan_mode,
            known_vulnerability_patterns=known_patterns,
        )
        trace_id = str(state.get("trace_id") or f"scan-{job.id}")
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker.trace",
            level="INFO",
            message=f"trace_id={trace_id}",
        ))
        db.commit()
        recursion_limit = max(100, len(state.get("mission_items", [])) * 4)
        final_state = app.invoke(
            state,
            config={
                "configurable": {"thread_id": f"scan-{job.id}"},
                "recursion_limit": recursion_limit,
            },
        )
        final_state["trace_id"] = trace_id

        llm_risk_cfg = parse_scan_llm_risk_config(job.state_data or {})
        if llm_risk_cfg.enabled:
            db.add(
                ScanLog(
                    scan_job_id=job.id,
                    source="llm-risk",
                    level="INFO",
                    message=(
                        "LLM Risk Assessment iniciado "
                        f"(profile={llm_risk_cfg.strategy_profile}, strategies={','.join(llm_risk_cfg.strategies)})"
                    ),
                )
            )
            db.commit()
            llm_risk_report = run_llm_risk_assessment(llm_risk_cfg)
            final_state["llm_risk_report"] = llm_risk_report
            db.add(
                ScanLog(
                    scan_job_id=job.id,
                    source="llm-risk",
                    level="INFO",
                    message=(
                        "LLM Risk Assessment concluido "
                        f"(failed={llm_risk_report.get('failed_tests', 0)}/{llm_risk_report.get('total_tests', 0)}, "
                        f"risk={llm_risk_report.get('risk_level', '-')})"
                    ),
                )
            )

        db.refresh(job)
        if job.status == "stopped":
            db.add(ScanLog(scan_job_id=job.id, source="worker", level="WARNING", message="Execucao interrompida apos solicitacao de stop"))
            _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
            db.commit()
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        for line in final_state.get("logs_terminais", []):
            db.add(ScanLog(scan_job_id=job.id, source="graph", level="INFO", message=line))

        seen_findings: set[tuple[str, str, str, str]] = set()
        for vuln in final_state.get("vulnerabilidades_encontradas", []):
            source_worker = vuln.get("source_worker", "vuln")
            details = dict(vuln)
            nested_details = details.get("details") if isinstance(details.get("details"), dict) else {}

            asset_hint = str(
                vuln.get("asset")
                or details.get("asset")
                or nested_details.get("asset")
                or nested_details.get("target")
                or ""
            ).strip().lower()
            port_hint = str(
                vuln.get("port")
                or details.get("port")
                or nested_details.get("port")
                or ""
            ).strip().lower()
            step_hint = str(
                vuln.get("step")
                or details.get("step")
                or nested_details.get("step")
                or ""
            ).strip().lower()
            tool_hint = str(
                vuln.get("tool")
                or details.get("tool")
                or nested_details.get("tool")
                or ""
            ).strip().lower()

            dedupe_key = (
                str(vuln.get("title") or "").strip().lower(),
                str(vuln.get("severity") or "low").strip().lower(),
                str(source_worker).strip().lower(),
                "|".join([asset_hint, port_hint, step_hint, tool_hint]),
            )
            if dedupe_key in seen_findings:
                continue
            seen_findings.add(dedupe_key)

            try:
                recommendations = generate_portuguese_recommendations(vuln, known_patterns=known_patterns)
            except Exception as rec_exc:
                db.add(
                    ScanLog(
                        scan_job_id=job.id,
                        source="ia",
                        level="WARNING",
                        message=f"Falha ao gerar recomendacao IA: {rec_exc}",
                    )
                )
                recommendations = {
                    "qwen_recomendacao_pt": "{\"resumo\":\"Recomendacao indisponivel temporariamente\",\"impacto\":\"Servico de IA indisponivel\",\"mitigacoes\":[\"Aplicar hardening baseline\",\"Executar reteste\"],\"prioridade\":\"media\",\"validacoes\":[\"Reexecutar analise\"]}",
                    "cloudcode_recomendacao_pt": "{\"resumo\":\"Recomendacao indisponivel temporariamente\",\"impacto\":\"Servico de IA indisponivel\",\"mitigacoes\":[\"Aplicar hardening baseline\",\"Executar reteste\"],\"prioridade\":\"media\",\"validacoes\":[\"Reexecutar analise\"]}",
                }
            details.update(recommendations)

            # Normaliza campos tecnicos no nivel raiz para facilitar consultas,
            # dashboard e geração de relatorio sem depender de parsing profundo.
            nested = details.get("details") if isinstance(details.get("details"), dict) else {}
            flattened_details = {**nested, **details}
            if "details" in flattened_details:
                flattened_details.pop("details", None)
            flattened_details["source_worker"] = source_worker
            flattened_details["scan_mode"] = scan_mode

            cve_id = enrichment_service.extract_cve(details, title=vuln.get("title"))
            if cve_id:
                details.update(enrichment_service.enrich(cve_id))
                flattened_details.update(enrichment_service.enrich(cve_id))

            # ── Extrai campos estruturados para colunas dedicadas ─────────────
            _cvss_raw = flattened_details.get("cvss") or details.get("cvss")
            _cvss = None
            if _cvss_raw is not None:
                try:
                    _cvss = float(_cvss_raw)
                except (TypeError, ValueError):
                    _cvss = None

            _tool_col = str(
                tool_hint
                or flattened_details.get("tool")
                or details.get("tool")
                or ""
            ).strip()[:100] or None

            _domain_col = str(
                asset_hint
                or flattened_details.get("asset")
                or flattened_details.get("target")
                or job.target_query
                or ""
            ).strip()[:255] or None

            _recommendation = str(
                flattened_details.get("qwen_recomendacao_pt")
                or flattened_details.get("cloudcode_recomendacao_pt")
                or ""
            ).strip() or None

            finding_obj = Finding(
                    scan_job_id=job.id,
                    title=vuln.get("title", "Potential issue"),
                    severity=vuln.get("severity", "low"),
                    cve=cve_id,
                    cvss=_cvss,
                    domain=_domain_col,
                    tool=_tool_col,
                    recommendation=_recommendation,
                    confidence_score=int(vuln.get("confidence_score", 50) or 50),
                    risk_score=vuln.get("risk_score", 1),
                    details=flattened_details,
                )
            db.add(finding_obj)

            # ── Persist Vulnerability + Asset ────────────────────────────────
            if _domain_col:
                try:
                    _port_int = None
                    if port_hint:
                        try:
                            _port_int = int(port_hint)
                        except (TypeError, ValueError):
                            pass
                    _proto = "https" if "443" in str(port_hint) else "http"
                    asset_obj = _get_or_create_asset(
                        db, job.owner_id, _domain_col, job.id,
                        port=_port_int, protocol=_proto,
                    )
                    db.flush()
                    _upsert_vulnerability(
                        db, asset_obj, finding_obj,
                        tool=_tool_col or "unknown",
                        cve_id=cve_id, cvss=_cvss,
                        severity=vuln.get("severity", "low"),
                        title=vuln.get("title", "Potential issue"),
                    )
                except Exception:
                    pass

        progress, progress_ctx = _progress_from_state(final_state)
        final_state["mission_progress_context"] = progress_ctx

        # ── EASM: propaga campos dos agentes 4 e 5 para report_v2 ─────────────
        existing_report_v2 = (job.state_data or {}).get("report_v2") or {}
        existing_report_v2.update({
            "easm_rating":        final_state.get("easm_rating") or {},
            "fair_decomposition": final_state.get("fair_decomposition") or {},
            "executive_summary":  final_state.get("executive_summary") or "",
        })
        final_state["report_v2"] = existing_report_v2
        # ───────────────────────────────────────────────────────────────────────

        # ── EASM: Persistir histórico de ratings (AssetRatingHistory) ────────
        from app.models.models import Asset, AssetRatingHistory
        easm_rating = final_state.get("easm_rating") or {}
        fair_decomp = final_state.get("fair_decomposition") or {}
        discovered_assets = final_state.get("lista_ativos", [])
        
        for asset_addr in discovered_assets:
            # Encontra ou cria o asset
            asset = db.query(Asset).filter(
                Asset.owner_id == job.owner_id,
                Asset.domain_or_ip == asset_addr,
            ).first()
            
            if asset:
                # Calcula contagem de vulnerabilidades por severidade
                asset_vulns = db.query(Vulnerability).filter(
                    Vulnerability.asset_id == asset.id
                ).all()
                
                open_counts = {
                    "critical": sum(1 for v in asset_vulns if v.severity == "critical" and not v.remediated_at),
                    "high": sum(1 for v in asset_vulns if v.severity == "high" and not v.remediated_at),
                    "medium": sum(1 for v in asset_vulns if v.severity == "medium" and not v.remediated_at),
                }
                remediated_count = sum(1 for v in asset_vulns if v.remediated_at)
                
                # Extrai scores dos pillares
                pillar_scores = {}
                if isinstance(fair_decomp, dict) and "pillars" in fair_decomp:
                    for pillar in fair_decomp.get("pillars", []):
                        pillar_scores[pillar.get("name", "unknown")] = pillar.get("score", 0)
                
                # Grava histórico
                history = AssetRatingHistory(
                    asset_id=asset.id,
                    scan_id=job.id,
                    easm_rating=float(easm_rating.get("score", 0)),
                    easm_grade=easm_rating.get("grade", "F"),
                    open_critical_count=open_counts.get("critical", 0),
                    open_high_count=open_counts.get("high", 0),
                    open_medium_count=open_counts.get("medium", 0),
                    remediated_this_period=remediated_count,
                    pillar_scores=pillar_scores,
                    recorded_at=datetime.utcnow(),
                )
                db.add(history)
        
        db.flush()
        # ───────────────────────────────────────────────────────────────────────

        # ── Burp Async: cria ScanJobs filhos e dispara chord ────────────────
        burp_targets = final_state.get("burp_targets") or []
        if burp_targets and final_state.get("burp_status") == "scheduled":
            burp_job_ids = dispatch_burp_async(db, job, burp_targets, scan_mode)
            final_state["burp_status"] = "pending"
            final_state["burp_async_task_ids"] = burp_job_ids
            final_state["burp_async_dispatched_at"] = datetime.utcnow().isoformat()
            final_state["burp_async_target_count"] = len(burp_targets)
        # ───────────────────────────────────────────────────────────────────────

        job.state_data = final_state
        job.mission_progress = progress
        job.current_step = "5. ExecutiveAnalysis"
        job.status = "completed"
        job.last_error = None
        job.next_retry_at = None
        
        # Log resumo final
        mission_summary = _format_mission_progress(final_state, job.current_step)
        easm_rating = final_state.get("easm_rating") or {}
        db.add(ScanLog(
            scan_job_id=job.id,
            source="worker.summary",
            level="INFO",
            message=(
                f"EXECUCAO EASM CONCLUIDA COM SUCESSO!\n"
                f"\n"
                f"PIPELINE 5 AGENTES:\n"
                f"{mission_summary}\n"
                f"\n"
                f"RESUMO:\n"
                f"  • Vulnerabilidades encontradas: {len(final_state.get('vulnerabilidades_encontradas', []))}\n"
                f"  • Portas descobertas: {len(final_state.get('discovered_ports', []))}\n"
                f"  • Ativos mapeados: {len(final_state.get('lista_ativos', []))}\n"
                f"  • Rating EASM: {easm_rating.get('score', 'N/A')}/100 (Grau {easm_rating.get('grade', 'N/A')})\n"
                f"  • Taxa de sucesso: {progress_ctx.get('tools_success', 0)}/{progress_ctx.get('tools_attempted', 0)} ferramentas"
            )
        ))
        
        db.add(ScanLog(scan_job_id=job.id, source="worker", level="INFO", message=f"Execucao [{scan_mode}] finalizada"))
        log_audit(
            db,
            event_type="scan.execution_completed",
            message=f"Execucao [{scan_mode}] concluida com sucesso",
            scan_job_id=job.id,
            metadata={
                "scan_mode": scan_mode,
                "discovered_ports": final_state.get("discovered_ports", []),
                "pending_port_tests": final_state.get("pending_port_tests", []),
            },
        )
        _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
        db.commit()
        return {"ok": True, "scan_id": scan_id, "scan_mode": scan_mode, "retryable": False}
    except Exception as exc:
        db.rollback()
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if job:
            if job.status == "stopped":
                _touch_worker_heartbeat(db, scan_mode=scan_mode, status="idle", scan_id=None, task_name=None)
                db.commit()
                return {"ok": False, "error": "scan_stopped", "retryable": False}
            job.status = "failed"
            job.last_error = str(exc)
            db.add(ScanLog(scan_job_id=job.id, source="worker", level="ERROR", message=str(exc)))
            log_audit(
                db,
                event_type="scan.execution_failed",
                message=f"Execucao [{scan_mode}] falhou",
                scan_job_id=job.id,
                level="ERROR",
                metadata={"error": str(exc), "scan_mode": scan_mode},
            )
            _touch_worker_heartbeat(db, scan_mode=scan_mode, status="error", scan_id=scan_id, task_name=f"run_scan_job_{scan_mode}")
            db.commit()
        return {"ok": False, "error": str(exc), "retryable": True}
    finally:
        if stop_pulse:
            try:
                stop_pulse()
            except Exception:
                pass
        db.close()


def _run_scan_with_retry(task_ctx, scan_id: int, scan_mode: ScanMode) -> dict:
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return {"ok": False, "error": "scan not found", "retryable": False}

        if job.status == "stopped":
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        retry_enabled, max_attempts, delay_seconds = _get_scan_retry_policy(db, job.owner_id)
        if not retry_enabled:
            max_attempts = 1

        attempt = int(getattr(task_ctx.request, "retries", 0)) + 1
        attempt = max(1, attempt)

        job.retry_attempt = attempt
        job.retry_max = max_attempts
        job.current_step = f"Execucao tentativa {attempt}/{max_attempts}"
        db.add(
            ScanLog(
                scan_job_id=scan_id,
                source="worker.retry",
                level="INFO",
                message=f"Tentativa {attempt}/{max_attempts} iniciada (modo={scan_mode})",
            )
        )
        db.commit()
    finally:
        db.close()

    result = _execute_scan(scan_id, scan_mode)
    if result.get("ok"):
        return result

    if not result.get("retryable"):
        return result

    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            return result

        if job.status == "stopped":
            return {"ok": False, "error": "scan_stopped", "retryable": False}

        retry_enabled, max_attempts, delay_seconds = _get_scan_retry_policy(db, job.owner_id)
        if not retry_enabled:
            max_attempts = 1
        attempt = int(getattr(task_ctx.request, "retries", 0)) + 1

        if attempt < max_attempts:
            max_delay = int(delay_seconds * 8)
            exponential_delay = int(min(max_delay, delay_seconds * (2 ** max(0, attempt - 1))))
            jitter = random.randint(0, max(1, min(15, delay_seconds // 2)))
            countdown = exponential_delay + jitter
            next_retry_at = datetime.utcnow() + timedelta(seconds=countdown)
            job.status = "retrying"
            job.next_retry_at = next_retry_at
            job.current_step = f"Retry agendado ({attempt + 1}/{max_attempts})"
            job.last_error = result.get("error", "falha desconhecida")
            db.add(
                ScanLog(
                    scan_job_id=scan_id,
                    source="worker.retry",
                    level="WARNING",
                    message=(
                        f"Falha na tentativa {attempt}/{max_attempts}: {result.get('error', 'erro')} | "
                        f"novo retry em {countdown}s"
                    ),
                )
            )
            db.commit()
            raise task_ctx.retry(exc=Exception(result.get("error", "scan failed")), countdown=countdown)

        job.status = "failed"
        job.next_retry_at = None
        job.current_step = f"Falha definitiva apos {attempt}/{max_attempts} tentativas"
        db.add(
            ScanLog(
                scan_job_id=scan_id,
                source="worker.retry",
                level="ERROR",
                message=f"Retry esgotado em {attempt}/{max_attempts} tentativas",
            )
        )
        db.commit()
        return result
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Tasks orquestradoras publicas — uma por modo de execucao
# ──────────────────────────────────────────────────────────────────────────────

@celery.task(bind=True, name="run_scan_job_unit", queue=SCAN_UNIT_QUEUE)
def run_scan_job_unit(self, scan_id: int):
    """
    Task para scans UNITARIOS (execucao manual/pontual).
    Consumida exclusivamente pelos workers 'worker_unit' no docker-compose.
    Prioridade alta | concurrency=1 | escopo focado.
    """
    return _run_scan_with_retry(self, scan_id, "unit")


@celery.task(bind=True, name="run_scan_job_scheduled", queue=SCAN_SCHEDULED_QUEUE)
def run_scan_job_scheduled(self, scan_id: int):
    """
    Task para scans AGENDADOS (execucao periodica/batch).
    Consumida exclusivamente pelos workers 'worker_scheduled' no docker-compose.
    Prioridade normal | concurrency=2 | cobertura completa.
    """
    return _run_scan_with_retry(self, scan_id, "scheduled")


# Alias retroativo — usado por fallback síncrono quando a fila nao esta disponivel
def run_scan_job(scan_id: int):
    """Compatibilidade retroativa: infere o modo pelo campo 'mode' do ScanJob."""
    db: Session = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        mode: ScanMode = "scheduled" if job and job.mode == "scheduled" else "unit"
    finally:
        db.close()
    return _execute_scan(scan_id, mode)


# ──────────────────────────────────────────────────────────────────────────────
# Scheduler tick — verifica ScheduledScan devidos e dispara ScanJobs
# Executado a cada minuto pelo Celery Beat
# ──────────────────────────────────────────────────────────────────────────────


