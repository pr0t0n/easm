from datetime import datetime, timedelta, timezone
import csv
import io
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.models import AuditEvent, FalsePositiveMemory, Finding, ScanJob, ScanLog, User
from app.models.models import WorkerHeartbeat
from app.schemas.scan import LogResponse, ReportResponse, ScanCreate, ScanResponse, ScanStatusResponse
from app.services.audit_service import log_audit
from app.services.chroma_service import FalsePositiveVectorStore
from app.services.policy_service import is_target_allowed
from app.services.risk_service import build_priority_reason, compute_age_metrics, compute_fair_metrics
from app.workers.celery_app import celery
from app.workers.tasks import run_scan_job, run_scan_job_unit


router = APIRouter(prefix="/api", tags=["scans"])
vector_store = FalsePositiveVectorStore()


def _extract_scan_id_from_task(task: dict) -> int | None:
    kwargs = task.get("kwargs")
    if isinstance(kwargs, dict) and "scan_id" in kwargs:
        try:
            return int(kwargs.get("scan_id"))
        except (TypeError, ValueError):
            return None

    args = task.get("args")
    if isinstance(args, (list, tuple)) and args:
        try:
            return int(args[0])
        except (TypeError, ValueError):
            return None

    if isinstance(args, str):
        digits = "".join(ch for ch in args if ch.isdigit())
        if digits:
            try:
                return int(digits)
            except ValueError:
                return None
    return None


def _active_scan_task_ids(scan_id: int) -> list[str]:
    inspector = celery.control.inspect(timeout=1.5)
    buckets = [inspector.active() or {}, inspector.reserved() or {}, inspector.scheduled() or {}]
    task_ids: list[str] = []
    for tasks_by_worker in buckets:
        for _, tasks in tasks_by_worker.items():
            for task in tasks or []:
                name = str(task.get("name") or "")
                if name not in {"run_scan_job_unit", "run_scan_job_scheduled"}:
                    continue
                resolved_scan_id = _extract_scan_id_from_task(task)
                if resolved_scan_id != scan_id:
                    continue
                task_id = str(task.get("id") or "").strip()
                if task_id:
                    task_ids.append(task_id)
    return list(dict.fromkeys(task_ids))


def _reconcile_orphan_running_scans(db: Session) -> int:
    inspector = celery.control.inspect(timeout=1.5)
    active = inspector.active()
    if active is None:
        return 0

    active_scan_ids: set[int] = set()
    for _, tasks in active.items():
        for task in tasks or []:
            if str(task.get("name") or "") not in {"run_scan_job_unit", "run_scan_job_scheduled"}:
                continue
            scan_id = _extract_scan_id_from_task(task)
            if scan_id is not None:
                active_scan_ids.add(scan_id)

    cutoff = datetime.utcnow() - timedelta(minutes=10)
    stale_rows = (
        db.query(ScanJob)
        .filter(ScanJob.status.in_(["running", "retrying"]), ScanJob.updated_at < cutoff)
        .all()
    )

    fixed = 0
    for row in stale_rows:
        if row.id in active_scan_ids:
            continue
        row.status = "failed"
        row.current_step = "Scan encerrado por reconciliacao de orfao"
        row.last_error = "Scan marcado como falho por estar running sem task ativa no worker"
        row.next_retry_at = None
        db.add(
            ScanLog(
                scan_job_id=row.id,
                source="reconciler",
                level="WARNING",
                message="Scan running/retrying sem task ativa; status corrigido para failed",
            )
        )
        fixed += 1

    if fixed:
        db.commit()
    return fixed


def _authorized_scan_query(db: Session, current_user: User):
    query = db.query(ScanJob)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    return query


def _authorized_finding_query(db: Session, current_user: User):
    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    return query


def _sev_weight(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity or "low").lower(), 1)


KNOWN_WAF_MODELS: list[str] = [
    "cloudflare",
    "akamai",
    "imperva",
    "modsecurity",
    "mod_security",
    "f5",
    "aws waf",
    "barracuda",
    "fortiweb",
]


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(str(severity or "low").strip().lower(), 0)


def _risk_text(severity: str, confidence_score: int | float | None = None) -> str:
    sev = str(severity or "low").strip().lower()
    conf = int(confidence_score or 0)
    if sev == "critical":
        return "Crítico"
    if sev == "high":
        return "Alto"
    if sev == "medium":
        return "Médio"
    if sev == "info":
        return "Informativo"
    if conf >= 80:
        return "Baixo (alta confiança)"
    return "Baixo"


def _detect_waf_vendor(text: str | None) -> str:
    blob = str(text or "").strip().lower()
    if not blob:
        return ""
    for model in KNOWN_WAF_MODELS:
        if model in blob:
            return model
    return ""


def _sanitize_text(value: str | None) -> str:
    if not value:
        return ""
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    sanitized = ansi_pattern.sub("", str(value))
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def _sanitize_multiline_text(value: str | None) -> str:
    if not value:
        return ""
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    sanitized = ansi_pattern.sub("", str(value))
    sanitized = sanitized.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"\s+$", "", line) for line in sanitized.split("\n")]
    compact = "\n".join(lines).strip()
    compact = re.sub(r"\n{3,}", "\n\n", compact)
    return compact


def _normalize_finding_title(value: str | None) -> str:
    title = _sanitize_text(value)
    lowered = title.lower()
    for prefix in ["nuclei:", "nuclei -", "nikto:", "ffuf:"]:
        if lowered.startswith(prefix):
            title = title[len(prefix):].strip(" -:")
            break
    return title or "Vulnerabilidade sem titulo"


def _normalize_recommendation(details: dict) -> str:
    rec = _extract_recommendation_payload(details)
    mitigacoes = rec.get("mitigacoes") or []
    if mitigacoes:
        return _sanitize_text("; ".join(str(m) for m in mitigacoes[:3] if str(m).strip()))
    if rec.get("resumo"):
        return _sanitize_text(str(rec.get("resumo")))

    severity = str((details or {}).get("severity") or "").lower()
    if severity == "critical":
        return "Aplicar mitigacao imediata, corrigir configuracao e validar por reteste priorizado."
    if severity == "high":
        return "Corrigir nesta sprint, aplicar hardening e validar com novo scan."
    if severity == "medium":
        return "Planejar correcao em curto prazo e monitorar exposicao residual."
    return "Registrar no backlog de seguranca, corrigir e confirmar por reteste."


def _extract_ports_from_text(value: str | None) -> set[int]:
    text = str(value or "")
    ports: set[int] = set()

    for match in re.finditer(r"porta\s+(\d{1,5})", text, re.IGNORECASE):
        try:
            port = int(match.group(1))
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)

    for match in re.finditer(r":(\d{1,5})\b", text):
        try:
            port = int(match.group(1))
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.add(port)

    return ports


def _build_top_recommendations(vulnerability_rows: list[dict], recommendations: list[dict]) -> list[dict]:
    top: list[dict] = []
    seen: set[str] = set()
    all_ports: set[int] = set()

    for row in vulnerability_rows or []:
        for field in [
            row.get("name"),
            row.get("problem"),
            row.get("target"),
            row.get("error"),
            row.get("recommendation"),
        ]:
            all_ports.update(_extract_ports_from_text(str(field or "")))

    if all_ports:
        ports = ",".join(str(p) for p in sorted(all_ports)[:20])
        top.append(
            {
                "id": "R-PORTS",
                "name": "Exposicao de portas externas",
                "recommendation": f"Desabilitar porta {ports}. Manter somente portas estritamente necessarias com filtro de origem e segmentacao.",
                "kind": "consolidated",
            }
        )
        seen.add(f"ports:{ports}")

    for rec in recommendations or []:
        text = _sanitize_text(rec.get("recommendation") or "")
        if not text:
            continue
        normalized = re.sub(r"\s+", " ", text).strip().lower()[:220]
        if normalized in seen:
            continue
        seen.add(normalized)
        top.append(
            {
                "id": _sanitize_text(rec.get("id") or f"R-{len(top) + 1}"),
                "name": _sanitize_text(rec.get("name") or "Correcao recomendada"),
                "recommendation": text,
                "kind": "consolidated",
            }
        )
        if len(top) >= 5:
            break

    return top[:5]


def _build_strategic_points(
    target: str,
    summary: dict[str, int],
    fair_total: dict[str, float],
    lifecycle: dict[str, int],
    category_scores: list[dict],
) -> list[str]:
    points: list[str] = []
    open_count = int(summary.get("open") or 0)
    critical = int(summary.get("critical") or 0)
    high = int(summary.get("high") or 0)
    corrected = int(lifecycle.get("corrected") or 0)
    ale_open = float(fair_total.get("ale_total_open_usd") or 0.0)

    points.append(
        f"Risco atual do alvo {target}: {open_count} vulnerabilidades abertas, com {critical} criticas e {high} altas exigindo prioridade executiva."
    )
    points.append(
        f"Exposicao financeira anual estimada (ALE aberto): USD {ale_open:,.0f}. Recomendado tratar como meta de reducao trimestral com dono e prazo definidos."
    )
    if corrected > 0:
        points.append(
            f"Evolucao positiva detectada: {corrected} vulnerabilidades nao reapareceram no re-scan. Manter cadencia de validacao para evitar reabertura de risco."
        )

    weak_categories = sorted(category_scores, key=lambda item: item.get("score", 100))[:2]
    if weak_categories:
        categories = ", ".join(str(item.get("category") or "-") for item in weak_categories)
        points.append(
            f"Prioridade de governanca: reforcar controles nas categorias com menor pontuacao ({categories}), com acompanhamento no comite de seguranca."
        )

    return points[:5]


def _build_technical_points(vulnerability_rows: list[dict], recommendations: list[dict]) -> list[str]:
    points: list[str] = []
    seen: set[str] = set()

    ports: set[int] = set()
    for row in vulnerability_rows:
        for field in [row.get("target"), row.get("name"), row.get("problem"), row.get("error"), row.get("recommendation")]:
            ports.update(_extract_ports_from_text(str(field or "")))
    if ports:
        ports_list = ",".join(str(p) for p in sorted(ports)[:20])
        points.append(
            f"Rede: desabilitar porta {ports_list} quando nao houver justificativa de negocio; aplicar ACL por origem e segmentacao por ambiente."
        )
        seen.add(f"ports:{ports_list}")

    for rec in recommendations or []:
        text = _sanitize_text(rec.get("recommendation") or "")
        if not text:
            continue
        normalized = text.lower()[:220]
        if normalized in seen:
            continue
        seen.add(normalized)
        points.append(f"Aplicacao: {text}")
        if len(points) >= 8:
            break

    if not points:
        points.append("Sem recomendacoes tecnicas disponiveis para este scan.")
    return points[:8]


def _severity_penalty(sev: str) -> int:
    return {
        "critical": 20,
        "high": 12,
        "medium": 6,
        "low": 2,
        "info": 1,
    }.get(str(sev or "low").lower(), 2)


def _compute_framework_scores(vulnerability_rows: list[dict]) -> dict:
    # Pesos por categoria para refletir impacto real do finding em cada framework.
    weights = {
        "iso27001": {
            "Application Security": 1.0,
            "Web Encryption": 1.0,
            "Network Filtering": 0.9,
            "Authentication": 1.0,
            "Authorization": 1.0,
            "Data Exposure": 1.0,
            "Software Patching": 0.8,
            "DNS Security": 0.7,
            "System Hosting": 0.7,
        },
        "nist": {
            "Application Security": 1.0,
            "Web Encryption": 0.9,
            "Network Filtering": 1.0,
            "Authentication": 1.0,
            "Authorization": 1.0,
            "Data Exposure": 0.9,
            "Software Patching": 0.9,
            "DNS Security": 0.8,
            "System Hosting": 0.8,
        },
        "cis_v8": {
            "Application Security": 0.9,
            "Web Encryption": 0.8,
            "Network Filtering": 1.0,
            "Authentication": 1.0,
            "Authorization": 0.9,
            "Data Exposure": 0.8,
            "Software Patching": 1.0,
            "DNS Security": 0.8,
            "System Hosting": 0.9,
        },
        "pci": {
            "Application Security": 1.0,
            "Web Encryption": 1.0,
            "Network Filtering": 1.0,
            "Authentication": 1.0,
            "Authorization": 1.0,
            "Data Exposure": 1.0,
            "Software Patching": 0.9,
            "DNS Security": 0.7,
            "System Hosting": 0.8,
        },
    }

    penalties = {"iso27001": 0.0, "nist": 0.0, "cis_v8": 0.0, "pci": 0.0}
    for row in vulnerability_rows:
        if row.get("is_false_positive"):
            continue
        sev = str(row.get("severity") or "low").lower()
        category = str(row.get("category") or "Application Security")
        base = _severity_penalty(sev)
        for fw in penalties.keys():
            penalties[fw] += base * float(weights.get(fw, {}).get(category, 0.75))

    def score_from_penalty(value: float) -> int:
        # Curva suavizada: evita queda excessiva de score por poucos achados.
        safe_value = max(0.0, float(value))
        if safe_value <= 0:
            return 100
        return max(55, min(100, int(round(100.0 / (1.0 + (safe_value / 55.0))))))

    return {
        "iso27001": {"score": score_from_penalty(penalties["iso27001"])},
        "nist": {"score": score_from_penalty(penalties["nist"])},
        "cis_v8": {"score": score_from_penalty(penalties["cis_v8"])},
        "pci": {"score": score_from_penalty(penalties["pci"])},
    }


def _compute_fair_summary(findings: list[Finding], enriched_findings: list[dict], fair_ale_total_open: float, fair_ale_total_all: float) -> dict:
    open_items = [item for item in enriched_findings if not item.get("is_false_positive")]
    lef_values = [float((item.get("fair") or {}).get("loss_event_frequency") or 0.0) for item in open_items]
    lm_values = [float((item.get("fair") or {}).get("loss_magnitude_usd") or 0.0) for item in open_items]
    fair_scores = [float((item.get("fair") or {}).get("fair_score") or 0.0) for item in open_items]

    def _avg(values: list[float]) -> float:
        return round(sum(values) / len(values), 4) if values else 0.0

    ale_peak = 0.0
    if open_items:
        ale_peak = max(float((item.get("fair") or {}).get("annualized_loss_exposure_usd") or 0.0) for item in open_items)

    return {
        "enabled": True,
        "ale_total_open_usd": round(fair_ale_total_open, 2),
        "ale_total_all_usd": round(fair_ale_total_all, 2),
        "daily_impact_open_usd": round(fair_ale_total_open / 365.0, 2),
        "mitigation_cost_estimate_open_usd": round(fair_ale_total_open * 0.057, 2),
        "fair_avg_score": round(_avg(fair_scores), 2),
        "loss_event_frequency_avg": _avg(lef_values),
        "loss_magnitude_avg_usd": round(_avg(lm_values), 2),
        "ale_peak_usd": round(ale_peak, 2),
        "open_findings_count": len(open_items),
        "total_findings_count": len(findings),
    }


def _try_parse_json_dict(value) -> dict | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _extract_recommendation_payload(details: dict) -> dict[str, object]:
    details = details if isinstance(details, dict) else {}
    candidates = [
        details.get("qwen_recomendacao_pt"),
        details.get("cloudcode_recomendacao_pt"),
    ]
    for candidate in candidates:
        parsed = _try_parse_json_dict(candidate)
        if not parsed:
            continue
        mitigacoes = parsed.get("mitigacoes")
        if not isinstance(mitigacoes, list):
            mitigacoes = []
        validacoes = parsed.get("validacoes")
        if not isinstance(validacoes, list):
            validacoes = []
        return {
            "resumo": _sanitize_text(parsed.get("resumo") or ""),
            "impacto": _sanitize_text(parsed.get("impacto") or ""),
            "mitigacoes": [_sanitize_text(str(item)) for item in mitigacoes if _sanitize_text(str(item))],
            "prioridade": _sanitize_text(parsed.get("prioridade") or ""),
            "validacoes": [_sanitize_text(str(item)) for item in validacoes if _sanitize_text(str(item))],
        }

    # fallback simples para texto cru quando IA nao devolve JSON
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return {
                "resumo": _sanitize_text(candidate),
                "impacto": "",
                "mitigacoes": [],
                "prioridade": "",
                "validacoes": [],
            }

    return {
        "resumo": "",
        "impacto": "",
        "mitigacoes": [],
        "prioridade": "",
        "validacoes": [],
    }


def _pick_first_text(details: dict, keys: list[str], preserve_linebreaks: bool = False) -> str:
    for key in keys:
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            if preserve_linebreaks:
                return _sanitize_multiline_text(value)
            return _sanitize_text(value)
    return ""


def _extract_method_and_endpoint(full_url: str, payload: str, evidence: str, command: str) -> tuple[str, str]:
    blob = "\n".join([full_url or "", payload or "", evidence or "", command or ""])
    method_match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", blob, re.IGNORECASE)
    method = str(method_match.group(1) if method_match else "GET").upper()

    endpoint = ""
    req_line = re.search(r"(?im)^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+([^\s]+)", blob)
    if req_line:
        endpoint = str(req_line.group(2) or "").strip()
    elif full_url:
        parsed = urlparse(full_url if "://" in full_url else f"http://{full_url}")
        endpoint = str(parsed.path or "/")
    if not endpoint:
        endpoint = "/"
    return method, endpoint


def _extract_parameter_name(payload: str, evidence: str, title: str) -> str:
    blob = "\n".join([payload or "", evidence or "", title or ""])

    patterns = [
        re.compile(r"(?:param(?:eter)?|campo|field)\s*[:=]\s*([a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
        re.compile(r"\"([a-zA-Z0-9_\-\.]+)\"\s*:\s*\"[^\"]+\""),
        re.compile(r"\b([a-zA-Z0-9_\-\.]+)='[^']+'"),
        re.compile(r"\b([a-zA-Z0-9_\-\.]+)=\S+"),
    ]
    for pattern in patterns:
        match = pattern.search(blob)
        if match:
            candidate = str(match.group(1) or "").strip()
            if candidate and candidate.lower() not in {"http", "https", "host", "content-type"}:
                return candidate
    return "-"


def _extract_http_response_status(evidence: str) -> str:
    match = re.search(r"(?im)^\s*HTTP/\S+\s+(\d{3})\b", evidence or "")
    if not match:
        return "-"
    return f"HTTP {str(match.group(1) or '').strip()}"


def _framework_context(category: str, title: str, details: dict) -> dict[str, str]:
    cat = str(category or "Application Security")
    title_blob = str(title or "").lower()
    detail_blob = " ".join(
        [
            str((details or {}).get("evidence") or ""),
            str((details or {}).get("payload") or ""),
            str((details or {}).get("output") or ""),
        ]
    ).lower()
    blob = f"{title_blob} {detail_blob}"

    mapping = {
        "Application Security": {
            "owasp": "A03:2021 - Injection",
            "cwe": "CWE-89",
            "class": "Improper Input Neutralization",
            "iso": "ISO 27001 A.8.28 Secure coding",
            "nist": "NIST PR.DS-6 / SI-10",
            "cis": "CIS v8 Control 16 - Application Software Security",
        },
        "Web Encryption": {
            "owasp": "A02:2021 - Cryptographic Failures",
            "cwe": "CWE-319",
            "class": "Cleartext Transmission of Sensitive Information",
            "iso": "ISO 27001 A.8.24 Use of cryptography",
            "nist": "NIST SC-8 / SC-13",
            "cis": "CIS v8 Control 3 - Data Protection",
        },
        "Authentication": {
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "cwe": "CWE-287",
            "class": "Improper Authentication",
            "iso": "ISO 27001 A.5.17 Authentication information",
            "nist": "NIST IA-2 / AC-7",
            "cis": "CIS v8 Control 6 - Access Control Management",
        },
        "Authorization": {
            "owasp": "A01:2021 - Broken Access Control",
            "cwe": "CWE-285",
            "class": "Improper Authorization",
            "iso": "ISO 27001 A.5.15 Access control",
            "nist": "NIST AC-3 / AC-6",
            "cis": "CIS v8 Control 6 - Access Control Management",
        },
        "Network Filtering": {
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-16",
            "class": "Configuration",
            "iso": "ISO 27001 A.8.20 Network security",
            "nist": "NIST SC-7 / CM-7",
            "cis": "CIS v8 Control 12 - Network Infrastructure Management",
        },
        "Data Exposure": {
            "owasp": "A01:2021 - Broken Access Control",
            "cwe": "CWE-200",
            "class": "Exposure of Sensitive Information",
            "iso": "ISO 27001 A.5.12 Classification of information",
            "nist": "NIST PR.DS-1 / PR.DS-5",
            "cis": "CIS v8 Control 3 - Data Protection",
        },
        "Software Patching": {
            "owasp": "A06:2021 - Vulnerable and Outdated Components",
            "cwe": "CWE-1104",
            "class": "Use of Unmaintained Third Party Components",
            "iso": "ISO 27001 A.8.8 Management of technical vulnerabilities",
            "nist": "NIST SI-2 / RA-5",
            "cis": "CIS v8 Control 7 - Continuous Vulnerability Management",
        },
        "DNS Security": {
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-346",
            "class": "Origin Validation Error",
            "iso": "ISO 27001 A.8.20 Network security",
            "nist": "NIST SC-20 / SC-21",
            "cis": "CIS v8 Control 12 - Network Infrastructure Management",
        },
        "System Hosting": {
            "owasp": "A05:2021 - Security Misconfiguration",
            "cwe": "CWE-16",
            "class": "Configuration",
            "iso": "ISO 27001 A.8.9 Configuration management",
            "nist": "NIST CM-2 / CM-6",
            "cis": "CIS v8 Control 4 - Secure Configuration",
        },
    }

    base = mapping.get(cat, mapping["Application Security"]).copy()

    if any(token in blob for token in ["xss", "cross-site scripting"]):
        base.update(
            {
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-79",
                "class": "Improper Neutralization of Input During Web Page Generation",
            }
        )
    elif any(token in blob for token in ["sql", "sqli", "injection"]):
        base.update(
            {
                "owasp": "A03:2021 - Injection",
                "cwe": "CWE-89",
                "class": "Improper Input Neutralization",
            }
        )

    return base


def _technical_recommendation(category: str, title: str, severity: str) -> dict[str, object]:
    sev = str(severity or "low").lower()
    cat = str(category or "Application Security")
    title_blob = str(title or "").lower()

    required_fix = "Aplicar correção definitiva no componente afetado e validar com reteste técnico orientado por evidência."
    controls = [
        "Validar entrada por allowlist e normalização estrita",
        "Aplicar princípio de privilégio mínimo",
        "Adicionar teste automatizado de segurança no pipeline",
    ]

    if cat == "Application Security":
        if "sql" in title_blob or "injection" in title_blob:
            required_fix = "Substituir concatenação dinâmica por consultas parametrizadas (prepared statements) em 100% dos pontos de entrada."
            controls = [
                "Prepared Statements / Parameter Binding",
                "ORM com queries parametrizadas e revisão de queries legadas",
                "Validação de entrada por tipo/regex e bloqueio de payload malicioso",
                "Conta de banco com privilégio mínimo e segregação de funções",
            ]
        elif "xss" in title_blob:
            required_fix = "Neutralizar saída no contexto correto (HTML/JS/URL) e bloquear execução de script não confiável."
            controls = [
                "Output encoding contextual",
                "Content-Security-Policy restritiva",
                "Sanitização server-side de campos ricos",
                "Cookies com HttpOnly/Secure/SameSite",
            ]
    elif cat == "Web Encryption":
        required_fix = "Desabilitar protocolos/ciphers legados e forçar TLS forte com cadeias válidas e renovação automatizada."
        controls = [
            "Desabilitar TLS 1.0/1.1 e ciphers fracos",
            "HSTS com includeSubDomains quando aplicável",
            "Rotação e monitoramento de certificados",
        ]
    elif cat == "Network Filtering":
        required_fix = "Restringir exposição de portas/serviços externamente e aplicar política de deny-by-default na borda."
        controls = [
            "Firewall/ACL por origem e serviço",
            "Segmentação por ambiente e função",
            "Bloqueio de administração remota fora de rede autorizada",
        ]

    if sev in {"critical", "high"}:
        validation_window = "Retestar em até 24h após correção e validar ausência de regressão funcional e de segurança."
    elif sev == "medium":
        validation_window = "Retestar na mesma sprint e confirmar mitigação em ambiente homologado e produção."
    else:
        validation_window = "Retestar no próximo ciclo e monitorar recorrência no baseline."

    validations = [
        "Executar reteste com a mesma ferramenta e payload da evidência",
        "Validar resposta HTTP e comportamento de negócio esperado",
        validation_window,
    ]

    return {
        "required_fix": required_fix,
        "controls": controls,
        "validations": validations,
    }


def _extract_technical_details(details: dict, default_target: str) -> dict[str, str]:
    details = details if isinstance(details, dict) else {}
    nested = details.get("details") if isinstance(details.get("details"), dict) else {}

    full_url = _pick_first_text(details, ["url", "full_url", "endpoint", "target", "asset"])
    if not full_url:
        full_url = _pick_first_text(nested, ["url", "full_url", "endpoint", "target", "asset"])
    if not full_url:
        full_url = _sanitize_text(default_target)

    exploit = _pick_first_text(details, ["exploit", "exploit_url", "exploitdb", "exploitdb_url", "poc"], preserve_linebreaks=True)
    if not exploit:
        exploit = _pick_first_text(nested, ["exploit", "exploit_url", "exploitdb", "exploitdb_url", "poc"], preserve_linebreaks=True)

    error = _pick_first_text(details, ["error", "stderr", "exception", "message", "http_error", "status_code"], preserve_linebreaks=True)
    if not error:
        error = _pick_first_text(nested, ["error", "stderr", "exception", "message", "http_error", "status_code"], preserve_linebreaks=True)

    evidence = _pick_first_text(details, ["evidence", "stdout", "output", "matched", "matched_at", "response", "banner"], preserve_linebreaks=True)
    if not evidence:
        evidence = _pick_first_text(nested, ["evidence", "stdout", "output", "matched", "matched_at", "response", "banner"], preserve_linebreaks=True)

    payload = _pick_first_text(
        details,
        [
            "payload",
            "request",
            "request_raw",
            "curl",
            "command",
            "cmd",
            "template_id",
            "matcher_name",
            "proof",
        ],
        preserve_linebreaks=True,
    )
    if not payload:
        payload = _pick_first_text(
            nested,
            [
                "payload",
                "request",
                "request_raw",
                "curl",
                "command",
                "cmd",
                "template_id",
                "matcher_name",
                "proof",
            ],
            preserve_linebreaks=True,
        )

    if not payload and nested:
        try:
            payload = _sanitize_multiline_text(json.dumps(nested, ensure_ascii=False, indent=2))
        except Exception:
            payload = ""

    step = _pick_first_text(details, ["step"])
    if not step:
        step = _pick_first_text(nested, ["step"])

    node = _pick_first_text(details, ["node", "source_worker"])
    if not node:
        node = _pick_first_text(nested, ["node", "source_worker"])

    asset = _pick_first_text(details, ["asset", "target"])
    if not asset:
        asset = _pick_first_text(nested, ["asset", "target"])

    port = details.get("port")
    if port in [None, ""]:
        port = nested.get("port")
    port_text = str(port) if port not in [None, ""] else ""

    service = _pick_first_text(details, ["service", "protocol"])
    if not service:
        service = _pick_first_text(nested, ["service", "protocol"])

    version = _pick_first_text(details, ["version", "banner"])
    if not version:
        version = _pick_first_text(nested, ["version", "banner"])

    tool = _pick_first_text(details, ["tool"])
    if not tool:
        tool = _pick_first_text(nested, ["tool"])

    command = _pick_first_text(details, ["command", "cmd"])
    if not command:
        command = _pick_first_text(nested, ["command", "cmd"])

    open_ports = details.get("open_ports")
    if open_ports in [None, ""]:
        open_ports = nested.get("open_ports")
    open_ports_text = ""
    if isinstance(open_ports, list):
        parsed_ports: list[str] = []
        for raw in open_ports:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                parsed_ports.append(str(port))
        if parsed_ports:
            open_ports_text = ",".join(parsed_ports[:50])

    if not evidence and open_ports_text:
        evidence = f"open_ports={open_ports_text}"

    if not payload and command:
        payload = command

    method, endpoint = _extract_method_and_endpoint(full_url, payload, evidence, command)
    parameter = _extract_parameter_name(payload, evidence, " ".join([details.get("title") or "", details.get("name") or ""]))
    response_http = _extract_http_response_status(evidence)

    response_application = ""
    if evidence:
        response_application = evidence[:1200]

    observed_behavior = _sanitize_text(evidence.splitlines()[0] if evidence else "")
    expected_behavior = "Retornar bloqueio/erro seguro para a entrada maliciosa e manter fluxo de negócio íntegro."

    if "waf" in (tool or "").lower() or "cloudflare" in (evidence or "").lower():
        expected_behavior = "WAF deve filtrar tráfego malicioso sem classificar indevidamente serviço de borda como vulnerabilidade da aplicação."
        observed_behavior = observed_behavior or "Comportamento de borda/proxy identificado no tráfego analisado."

    root_cause = "Entrada e/ou configuração de segurança sem controle defensivo suficiente para o vetor observado."
    if "sql" in (payload + " " + evidence).lower():
        root_cause = "Possível concatenação de input não confiável em consulta SQL ou validação insuficiente de entrada."
    elif "xss" in (payload + " " + evidence).lower():
        root_cause = "Possível falta de neutralização/encoding contextual de saída para conteúdo controlado por usuário."
    elif "tls" in (payload + " " + evidence).lower() or "ssl" in (payload + " " + evidence).lower():
        root_cause = "Configuração criptográfica legada ou inconsistente com baseline de segurança."

    technical_validation = "Evidência coletada por ferramenta de segurança e correlacionada com contexto técnico do alvo."
    if response_http != "-":
        technical_validation = f"{technical_validation} Resposta observada: {response_http}."

    return {
        "full_url": full_url,
        "endpoint": endpoint,
        "http_method": method,
        "parameter": parameter,
        "exploit": exploit,
        "error": error,
        "evidence": evidence,
        "response_http": response_http,
        "response_application": response_application,
        "payload": payload,
        "attack_input": payload[:500] if payload else "-",
        "poc_request": payload[:1200] if payload else "-",
        "technical_validation": technical_validation,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior or "-",
        "root_cause": root_cause,
        "step": step,
        "node": node,
        "asset": asset,
        "port": port_text,
        "service": service,
        "version": version,
        "tool": tool,
        "command": command,
    }


def _infer_target_segment(target: str | None) -> str:
    raw = (target or "").strip().lower()
    if not raw:
        return "Digital Services"
    if any(token in raw for token in ["bank", "banco", "fin", "credit", "certificadora", "pag", "payment"]):
        return "Financial Services"
    if any(token in raw for token in ["health", "hospital", "saude", "clinic"]):
        return "Healthcare"
    if any(token in raw for token in ["gov", "gov.br", "prefeitura", "ministerio", "tribunal"]):
        return "Public Sector"
    if any(token in raw for token in ["edu", "school", "universidade", "faculdade"]):
        return "Education"
    if any(token in raw for token in ["shop", "store", "ecom", "market"]):
        return "Retail"
    return "Digital Services"


def _build_wef_benchmark(segment: str, fair_open_usd: float, severity_count: dict[str, int]) -> dict:
    base = {
        "Financial Services": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 7,
            "expected_external_exposure_index": 32,
            "expected_third_party_risk_index": 44,
            "expected_identity_attack_pressure": 68,
        },
        "Healthcare": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 10,
            "expected_external_exposure_index": 39,
            "expected_third_party_risk_index": 48,
            "expected_identity_attack_pressure": 57,
        },
        "Public Sector": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 12,
            "expected_external_exposure_index": 41,
            "expected_third_party_risk_index": 46,
            "expected_identity_attack_pressure": 52,
        },
        "Education": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 14,
            "expected_external_exposure_index": 47,
            "expected_third_party_risk_index": 49,
            "expected_identity_attack_pressure": 51,
        },
        "Retail": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 9,
            "expected_external_exposure_index": 43,
            "expected_third_party_risk_index": 55,
            "expected_identity_attack_pressure": 61,
        },
        "Digital Services": {
            "source": "WEF Global Cybersecurity Outlook (referencia setorial)",
            "expected_patch_sla_days": 10,
            "expected_external_exposure_index": 40,
            "expected_third_party_risk_index": 50,
            "expected_identity_attack_pressure": 58,
        },
    }
    segment_base = base.get(segment, base["Digital Services"])

    target_pressure = (
        int(severity_count.get("critical", 0)) * 20
        + int(severity_count.get("high", 0)) * 9
        + int(severity_count.get("medium", 0)) * 4
        + int(severity_count.get("low", 0)) * 1
    )
    target_exposure_index = min(100, max(0, target_pressure))

    return {
        "segment": segment,
        "source": segment_base["source"],
        "wef_reference_year": 2025,
        "target_external_exposure_index": target_exposure_index,
        "segment_external_exposure_index": int(segment_base["expected_external_exposure_index"]),
        "segment_identity_attack_pressure": int(segment_base["expected_identity_attack_pressure"]),
        "segment_third_party_risk_index": int(segment_base["expected_third_party_risk_index"]),
        "segment_patch_sla_days": int(segment_base["expected_patch_sla_days"]),
        "target_ale_open_usd": round(float(fair_open_usd or 0.0), 2),
        "assessment": (
            "acima_do_benchmark" if target_exposure_index > int(segment_base["expected_external_exposure_index"]) else "dentro_do_benchmark"
        ),
    }


def _build_target_evolution(db: Session, target_query: str, current_scan_id: int) -> dict:
    scans = (
        db.query(ScanJob)
        .filter(ScanJob.target_query == target_query)
        .order_by(ScanJob.created_at.asc(), ScanJob.id.asc())
        .all()
    )
    if not scans:
        return {"timeline": [], "recurring_findings": []}

    scan_ids = [s.id for s in scans]
    findings_all = db.query(Finding).filter(Finding.scan_job_id.in_(scan_ids), Finding.is_false_positive.is_(False)).all()
    by_scan: dict[int, list[Finding]] = {}
    for f in findings_all:
        by_scan.setdefault(f.scan_job_id, []).append(f)

    timeline: list[dict] = []
    previous_open: int | None = None
    for s in scans:
        findings_scan = by_scan.get(s.id, [])
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_scan:
            key = str(f.severity or "low").lower()
            if key in sev:
                sev[key] += 1
        open_count = len(findings_scan)
        delta_open = 0 if previous_open is None else open_count - previous_open
        previous_open = open_count
        timeline.append(
            {
                "scan_id": s.id,
                "created_at": s.created_at,
                "status": s.status,
                "mode": s.mode,
                "open_findings": open_count,
                "severity": sev,
                "delta_open_vs_previous": delta_open,
                "is_current": s.id == current_scan_id,
            }
        )

    recurring_map: dict[str, dict] = {}
    for s in scans:
        for f in by_scan.get(s.id, []):
            title = _normalize_finding_title(f.title)
            severity = str(f.severity or "low").lower()
            signature = f"{title.lower()}|{severity}"
            if signature not in recurring_map:
                recurring_map[signature] = {
                    "signature": signature,
                    "title": title,
                    "severity": severity,
                    "first_scan_id": s.id,
                    "last_scan_id": s.id,
                    "occurrences": 0,
                }
            recurring_map[signature]["occurrences"] += 1
            recurring_map[signature]["last_scan_id"] = s.id

    recurring = sorted(recurring_map.values(), key=lambda item: item.get("occurrences", 0), reverse=True)
    for row in recurring:
        if row["last_scan_id"] == current_scan_id and row["occurrences"] > 1:
            row["trend"] = "persisting"
        elif row["last_scan_id"] == current_scan_id and row["occurrences"] == 1:
            row["trend"] = "new"
        else:
            row["trend"] = "resolved_or_not_reproduced"

    return {
        "timeline": timeline,
        "recurring_findings": recurring[:40],
    }


CATEGORY_ORDER = [
    "Software Patching",
    "Application Security",
    "Web Encryption",
    "Network Filtering",
    "Authentication",
    "Authorization",
    "Data Exposure",
    "DNS Security",
    "System Hosting",
]


def _infer_category(title: str, details: dict) -> str:
    blob = " ".join(
        [
            str(title or ""),
            str(details.get("service") or ""),
            str(details.get("protocol") or ""),
            str(details.get("url") or details.get("target") or ""),
            str(details.get("error") or details.get("stderr") or ""),
            str(details.get("output") or ""),
        ]
    ).lower()

    if any(k in blob for k in ["tls", "ssl", "cipher", "https", "hsts", "certificate"]):
        return "Web Encryption"
    if any(k in blob for k in ["dns", "subdomain takeover", "subdomain", "cname", "ns ", "mx "]):
        return "DNS Security"
    if any(k in blob for k in ["auth", "login", "jwt", "token", "session", "password", "credential"]):
        return "Authentication"
    if any(k in blob for k in ["idor", "forbidden", "403", "access control", "authorization", "privilege"]):
        return "Authorization"
    if any(k in blob for k in ["open port", "nmap", "naabu", "firewall", "exposed service", "waf"]):
        return "Network Filtering"
    if any(k in blob for k in ["xss", "sqli", "sql", "ssti", "rce", "xxe", "csrf", "command injection", "template"]):
        return "Application Security"
    if any(k in blob for k in ["cve", "version", "outdated", "vuln", "patch", "upgrade"]):
        return "Software Patching"
    if any(k in blob for k in ["secret", "leak", "exposure", "directory listing", "bucket", "metadata"]):
        return "Data Exposure"
    if any(k in blob for k in ["hosting", "server", "docker", "kubernetes", "cloud", "misconfig"]):
        return "System Hosting"

    return "Application Security"


def _build_category_scores(rows: list[dict]) -> list[dict]:
    sev_weight = {"critical": 20, "high": 12, "medium": 7, "low": 3, "info": 1}
    aggregate: dict[str, dict[str, int]] = {category: {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_points": 0} for category in CATEGORY_ORDER}

    for row in rows:
        category = row.get("category") or "Application Security"
        sev = str(row.get("severity") or "low").lower()
        if category not in aggregate:
            aggregate[category] = {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_points": 0}
        aggregate[category]["findings"] += 1
        if sev in aggregate[category]:
            aggregate[category][sev] += 1
        aggregate[category]["risk_points"] += sev_weight.get(sev, 1)

    results: list[dict] = []
    for category in CATEGORY_ORDER:
        item = aggregate.get(category)
        if not item:
            continue
        score = max(0, 100 - min(95, int(item["risk_points"] * 3)))
        results.append({"category": category, "score": score, **item})
    return results


def _finding_signature(title: str, severity: str, target: str) -> str:
    return "|".join(
        [
            _sanitize_text(title).lower(),
            _sanitize_text(severity).lower(),
            _sanitize_text(target).lower(),
        ]
    )


def _source_group_from_details(details: dict) -> str:
    details = details if isinstance(details, dict) else {}
    nested = details.get("details") if isinstance(details.get("details"), dict) else {}

    node = str(details.get("node") or nested.get("node") or "").strip().lower()
    worker = str(details.get("source_worker") or nested.get("source_worker") or "").strip().lower()
    tool = str(details.get("tool") or nested.get("tool") or "").strip().lower()

    if node in {"recon", "scan", "fingerprint"} or worker in {"recon", "reconhecimento", "scan"}:
        return "recon"
    if node == "osint" or worker == "osint":
        return "osint"
    if node in {"vuln", "fuzzing", "api", "code_js"} or worker in {"analise_vulnerabilidade", "vuln"}:
        return "vuln"
    if tool in {"nuclei", "nikto", "sqlmap", "commix", "tplmap", "wapiti", "dalfox", "nmap-vulscan", "vulscan", "sslscan", "shcheck", "curl-headers", "wafw00f"}:
        return "vuln"
    return "other"


def _is_vulnerability_row(row: dict) -> bool:
    source_group = str(row.get("source_group") or "").strip().lower()
    severity = str(row.get("severity") or "low").strip().lower()
    if source_group == "vuln":
        return True
    if severity in {"critical", "high", "medium"}:
        return True
    return False


def _finding_lifecycle_signature(finding: Finding) -> str:
    details = finding.details or {}
    nested = details.get("details") if isinstance(details.get("details"), dict) else {}
    tool = _sanitize_text(details.get("tool") or nested.get("tool") or "")
    target = _sanitize_text(finding.scan_job.target_query if finding.scan_job else "")
    title = _sanitize_text(finding.title or "")
    cve = _sanitize_text(finding.cve or "")
    return "|".join([target.lower(), tool.lower(), title.lower(), cve.lower()])


def _build_finding_lifecycle_status_map(findings: list[Finding]) -> dict[int, str]:
    """
    Define status por ciclo de scans do mesmo target:
    - false_positive: marcado como FP
    - open: encontrado no scan posterior imediato (ou nao existe scan posterior)
    - closed: nao encontrado no scan posterior imediato
    """
    status_by_id: dict[int, str] = {}
    if not findings:
        return status_by_id

    scans_by_target: dict[str, list[ScanJob]] = {}
    findings_by_scan: dict[int, list[Finding]] = {}

    for finding in findings:
        if finding.is_false_positive:
            status_by_id[finding.id] = "false_positive"

        if not finding.scan_job:
            status_by_id.setdefault(finding.id, "open")
            continue

        target = str(finding.scan_job.target_query or "").strip().lower()
        if not target:
            status_by_id.setdefault(finding.id, "open")
            continue

        scans_by_target.setdefault(target, []).append(finding.scan_job)
        findings_by_scan.setdefault(finding.scan_job_id, []).append(finding)

    for target, scans in scans_by_target.items():
        unique_scans = {scan.id: scan for scan in scans}
        ordered_scans = sorted(
            unique_scans.values(),
            key=lambda s: ((s.created_at or datetime.min), s.id),
        )
        if not ordered_scans:
            continue

        signatures_by_scan: dict[int, set[str]] = {}
        for scan in ordered_scans:
            sigs: set[str] = set()
            for finding in findings_by_scan.get(scan.id, []):
                if finding.is_false_positive:
                    continue
                sigs.add(_finding_lifecycle_signature(finding))
            signatures_by_scan[scan.id] = sigs

        for idx, scan in enumerate(ordered_scans):
            next_scan = ordered_scans[idx + 1] if idx + 1 < len(ordered_scans) else None
            next_signatures = signatures_by_scan.get(next_scan.id, set()) if next_scan else set()

            for finding in findings_by_scan.get(scan.id, []):
                if finding.is_false_positive:
                    status_by_id[finding.id] = "false_positive"
                    continue

                if not next_scan:
                    status_by_id[finding.id] = "open"
                    continue

                current_sig = _finding_lifecycle_signature(finding)
                if current_sig in next_signatures:
                    status_by_id[finding.id] = "open"
                else:
                    status_by_id[finding.id] = "closed"

    return status_by_id


def _infer_asset_type(name: str) -> str:
    value = str(name or "").strip().lower()
    if not value:
        return "asset"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if "*" in value:
        return "wildcard"
    if value.replace(".", "").isdigit() and value.count(".") == 3:
        return "ip"
    if "." in value:
        return "domain"
    return "asset"


def _append_technology(counter: dict[str, int], value) -> None:
    if isinstance(value, str):
        name = value.strip()
        if len(name) >= 2:
            counter[name] = counter.get(name, 0) + 1
        return
    if isinstance(value, list):
        for item in value:
            _append_technology(counter, item)
        return
    if isinstance(value, dict):
        preferred_keys = [
            "name", "product", "technology", "tech", "server", "framework", "cms", "vendor",
            "technologies", "stack", "web_server", "x_powered_by",
        ]
        for key in preferred_keys:
            if key in value:
                _append_technology(counter, value[key])


def _collect_technologies(job: ScanJob, scan_findings: list[Finding]) -> dict[str, int]:
    counter: dict[str, int] = {}
    state = job.state_data or {}
    for key in ["technologies", "technology", "tech", "tech_stack", "stack", "fingerprint", "fingerprints"]:
        if key in state:
            _append_technology(counter, state.get(key))
    for finding in scan_findings:
        details = finding.details or {}
        for key in ["technologies", "technology", "tech", "tech_stack", "stack", "server", "web_server", "x_powered_by", "framework", "cms"]:
            if key in details:
                _append_technology(counter, details.get(key))
    return counter


@router.post("/scans", response_model=ScanResponse)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    access_group_id = payload.access_group_id
    if access_group_id is not None and not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        if access_group_id not in allowed_ids:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Grupo de acesso nao permitido")

    allowlist_ok = is_target_allowed(db, current_user.id, payload.target_query, "*")

    if not allowlist_ok:
        compliance_status = "blocked_policy"
    else:
        compliance_status = "approved"

    job = ScanJob(
        owner_id=current_user.id,
        access_group_id=access_group_id,
        target_query=payload.target_query,
        mode=payload.mode,
        status="queued" if compliance_status == "approved" else "blocked",
        compliance_status=compliance_status,
        authorization_id=None,
        current_step="1. Amass Subdomain Recon",
    )
    db.add(job)
    db.flush()
    log_audit(
        db,
        event_type="scan.created",
        message=f"Scan criado para alvo {payload.target_query}",
        actor_user_id=current_user.id,
        scan_job_id=job.id,
        metadata={"target": payload.target_query, "mode": payload.mode},
    )

    if compliance_status == "approved":
        log_audit(
            db,
            event_type="compliance.gate_pass",
            message="Gate de compliance aprovado para execucao",
            actor_user_id=current_user.id,
            scan_job_id=job.id,
            metadata={"target": payload.target_query, "mode": payload.mode},
        )
    else:
        log_audit(
            db,
            event_type="compliance.gate_block",
            message="Scan bloqueado pelo gate de compliance/policy",
            actor_user_id=current_user.id,
            scan_job_id=job.id,
            level="WARNING",
            metadata={"target": payload.target_query, "reason": compliance_status},
        )

    db.commit()
    db.refresh(job)

    if compliance_status == "approved":
        try:
            run_scan_job_unit.delay(job.id)
        except Exception as exc:
            log_audit(
                db,
                event_type="scan.queue_fallback",
                message="Fila indisponivel, executando scan unitario de forma imediata",
                actor_user_id=current_user.id,
                scan_job_id=job.id,
                level="WARNING",
                metadata={"error": str(exc)},
            )
            db.commit()
            run_scan_job(job.id)

    return ScanResponse(
        id=job.id,
        target_query=job.target_query,
        mode=job.mode,
        access_group_id=job.access_group_id,
        status=job.status,
        compliance_status=job.compliance_status,
        current_step=job.current_step,
        mission_progress=job.mission_progress,
        retry_attempt=job.retry_attempt,
        retry_max=job.retry_max,
        next_retry_at=job.next_retry_at,
        last_error=job.last_error,
        created_at=job.created_at,
    )


@router.get("/scans", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _reconcile_orphan_running_scans(db)
    query = _authorized_scan_query(db, current_user)
    rows = query.order_by(ScanJob.created_at.desc()).all()
    return [
        ScanResponse(
            id=s.id,
            target_query=s.target_query,
            mode=s.mode,
            access_group_id=s.access_group_id,
            status=s.status,
            compliance_status=s.compliance_status,
            current_step=s.current_step,
            mission_progress=s.mission_progress,
            retry_attempt=s.retry_attempt,
            retry_max=s.retry_max,
            next_retry_at=s.next_retry_at,
            last_error=s.last_error,
            created_at=s.created_at,
        )
        for s in rows
    ]


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status in {"queued", "running", "retrying"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido excluir scan em execucao")

    # Limpar referências de audit_events antes de deletar o scan
    db.query(AuditEvent).filter(AuditEvent.scan_job_id == scan_id).delete(synchronize_session=False)
    
    db.delete(job)
    log_audit(
        db,
        event_type="scan.deleted",
        message=f"Scan {scan_id} excluido",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id},
    )
    db.commit()
    return {"ok": True}


@router.post("/scans/reset-operational")
def reset_operational_scans(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    scan_rows = db.query(ScanJob.id, ScanJob.status).all()
    scan_ids = [row.id for row in scan_rows]
    active_scan_ids = [row.id for row in scan_rows if row.status in {"queued", "running", "retrying"}]

    revoked_task_ids: list[str] = []
    for scan_id in active_scan_ids:
        task_ids = _active_scan_task_ids(scan_id)
        for task_id in task_ids:
            try:
                celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
                revoked_task_ids.append(task_id)
            except Exception:
                continue

    try:
        # Limpa primeiro as referencias de workers para evitar violacao de FK em scan_jobs.
        db.query(WorkerHeartbeat).filter(WorkerHeartbeat.current_scan_id.is_not(None)).update(
            {
                WorkerHeartbeat.current_scan_id: None,
                WorkerHeartbeat.status: "idle",
                WorkerHeartbeat.last_task_name: None,
            },
            synchronize_session=False,
        )

        deleted_audit_events = db.query(AuditEvent).filter(AuditEvent.scan_job_id.is_not(None)).delete(synchronize_session=False)
        deleted_scan_logs = db.query(ScanLog).delete(synchronize_session=False)
        deleted_findings = db.query(Finding).delete(synchronize_session=False)
        deleted_scan_jobs = db.query(ScanJob).delete(synchronize_session=False)

        db.execute(text("ALTER SEQUENCE scan_jobs_id_seq RESTART WITH 1"))
        db.execute(text("ALTER SEQUENCE findings_id_seq RESTART WITH 1"))
        db.execute(text("ALTER SEQUENCE scan_logs_id_seq RESTART WITH 1"))

        log_audit(
            db,
            event_type="scan.reset_operational",
            message="Reset operacional executado: scans, findings e logs removidos",
            actor_user_id=current_user.id,
            metadata={
                "scan_ids": scan_ids,
                "revoked_task_ids": revoked_task_ids,
                "deleted": {
                    "scan_jobs": deleted_scan_jobs,
                    "findings": deleted_findings,
                    "scan_logs": deleted_scan_logs,
                    "audit_events": deleted_audit_events,
                },
            },
        )
        db.commit()

        return {
            "ok": True,
            "deleted": {
                "scan_jobs": deleted_scan_jobs,
                "findings": deleted_findings,
                "scan_logs": deleted_scan_logs,
                "audit_events": deleted_audit_events,
            },
            "revoked_task_ids": list(dict.fromkeys(revoked_task_ids)),
        }
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Falha ao executar reset operacional: {exc.__class__.__name__}") from exc


@router.post("/scans/{scan_id}/stop")
def stop_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status not in {"queued", "running", "retrying"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Somente scans em execucao/fila podem ser interrompidos")

    task_ids = _active_scan_task_ids(scan_id)
    for task_id in task_ids:
        try:
            celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
        except Exception:
            continue

    job.status = "stopped"
    job.current_step = "Scan interrompido manualmente"
    job.next_retry_at = None
    job.last_error = "Interrompido manualmente por administrador"
    db.add(
        ScanLog(
            scan_job_id=scan_id,
            source="manager",
            level="WARNING",
            message=f"Scan interrompido manualmente (task_ids={task_ids or ['nao_encontrada']})",
        )
    )
    log_audit(
        db,
        event_type="scan.stopped",
        message=f"Scan {scan_id} interrompido manualmente",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id, "task_ids": task_ids},
    )
    db.commit()
    return {"ok": True, "scan_id": scan_id, "revoked_task_ids": task_ids}


@router.delete("/scans/{scan_id}/report")
def delete_scan_report(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    job = _authorized_scan_query(db, current_user).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    if job.status in {"queued", "running", "retrying"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nao e permitido excluir relatorio de scan em execucao")

    findings_deleted = db.query(Finding).filter(Finding.scan_job_id == scan_id).delete(synchronize_session=False)
    job.state_data = {}
    job.mission_progress = 0
    job.current_step = "Relatorio removido"

    log_audit(
        db,
        event_type="scan.report_deleted",
        message=f"Relatorio do scan {scan_id} removido",
        actor_user_id=current_user.id,
        metadata={"scan_id": scan_id, "findings_deleted": findings_deleted},
    )
    db.commit()
    return {"ok": True, "findings_deleted": findings_deleted}


@router.get("/targets/summary")
def list_targets_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = _authorized_scan_query(db, current_user).order_by(ScanJob.created_at.desc()).all()
    findings = _authorized_finding_query(db, current_user).all()

    findings_by_scan: dict[int, list[Finding]] = {}
    for finding in findings:
        findings_by_scan.setdefault(finding.scan_job_id, []).append(finding)

    targets: dict[str, dict] = {}
    for scan in scans:
        key = str(scan.target_query)
        item = targets.get(key)
        if not item:
            item = {
                "target": key,
                "scans": 0,
                "last_status": scan.status,
                "last_mode": scan.mode,
                "last_scan_at": scan.created_at,
                "findings_total": 0,
                "findings_open": 0,
                "highest_severity": "low",
            }
            targets[key] = item

        item["scans"] += 1
        if scan.created_at and scan.created_at >= item["last_scan_at"]:
            item["last_status"] = scan.status
            item["last_mode"] = scan.mode
            item["last_scan_at"] = scan.created_at

        current_findings = findings_by_scan.get(scan.id, [])
        item["findings_total"] += len(current_findings)
        item["findings_open"] += len([f for f in current_findings if not f.is_false_positive])
        for finding in current_findings:
            sev = str(finding.severity or "low").lower()
            if _sev_weight(sev) > _sev_weight(item["highest_severity"]):
                item["highest_severity"] = sev

    rows = list(targets.values())
    rows.sort(key=lambda item: item["last_scan_at"] or datetime.min, reverse=True)
    return rows


@router.get("/assets")
def list_assets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scans = _authorized_scan_query(db, current_user).order_by(ScanJob.created_at.desc()).all()
    findings = _authorized_finding_query(db, current_user).all()

    findings_by_scan: dict[int, list[Finding]] = {}
    for finding in findings:
        findings_by_scan.setdefault(finding.scan_job_id, []).append(finding)

    assets_map: dict[str, dict] = {}
    for scan in scans:
        state = scan.state_data or {}
        raw_assets: list[str] = []
        raw_assets.extend(state.get("lista_ativos", []) or [])
        raw_assets.extend(state.get("discovered_assets", []) or [])
        raw_assets.extend(state.get("hosts", []) or [])
        raw_assets.append(scan.target_query)

        # Remove vazios e mantem apenas ativos unicos por scan.
        unique_scan_assets = {str(asset).strip() for asset in raw_assets if str(asset).strip()}
        scan_risk = "low"
        for finding in findings_by_scan.get(scan.id, []):
            sev = str(finding.severity or "low").lower()
            if _sev_weight(sev) > _sev_weight(scan_risk):
                scan_risk = sev

        for asset in unique_scan_assets:
            item = assets_map.get(asset)
            if not item:
                item = {
                    "name": asset,
                    "type": _infer_asset_type(asset),
                    "source_target": scan.target_query,
                    "last_seen_at": scan.created_at,
                    "risk": scan_risk,
                    "seen_in_scans": 0,
                }
                assets_map[asset] = item

            item["seen_in_scans"] += 1
            if scan.created_at and scan.created_at >= item["last_seen_at"]:
                item["last_seen_at"] = scan.created_at
                item["source_target"] = scan.target_query
            if _sev_weight(scan_risk) > _sev_weight(item["risk"]):
                item["risk"] = scan_risk

    rows = list(assets_map.values())
    rows.sort(key=lambda item: item["last_seen_at"] or datetime.min, reverse=True)
    return rows[:500]


@router.get("/findings")
def list_findings(
    severity: str | None = None,
    status_filter: str = "all",
    target: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    max_limit = max(1, min(limit, 1000))
    query = _authorized_finding_query(db, current_user)

    if severity:
        query = query.filter(Finding.severity == severity.lower())
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))

    lifecycle_query = _authorized_finding_query(db, current_user)
    if target:
        lifecycle_query = lifecycle_query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))
    lifecycle_rows = lifecycle_query.order_by(Finding.created_at.desc()).all()
    lifecycle_status = _build_finding_lifecycle_status_map(lifecycle_rows)

    rows = query.order_by(Finding.created_at.desc()).all()
    normalized_status = status_filter.strip().lower()
    if normalized_status in {"open", "closed", "false_positive"}:
        rows = [finding for finding in rows if lifecycle_status.get(finding.id, "open") == normalized_status]
    rows = rows[:max_limit]
    response = []
    for finding in rows:
        details = finding.details or {}
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        response.append(
            {
                "id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "target_query": finding.scan_job.target_query if finding.scan_job else None,
                "scan_status": finding.scan_job.status if finding.scan_job else None,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "is_false_positive": finding.is_false_positive,
                "retest_status": finding.retest_status,
                "cve": finding.cve,
                "lifecycle_status": lifecycle_status.get(finding.id, "open"),
                "details": details,
                "age": age,
                "fair": fair,
                "created_at": finding.created_at,
            }
        )
    return response


@router.get("/findings/page")
def list_findings_paginated(
    severity: str | None = None,
    status_filter: str = "all",
    target: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=50000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = _authorized_finding_query(db, current_user)

    if severity:
        query = query.filter(Finding.severity == severity.lower())
    if target:
        query = query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))

    lifecycle_query = _authorized_finding_query(db, current_user)
    if target:
        lifecycle_query = lifecycle_query.filter(ScanJob.target_query.ilike(f"%{target.strip()}%"))
    lifecycle_rows = lifecycle_query.order_by(Finding.created_at.desc()).all()
    lifecycle_status = _build_finding_lifecycle_status_map(lifecycle_rows)

    rows = query.order_by(Finding.created_at.desc()).all()
    normalized_status = status_filter.strip().lower()
    if normalized_status in {"open", "closed", "false_positive"}:
        rows = [finding for finding in rows if lifecycle_status.get(finding.id, "open") == normalized_status]

    total = len(rows)
    rows = rows[offset:offset + limit]

    items = []
    for finding in rows:
        details = finding.details or {}
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        items.append(
            {
                "id": finding.id,
                "scan_job_id": finding.scan_job_id,
                "target_query": finding.scan_job.target_query if finding.scan_job else None,
                "scan_status": finding.scan_job.status if finding.scan_job else None,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "is_false_positive": finding.is_false_positive,
                "retest_status": finding.retest_status,
                "cve": finding.cve,
                "lifecycle_status": lifecycle_status.get(finding.id, "open"),
                "details": details,
                "age": age,
                "fair": fair,
                "created_at": finding.created_at,
            }
        )

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/jobs/registry")
def jobs_registry(limit: int = 200, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    max_limit = max(1, min(limit, 1000))
    scans = _authorized_scan_query(db, current_user).order_by(ScanJob.created_at.desc()).limit(max_limit).all()
    findings = _authorized_finding_query(db, current_user).all()

    findings_count: dict[int, int] = {}
    for finding in findings:
        findings_count[finding.scan_job_id] = findings_count.get(finding.scan_job_id, 0) + 1

    rows = []
    for scan in scans:
        duration_seconds = None
        if scan.updated_at and scan.created_at:
            duration_seconds = int(max((scan.updated_at - scan.created_at).total_seconds(), 0))

        rows.append(
            {
                "id": scan.id,
                "target_query": scan.target_query,
                "mode": scan.mode,
                "status": scan.status,
                "compliance_status": scan.compliance_status,
                "current_step": scan.current_step,
                "mission_progress": scan.mission_progress,
                "retry_attempt": scan.retry_attempt,
                "retry_max": scan.retry_max,
                "last_error": scan.last_error,
                "findings_count": findings_count.get(scan.id, 0),
                "duration_seconds": duration_seconds,
                "created_at": scan.created_at,
                "updated_at": scan.updated_at,
            }
        )

    return rows


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
def scan_status(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    state_data = job.state_data or {}
    return ScanStatusResponse(
        id=job.id,
        status=job.status,
        compliance_status=job.compliance_status,
        current_step=job.current_step,
        mission_progress=job.mission_progress,
        discovered_ports=state_data.get("discovered_ports", []),
        pending_port_tests=state_data.get("pending_port_tests", []),
        retry_attempt=job.retry_attempt,
        retry_max=job.retry_max,
        next_retry_at=job.next_retry_at,
        last_error=job.last_error,
    )


@router.get("/scans/{scan_id}/logs", response_model=list[LogResponse])
def scan_logs(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    logs = db.query(ScanLog).filter(ScanLog.scan_job_id == scan_id).order_by(ScanLog.created_at.asc()).all()
    return [
        LogResponse(
            id=l.id,
            source=l.source,
            level=l.level,
            message=l.message,
            created_at=l.created_at,
        )
        for l in logs
    ]


@router.get("/scans/{scan_id}/report", response_model=ReportResponse)
def scan_report(
    scan_id: int,
    prioritized_limit: int = Query(default=10, ge=1, le=100),
    prioritized_offset: int = Query(default=0, ge=0, le=10000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanJob).filter(ScanJob.id == scan_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    job = query.first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan nao encontrado")

    findings = db.query(Finding).filter(Finding.scan_job_id == scan_id).all()
    scan_logs = db.query(ScanLog).filter(ScanLog.scan_job_id == scan_id).order_by(ScanLog.created_at.asc()).all()
    previous_scan = (
        db.query(ScanJob)
        .filter(
            ScanJob.target_query == job.target_query,
            ScanJob.id < scan_id,
            ScanJob.status == "completed",
        )
        .order_by(ScanJob.id.desc())
        .first()
    )
    previous_findings = []
    if previous_scan:
        previous_findings = db.query(Finding).filter(Finding.scan_job_id == previous_scan.id, Finding.is_false_positive.is_(False)).all()

    enriched_findings = []
    prioritized_actions = []
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    fair_ale_total_open = 0.0
    fair_ale_total_all = 0.0
    fair_score_samples: list[float] = []
    vulnerability_rows: list[dict] = []

    for finding in findings:
        details = finding.details or {}
        normalized_title = _normalize_finding_title(finding.title)
        recommendation_payload = _extract_recommendation_payload(details)
        technical = _extract_technical_details(details, job.target_query)
        category = _infer_category(normalized_title, details)
        sev = str(finding.severity or "low").lower()
        framework_ctx = _framework_context(category, normalized_title, details)
        recommendation_ctx = _technical_recommendation(category, normalized_title, sev)
        age = compute_age_metrics(finding.created_at, details)
        fair = compute_fair_metrics(finding.severity, finding.confidence_score, details, age)
        reasons = build_priority_reason(normalized_title, finding.severity, fair, age)

        if sev in severity_count:
            severity_count[sev] += 1

        ale_value = float(fair.get("annualized_loss_exposure_usd") or 0.0)
        fair_ale_total_all += ale_value
        fair_score_samples.append(float(fair.get("fair_score") or 0.0))

        target_value = technical.get("full_url") or _sanitize_text(details.get("url") or details.get("target") or job.target_query)
        report_id = f"F-{finding.id}"
        signature = _finding_signature(normalized_title, sev, target_value)
        vulnerability_rows.append(
            {
                "index": len(vulnerability_rows) + 1,
                "signature": signature,
            "id": report_id,
                "cve": _sanitize_text(finding.cve or ""),
                "target": target_value,
                "full_url": technical.get("full_url") or target_value,
            "endpoint": technical.get("endpoint") or "/",
            "http_method": technical.get("http_method") or "GET",
            "parameter": technical.get("parameter") or "-",
                "name": normalized_title,
                "problem": normalized_title,
                "service": _sanitize_text(technical.get("service") or "-"),
                "version": _sanitize_text(technical.get("version") or ""),
                "cvss": details.get("cvss_score") or details.get("cvss") or finding.risk_score or "-",
                "risk_text": _risk_text(sev, finding.confidence_score),
                "severity": sev,
                "category": category,
                "header_name": _sanitize_text(details.get("header_name") or ""),
                "header_issue": _sanitize_text(details.get("header_issue") or ""),
                "owasp": _sanitize_text(framework_ctx.get("owasp") or "-"),
                "cwe": _sanitize_text(framework_ctx.get("cwe") or "-"),
                "vuln_class": _sanitize_text(framework_ctx.get("class") or "-"),
                "nist_control": _sanitize_text(details.get("nist_control") or details.get("nist") or framework_ctx.get("nist") or "-"),
                "iso_control": _sanitize_text(details.get("iso_control") or details.get("iso27001") or framework_ctx.get("iso") or "-"),
                "cis_control": _sanitize_text(details.get("cis_control") or framework_ctx.get("cis") or "-"),
                "recommendation": _normalize_recommendation({**details, "severity": sev}),
                "recommendation_structured": recommendation_payload,
                "recommendation_required": _sanitize_multiline_text(str(recommendation_ctx.get("required_fix") or "")),
                "recommendation_controls": recommendation_ctx.get("controls") or [],
                "recommendation_validation": recommendation_ctx.get("validations") or [],
                "exploit": technical.get("exploit") or "-",
                "error": _sanitize_multiline_text(technical.get("error") or "-") or "-",
                "evidence": _sanitize_multiline_text(technical.get("evidence") or "-") or "-",
                "payload": _sanitize_multiline_text(technical.get("payload") or "-") or "-",
                "attack_input": _sanitize_multiline_text(technical.get("attack_input") or "-") or "-",
                "poc_request": _sanitize_multiline_text(technical.get("poc_request") or "-") or "-",
                "response_http": _sanitize_multiline_text(technical.get("response_http") or "-") or "-",
                "response_application": _sanitize_multiline_text(technical.get("response_application") or "-") or "-",
                "technical_validation": _sanitize_multiline_text(technical.get("technical_validation") or "-") or "-",
                "expected_behavior": _sanitize_multiline_text(technical.get("expected_behavior") or "-") or "-",
                "observed_behavior": _sanitize_multiline_text(technical.get("observed_behavior") or "-") or "-",
                "root_cause": _sanitize_multiline_text(technical.get("root_cause") or "-") or "-",
                "step": technical.get("step") or "-",
                "node": technical.get("node") or "-",
                "asset": technical.get("asset") or "-",
                "port": technical.get("port") or "-",
                "tool": technical.get("tool") or "-",
                "command": technical.get("command") or "-",
                "http_headers_raw": _sanitize_text(details.get("http_headers_raw") or ""),
                "technical_context": _sanitize_text(
                    f"step={technical.get('step') or '-'}; node={technical.get('node') or '-'}; tool={technical.get('tool') or '-'}; asset={technical.get('asset') or '-'}; porta={technical.get('port') or '-'}; servico={technical.get('service') or '-'}"
                ),
                "source_group": _source_group_from_details(details),
                "is_false_positive": bool(finding.is_false_positive),
            }
        )

        enriched_findings.append(
            {
                "id": finding.id,
                "title": normalized_title,
                "severity": finding.severity,
                "sn1per_priority": finding.sn1per_priority,
                "cve": finding.cve,
                "risk_score": finding.risk_score,
                "confidence_score": finding.confidence_score,
                "is_false_positive": finding.is_false_positive,
                "fp_notes": finding.fp_notes,
                "fp_reviewed_by_id": finding.fp_reviewed_by_id,
                "fp_reviewed_at": finding.fp_reviewed_at,
                "retest_status": finding.retest_status,
                "details": details,
                "age": age,
                "fair": fair,
            }
        )

        if not finding.is_false_positive:
            fair_ale_total_open += ale_value
            prioritized_actions.append(
                {
                    "finding_id": finding.id,
                    "title": normalized_title,
                    "severity": finding.severity,
                    "fair_score": fair["fair_score"],
                    "annualized_loss_exposure_usd": fair["annualized_loss_exposure_usd"],
                    "age": age,
                    "operational_reason": reasons["operational"],
                    "financial_reason": reasons["financial"],
                }
            )

    prioritized_actions.sort(key=lambda item: item.get("annualized_loss_exposure_usd", 0), reverse=True)

    paged_prioritized = prioritized_actions[prioritized_offset:prioritized_offset + prioritized_limit]

    open_rows = [row for row in vulnerability_rows if not row["is_false_positive"]]
    open_vulnerability_table = [row for row in open_rows if _is_vulnerability_row(row)]
    open_recon_table = [row for row in open_rows if str(row.get("source_group") or "") == "recon"]
    open_osint_table = [row for row in open_rows if str(row.get("source_group") or "") == "osint"]

    severity_count_vuln = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in open_vulnerability_table:
        sev = str(row.get("severity") or "low").lower()
        if sev in severity_count_vuln:
            severity_count_vuln[sev] += 1

    score = max(
        0,
        min(
            100,
            100
            - (
                severity_count_vuln["critical"] * 30
                + severity_count_vuln["high"] * 15
                + severity_count_vuln["medium"] * 8
                + severity_count_vuln["low"] * 2
            ),
        ),
    )
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    fair_total = _compute_fair_summary(findings, enriched_findings, fair_ale_total_open, fair_ale_total_all)

    frameworks = _compute_framework_scores(open_vulnerability_table)

    prev_signatures: set[str] = set()
    resolved_vulnerabilities: list[dict] = []
    for prev in previous_findings:
        prev_details = prev.details or {}
        prev_target = _sanitize_text(prev_details.get("url") or prev_details.get("target") or job.target_query)
        prev_signature = _finding_signature(_normalize_finding_title(prev.title), str(prev.severity or "low"), prev_target)
        prev_signatures.add(prev_signature)

    curr_signatures = {row["signature"] for row in open_vulnerability_table}
    for prev in previous_findings:
        prev_details = prev.details or {}
        prev_title = _normalize_finding_title(prev.title)
        prev_sev = str(prev.severity or "low").lower()
        prev_target = _sanitize_text(prev_details.get("url") or prev_details.get("target") or job.target_query)
        prev_signature = _finding_signature(prev_title, prev_sev, prev_target)
        if prev_signature not in curr_signatures:
            resolved_vulnerabilities.append(
                {
                    "id": _sanitize_text(prev.cve or f"F-{prev.id}"),
                    "target": prev_target,
                    "name": prev_title,
                    "severity": prev_sev,
                    "status": "corrected",
                    "correction_note": "Vulnerabilidade nao reapareceu no scan mais recente do mesmo alvo.",
                }
            )

    for row in open_vulnerability_table:
        row["status"] = "open" if row["signature"] in prev_signatures else "new"
        row.pop("signature", None)

    open_vulnerability_table.sort(
        key=lambda item: (
            -_severity_rank(str(item.get("severity") or "low")),
            -int(item.get("risk_score") or 0),
            str(item.get("name") or ""),
        )
    )

    waf_vendors: dict[str, int] = {}
    waf_assets: set[str] = set()
    waf_findings_count = 0

    security_header_missing: dict[str, int] = {}
    security_header_present: dict[str, int] = {}
    security_header_assets: set[str] = set()
    security_header_samples: list[dict[str, str]] = []
    security_header_sample_keys: set[str] = set()
    security_header_findings_count = 0
    header_pattern = re.compile(
        r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection)",
        re.IGNORECASE,
    )

    for row in open_vulnerability_table:
        tool = str(row.get("tool") or "").strip().lower()
        title = str(row.get("name") or row.get("problem") or "")
        evidence = str(row.get("evidence") or "")
        blob = f"{title}\n{evidence}".lower()
        target = str(row.get("target") or "").strip()

        if tool == "wafw00f" or "waf" in blob:
            waf_findings_count += 1
            if target:
                waf_assets.add(target)
            vendor_match = re.search(r"behind\s+(.+?)\s+waf", f"{title} {evidence}", re.IGNORECASE)
            parsed_vendor = str(vendor_match.group(1) or "").strip() if vendor_match else ""
            vendor = _detect_waf_vendor(f"{parsed_vendor} {title} {evidence}") or parsed_vendor or "WAF nao identificado"
            waf_vendors[vendor] = int(waf_vendors.get(vendor, 0)) + 1

        if tool in {"shcheck", "curl-headers"} or any(tok in blob for tok in ["header", "hsts", "content-security-policy", "x-frame-options", "x-content-type-options"]):
            explicit_header = str(row.get("header_name") or "").strip().lower()
            explicit_issue = str(row.get("header_issue") or "").strip().lower()
            raw_http_headers = str(row.get("http_headers_raw") or "").strip()
            matched_headers = header_pattern.findall(f"{title}\n{evidence}")
            candidate_headers = [explicit_header] if explicit_header else [str(h or "").strip().lower() for h in matched_headers]
            if candidate_headers:
                security_header_findings_count += 1
                if target:
                    security_header_assets.add(target)
            if tool == "curl-headers" and raw_http_headers:
                sample_key = f"{target}|{raw_http_headers[:120]}"
                if sample_key not in security_header_sample_keys:
                    security_header_sample_keys.add(sample_key)
                    security_header_samples.append(
                        {
                            "target": target or "-",
                            "raw": raw_http_headers[:1200],
                        }
                    )
            for normalized_header in candidate_headers:
                if not normalized_header:
                    continue
                if explicit_issue == "present":
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1
                elif explicit_issue == "missing":
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                elif "ausente" in blob or "missing" in blob or "not set" in blob:
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                else:
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1

    category_scores = _build_category_scores(open_vulnerability_table)

    # Fallback de evidencias para linhas sem payload/evidence explicitos.
    execution_lines: list[str] = []
    for log in scan_logs:
        message = _sanitize_text(log.message)
        if not message:
            continue
        lower = message.lower()
        if any(token in lower for token in ["cmd", "return_code", "stderr", "stdout", "error", "execut"]):
            execution_lines.append(message)
        if len(execution_lines) >= 30:
            break

    if execution_lines:
        fallback_payload = " | ".join(execution_lines[:5])
        for row in open_vulnerability_table:
            if row.get("payload") in [None, "", "-"]:
                row["payload"] = fallback_payload
            if row.get("evidence") in [None, "", "-"]:
                row["evidence"] = fallback_payload

    detailed_recommendations = [
        {
            "id": row["id"],
            "cve": row.get("cve") or "",
            "name": row["name"],
            "problem": row.get("problem") or row["name"],
            "category": row.get("category") or "Application Security",
            "severity": row["severity"],
            "target": row["target"],
            "technical": {
                "exploit": row.get("exploit") or "-",
                "error": row.get("error") or "-",
                "evidence": row.get("evidence") or "-",
                "payload": row.get("payload") or "-",
                "step": row.get("step") or "-",
                "node": row.get("node") or "-",
                "port": row.get("port") or "-",
            },
            "recommendation": row["recommendation"],
            "recommendation_structured": row.get("recommendation_structured") or {},
        }
        for row in open_vulnerability_table[:120]
    ]
    top_recommendations = _build_top_recommendations(open_vulnerability_table, detailed_recommendations)

    lifecycle = {
        "open": len([r for r in open_vulnerability_table if r.get("status") == "open"]),
        "new": len([r for r in open_vulnerability_table if r.get("status") == "new"]),
        "corrected": len(resolved_vulnerabilities),
    }
    triaged_vulnerability_count = len([row for row in vulnerability_rows if row.get("is_false_positive") and _is_vulnerability_row(row)])

    summary_data = {
        "total": len(open_vulnerability_table),
        "total_raw": len(findings),
        "critical": severity_count_vuln["critical"],
        "high": severity_count_vuln["high"],
        "medium": severity_count_vuln["medium"],
        "low": severity_count_vuln["low"],
        "info": severity_count_vuln["info"],
        "open": len(open_vulnerability_table),
        "triaged": triaged_vulnerability_count,
    }
    strategic_points = _build_strategic_points(
        target=job.target_query,
        summary=summary_data,
        fair_total=fair_total,
        lifecycle=lifecycle,
        category_scores=category_scores,
    )
    technical_points = _build_technical_points(open_vulnerability_table, detailed_recommendations)

    segment = _infer_target_segment(job.target_query)
    benchmark = _build_wef_benchmark(segment, fair_ale_total_open, severity_count_vuln)
    target_evolution = _build_target_evolution(db, job.target_query, scan_id)

    return ReportResponse(
        scan_id=scan_id,
        status=job.status,
        findings=enriched_findings,
        state_data={
            **(job.state_data or {}),
            "report_v2": {
                "domain": job.target_query,
                "scan_type": "ASM_EXTERNAL",
                "risk_score": score,
                "grade": grade,
                "summary": summary_data,
                "fair": fair_total,
                "frameworks": frameworks,
                "category_scores": category_scores,
                "vulnerability_table": open_vulnerability_table,
                "recommendations": top_recommendations,
                "recommendations_detailed": detailed_recommendations,
                "strategic_points": strategic_points,
                "technical_points": technical_points,
                "segment_benchmark": benchmark,
                "target_evolution": target_evolution,
                "waf_summary": {
                    "findings_count": waf_findings_count,
                    "assets_count": len(waf_assets),
                    "assets": sorted(list(waf_assets))[:30],
                    "vendors": [
                        {"name": name, "count": count}
                        for name, count in sorted(waf_vendors.items(), key=lambda item: item[1], reverse=True)
                    ][:10],
                },
                "security_headers_summary": {
                    "findings_count": security_header_findings_count,
                    "assets_count": len(security_header_assets),
                    "assets": sorted(list(security_header_assets))[:30],
                    "present_headers": [
                        {"header": name, "count": count}
                        for name, count in sorted(security_header_present.items(), key=lambda item: item[1], reverse=True)
                    ][:20],
                    "missing_headers": [
                        {"header": name, "count": count}
                        for name, count in sorted(security_header_missing.items(), key=lambda item: item[1], reverse=True)
                    ][:20],
                    "samples": security_header_samples[:5],
                    "owasp_top10_alignment": [
                        {
                            "owasp": "A05 Security Misconfiguration",
                            "coverage": "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy e Permissions-Policy reduzem superfície de configuração insegura.",
                        },
                        {
                            "owasp": "A03 Injection",
                            "coverage": "CSP restringe execução de scripts e reduz impacto de XSS/injeções no browser.",
                        },
                    ],
                },
                "coverage_summary": {
                    "vulnerability_findings": len(open_vulnerability_table),
                    "recon_findings": len(open_recon_table),
                    "osint_findings": len(open_osint_table),
                },
                "recon_findings": open_recon_table[:60],
                "osint_findings": open_osint_table[:60],
                "lifecycle": lifecycle,
                "resolved_vulnerabilities": resolved_vulnerabilities,
                "comparison": {
                    "current_scan_id": scan_id,
                    "previous_scan_id": previous_scan.id if previous_scan else None,
                },
            },
            "prioritized_actions": paged_prioritized,
            "prioritized_actions_page": {
                "items": paged_prioritized,
                "total": len(prioritized_actions),
                "limit": prioritized_limit,
                "offset": prioritized_offset,
            },
        },
    )


@router.get("/scans/{scan_id}/report.csv")
def scan_report_csv(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report = scan_report(
        scan_id=scan_id,
        prioritized_limit=100,
        prioritized_offset=0,
        db=db,
        current_user=current_user,
    )

    report_v2 = (report.state_data or {}).get("report_v2") or {}
    rows = report_v2.get("vulnerability_table") or []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "index",
            "id",
            "cve",
            "target",
            "problem",
            "service",
            "version",
            "severity",
            "category",
            "cvss",
            "status",
            "exploit",
            "error",
            "evidence",
            "payload",
            "step",
            "node",
            "recommendation",
            "priority",
            "mitigations",
            "validations",
        ]
    )

    for row in rows:
        rec = row.get("recommendation_structured") or {}
        mitigations = rec.get("mitigacoes") if isinstance(rec, dict) else []
        validations = rec.get("validacoes") if isinstance(rec, dict) else []
        writer.writerow(
            [
                row.get("index"),
                row.get("id") or "",
                row.get("cve") or "",
                row.get("target") or "",
                row.get("problem") or row.get("name") or "",
                row.get("service") or "",
                row.get("version") or "",
                row.get("severity") or "",
                row.get("category") or "",
                row.get("cvss") or "",
                row.get("status") or "",
                row.get("exploit") or "",
                row.get("error") or "",
                row.get("evidence") or "",
                row.get("payload") or "",
                row.get("step") or "",
                row.get("node") or "",
                row.get("recommendation") or "",
                rec.get("prioridade") if isinstance(rec, dict) else "",
                "; ".join(str(item) for item in mitigations) if isinstance(mitigations, list) else "",
                "; ".join(str(item) for item in validations) if isinstance(validations, list) else "",
            ]
        )

    csv_text = output.getvalue()
    filename = f"scan_{scan_id}_report.csv"
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/findings/{finding_id}/false-positive")
def mark_false_positive(
    finding_id: int,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Marca ou desmarca um finding como falso positivo.

    Payload opcional:
      - is_false_positive (bool, default true)  — permite toggle (desmarcar FP)
      - fp_notes (str)                           — justificativa obrigatória na prática
    """
    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id).filter(Finding.id == finding_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    finding = query.first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding nao encontrado")

    body = payload or {}
    new_fp_value = bool(body.get("is_false_positive", True))
    fp_notes = (body.get("fp_notes") or "").strip() or None

    finding.is_false_positive = new_fp_value
    finding.fp_notes = fp_notes
    finding.fp_reviewed_by_id = current_user.id
    finding.fp_reviewed_at = datetime.now(timezone.utc)
    # Ao marcar como FP, limpa retest pendente (o finding foi validado pelo analista)
    if new_fp_value:
        finding.retest_status = None

    if new_fp_value:
        # Persiste na memória vetorial para prevenir reincidência
        signature = f"{finding.title}|{finding.severity}|{finding.details}"
        vector_id = f"fp-{finding.id}"
        vector_store.add_false_positive(vector_id, signature, {"finding_id": finding.id})
        fp_mem = FalsePositiveMemory(
            finding_id=finding.id,
            signature=signature,
            embedding_ref=vector_id,
            memory_metadata={"severity": finding.severity, "fp_notes": fp_notes},
        )
        db.add(fp_mem)
    else:
        # Desmarcando FP: remove da memória vetorial se existir
        try:
            vector_store.remove_false_positive(f"fp-{finding.id}")
        except Exception:
            pass

    log_audit(
        db,
        event_type="finding.false_positive_updated",
        message=f"Finding #{finding.id} marcado como FP={new_fp_value} por {current_user.email}",
        actor_user_id=current_user.id,
        metadata={
            "finding_id": finding.id,
            "is_false_positive": new_fp_value,
            "fp_notes": fp_notes,
        },
    )
    db.commit()
    return {"ok": True, "is_false_positive": new_fp_value}


@router.post("/findings/{finding_id}/retest")
def request_retest(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Solicita retest de um finding (ex: após patch aplicado ou FP questionado).
    Define retest_status='pending_retest' e remove is_false_positive.
    O worker, ao encontrar este status, re-executa a verificação do finding.
    """
    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id).filter(Finding.id == finding_id)
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    finding = query.first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding nao encontrado")

    finding.retest_status = "pending_retest"
    finding.is_false_positive = False
    finding.fp_notes = None
    finding.fp_reviewed_by_id = current_user.id
    finding.fp_reviewed_at = datetime.now(timezone.utc)

    log_audit(
        db,
        event_type="finding.retest_requested",
        message=f"Retest solicitado para finding #{finding.id} por {current_user.email}",
        actor_user_id=current_user.id,
        metadata={"finding_id": finding.id},
    )
    db.commit()
    return {"ok": True, "retest_status": "pending_retest"}


@router.post("/findings/bulk-false-positive")
def bulk_mark_false_positive(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Marca/desmarca múltiplos findings como falso positivo em uma única operação.

    Payload: { "finding_ids": [1,2,3], "is_false_positive": true, "fp_notes": "..." }
    """
    finding_ids: list[int] = payload.get("finding_ids") or []
    if not finding_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="finding_ids nao pode ser vazio")
    new_fp_value = bool(payload.get("is_false_positive", True))
    fp_notes = (payload.get("fp_notes") or "").strip() or None

    query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id).filter(Finding.id.in_(finding_ids))
    if not current_user.is_admin:
        allowed_ids = [g.id for g in current_user.groups]
        query = query.filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
    findings = query.all()

    updated_ids = []
    for finding in findings:
        finding.is_false_positive = new_fp_value
        finding.fp_notes = fp_notes
        finding.fp_reviewed_by_id = current_user.id
        finding.fp_reviewed_at = datetime.now(timezone.utc)
        if new_fp_value:
            finding.retest_status = None
            signature = f"{finding.title}|{finding.severity}|{finding.details}"
            vector_id = f"fp-{finding.id}"
            vector_store.add_false_positive(vector_id, signature, {"finding_id": finding.id})
            db.add(FalsePositiveMemory(
                finding_id=finding.id,
                signature=signature,
                embedding_ref=vector_id,
                memory_metadata={"severity": finding.severity, "fp_notes": fp_notes},
            ))
        updated_ids.append(finding.id)

    log_audit(
        db,
        event_type="finding.bulk_false_positive",
        message=f"{len(updated_ids)} findings marcados como FP={new_fp_value} por {current_user.email}",
        actor_user_id=current_user.id,
        metadata={"finding_ids": updated_ids, "is_false_positive": new_fp_value, "fp_notes": fp_notes},
    )
    db.commit()
    return {"ok": True, "updated": len(updated_ids), "ids": updated_ids}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.is_admin:
        jobs = db.query(ScanJob).all()
        findings = db.query(Finding).all()
    else:
        allowed_ids = [g.id for g in current_user.groups]
        jobs = db.query(ScanJob).filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids))).all()
        findings = (
            db.query(Finding)
            .join(ScanJob, ScanJob.id == Finding.scan_job_id)
            .filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
            .all()
        )

    total = len(findings)
    mitigated = len([f for f in findings if f.is_false_positive])
    open_issues = total - mitigated

    return {
        "stats": {
            "scans": len(jobs),
            "findings_total": total,
            "findings_open": open_issues,
            "findings_triaged": mitigated,
        },
        "frameworks": {
            "iso27001": {"score": max(0, 100 - open_issues)},
            "nist": {"score": max(0, 100 - int(open_issues * 0.8))},
            "cis_v8": {"score": max(0, 100 - int(open_issues * 0.7))},
            "pci": {"score": max(0, 100 - int(open_issues * 0.9))},
        },
    }


@router.get("/dashboard/insights")
def dashboard_insights(
    prioritized_limit: int = Query(default=10, ge=1, le=100),
    prioritized_offset: int = Query(default=0, ge=0, le=10000),
    target: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.is_admin:
        jobs_query = db.query(ScanJob)
        findings_query = db.query(Finding).join(ScanJob, ScanJob.id == Finding.scan_job_id)
    else:
        allowed_ids = [g.id for g in current_user.groups]
        jobs_query = db.query(ScanJob).filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
        findings_query = (
            db.query(Finding)
            .join(ScanJob, ScanJob.id == Finding.scan_job_id)
            .filter((ScanJob.owner_id == current_user.id) | (ScanJob.access_group_id.in_(allowed_ids)))
        )

    normalized_target = (target or "").strip()
    if normalized_target:
        jobs_query = jobs_query.filter(ScanJob.target_query.ilike(f"%{normalized_target}%"))
        findings_query = findings_query.filter(ScanJob.target_query.ilike(f"%{normalized_target}%"))

    jobs = jobs_query.order_by(ScanJob.created_at.desc()).all()
    findings = findings_query.all()

    findings_by_scan: dict[int, list[Finding]] = {}
    for f in findings:
        findings_by_scan.setdefault(f.scan_job_id, []).append(f)

    total = len(findings)
    mitigated = len([f for f in findings if f.is_false_positive])
    open_issues = total - mitigated

    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sev_count_vuln = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    waf_vendors: dict[str, int] = {}
    waf_assets: set[str] = set()
    security_header_missing: dict[str, int] = {}
    security_header_present: dict[str, int] = {}
    security_header_assets: set[str] = set()
    waf_findings_count = 0
    security_header_findings_count = 0
    header_pattern = re.compile(
        r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection)",
        re.IGNORECASE,
    )
    fair_total = 0.0
    ale_total = 0.0
    recon_findings_count = 0
    osint_findings_count = 0
    vulnerability_findings_count = 0
    age_env_samples: list[int] = []
    age_market_samples: list[int] = []
    age_exploit_samples: list[int] = []
    prioritized_actions: list[dict] = []
    vuln_counter: dict[tuple[str, str], int] = {}
    technologies_counter: dict[str, int] = {}
    for f in findings:
        sev = str(f.severity or "low").lower()
        if sev in sev_count:
            sev_count[sev] += 1

        details = f.details or {}
        nested_details = details.get("details") if isinstance(details.get("details"), dict) else {}
        source_group = _source_group_from_details(details)
        if source_group == "recon":
            recon_findings_count += 1
        elif source_group == "osint":
            osint_findings_count += 1
        elif source_group == "vuln" or sev in {"critical", "high", "medium"}:
            vulnerability_findings_count += 1
            if sev in sev_count_vuln:
                sev_count_vuln[sev] += 1

        key = (str(f.title or "Finding"), sev)
        vuln_counter[key] = vuln_counter.get(key, 0) + 1

        tool = str(details.get("tool") or nested_details.get("tool") or "").strip().lower()
        evidence_text = str(details.get("evidence") or nested_details.get("evidence") or "")
        title_blob = f"{f.title or ''}\n{evidence_text}".lower()
        if tool == "wafw00f" or "waf" in title_blob:
            waf_findings_count += 1
            target_query = str(f.scan_job.target_query or "").strip() if f.scan_job else ""
            if target_query:
                waf_assets.add(target_query)
            vendor_match = re.search(r"behind\s+(.+?)\s+waf", f"{f.title or ''} {evidence_text}", re.IGNORECASE)
            parsed_vendor = str(vendor_match.group(1) or "").strip() if vendor_match else ""
            vendor = _detect_waf_vendor(f"{parsed_vendor} {f.title or ''} {evidence_text}") or parsed_vendor or "WAF nao identificado"
            waf_vendors[vendor] = int(waf_vendors.get(vendor, 0)) + 1

        if tool in {"shcheck", "curl-headers"} or any(tok in title_blob for tok in ["header", "hsts", "content-security-policy", "x-frame-options", "x-content-type-options"]):
            header_name = str(details.get("header_name") or nested_details.get("header_name") or "").strip().lower()
            header_issue = str(details.get("header_issue") or nested_details.get("header_issue") or "").strip().lower()
            matched_headers = [header_name] if header_name else [str(h or "").strip().lower() for h in header_pattern.findall(f"{f.title or ''}\n{evidence_text}")]
            if matched_headers:
                security_header_findings_count += 1
                target_query = str(f.scan_job.target_query or "").strip() if f.scan_job else ""
                if target_query:
                    security_header_assets.add(target_query)
            for normalized_header in matched_headers:
                if not normalized_header:
                    continue
                if header_issue == "present":
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1
                elif header_issue == "missing":
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                elif "ausente" in title_blob or "missing" in title_blob or "not set" in title_blob:
                    security_header_missing[normalized_header] = int(security_header_missing.get(normalized_header, 0)) + 1
                else:
                    security_header_present[normalized_header] = int(security_header_present.get(normalized_header, 0)) + 1

        age = compute_age_metrics(f.created_at, details)
        fair = compute_fair_metrics(f.severity, f.confidence_score, details, age)
        fair_total += float(fair.get("fair_score") or 0.0)
        ale_total += float(fair.get("annualized_loss_exposure_usd") or 0.0)

        if age.get("known_in_environment_days") is not None:
            age_env_samples.append(int(age["known_in_environment_days"]))
        if age.get("known_in_market_days") is not None:
            age_market_samples.append(int(age["known_in_market_days"]))
        if age.get("exploit_published_days") is not None:
            age_exploit_samples.append(int(age["exploit_published_days"]))

        if not f.is_false_positive:
            reasons = build_priority_reason(f.title, f.severity, fair, age)
            prioritized_actions.append(
                {
                    "finding_id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "target_query": f.scan_job.target_query if f.scan_job else None,
                    "fair_score": fair["fair_score"],
                    "annualized_loss_exposure_usd": fair["annualized_loss_exposure_usd"],
                    "age": age,
                    "operational_reason": reasons["operational"],
                    "financial_reason": reasons["financial"],
                }
            )

    for job in jobs:
        techs = _collect_technologies(job, findings_by_scan.get(job.id, []))
        for name, count in techs.items():
            technologies_counter[name] = technologies_counter.get(name, 0) + count

    def _sev_weight(sev: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 1)

    asset_risk: dict[str, str] = {}
    for job in jobs:
        target = str(job.target_query)
        current = asset_risk.get(target, "low")
        for f in findings_by_scan.get(job.id, []):
            sev = str(f.severity or "low").lower()
            if _sev_weight(sev) > _sev_weight(current):
                current = sev
        asset_risk[target] = current

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=6)
    day_labels = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sab"]
    activity_map: dict[int, dict[str, int]] = {i: {"scans": 0, "findings": 0} for i in range(7)}
    for job in jobs:
        created = job.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created < cutoff:
            continue
        weekday = int(created.strftime("%w"))
        activity_map[weekday]["scans"] += 1
        activity_map[weekday]["findings"] += len(findings_by_scan.get(job.id, []))

    recent_scans = [
        {
            "id": j.id,
            "target_query": j.target_query,
            "status": j.status,
            "mode": j.mode,
            "mission_progress": j.mission_progress,
            "created_at": j.created_at,
            "findings": len(findings_by_scan.get(j.id, [])),
        }
        for j in jobs[:8]
    ]

    ongoing_scans = [
        {
            "id": j.id,
            "target_query": j.target_query,
            "status": j.status,
            "mode": j.mode,
            "current_step": j.current_step,
            "mission_progress": j.mission_progress,
            "created_at": j.created_at,
        }
        for j in jobs if j.status in {"queued", "running", "retrying"}
    ][:8]

    top_vulns = [
        {"title": title, "severity": severity, "count": count}
        for (title, severity), count in sorted(vuln_counter.items(), key=lambda item: item[1], reverse=True)[:7]
    ]

    top_technologies = [
        {"name": name, "count": count}
        for name, count in sorted(technologies_counter.items(), key=lambda item: item[1], reverse=True)[:10]
    ]

    assets = [
        {
            "name": target,
            "type": "wildcard" if "*." in target else ("domain" if "." in target else "asset"),
            "risk": risk,
        }
        for target, risk in list(asset_risk.items())[:12]
    ]

    activity = [
        {
            "day": day_labels[idx],
            "scans": activity_map[idx]["scans"],
            "findings": activity_map[idx]["findings"],
        }
        for idx in range(7)
    ]

    prioritized_actions.sort(key=lambda item: item.get("annualized_loss_exposure_usd", 0), reverse=True)

    def _avg(values: list[int]) -> float:
        return round(sum(values) / len(values), 2) if values else 0.0

    avg_fair = round(fair_total / max(len(findings), 1), 2)

    paged_prioritized = prioritized_actions[prioritized_offset:prioritized_offset + prioritized_limit]

    risk_points = (
        int(sev_count_vuln.get("critical", 0)) * 6
        + int(sev_count_vuln.get("high", 0)) * 4
        + int(sev_count_vuln.get("medium", 0)) * 2
        + int(sev_count_vuln.get("low", 0))
    )
    base_framework_score = max(55, min(100, int(round(100.0 / (1.0 + (risk_points / 55.0))))))

    return {
        "stats": {
            "scans": len(jobs),
            "findings_total": total,
            "findings_open": open_issues,
            "findings_triaged": mitigated,
            "critical": sev_count["critical"],
            "high": sev_count["high"],
            "medium": sev_count["medium"],
            "low": sev_count["low"],
            "fair_avg_score": avg_fair,
            "fair_ale_total_usd": round(ale_total, 2),
            "age_env_avg_days": _avg(age_env_samples),
            "age_market_avg_days": _avg(age_market_samples),
            "age_exploit_avg_days": _avg(age_exploit_samples),
            "waf_findings": waf_findings_count,
            "security_header_findings": security_header_findings_count,
            "recon_findings": recon_findings_count,
            "osint_findings": osint_findings_count,
            "vulnerability_findings": vulnerability_findings_count,
        },
        "frameworks": {
            "iso27001": {"score": base_framework_score},
            "nist": {"score": max(55, min(100, base_framework_score + 3))},
            "cis_v8": {"score": max(55, min(100, base_framework_score + 5))},
            "pci": {"score": max(55, min(100, base_framework_score - 2))},
        },
        "recent_scans": recent_scans,
        "ongoing_scans": ongoing_scans,
        "top_vulns": top_vulns,
        "top_technologies": top_technologies,
        "waf_summary": {
            "findings_count": waf_findings_count,
            "assets_count": len(waf_assets),
            "assets": sorted(list(waf_assets))[:30],
            "vendors": [
                {"name": name, "count": count}
                for name, count in sorted(waf_vendors.items(), key=lambda item: item[1], reverse=True)
            ][:10],
        },
        "security_headers_summary": {
            "findings_count": security_header_findings_count,
            "assets_count": len(security_header_assets),
            "assets": sorted(list(security_header_assets))[:30],
            "present_headers": [
                {"header": name, "count": count}
                for name, count in sorted(security_header_present.items(), key=lambda item: item[1], reverse=True)
            ][:20],
            "missing_headers": [
                {"header": name, "count": count}
                for name, count in sorted(security_header_missing.items(), key=lambda item: item[1], reverse=True)
            ][:20],
            "owasp_top10_alignment": [
                {
                    "owasp": "A05 Security Misconfiguration",
                    "coverage": "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy e Permissions-Policy reduzem superficie de configuracao insegura.",
                },
                {
                    "owasp": "A03 Injection",
                    "coverage": "CSP restringe execucao de scripts e reduz impacto de XSS/injecoes no browser.",
                },
            ],
        },
        "assets": assets,
        "activity": activity,
        "prioritized_actions": paged_prioritized,
        "filters": {"target": normalized_target},
        "targets": sorted(list({j.target_query for j in jobs if j.target_query})),
        "prioritized_actions_page": {
            "items": paged_prioritized,
            "total": len(prioritized_actions),
            "limit": prioritized_limit,
            "offset": prioritized_offset,
        },
    }
