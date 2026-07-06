from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import and_, case, func, or_, text
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
from app.services.offensive_operator_core import PHASE_CONTRACTS, PHASE_TOOL_BINDINGS, ToolCatalog


MODULE_TOOL_REQUIREMENTS: dict[str, set[str]] = {
    "recon": {
        "subfinder", "httpx", "naabu", "dnsx", "shuffledns", "alterx",
        "katana", "katana-js", "interactsh-client", "amass", "amass-brute",
        "amass-intel", "assetfinder", "waybackurls", "gau", "hakrawler",
        "gospider", "subjack", "massdns", "paramspider", "linkfinder",
    },
    "nuclei": {"nuclei"},
    "web": {"ffuf", "ffuf-params", "ffuf-content", "dalfox", "sqlmap", "wapiti", "arjun"},
    "secrets": {"bandit", "gitleaks", "retire", "semgrep", "trivy", "trufflehog", "trufflehog-filesystem"},
    "weaponization": {"shodan-cli", "wpscan"},
    "post_exploit": {"jwt_tool"},
}


def _tool_module_id(tool: str) -> str | None:
    name = str(tool or "").strip().lower()
    if name.startswith("nuclei"):
        return "nuclei"
    for module_id, tools in MODULE_TOOL_REQUIREMENTS.items():
        if name in tools:
            return module_id
    return None


def _installed_kali_modules() -> dict[str, str]:
    try:
        from urllib.request import urlopen

        with urlopen(f"{settings.kali_runner_url.rstrip('/')}/modules", timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
        modules = payload.get("modules") if isinstance(payload, dict) else payload
        if not isinstance(modules, list):
            return {}
        return {
            str(module.get("id") or "").strip(): str(module.get("status") or "").strip().lower()
            for module in modules
            if isinstance(module, dict) and str(module.get("id") or "").strip()
        }
    except Exception:
        return {}


def _filter_tools_by_kali_modules(tools: list[str], module_status: dict[str, str]) -> tuple[list[str], list[str]]:
    if not module_status:
        return tools, []
    selected: list[str] = []
    missing: list[str] = []
    for tool in tools:
        module_id = _tool_module_id(tool)
        if module_id and module_status.get(module_id) != "installed":
            missing.append(tool)
            continue
        selected.append(tool)
    return selected, missing


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

WEB_HEAVY_PHASES = {
    "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10",
    "P11", "P12", "P13", "P14", "P15", "P16", "P17", "P19",
}
HTTP_SURFACE_TOOLS = {
    "arjun", "paramspider", "ffuf", "ffuf-params", "ffuf-content",
    "gobuster", "feroxbuster", "dirsearch", "wfuzz", "katana",
    "katana-js", "hakrawler", "gospider", "curl", "curl-headers",
    "httpx", "whatweb", "whatweb-basic", "nikto", "wpscan", "wapiti",
    "dalfox", "sqlmap", "zap-baseline", "zap-ajax", "zap-active",
    "zap-api", "bl-test", "chromium-capture",
}
HTTP_NUCLEI_TOOLS = {
    "nuclei", "nuclei-cves", "nuclei-headers", "nuclei-exposure",
    "nuclei-cors", "nuclei-crlf", "nuclei-redirect", "nuclei-graphql",
    "nuclei-xss", "nuclei-sqli", "nuclei-ssrf", "nuclei-lfi",
    "nuclei-ssti", "nuclei-xxe", "nuclei-idor", "nuclei-csrf",
    "nuclei-race", "nuclei-rce", "nuclei-auth", "nuclei-deserialization",
    "nuclei-clickjacking", "nuclei-jwt",
}
PORT_REQUIRED_TOOLS: dict[str, set[int]] = {
    "crackmapexec": {139, 445, 389, 636, 5985, 5986},
    "nmap-smb": {139, 445},
    "nmap-ssh": {22},
    "nmap-dns": {53},
    "sslscan": {443, 8443, 9443, 10443},
    "testssl": {443, 8443, 9443, 10443},
    "nmap-ssl": {443, 8443, 9443, 10443},
}
TECH_REQUIRED_TOOLS: dict[str, set[str]] = {
    "wpscan": {"wordpress", "wp-content", "wp-includes"},
}
SKILL_SELECTION_THRESHOLD = 0.35

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
    # ADAPTATIVO: o cap sobe/desce conforme a saúde do ambiente (AIMD), em vez
    # de fixo. Fail-safe: se o controlador falhar, usa os caps de config.
    try:
        from app.services.adaptive_capacity import get_capacity
        cap = get_capacity()
        if cap:
            return cap
    except Exception:
        pass
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


def _skill_ids_for_phase_tool(phase_id: str, tool_name: str) -> list[str]:
    """Return skills that should be credited for a phase/tool work item."""
    contract = PHASE_CONTRACTS.get(phase_id) or {}
    skills = [str(s) for s in contract.get("required_skills") or [] if str(s)]
    tool = str(tool_name or "").strip()
    bound = (PHASE_TOOL_BINDINGS.get(phase_id) or {}).get(tool)
    if bound is not None:
        allowed = {str(s) for s in bound}
        skills = [s for s in skills if s in allowed]
    return list(dict.fromkeys(skills))


def skill_ids_for_phase_tool(phase_id: str, tool_name: str) -> list[str]:
    """Public wrapper used by auxiliary schedulers to keep skill attribution consistent."""
    return _skill_ids_for_phase_tool(phase_id, tool_name)


def gate_reason_for_phase(phase_id: str) -> str | None:
    """Return the explicit gate reason for a newly-blocked phase item."""
    gate = PHASE_GATE.get(str(phase_id or ""))
    return f"waiting_for:{gate}" if gate else None


def apply_phase_tool_metadata(
    metadata: dict[str, Any] | None,
    phase_id: str,
    tool_name: str,
    *,
    source: str = "",
    decision_source: str = "supervisor_skill_contract+accepted_learning",
) -> dict[str, Any]:
    """Attach skill + gate metadata to any work item producer.

    Several services create ScanWorkItem rows outside enqueue_scan_work_items
    (PoC validation, JS endpoint extraction, tech correlation, etc.). This keeps
    all of them aligned with the same supervisor model used by the main queue.
    """
    result = dict(metadata or {})
    if source and not result.get("source"):
        result["source"] = source
    skill_ids = result.get("skill_ids") or _skill_ids_for_phase_tool(phase_id, tool_name)
    skill_ids = [str(s) for s in skill_ids if str(s)]
    result["skill_ids"] = list(dict.fromkeys(skill_ids))
    result["skill_id"] = str(result.get("skill_id") or (skill_ids[0] if skill_ids else ""))
    result.setdefault("skill_attribution", "phase_contract_tool_binding")
    result.setdefault("skill_decision_source", decision_source)
    reason = gate_reason_for_phase(phase_id)
    if reason:
        result.setdefault("gate_reason", reason)
        result.setdefault("blocked_reason", reason)
    return result


def initial_status_for_phase(phase_id: str) -> str:
    return "blocked" if phase_id in _BLOCKED_AT_CREATE else "queued"


def initial_last_error_for_phase(phase_id: str) -> str | None:
    return gate_reason_for_phase(phase_id) if phase_id in _BLOCKED_AT_CREATE else None


def _skill_consultations_for_phase(
    phase_id: str,
    target: str,
    selected_tools: list[str],
    *,
    state: dict[str, Any],
    source: str,
    learning_playbook: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build deterministic supervisor skill-consultation records for a phase.

    This is the missing bridge between skill library / accepted learning and
    work queue execution. The queue may still execute tools, but every tool is
    now traceable back to a consulted skill decision.
    """
    contract = PHASE_CONTRACTS.get(phase_id) or {}
    skill_ids = [str(s) for s in contract.get("required_skills") or [] if str(s)]
    if not skill_ids:
        return []

    selected = [str(t) for t in selected_tools if str(t or "").strip()]
    learning_playbook = dict(learning_playbook or {})

    learning_tools = [str(t) for t in learning_playbook.get("recommended_tools") or [] if str(t)]
    learning_sources = list(learning_playbook.get("sources") or [])[:8]
    learning_techniques = list(learning_playbook.get("techniques") or [])[:8]
    consultations: list[dict[str, Any]] = []
    for skill_id in skill_ids:
        bound_tools = {
            tool for tool in selected
            if skill_id in _skill_ids_for_phase_tool(phase_id, tool)
        }
        if not bound_tools:
            bound_tools = set(selected)
        recommended = list(dict.fromkeys(
            [tool for tool in selected if tool in bound_tools]
            + [tool for tool in learning_tools if tool in bound_tools]
        ))
        applicability_decisions = [
            validate_skill_applicability(phase_id, skill_id, tool, target, state, at="enqueue")
            for tool in recommended
        ]
        applicable_tools = [
            str(decision.get("tool_name"))
            for decision in applicability_decisions
            if decision.get("applicable") and decision.get("tool_name")
        ]
        best_score = max(
            (float(decision.get("score") or 0.0) for decision in applicability_decisions),
            default=0.0,
        )
        selected_for_execution = bool(applicable_tools) and best_score >= SKILL_SELECTION_THRESHOLD
        matching_techniques = [
            technique for technique in learning_techniques
            if not technique.get("affected_skills")
            or skill_id in {str(s) for s in technique.get("affected_skills") or []}
        ][:5]
        consultation_id = "SC-" + hashlib.sha256(
            json.dumps(
                {"phase_id": phase_id, "skill_id": skill_id, "target": target, "tools": selected},
                sort_keys=True,
                default=str,
            ).encode()
        ).hexdigest()[:16]
        consultations.append({
            "consultation_id": consultation_id,
            "phase_id": phase_id,
            "target": target,
            "skill_id": skill_id,
            "consulted": True,
            "selected": selected_for_execution,
            "selection_threshold": SKILL_SELECTION_THRESHOLD,
            "applicability_score": round(best_score, 4),
            "applicability_decisions": applicability_decisions,
            "source": source,
            "decision_source": "supervisor_skill_contract+accepted_learning",
            "contract_required": skill_id in skill_ids,
            "candidate_tools": selected,
            "recommended_tools": applicable_tools,
            "learning_sources": learning_sources,
            "learning_techniques": matching_techniques,
            "learning_used": bool(matching_techniques or learning_sources),
            "reason": (
                f"Skill {skill_id} consultada para {phase_id}; selecionada={selected_for_execution} "
                f"score={round(best_score, 4)} com ferramentas aplicáveis: {', '.join(applicable_tools) or 'nenhuma'}."
            ),
            "created_at": datetime.now().isoformat(),
        })
    return consultations


def _append_skill_consultations_to_state(
    db: Session,
    job: ScanJob,
    consultations: list[dict[str, Any]],
) -> None:
    if not consultations:
        return
    from app.models.models import AgentTraceEvent

    state = dict(job.state_data or {})
    existing = list(state.get("skill_consultations") or [])
    existing_keys = {
        (str(c.get("phase_id")), str(c.get("target")), str(c.get("skill_id")))
        for c in existing
        if isinstance(c, dict)
    }
    added = []
    for consultation in consultations:
        key = (str(consultation.get("phase_id")), str(consultation.get("target")), str(consultation.get("skill_id")))
        if key in existing_keys:
            continue
        existing_keys.add(key)
        added.append(consultation)
        db.add(AgentTraceEvent(
            scan_id=job.id,
            event_type="skill_consulted",
            from_node="supervisor",
            to_node="work_queue",
            skill_id=str(consultation.get("skill_id") or "")[:120] or None,
            tool_name=",".join(consultation.get("recommended_tools") or [])[:100] or None,
            capability=str(consultation.get("phase_id") or "")[:100],
            status="selected" if consultation.get("selected") else "consulted",
            payload=consultation,
            created_at=datetime.now(),
        ))
    if not added:
        return
    existing.extend(added)
    state["skill_consultations"] = existing[-1000:]
    state["selected_skills"] = list(dict.fromkeys(
        list(state.get("selected_skills") or [])
        + [str(c.get("skill_id")) for c in added if c.get("skill_id") and c.get("selected")]
    ))
    state["skill_invocation"] = list(state.get("skill_invocation") or [])[-500:] + [
        {
            "phase_id": c.get("phase_id"),
            "skill_id": c.get("skill_id"),
            "target": c.get("target"),
            "source": c.get("decision_source"),
            "recommended_tools": c.get("recommended_tools") or [],
            "learning_used": bool(c.get("learning_used")),
            "created_at": c.get("created_at"),
        }
        for c in added
    ]
    state["skill_invocation"] = state["skill_invocation"][-1000:]
    job.state_data = state
    db.flush()


def _tool_profile(tool_name: str) -> str:
    entry = ToolCatalog().get(tool_name)
    return entry.profile if entry else tool_name


def _target_host(target: str) -> str:
    raw = str(target or "").strip()
    if not raw or raw == "__batch__":
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        return (parsed.hostname or raw.split("/")[0].split(":")[0]).lower()
    except Exception:
        return raw.split("/")[0].split(":")[0].lower()


def _target_type(target: str) -> str:
    raw = str(target or "").strip()
    if raw == "__batch__":
        return "batch"
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        if "://" in raw:
            if query:
                return "parameterized_endpoint"
            if "/api" in path.lower():
                return "api_endpoint"
            return "url"
        try:
            ipaddress.ip_address(host)
            return "ip"
        except ValueError:
            pass
        return "subdomain" if host.count(".") >= 2 else "domain"
    except Exception:
        return "unknown"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _extract_ports(*values: Any) -> list[int]:
    ports: list[int] = []
    for value in values:
        for entry in _as_list(value):
            if isinstance(entry, dict):
                entry = entry.get("port") or entry.get("number") or entry.get("port_id")
            try:
                port = int(entry)
            except (TypeError, ValueError):
                continue
            if 0 < port < 65536:
                ports.append(port)
    return sorted(set(ports))


def _flatten_tokens(value: Any) -> set[str]:
    tokens: set[str] = set()
    if value is None:
        return tokens
    if isinstance(value, dict):
        for nested in value.values():
            tokens.update(_flatten_tokens(nested))
        return tokens
    if isinstance(value, (list, tuple, set)):
        for nested in value:
            tokens.update(_flatten_tokens(nested))
        return tokens
    raw = str(value or "").lower()
    for token in raw.replace("/", " ").replace("_", " ").replace("-", " ").split():
        cleaned = "".join(ch for ch in token if ch.isalnum() or ch in {".", "#", "+"})
        if len(cleaned) >= 2:
            tokens.add(cleaned)
    if raw:
        tokens.add(raw)
    return tokens


def _preflight_profile_for_target(state: dict[str, Any], target: str) -> dict[str, Any]:
    preflight_targets = ((state.get("preflight") or {}).get("targets") or {})
    if not isinstance(preflight_targets, dict):
        return {}
    host = _target_host(target)
    candidates = [target, host, f"http://{host}", f"https://{host}"]
    for candidate in candidates:
        if candidate and isinstance(preflight_targets.get(candidate), dict):
            return dict(preflight_targets[candidate])
    return {}


def _target_context(state: dict[str, Any], target: str) -> dict[str, Any]:
    profile = _preflight_profile_for_target(state, target)
    status = str(profile.get("status") or "").lower()
    http_signals = list(profile.get("http") or [])
    ports = _extract_ports(
        profile.get("open_ports"),
        profile.get("ports"),
        state.get("preflight_ports"),
    )
    tech_tokens = _flatten_tokens(state.get("detected_tech_stack"))
    tech_tokens.update(_flatten_tokens(state.get("technologies")))
    tech_tokens.update(_flatten_tokens(state.get("technology_hints")))
    tech_tokens.update(_flatten_tokens(state.get("tech_stack")))
    for signal in http_signals:
        tech_tokens.update(_flatten_tokens(signal))
    waf_tokens = _flatten_tokens(state.get("waf_fingerprints"))
    waf_tokens.update(_flatten_tokens(state.get("waf")))
    has_http = bool(http_signals) or status == "http_live"
    return {
        "target": target,
        "host": _target_host(target),
        "target_type": _target_type(target),
        "preflight_known": bool(status),
        "preflight_status": status,
        "preflight_reason": profile.get("reason") or "",
        "open_ports": ports,
        "ports_known": bool(profile) and ("open_ports" in profile or "ports" in profile),
        "has_http": has_http,
        "tech_tokens": sorted(tech_tokens),
        "tech_known": bool(tech_tokens),
        "waf_tokens": sorted(waf_tokens),
    }


def _requires_http_surface(phase_id: str, tool_name: str) -> bool:
    tool = str(tool_name or "").strip().lower()
    return phase_id in WEB_HEAVY_PHASES or tool in HTTP_SURFACE_TOOLS or tool in HTTP_NUCLEI_TOOLS or tool.startswith("nuclei-")


def validate_skill_applicability(
    phase_id: str,
    skill_id: str,
    tool_name: str,
    target: str,
    state: dict[str, Any] | None,
    *,
    at: str = "enqueue",
) -> dict[str, Any]:
    """Return a conservative skill/tool applicability decision.

    Missing reconnaissance is never treated as a hard reject. Hard skips happen
    only when fresh state proves the tool cannot produce useful evidence.
    """
    state = dict(state or {})
    phase_id = str(phase_id or "")
    skill_id = str(skill_id or "")
    tool = str(tool_name or "").strip()
    tool_l = tool.lower()
    ctx = _target_context(state, target)

    decision = {
        "applicable": True,
        "score": 1.0,
        "reason": "applicable",
        "phase_id": phase_id,
        "skill_id": skill_id,
        "tool_name": tool,
        "target": target,
        "validated_at": at,
        "context": {
            "target_type": ctx["target_type"],
            "preflight_known": ctx["preflight_known"],
            "preflight_status": ctx["preflight_status"],
            "has_http": ctx["has_http"],
            "open_ports": ctx["open_ports"],
            "tech_known": ctx["tech_known"],
            "tech_tokens": ctx["tech_tokens"][:20],
        },
    }

    if target == "__batch__":
        decision["reason"] = "batch_item_validated_per_target_at_dispatch"
        decision["score"] = 0.75
        return decision

    dead_statuses = {"invalid", "dns_dead", "dead", "unresolved", "no_tcp"}
    if ctx["preflight_status"] in dead_statuses and phase_id not in {"P18", "P21", "P22"}:
        decision.update(
            applicable=False,
            score=0.0,
            reason=f"target_not_reachable:{ctx['preflight_status']}",
        )
        return decision

    if _requires_http_surface(phase_id, tool) and ctx["preflight_known"]:
        if ctx["preflight_status"] == "tcp_closed" and not ctx["has_http"]:
            decision.update(applicable=False, score=0.0, reason="no_http_surface:tcp_closed")
            return decision

    required_ports = PORT_REQUIRED_TOOLS.get(tool_l)
    if required_ports and ctx["ports_known"] and ctx["open_ports"]:
        if not (set(ctx["open_ports"]) & set(required_ports)):
            decision.update(
                applicable=False,
                score=0.0,
                reason=f"required_port_absent:{','.join(str(p) for p in sorted(required_ports))}",
            )
            return decision

    required_tech = TECH_REQUIRED_TOOLS.get(tool_l)
    if required_tech and ctx["tech_known"]:
        tech_blob = " ".join(ctx["tech_tokens"])
        if not any(token in tech_blob for token in required_tech):
            decision.update(
                applicable=False,
                score=0.0,
                reason=f"required_technology_absent:{','.join(sorted(required_tech))}",
            )
            return decision

    if not ctx["preflight_known"] and at == "enqueue":
        decision["score"] = 0.65
        decision["reason"] = "insufficient_context_defer_to_dispatch"
    elif not ctx["preflight_known"]:
        decision["score"] = 0.7
        decision["reason"] = "insufficient_context_allow_conservative"

    # ── Score real feedback: modulate by within-scan execution history ────────
    # After ≥2 real runs of skill+tool in this scan, their EMA positive rate
    # adjusts the score. A tool that never found anything gets a floor reduction;
    # one that consistently fires findings is boosted.
    _exec_scores = (state or {}).get("skill_execution_scores") or {}
    _hist_key = f"{skill_id}:{tool_l}"
    _hist = _exec_scores.get(_hist_key) or {}
    if _hist and int(_hist.get("runs") or 0) >= 2:
        _hist_rate = float(_hist.get("positive_rate") or 0.0)
        # Blend: 50% static score + 50% historical signal; floor at 0.1
        _adj = round(max(0.1, float(decision["score"]) * (0.5 + 0.5 * _hist_rate)), 4)
        decision["score"] = _adj
        decision["score_history_adjusted"] = True
        decision["history_positive_rate"] = _hist_rate
        decision["history_runs"] = int(_hist.get("runs") or 0)

    return decision


def update_skill_execution_score(
    state: dict[str, Any],
    skill_id: str,
    tool_name: str,
    result: str,  # "positive" | "negative" | "skipped"
    findings_count: int = 0,
) -> dict[str, Any]:
    """Update the within-scan EMA score for a skill+tool pair.

    Scores are stored in state["skill_execution_scores"] keyed by
    "{skill_id}:{tool_name_lower}". The caller is responsible for writing
    the mutated state dict back to the ScanJob.

    Returns the updated score record.
    """
    skill_id = str(skill_id or "")
    tool_key = str(tool_name or "").strip().lower()
    skey = f"{skill_id}:{tool_key}"

    scores: dict[str, Any] = dict(state.get("skill_execution_scores") or {})
    cur = dict(scores.get(skey) or {})

    runs = int(cur.get("runs") or 0) + 1
    used = int(cur.get("used") or 0) + (0 if result == "skipped" else 1)
    positives = int(cur.get("positives") or 0) + (1 if findings_count > 0 else 0)

    prev_rate = float(cur.get("positive_rate") or 0.5)
    alpha = min(0.4, 2.0 / (runs + 1))
    obs = 1.0 if findings_count > 0 else 0.0
    positive_rate = round(prev_rate * (1 - alpha) + obs * alpha, 4)

    record: dict[str, Any] = {
        "skill_id": skill_id,
        "tool_name": tool_key,
        "runs": runs,
        "used": used,
        "positives": positives,
        "positive_rate": positive_rate,
        "applicability_score": round(max(0.1, positive_rate), 4),
        "last_result": result,
    }
    scores[skey] = record
    state["skill_execution_scores"] = scores
    return record


def _tool_applicability_decision(
    phase_id: str,
    tool_name: str,
    target: str,
    state: dict[str, Any],
    *,
    at: str,
) -> dict[str, Any]:
    skill_ids = _skill_ids_for_phase_tool(phase_id, tool_name)
    if not skill_ids:
        skill_ids = [""]
    decisions = [
        validate_skill_applicability(phase_id, skill_id, tool_name, target, state, at=at)
        for skill_id in skill_ids
    ]
    applicable = [d for d in decisions if d.get("applicable")]
    chosen = applicable[0] if applicable else decisions[0]
    return {
        **chosen,
        "applicable": bool(applicable),
        "skill_decisions": decisions,
        "skill_ids": [sid for sid in skill_ids if sid],
    }


def work_item_applicability_decision(
    item: ScanWorkItem,
    state: dict[str, Any] | None,
    *,
    at: str = "dispatch",
) -> dict[str, Any]:
    metadata = dict(item.item_metadata or {})
    if str(item.target or "") != "__batch__":
        return _tool_applicability_decision(
            str(item.phase_id or ""),
            str(item.tool_name or ""),
            str(item.target or ""),
            dict(state or {}),
            at=at,
        )

    targets = [str(t) for t in metadata.get("batch_targets") or [] if str(t)]
    if not targets:
        return {
            "applicable": False,
            "score": 0.0,
            "reason": "batch_without_targets",
            "phase_id": str(item.phase_id or ""),
            "tool_name": str(item.tool_name or ""),
            "target": "__batch__",
            "validated_at": at,
            "batch_targets": [],
            "skipped_batch_targets": [],
        }
    decisions = [
        _tool_applicability_decision(
            str(item.phase_id or ""),
            str(item.tool_name or ""),
            target,
            dict(state or {}),
            at=at,
        )
        for target in targets
    ]
    kept = [str(d.get("target")) for d in decisions if d.get("applicable")]
    skipped_targets = [
        {"target": str(d.get("target")), "reason": str(d.get("reason") or "")}
        for d in decisions
        if not d.get("applicable")
    ]
    if not kept:
        return {
            "applicable": False,
            "score": 0.0,
            "reason": "no_applicable_batch_targets",
            "phase_id": str(item.phase_id or ""),
            "tool_name": str(item.tool_name or ""),
            "target": "__batch__",
            "validated_at": at,
            "batch_targets": [],
            "skipped_batch_targets": skipped_targets,
            "target_decisions": decisions[:50],
        }
    return {
        "applicable": True,
        "score": round(len(kept) / max(1, len(targets)), 4),
        "reason": "applicable_batch_targets",
        "phase_id": str(item.phase_id or ""),
        "tool_name": str(item.tool_name or ""),
        "target": "__batch__",
        "validated_at": at,
        "batch_targets": kept,
        "skipped_batch_targets": skipped_targets[:100],
        "target_decisions": decisions[:50],
    }


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

# Fases-GATE: as fases das quais OUTRAS dependem (valores do PHASE_GATE).
# Enquanto uma fase-gate tem itens pendentes, todas as fases que esperam por ela
# ficam 'blocked'. Por isso o dispatcher prioriza drenar fases-gate primeiro
# (ver claim_work_items) — senão uma fase-gate pode ser estarvada por uma fase
# não-gate de prioridade melhor que compete pela mesma capacidade, deixando a
# exploração bloqueada para sempre (vira "scan de vuln", não pentest).
_GATE_TARGET_PHASES: frozenset[str] = frozenset(g for g in PHASE_GATE.values() if g)

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

    now = datetime.now()
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
            {"status": "queued", "last_error": None, "updated_at": now},
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
    consultation_by_phase_target: dict[tuple[str, str], list[dict[str, Any]]] = {}
    learning_playbook_cache: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    module_status = _installed_kali_modules()
    missing_module_tools: dict[str, set[str]] = {}

    clean_targets = [str(t).strip() for t in targets if str(t or "").strip()]

    for target in clean_targets:
        for phase_id in _eligible_phases_for_target(target, state):
            tools = _phase_tools(phase_id)
            if not tools:
                continue
            required = list((PHASE_CONTRACTS.get(phase_id) or {}).get("required_tools") or [])
            optional = [tool for tool in tools if tool not in set(required)]
            selected = list(dict.fromkeys(required + optional[:max_optional_per_phase]))
            selected, missing_for_modules = _filter_tools_by_kali_modules(selected, module_status)
            for missing_tool in missing_for_modules:
                module_id = _tool_module_id(missing_tool) or "unknown"
                missing_module_tools.setdefault(module_id, set()).add(missing_tool)
            skipped += len(missing_for_modules)
            if not selected:
                continue
            applicability_by_tool = {
                tool: _tool_applicability_decision(phase_id, tool, target, state, at="enqueue")
                for tool in selected
            }
            selected = [
                tool for tool in selected
                if applicability_by_tool.get(tool, {}).get("applicable")
            ]
            skipped += len([d for d in applicability_by_tool.values() if not d.get("applicable")])
            if not selected:
                continue
            learning_key = (phase_id, tuple(selected))
            if learning_key not in learning_playbook_cache:
                try:
                    from app.services.vulnerability_learning_service import build_runtime_learning_playbook
                    learning_playbook_cache[learning_key] = build_runtime_learning_playbook(
                        candidate_tools=selected,
                        phase=phase_id,
                        limit=8,
                        tech_stack=list(state.get("detected_tech_stack") or state.get("technologies") or []),
                    ) or {}
                except Exception:
                    learning_playbook_cache[learning_key] = {}
            consultations = _skill_consultations_for_phase(
                phase_id,
                target,
                selected,
                state=state,
                source=source,
                learning_playbook=learning_playbook_cache.get(learning_key) or {},
            )
            consultation_by_phase_target[(phase_id, target)] = consultations
            for tool in selected:
                if tool in BATCH_CAPABLE_TOOLS:
                    batch_accumulator[(phase_id, tool)].add(target)
                else:
                    single_items.append((phase_id, tool, target))

    _append_skill_consultations_to_state(
        db,
        job,
        [c for items in consultation_by_phase_target.values() for c in items],
    )

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
                skill_ids = _skill_ids_for_phase_tool(phase_id, tool)
                old_meta = apply_phase_tool_metadata(old_meta, phase_id, tool, source=source)
                existing_consultation_ids = {
                    str(x) for x in old_meta.get("skill_consultation_ids") or [] if str(x)
                }
                new_consultation_ids = {
                    str(c.get("consultation_id"))
                    for target in merged
                    for c in consultation_by_phase_target.get((phase_id, target), [])
                    if c.get("skill_id") in skill_ids and c.get("consultation_id")
                }
                old_meta["skill_consultation_ids"] = sorted(existing_consultation_ids | new_consultation_ids)
                old_meta["skill_decision_source"] = "supervisor_skill_contract+accepted_learning"
                old_meta["applicability"] = _tool_applicability_decision(phase_id, tool, "__batch__", state, at="enqueue")
                old_learning_sources = {str(x) for x in old_meta.get("learning_sources") or [] if str(x)}
                new_learning_sources = {
                    str(src.get("id") or src.get("title") or "")
                    for target in merged
                    for c in consultation_by_phase_target.get((phase_id, target), [])
                    if c.get("skill_id") in skill_ids
                    for src in c.get("learning_sources") or []
                    if isinstance(src, dict) and str(src.get("id") or src.get("title") or "")
                }
                old_meta["learning_sources"] = sorted(old_learning_sources | new_learning_sources)[:20]
                if merged != list(existing_tgts):
                    old_meta["batch_targets"] = merged
                existing_batch.item_metadata = old_meta
                if existing_batch.status == "blocked" and not existing_batch.last_error:
                    existing_batch.last_error = initial_last_error_for_phase(phase_id)
                existing_batch.updated_at = datetime.now()
                db.flush()
            existing += 1
            continue

        rc = resource_class_for_tool(tool)
        base_priority = PHASE_PRIORITY.get(phase_id, 100) + {"light": 0, "medium": 5, "heavy": 15, "oob": 20}.get(rc, 0)
        # Batch item gets best priority of all targets in the set
        best_boost = min(_high_risk_priority_boost(t) for t in sorted_targets) if sorted_targets else 0

        _batch_status = initial_status_for_phase(phase_id)
        _batch_skill_ids = _skill_ids_for_phase_tool(phase_id, tool)
        _batch_consultations = [
            c
            for target in sorted_targets
            for c in consultation_by_phase_target.get((phase_id, target), [])
            if c.get("skill_id") in _batch_skill_ids
        ]
        _batch_consultation_ids = sorted({str(c.get("consultation_id")) for c in _batch_consultations if c.get("consultation_id")})
        _batch_learning_sources = list({
            str(src.get("id") or src.get("title") or "")
            for c in _batch_consultations
            for src in c.get("learning_sources") or []
            if isinstance(src, dict) and str(src.get("id") or src.get("title") or "")
        })[:20]
        item = ScanWorkItem(
            scan_job_id=job.id,
            phase_id=phase_id,
            target="__batch__",
            tool_name=tool[:120],
            profile=_tool_profile(tool)[:120],
            resource_class=rc,
            priority=max(1, base_priority + best_boost),
            status=_batch_status,
            last_error=initial_last_error_for_phase(phase_id),
            max_attempts=2,
            item_metadata=apply_phase_tool_metadata({
                "source": source,
                "engine": "capacity_work_queue",
                "skill_ids": _batch_skill_ids,
                "skill_id": (_batch_skill_ids or [""])[0],
                "skill_attribution": "phase_contract_tool_binding",
                "skill_decision_source": "supervisor_skill_contract+accepted_learning",
                "skill_consultation_ids": _batch_consultation_ids,
                "learning_sources": _batch_learning_sources,
                "batch_targets": sorted_targets,
                "batch_count": len(sorted_targets),
                "high_risk": best_boost < 0,
                "applicability": _tool_applicability_decision(phase_id, tool, "__batch__", state, at="enqueue"),
            }, phase_id, tool, source=source),
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )
        db.add(item)
        try:
            db.flush()
            created += 1
        except Exception:
            db.rollback()
            skipped += 1

    # Timeout is no longer set from the backend — the Kali runner's profile
    # timeout is the authoritative limit for every tool. This avoids the pattern
    # where a low backend-side value (e.g. 300s) kills tools before their own
    # internal completion (nikto, sqlmap, wapiti can run for 30+ minutes).
    def _adaptive_timeout(tool: str, target: str) -> int | None:
        return None  # always defer to kali profile timeout

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
        _skill_ids = _skill_ids_for_phase_tool(phase_id, tool)
        _consultations = [c for c in consultation_by_phase_target.get((phase_id, target), []) if c.get("skill_id") in _skill_ids]
        _consultation_ids = [str(c.get("consultation_id")) for c in _consultations if c.get("consultation_id")]
        _learning_sources = list({
            str(src.get("id") or src.get("title") or "")
            for c in _consultations
            for src in c.get("learning_sources") or []
            if isinstance(src, dict) and str(src.get("id") or src.get("title") or "")
        })[:20]
        _item_meta: dict[str, Any] = {
            "source": source,
            "engine": "capacity_work_queue",
            "high_risk": risk_boost < 0,
            "skill_ids": _skill_ids,
            "skill_id": _skill_ids[0] if _skill_ids else "",
            "skill_attribution": "phase_contract_tool_binding",
            "skill_decision_source": "supervisor_skill_contract+accepted_learning",
            "skill_consultation_ids": _consultation_ids,
            "learning_sources": _learning_sources,
            "applicability": _tool_applicability_decision(phase_id, tool, target, state, at="enqueue"),
        }
        _to = _adaptive_timeout(tool, target)
        if _to is not None:
            _item_meta["timeout_override"] = _to
        _single_status = initial_status_for_phase(phase_id)
        item = ScanWorkItem(
            scan_job_id=job.id,
            phase_id=phase_id,
            target=target[:500],
            tool_name=tool[:120],
            profile=_tool_profile(tool)[:120],
            resource_class=rc,
            priority=max(1, base_priority + risk_boost),
            status=_single_status,
            last_error=initial_last_error_for_phase(phase_id),
            max_attempts=2,
            item_metadata=apply_phase_tool_metadata(_item_meta, phase_id, tool, source=source),
            created_at=datetime.now(),
            updated_at=datetime.now(),
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
    if missing_module_tools:
        db.add(ScanLog(
            scan_job_id=job.id,
            source="work-queue",
            level="WARNING",
            message=(
                "work_queue_skipped_uninstalled_modules "
                + json.dumps(
                    {module: sorted(tools) for module, tools in sorted(missing_module_tools.items())},
                    sort_keys=True,
                )
            ),
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


def work_queue_skill_snapshot(db: Session, scan_id: int) -> dict[str, Any]:
    """Aggregate work-item skill/tool coverage without changing execution.

    This is the authoritative runtime view while a scan is running. Phase
    ledgers can be sparse because direct operator phases and queued work items
    are produced by different paths; this snapshot bridges them for supervisor
    and UI reporting.
    """
    items = (
        db.query(ScanWorkItem)
        .filter(ScanWorkItem.scan_job_id == scan_id)
        .all()
    )
    by_phase: dict[str, dict[str, Any]] = {}
    terminal_ok = {"completed", "done", "success"}
    terminal_bad = {"failed", "timeout", "skipped"}
    active = {"queued", "retry", "dispatched", "running", "submitted"}

    for item in items:
        phase_id = str(item.phase_id or "")
        if not phase_id:
            continue
        phase = by_phase.setdefault(phase_id, {
            "phase_id": phase_id,
            "targets": set(),
            "selected_skills": set(),
            "tools_attempted": set(),
            "tools_success": set(),
            "tools_failed": set(),
            "tools_blocked": set(),
            "status_counts": {},
            "skill_coverage": {},
            "gate_reasons": set(),
            "blocked_reasons": set(),
        })
        target = str(item.target or "")
        if target:
            phase["targets"].add(target)
        status = str(item.status or "")
        phase["status_counts"][status] = int(phase["status_counts"].get(status, 0)) + 1
        tool_name = str(item.tool_name or "")
        if tool_name:
            phase["tools_attempted"].add(tool_name)
            if status in terminal_ok:
                phase["tools_success"].add(tool_name)
            elif status in terminal_bad:
                phase["tools_failed"].add(tool_name)
            elif status == "blocked":
                phase["tools_blocked"].add(tool_name)

        meta = dict(item.item_metadata or {})
        skill_ids = [str(s) for s in meta.get("skill_ids") or [] if str(s)]
        if not skill_ids and meta.get("skill_id"):
            skill_ids = [str(meta.get("skill_id"))]
        if not skill_ids:
            skill_ids = _skill_ids_for_phase_tool(phase_id, tool_name)
        gate_reason = str(meta.get("gate_reason") or "")
        blocked_reason = str(item.last_error or meta.get("blocked_reason") or "")
        if gate_reason:
            phase["gate_reasons"].add(gate_reason)
        if blocked_reason:
            phase["blocked_reasons"].add(blocked_reason)
        for skill_id in skill_ids:
            phase["selected_skills"].add(skill_id)
            cov = phase["skill_coverage"].setdefault(skill_id, {
                "status": "queued",
                "tools_required": set(),
                "tools_attempted": set(),
                "tools_success": set(),
                "tools_failed": set(),
                "evidence_ids": [],
                "blocking_reason": None,
            })
            if tool_name:
                cov["tools_attempted"].add(tool_name)
                if status in terminal_ok:
                    cov["tools_success"].add(tool_name)
                elif status in terminal_bad:
                    cov["tools_failed"].add(tool_name)
                elif status == "blocked":
                    cov["blocking_reason"] = blocked_reason or gate_reason or "waiting_for_gate"
            if status in terminal_ok:
                cov["status"] = "completed"
            elif cov["status"] != "completed" and status in terminal_bad:
                cov["status"] = "partial"
            elif cov["status"] not in {"completed", "partial"} and status == "blocked":
                cov["status"] = "gate_blocked" if gate_reason or "waiting_for:" in blocked_reason else "blocked"
            elif cov["status"] not in {"completed", "partial"} and status in active:
                cov["status"] = "executing" if status in {"dispatched", "running", "submitted"} else "queued"

    serialised: dict[str, Any] = {}
    for phase_id, phase in by_phase.items():
        skill_coverage: dict[str, Any] = {}
        for skill_id, cov in phase["skill_coverage"].items():
            skill_coverage[skill_id] = {
                **cov,
                "tools_required": sorted(cov["tools_required"]),
                "tools_attempted": sorted(cov["tools_attempted"]),
                "tools_success": sorted(cov["tools_success"]),
                "tools_failed": sorted(cov["tools_failed"]),
            }
        serialised[phase_id] = {
            "phase_id": phase_id,
            "targets": sorted(phase["targets"]),
            "selected_skills": sorted(phase["selected_skills"]),
            "tools_attempted": sorted(phase["tools_attempted"]),
            "tools_success": sorted(phase["tools_success"]),
            "tools_failed": sorted(phase["tools_failed"]),
            "tools_blocked": sorted(phase["tools_blocked"]),
            "status_counts": dict(sorted(phase["status_counts"].items())),
            "skill_coverage": skill_coverage,
            "gate_reasons": sorted(phase["gate_reasons"]),
            "blocked_reasons": sorted(phase["blocked_reasons"]),
        }
    return serialised


def enrich_phase_ledgers_from_work_items(db: Session, job: ScanJob) -> dict[str, Any]:
    """Persist work-queue-derived skill coverage into ScanJob.state_data."""
    snapshot = work_queue_skill_snapshot(db, int(job.id))
    state = dict(job.state_data or {})
    state["work_queue_skill_coverage"] = snapshot
    ledgers = list(state.get("phase_ledger_v2") or state.get("phase_ledger") or [])
    changed = False
    enriched_ledgers: list[dict[str, Any]] = []
    for ledger in ledgers:
        if not isinstance(ledger, dict):
            enriched_ledgers.append(ledger)
            continue
        phase_id = str(ledger.get("phase_id") or "")
        snap = snapshot.get(phase_id)
        if not snap:
            enriched_ledgers.append(ledger)
            continue
        merged = dict(ledger)
        for key in ("selected_skills", "tools_attempted", "tools_success", "tools_failed"):
            existing = [str(x) for x in merged.get(key) or [] if str(x)]
            incoming = [str(x) for x in snap.get(key) or [] if str(x)]
            union = list(dict.fromkeys(existing + incoming))
            if union != existing:
                merged[key] = union
                changed = True
        existing_cov = dict(merged.get("skill_coverage") or {})
        for skill_id, cov in (snap.get("skill_coverage") or {}).items():
            if skill_id not in existing_cov:
                existing_cov[skill_id] = cov
                changed = True
        if existing_cov != (merged.get("skill_coverage") or {}):
            merged["skill_coverage"] = existing_cov
        merged["work_queue_status_counts"] = snap.get("status_counts") or {}
        merged["work_queue_gate_reasons"] = snap.get("gate_reasons") or []
        enriched_ledgers.append(merged)
    if ledgers:
        state["phase_ledger_v2"] = enriched_ledgers
    state["selected_skills"] = list(dict.fromkeys(
        [str(s) for s in state.get("selected_skills") or [] if str(s)]
        + [s for snap in snapshot.values() for s in (snap.get("selected_skills") or [])]
    ))
    job.state_data = state
    db.flush()
    return {"updated_ledgers": int(changed), "phases": len(snapshot)}


def claim_work_items(db: Session, scan_id: int, *, limit: int | None = None) -> list[int]:
    now = datetime.now()
    lease_until = now + timedelta(seconds=max(60, int(settings.scan_work_queue_lease_seconds)))
    dispatch_limit = max(1, int(limit or settings.scan_work_queue_dispatch_limit))
    caps = capacity_limits()
    claimed: list[int] = []
    lock_key = 917000 + int(scan_id)
    lock_acquired = bool(db.execute(text("select pg_try_advisory_xact_lock(:key)"), {"key": lock_key}).scalar())
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
                # GATE-AWARE: fases-gate (P02/P06/P09…) são reivindicadas ANTES
                # de qualquer fase não-gate que dispute a mesma capacidade. Isso
                # impede que uma fase-gate seja estarvada (ex.: P09=prio 50 perdia
                # p/ P16=45 e nunca drenava → exploração bloqueada eternamente).
                # Uma fase-gate sempre drena → seu gate abre → o pentest avança.
                .order_by(
                    case((ScanWorkItem.phase_id.in_(_GATE_TARGET_PHASES), 0), else_=1).asc(),
                    ScanWorkItem.priority.asc(),
                    ScanWorkItem.created_at.asc(),
                    ScanWorkItem.id.asc(),
                )
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
    except Exception:
        db.rollback()
        raise
    # pg_try_advisory_xact_lock auto-libera no commit/rollback — nenhum unlock explícito necessário.


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
        item.result = {"skipped_reason": f"target_triage:{reason}", "triage_at": datetime.now().isoformat()}
        item.last_error = f"skipped:target_triage:{reason}"
        item.updated_at = datetime.now()
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

    def _finding_targets(finding: Finding) -> set[str]:
        values: set[str] = set()
        for raw in (
            getattr(finding, "domain", None),
            getattr(finding, "url", None),
            (getattr(finding, "details", None) or {}).get("target"),
            (getattr(finding, "details", None) or {}).get("host"),
            (getattr(finding, "details", None) or {}).get("asset"),
            (getattr(finding, "details", None) or {}).get("matched_at"),
        ):
            text = str(raw or "").strip()
            if not text:
                continue
            try:
                from urllib.parse import urlparse

                parsed = urlparse(text if "://" in text else f"http://{text}")
                host = parsed.hostname or text.split("/")[0].split(":")[0]
            except Exception:
                host = text.split("/")[0].split(":")[0]
            host = host.strip().lower().rstrip(".")
            if host:
                values.add(host)
        return values

    # 1. Subdomínios com achados medium/high/critical de ferramentas P09
    finding_rows = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.severity.in_(list(_HIGH_SEV)),
            Finding.tool.in_(list(_P09_TOOLS)),
        )
        .all()
    )
    targets_with_findings: set[str] = set()
    for finding in finding_rows:
        targets_with_findings.update(_finding_targets(finding))

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
    now = datetime.now()
    for wi in items_to_cancel:
        wi.status = "skipped"
        wi.result = {
            "skipped_reason": "triage_post_p09_no_p09_findings",
            "targets_with_findings_count": len(targets_with_findings),
            "triage_at": now.isoformat(),
        }
        wi.last_error = "skipped:triage_post_p09_no_p09_findings"
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
    now = datetime.now()
    return db.query(ScanWorkItem.id).filter(
        ScanWorkItem.scan_job_id == scan_id,
        or_(
            ScanWorkItem.status.in_(["queued", "retry", "dispatched", "running", "submitted", "blocked"]),
            and_(ScanWorkItem.status.in_(["dispatched", "running", "submitted"]), ScanWorkItem.lease_until <= now),
        ),
    ).first() is not None
