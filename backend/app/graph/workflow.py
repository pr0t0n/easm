from __future__ import annotations

import json
import re
import socket
import logging
from datetime import datetime
from time import perf_counter
from typing import Any, TypedDict
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from langgraph.graph import END, StateGraph

from app.graph.checkpointer import create_checkpointer
from app.graph.mission import MISSION_ITEMS as AUTONOMOUS_MISSION_ITEMS

# ─────────────────────────────────────────────────────────────
# Re-exports from split modules (keep existing callers working)
# ─────────────────────────────────────────────────────────────
from app.graph.state import (
    AgentState,
    MISSION_PHASE_TO_GROUP,
    TOOL_CAPABILITY_NODES,
    CAPABILITY_SKILL_CATEGORIES,
)
from app.graph.tool_parsers import (
    ANSI_ESCAPE_PATTERN,
    KNOWN_WAF_MODELS,
    WAF_VENDOR_ALIASES,
    _strip_ansi_codes,
    _sanitize_cli_text,
    _normalize_waf_vendor,
    _truncate_log,
    _severity_to_risk_score,
    _extract_asm_findings,
    _extract_tool_output_findings,
    _extract_shodan_findings,
    _extract_wafw00f_findings,
    _extract_shcheck_findings,
    _extract_curl_headers_findings,
    _extract_nikto_findings,
    _extract_nmap_vulscan_findings,
    _extract_sslscan_findings,
    _extract_testssl_findings,
    _extract_wapiti_findings,
    _extract_sqlmap_findings,
    _extract_dalfox_findings,
    _extract_amass_findings,
    _extract_sublist3r_findings,
    _extract_dnsenum_findings,
    _extract_massdns_findings,
    _extract_subjack_findings,
    _extract_ffuf_findings,
    _extract_gobuster_findings,
    _extract_cloudenum_findings,
    _extract_whatweb_findings,
    _extract_katana_findings,
)

from app.graph.mission import build_autonomous_mission_contract, select_mission_skills
from app.services.risk_service import (
    build_fair_decomposition,
    compute_easm_rating,
    compute_asset_risk,
    METHODOLOGY_VERSION,
)
from app.services.cyber_autoagent_alignment import build_supervisor_prompt_contract
from app.services.worker_dispatcher import execute_tool_with_workers
from app.workers.worker_groups import ScanMode, get_worker_groups


logger = logging.getLogger(__name__)

# Função utilitária para obter o grupo de worker para uma fase
def get_worker_group_for_phase(phase_title: str) -> str:
    for key, group in MISSION_PHASE_TO_GROUP.items():
        if key.lower() in phase_title.lower():
            return group
    return "recon"  # fallback padrão


# Senior Cyber Analyst pipeline (framework-driven)
GROUP_MISSION_ITEMS: list[str] = [
    *AUTONOMOUS_MISSION_ITEMS,
]

ANALYST_CONFIDENCE_THRESHOLDS: dict[str, int] = {
    "high": 80,
    "medium": 50,
    "low": 0,
}

EVIDENCE_RULES: dict[str, Any] = {
    "critical_requires": ["reproducible_steps", "impact", "technical_evidence"],
    "high_requires": ["impact", "technical_evidence"],
    "minimum_confidence_for_promote": 70,
}

checkpointer = create_checkpointer()

# Portas comuns de superficie externa para fallback quando o scanner nao retorna
# uma lista real de portas abertas.
MAX_DISCOVERED_ASSETS = 40


STEP_TOOL_MAP: list[tuple[str, str]] = [
    # Recon
    ("subfinder", "subfinder"),
    ("findomain", "findomain"),
    ("assetfinder", "assetfinder"),
    ("amass", "amass"),
    ("massdns", "massdns"),
    ("shuffledns", "shuffledns"),
    ("chaos", "chaos"),
    ("dnsx", "dnsx"),
    ("hakrawler", "hakrawler"),
    ("gau", "gau"),
    ("waybackurls", "waybackurls"),
    ("paramspider", "paramspider"),
    # OSINT
    ("shodan", "shodan-cli"),
    ("theharvester", "theHarvester"),
    ("h8mail", "h8mail"),
    ("metagoofil", "metagoofil"),
    # Serviços
    ("nmap", "nmap"),
    ("naabu", "naabu"),
    ("masscan", "masscan"),
    ("httpx", "httpx"),
    ("whatweb", "whatweb"),
    ("sslscan", "sslscan"),
    # Web/HTTP
    ("ffuf", "ffuf"),
    ("gobuster", "gobuster"),
    ("feroxbuster", "feroxbuster"),
    ("dirsearch", "dirsearch"),
    ("katana", "katana"),
    ("waymore", "waymore"),
    # Fingerprint
    ("curl", "curl-headers"),
    ("header", "curl-headers"),
    ("nikto", "nikto"),
    # SAST/Secrets/Deps
    ("semgrep", "semgrep"),
    ("bandit", "bandit"),
    ("gitleaks", "gitleaks"),
    ("trufflehog", "trufflehog"),
    ("retire", "retire"),
    ("eslint", "eslint"),
    ("jshint", "jshint"),
    # WAF
    ("wafw00f", "wafw00f"),
    # Vuln Web
    ("vulscan", "nmap-vulscan"),
    ("dalfox", "dalfox"),
    ("wapiti", "wapiti"),
    ("nuclei", "nuclei"),
    # Exploitation
    ("hydra", "hydra"),
    ("john", "john"),
    ("hashcat", "hashcat"),
    ("cme", "CrackMapExec"),
    ("responder", "Responder"),
]


# ─────────────────────────────────────────────────────────────
# Metric / step helpers
# ─────────────────────────────────────────────────────────────

def _metric_start() -> float:
    return perf_counter()


def _metric_end(state: AgentState, node_name: str, started_at: float):
    duration_ms = round((perf_counter() - started_at) * 1000, 2)
    state["activity_metrics"].append(
        {
            "node": node_name,
            "duration_ms": duration_ms,
            "timestamp": datetime.utcnow().isoformat(),
            "mission_index": state.get("mission_index", 0),
        }
    )
    state["node_history"].append(node_name)
    state["last_completed_node"] = node_name


def _node_for_step(step_name: str, scan_mode: str) -> str:
    step = str(step_name or "").strip().lower()
    if step in {"", "done"}:
        return "supervisor"
    if "supervisor" in step:
        return "supervisor"
    if "planning" in step or "strategic" in step:
        return "skill_planner"
    if "selector" in step:
        return "tool_selector"
    if "executor" in step:
        return "tool_executor"
    if "asset" in step or "recon" in step or "discovery" in step:
        return "asset_discovery"
    if "hypothesis" in step:
        return "skill_planner"
    if "risk" in step or "vuln" in step or "assessment" in step:
        return "risk_assessment"
    if "adjudication" in step or "evidence" in step:
        return "evidence_gate"
    if "governance" in step:
        return "governance"
    if "executive" in step:
        return "executive_analyst"
    return "supervisor"


def _sync_step_to_db(state: AgentState, step_label: str) -> None:
    """Persiste current_step, mission_index, e node_history no ScanJob durante execução do grafo."""
    scan_id = state.get("scan_id")
    if not scan_id:
        return
    try:
        from app.db.session import SessionLocal
        from app.models.models import ScanJob
        _db = SessionLocal()
        try:
            job = _db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if job and job.status not in ("completed", "failed", "stopped"):
                job.current_step = step_label
                mission_items = state.get("mission_items") or []
                mi = state.get("mission_index", 0)
                total = max(1, len(mission_items))
                job.mission_progress = int(round(min(mi, total) / total * 100))
                current_node = _node_for_step(step_label, state.get("scan_mode", "unit"))
                snapshot_node_history = list(state.get("node_history", []))
                if current_node and (not snapshot_node_history or snapshot_node_history[-1] != current_node):
                    snapshot_node_history.append(current_node)
                # Snapshot para o frontend consultar via /status
                sd = dict(job.state_data or {})
                sd["mission_index"] = mi
                sd["mission_items"] = mission_items
                sd["node_history"] = snapshot_node_history
                sd["current_node"] = current_node
                sd["detected_tech_stack"] = list(state.get("detected_tech_stack") or [])
                sd["kill_chain_stage"] = str(state.get("kill_chain_stage") or "RECONNAISSANCE")
                sd["pentest_phase_index"] = int(state.get("pentest_phase_index", 0) or 0)
                sd["pentest_hypotheses"] = list(state.get("pentest_hypotheses") or [])[:30]
                job.state_data = sd
                # Persist tech_stack to its dedicated column too (queryable by GIN index).
                try:
                    job.tech_stack = list(state.get("detected_tech_stack") or [])
                except Exception:
                    pass
                _db.commit()
        finally:
            _db.close()
    except Exception:
        logger.exception("Falha ao sincronizar step no banco")


def _refresh_tech_stack(state: AgentState) -> bool:
    """Re-detecta a fingerprint do ambiente e persiste no estado.

    Retorna True quando a assinatura mudou em relacao a iteracao anterior,
    sinalizando ao supervisor que deve reavaliar active_skills.
    """
    try:
        from app.services.tech_stack_detector import detect_tech_stack, tech_stack_signature

        stack = detect_tech_stack(
            findings=list(state.get("vulnerabilidades_encontradas") or []),
            target=str(state.get("target") or ""),
        )
    except Exception as exc:
        logger.warning("tech_stack detection failed: %s", exc)
        return False

    signature = tech_stack_signature(stack)
    previous = str(state.get("tech_stack_signature") or "")
    state["detected_tech_stack"] = stack
    state["tech_stack_signature"] = signature

    # ── Hypothesis engine: always refresh after any state change in tech
    # stack or findings. Idempotent: same evidence -> same hypothesis ids.
    try:
        from app.services.hypothesis_engine import extract_pentest_hypotheses
        hypotheses = extract_pentest_hypotheses(dict(state))
        prev_ids = {str(h.get("id") or "") for h in (state.get("pentest_hypotheses") or [])}
        new_ids = {str(h.get("id") or "") for h in hypotheses}
        state["pentest_hypotheses"] = hypotheses
        added = new_ids - prev_ids
        if added:
            state.setdefault("logs_terminais", []).append(
                f"[hypothesis-engine] +{len(added)} novas hipoteses "
                f"(total={len(hypotheses)}, families={sorted({h.get('family') for h in hypotheses})})"
            )
    except Exception as exc:
        logger.warning("hypothesis engine failed: %s", exc)

    if signature != previous:
        state.setdefault("logs_terminais", []).append(
            f"[tech-stack] detectado={','.join(stack) or '-'} (mudanca de fingerprint)"
        )
        return True
    return False


# ─────────────────────────────────────────────────────────────
# Tool / step helpers
# ─────────────────────────────────────────────────────────────

def _tool_for_step(step_name: str) -> str | None:
    step = str(step_name or "").strip().lower()
    semantic_overrides = [
        (("riskassessment", "risk assessment", "analise de vulnerabilidade"), "nuclei"),
        (("waf",), "wafw00f"),
        (("headers",), "curl-headers"),
    ]
    for keywords, tool in semantic_overrides:
        if any(keyword in step for keyword in keywords):
            return tool
    for keyword, tool in STEP_TOOL_MAP:
        if keyword in step:
            return tool
    return None


def _tools_for_group(scan_mode: str, group_name: str) -> list[str]:
    """Returns the candidate tool catalog for a capability label."""
    groups = get_worker_groups(mode=scan_mode)

    node_to_groups: dict[str, list[str]] = {
        "asset_discovery":        ["reconnaissance"],
        "threat_intel":           ["weaponization", "actions_on_objectives"],
        "risk_assessment":        ["exploitation", "delivery", "weaponization", "actions_on_objectives"],
        "governance":             ["command_control"],
        "executive_analyst":      ["reporting"],
        # Legacy aliases
        "reconhecimento":         ["reconnaissance"],
        "analise_vulnerabilidade": ["exploitation", "weaponization"],
    }

    target_groups = node_to_groups.get(group_name, [group_name])
    seen: set[str] = set()
    out: list[str] = []
    for g in target_groups:
        for t in (groups.get(g, {}).get("tools") or []):
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def _ordered_tools_for_step(scan_mode: str, group_name: str, step_name: str) -> list[str]:
    tools = _tools_for_group(scan_mode, group_name)
    primary_tool = _tool_for_step(step_name)
    if primary_tool and primary_tool in tools:
        return [primary_tool] + [tool for tool in tools if tool != primary_tool]
    if primary_tool and primary_tool not in tools:
        return [primary_tool] + tools
    return tools


def _step_name(state: AgentState) -> str:
    idx = state.get("mission_index", 0)
    items = state.get("mission_items", GROUP_MISSION_ITEMS)
    if idx >= len(items):
        return "done"
    return items[idx]


def _mark_step_metric(state: AgentState, success: bool) -> None:
    metrics = state.get("mission_metrics", {})
    metrics["steps_done"] = int(metrics.get("steps_done", 0)) + 1
    if success:
        metrics["steps_success"] = int(metrics.get("steps_success", 0)) + 1
    state["mission_metrics"] = metrics


def _register_tool_result_metric(state: AgentState, status: str) -> None:
    metrics = state.get("mission_metrics", {})
    metrics["tools_attempted"] = int(metrics.get("tools_attempted", 0)) + 1
    if status == "executed":
        metrics["tools_success"] = int(metrics.get("tools_success", 0)) + 1
    state["mission_metrics"] = metrics


# ─────────────────────────────────────────────────────────────
# Target helpers
# ─────────────────────────────────────────────────────────────

def _target_host(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = str(parsed.hostname or "").strip().lower()
    if not host:
        host = raw.split("/")[0].split(":")[0].strip().lower()
    return host.lstrip("*.").strip(".")


def _target_explicit_port(target: str) -> int | None:
    raw = str(target or "").strip()
    if not raw:
        return None
    try:
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        return parsed.port
    except ValueError:
        return None


def _infer_target_type(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return "dominio"

    has_scheme = "://" in raw
    parsed = urlparse(raw if has_scheme else f"http://{raw}")

    if parsed.path.rstrip("/") or parsed.query or parsed.fragment:
        return "site"

    if has_scheme:
        return "site"

    return "dominio"


def _is_local_target(target: str) -> bool:
    host = _target_host(target)
    return host in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def _adapt_recon_tools_for_target(target: str, tools: list[str]) -> list[str]:
    if not _is_local_target(target):
        return tools

    if _target_explicit_port(target):
        preferred = ["httpx", "katana", "curl-headers", "whatweb", "wafw00f"]
        filtered = [tool for tool in preferred if tool in tools]
        return filtered or [tool for tool in tools if tool in {"httpx", "katana", "curl-headers"}] or tools[:1]

    preferred = ["httpx", "katana", "gowitness", "naabu"]
    filtered = [tool for tool in preferred if tool in tools]
    return filtered or [tool for tool in tools if tool in {"httpx", "naabu"}] or tools[:1]


def _adapt_vuln_tools_for_target(target: str, tools: list[str]) -> list[str]:
    if not _is_local_target(target):
        return tools

    if _target_explicit_port(target):
        preferred = ["nuclei", "nikto", "wapiti", "dalfox", "sqlmap"]
        filtered = [tool for tool in preferred if tool in tools]
        if filtered:
            return filtered
        return tools[:3]

    preferred = ["nuclei", "nmap-vulscan", "nikto", "wapiti"]
    filtered = [tool for tool in preferred if tool in tools]
    if filtered:
        return filtered
    return tools[:3]


def _split_input_targets(raw_target: str) -> list[str]:
    raw = str(raw_target or "").strip()
    if not raw:
        return []

    targets: list[str] = []
    for token in re.split(r"[;,\n]", raw):
        value = str(token or "").strip()
        if value and value not in targets:
            targets.append(value)
    return targets


# ─────────────────────────────────────────────────────────────
# Port / network helpers
# ─────────────────────────────────────────────────────────────

def _extract_open_ports(result: dict[str, Any], step_name: str = "", tool_name: str = "") -> list[int]:
    raw_ports = result.get("open_ports")
    if isinstance(raw_ports, list):
        parsed = []
        for p in raw_ports:
            try:
                port = int(p)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                parsed.append(port)
        if parsed:
            return sorted(set(parsed))

    return []


def _extract_url_from_tool_line(line: str) -> str:
    """Extract a URL from raw or JSONL tool output without swallowing JSON fields."""
    raw = str(line or "").strip()
    if not raw:
        return ""

    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError, TypeError):
            data = None
        if isinstance(data, dict):
            for key in ("url", "input", "matched-at", "host"):
                value = str(data.get(key) or "").strip()
                if value.startswith(("http://", "https://")):
                    return value

    url_match = re.search(r"https?://[^\s\]\"'<>]+", raw)
    return url_match.group(0).rstrip(".,;") if url_match else ""


def _extract_port_service_evidence(result: dict[str, Any], tool_name: str = "") -> dict[int, dict[str, str]]:
    normalized_tool = str(tool_name or "").strip().lower()
    stdout = str(result.get("stdout") or "")
    command = _truncate_log(result.get("command"), 350)
    evidence: dict[int, dict[str, str]] = {}

    if normalized_tool in {"nmap", "nmap-vulscan", "vulscan"}:
        line_pattern = re.compile(r"^(?P<port>\d{1,5})/tcp\s+open\s+(?P<service>[a-zA-Z0-9\-_/\.]+)(?:\s+(?P<version>.*))?$")
        for raw in stdout.splitlines():
            line = str(raw or "").strip()
            match = line_pattern.match(line)
            if not match:
                continue
            try:
                port = int(match.group("port"))
            except Exception:
                continue
            if not (1 <= port <= 65535):
                continue
            service = str(match.group("service") or "").strip()
            version = str(match.group("version") or "").strip()
            evidence[port] = {
                "service": service,
                "version": version,
                "evidence": line,
                "command": command,
                "tool": normalized_tool,
            }

    if normalized_tool == "naabu":
        for raw in stdout.splitlines():
            line = str(raw or "").strip()
            match = re.search(r":(\d{1,5})\b", line)
            if not match:
                continue
            try:
                port = int(match.group(1))
            except Exception:
                continue
            if not (1 <= port <= 65535):
                continue
            if port not in evidence:
                evidence[port] = {
                    "service": "",
                    "version": "",
                    "evidence": line,
                    "command": command,
                    "tool": "naabu",
                }

    if normalized_tool in {"httpx", "whatweb"}:
        for raw in stdout.splitlines():
            line = str(raw or "").strip()
            if not line:
                continue
            url_raw = _extract_url_from_tool_line(line)
            if not url_raw:
                continue
            parsed = urlparse(url_raw)
            try:
                port = parsed.port
            except ValueError:
                continue
            if port is None and parsed.scheme == "https":
                port = 443
            elif port is None:
                port = 80
            if not (1 <= int(port) <= 65535):
                continue

            service = "https" if parsed.scheme == "https" else "http"
            version = ""
            if normalized_tool == "whatweb":
                server_match = re.search(r"Server\[([^\]]+)\]", line)
                if server_match:
                    version = str(server_match.group(1) or "").strip()

            if int(port) not in evidence:
                evidence[int(port)] = {
                    "service": service,
                    "version": version,
                    "evidence": line,
                    "command": command,
                    "tool": normalized_tool,
                }

    if normalized_tool == "nikto":
        target_port: int | None = None
        target_proto = ""
        target_host = ""
        for raw in stdout.splitlines():
            line = str(raw or "").strip()
            if not line:
                continue
            port_match = re.search(r"(?i)^\+\s*Target\s+Port:\s*(\d{1,5})\b", line)
            if port_match:
                try:
                    parsed_port = int(port_match.group(1))
                    if 1 <= parsed_port <= 65535:
                        target_port = parsed_port
                except Exception:
                    pass
            host_match = re.search(r"(?i)^\+\s*Target\s+Host(?:name)?:\s*(.+)$", line)
            if host_match:
                target_host = str(host_match.group(1) or "").strip()
            proto_match = re.search(r"(?i)^\+\s*Target\s+IP:\s*\S+\s*\(([^\)]+)\)", line)
            if proto_match:
                target_proto = str(proto_match.group(1) or "").strip().lower()

        if target_port is not None and target_port not in evidence:
            service = "https" if target_port == 443 or "https" in target_proto else "http"
            summary = f"Nikto target={target_host or '-'} port={target_port}"
            evidence[target_port] = {
                "service": service,
                "version": "",
                "evidence": summary,
                "command": command,
                "tool": "nikto",
            }

    return evidence


# ─────────────────────────────────────────────────────────────
# Asset discovery helpers
# ─────────────────────────────────────────────────────────────

def _extract_assets_from_result(result: dict[str, Any], root_domain: str) -> list[str]:
    scope = str(root_domain or "").strip().lower().lstrip("*.").strip(".")
    if not scope:
        return []

    text = "\n".join(
        [
            str(result.get("stdout") or ""),
            str(result.get("output") or ""),
        ]
    )
    if not text.strip():
        return []

    host_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
    candidates: set[str] = set()
    for match in host_pattern.findall(text):
        host = str(match or "").strip().lower().strip(".")
        if not host:
            continue
        if host == scope or host.endswith(f".{scope}"):
            candidates.add(host)

    return sorted(candidates)


def _register_discovered_assets(state: AgentState, root_domain: str, assets: list[str]) -> None:
    scope = str(root_domain or "").strip().lower().lstrip("*.").strip(".")
    if not scope:
        return

    current_assets = list(state.get("lista_ativos") or [])
    pending = list(state.get("pending_asset_scans") or [])
    scanned = set(state.get("scanned_assets") or [])

    eligible = [asset for asset in assets if asset and asset != scope]
    if not eligible:
        return

    added_assets = 0
    added_pending = 0
    for asset in sorted(set(eligible))[:MAX_DISCOVERED_ASSETS]:
        if asset not in current_assets:
            current_assets.append(asset)
            added_assets += 1
        if asset not in pending and asset not in scanned:
            pending.append(asset)
            added_pending += 1

    state["lista_ativos"] = current_assets
    state["pending_asset_scans"] = pending
    state["logs_terminais"].append(
        f"ReconNode: subdomains_discovered={len(eligible)} ativos_adicionados={added_assets} fila_scan={added_pending}"
    )


def _persist_discovered_assets_to_db(scan_job_id: int, owner_id: int, assets: list[str], source_tool: str = "recon") -> int:
    """Persiste subdomínios descobertos na tabela Asset do banco de dados."""
    try:
        from app.db.session import SessionLocal
        from app.models.models import Asset
        from datetime import datetime

        _db = SessionLocal()
        try:
            inserted_count = 0
            now = datetime.utcnow()

            for asset_str in (assets or []):
                domain_normalized = str(asset_str or "").strip().lower()
                if not domain_normalized:
                    continue

                try:
                    existing = _db.query(Asset).filter(
                        Asset.owner_id == owner_id,
                        Asset.domain_or_ip == domain_normalized,
                    ).first()

                    if existing:
                        existing.last_seen = now
                        existing.last_scan_id = scan_job_id
                        existing.scan_count = (existing.scan_count or 0) + 1
                    else:
                        new_asset = Asset(
                            owner_id=owner_id,
                            domain_or_ip=domain_normalized,
                            asset_type="domain",
                            first_seen=now,
                            last_seen=now,
                            last_scan_id=scan_job_id,
                            scan_count=1,
                        )
                        _db.add(new_asset)
                        inserted_count += 1
                except Exception:
                    continue

            _db.commit()
            return inserted_count
        finally:
            _db.close()
    except Exception:
        return 0


# ─────────────────────────────────────────────────────────────
# DB execution tracking
# ─────────────────────────────────────────────────────────────

def _has_tool_run_in_db(scan_id: int, tool_name: str, target: str) -> bool:
    """Verifica se ferramenta já teve execução bem-sucedida para este target neste scan."""
    try:
        from app.db.session import SessionLocal
        from app.models.models import ExecutedToolRun

        db = SessionLocal()
        try:
            existing = db.query(ExecutedToolRun).filter(
                ExecutedToolRun.scan_job_id == scan_id,
                ExecutedToolRun.tool_name == tool_name.lower(),
                ExecutedToolRun.target == target.lower(),
                ExecutedToolRun.status == "success",
            ).first()
            return existing is not None
        finally:
            db.close()
    except Exception:
        logger.exception("Falha ao verificar execução idempotente da ferramenta")
        return False


def _record_tool_execution_in_db(scan_id: int, tool_name: str, target: str, execution_status: str = "success", error_msg: str | None = None, exec_time: float | None = None) -> None:
    """Registra execução da ferramenta no banco para idempotência."""
    try:
        from app.db.session import SessionLocal
        from app.models.models import ExecutedToolRun
        from datetime import datetime

        db = SessionLocal()
        try:
            normalized_tool = tool_name.lower()
            normalized_target = target.lower()
            existing = db.query(ExecutedToolRun).filter(
                ExecutedToolRun.scan_job_id == scan_id,
                ExecutedToolRun.tool_name == normalized_tool,
                ExecutedToolRun.target == normalized_target,
            ).first()

            if existing:
                existing.status = execution_status
                existing.error_message = error_msg
                existing.execution_time_seconds = exec_time
                existing.created_at = datetime.utcnow()
            else:
                record = ExecutedToolRun(
                    scan_job_id=scan_id,
                    tool_name=normalized_tool,
                    target=normalized_target,
                    status=execution_status,
                    error_message=error_msg,
                    execution_time_seconds=exec_time,
                    created_at=datetime.utcnow(),
                )
                db.add(record)
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.exception("Falha ao registrar execução da ferramenta")


# ─────────────────────────────────────────────────────────────
# Validation / target resolution helpers
# ─────────────────────────────────────────────────────────────

def _validate_osint_targets(targets: list[str]) -> list[str]:
    import ipaddress

    valid = []
    for target in (targets or []):
        if not target or not isinstance(target, str):
            continue

        target_str = str(target).strip().lower()
        if not target_str or target_str in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
            continue

        try:
            ipaddress.ip_address(target_str.split("/")[0])
            valid.append(target_str)
            continue
        except ValueError:
            pass

        if "." in target_str and len(target_str) > 4:
            if (not target_str.startswith(".") and not target_str.endswith(".") and
                    all(c.isalnum() or c in ".-" for c in target_str)):
                valid.append(target_str)

    return valid


def _normalize_host_for_resolution(target: str) -> str:
    raw = str(target or "").strip().lower()
    if not raw:
        return ""
    try:
        if "://" in raw:
            parsed = urlparse(raw)
            return str(parsed.hostname or "").strip().lower()
    except Exception:
        pass
    return raw.split("/")[0].split(":")[0].strip().lower()


def _is_target_resolvable(target: str) -> bool:
    host = _normalize_host_for_resolution(target)
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return False
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def _filter_resolvable_targets(targets: list[str]) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    for target in targets or []:
        if _is_target_resolvable(target):
            valid.append(target)
        else:
            invalid.append(target)
    return valid, invalid


def _scope_compare_host(target: str) -> str:
    parsed = urlparse(str(target or "") if "://" in str(target or "") else f"http://{target}")
    host = (parsed.hostname or "").strip().lower()
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}:
        return "local"
    return host


def _base_url_for_target(target: str) -> str:
    raw = str(target or "").strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = parsed.hostname or raw.split("/")[0]
    if not host:
        return raw
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return f"{parsed.scheme or 'http'}://{netloc}/"


def _normalize_discovered_url(raw_value: Any, root: str) -> str:
    raw = str(raw_value or "").strip().strip("'\"<>")
    raw = raw.rstrip(".,);]")
    if not raw:
        return ""
    if raw.startswith("//"):
        raw = f"http:{raw}"
    elif raw.startswith("/"):
        raw = urljoin(_base_url_for_target(root), raw)
    elif not re.match(r"^https?://", raw, flags=re.IGNORECASE):
        return ""

    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""

    root_host = _scope_compare_host(root)
    url_host = _scope_compare_host(raw)
    if root_host and url_host and root_host != url_host:
        return ""

    return raw.split("#", 1)[0]


def _collect_url_strings(value: Any, out: list[str]) -> None:
    if value is None:
        return
    if isinstance(value, str):
        out.extend(re.findall(r"https?://[^\s'\"<>]+", value))
        if value.startswith("/"):
            out.append(value)
        return
    if isinstance(value, dict):
        for nested in value.values():
            _collect_url_strings(nested, out)
        return
    if isinstance(value, (list, tuple, set)):
        for nested in value:
            _collect_url_strings(nested, out)


def _is_parameterized_url(url: str) -> bool:
    parsed = urlparse(str(url or "") if "://" in str(url or "") else f"http://{url}")
    return bool(parsed.query and "=" in parsed.query)


def _is_interesting_validation_path(url: str) -> bool:
    parsed = urlparse(str(url or "") if "://" in str(url or "") else f"http://{url}")
    path = (parsed.path or "").lower()
    if _is_parameterized_url(url):
        return True
    tokens = (
        "/api/", "/rest/", "/admin", "/login", "/user", "/users", "/basket",
        "/cart", "/order", "/ftp", "backup", ".bak", ".old", ".zip", ".sql",
        ".env", ".kdbx", "package.json", "package-lock.json", "node_modules",
    )
    return any(token in path for token in tokens)


def _discovered_validation_targets(state: AgentState, root: str, limit: int = 40) -> list[str]:
    raw_values: list[str] = []
    for finding in list(state.get("vulnerabilidades_encontradas") or []):
        if not isinstance(finding, dict):
            continue
        details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
        for key in (
            "discovered_urls",
            "sensitive_urls",
            "candidate_urls",
            "robots_urls",
            "sitemap_urls",
            "urls",
            "endpoints",
            "evidence",
            "discovered_paths",
            "sensitive_paths",
            "exposed_artifacts",
            "exposed_source_paths",
            "sensitive_api_urls",
            "redirect_candidate_urls",
        ):
            _collect_url_strings(details.get(key), raw_values)

    normalized: list[str] = []
    for raw in raw_values:
        url = _normalize_discovered_url(raw, root)
        if url and _is_interesting_validation_path(url) and url not in normalized:
            normalized.append(url)

    normalized.sort(
        key=lambda item: (
            0 if _is_parameterized_url(item) else 1,
            0 if "/rest/" in item.lower() or "/api/" in item.lower() else 1,
            len(item),
        )
    )
    return normalized[: max(1, limit)]


def _targets_for_deep_scan(state: AgentState, limit: int = 8) -> list[str]:
    root = str(state.get("target") or "").strip()
    candidates: list[str] = []
    if root:
        for token in re.split(r"[;,]", root):
            value = str(token or "").strip()
            if value and value not in candidates:
                candidates.append(value)

    for asset in list(state.get("scanned_assets") or []):
        host = str(asset or "").strip()
        if host and host not in candidates:
            candidates.append(host)

    for asset in list(state.get("pending_asset_scans") or []):
        host = str(asset or "").strip()
        if host and host not in candidates:
            candidates.append(host)

    for url in _discovered_validation_targets(state, root, limit=limit * 6):
        if url and url not in candidates:
            candidates.append(url)

    return candidates[: max(1, limit)]


def _tools_for_validation_target(scan_target: str, tools: list[str]) -> list[str]:
    """Avoid running path-fuzzers against full query URLs."""
    if not _is_parameterized_url(scan_target):
        return tools
    preferred = {"sqlmap", "dalfox", "wapiti", "nuclei", "arjun", "curl-headers"}
    selected = [tool for tool in tools if tool in preferred]
    return selected or tools


# ─────────────────────────────────────────────────────────────
# WAF false positive filter
# ─────────────────────────────────────────────────────────────

def _suppress_waf_proxy_false_positives(
    findings: list[dict[str, Any]],
    step_name: str,
    default_target: str,
) -> list[dict[str, Any]]:
    if not findings:
        return findings

    waf_vendors: set[str] = set()
    header_blob_parts: list[str] = []
    nmap_vulscan_cve_findings: list[dict[str, Any]] = []
    evidence_blob_parts: list[str] = []

    for item in findings:
        details = item.get("details") or {}
        tool = str(details.get("tool") or "").strip().lower()

        if tool == "wafw00f" and details.get("waf_detected"):
            vendor = str(details.get("waf_vendor") or "").strip().lower()
            if vendor:
                waf_vendors.add(vendor)

        if tool == "curl-headers":
            raw_headers = str(details.get("http_headers_raw") or "")
            if raw_headers:
                header_blob_parts.append(raw_headers.lower())

        if tool == "nmap-vulscan" and details.get("cve"):
            nmap_vulscan_cve_findings.append(item)
            evidence = str(details.get("evidence") or "").lower()
            if evidence:
                evidence_blob_parts.append(evidence)

    if not nmap_vulscan_cve_findings:
        return findings

    if not waf_vendors:
        return findings

    header_blob = "\n".join(header_blob_parts)
    evidence_blob = "\n".join(evidence_blob_parts)

    header_indicates_waf = any(
        token in header_blob
        for token in ["server: cloudflare", "cf-ray", "cf-cache-status", "__cf_bm", "cloudflare"]
    )
    evidence_indicates_proxy = any(
        token in evidence_blob
        for token in ["cloudflare", "http proxy", "reverse proxy", "proxy"]
    )

    known_waf = any(model in " ".join(sorted(waf_vendors)) for model in KNOWN_WAF_MODELS)

    should_suppress = header_indicates_waf and known_waf and evidence_indicates_proxy
    if not should_suppress:
        return findings

    filtered_findings = [
        item
        for item in findings
        if not (
            str((item.get("details") or {}).get("tool") or "").strip().lower() == "nmap-vulscan"
            and bool((item.get("details") or {}).get("cve"))
        )
    ]

    filtered_findings.append(
        {
            "title": "nmap-vulscan suprimido por possivel falso positivo de WAF/proxy",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "analise_vulnerabilidade",
            "details": {
                "node": "vuln",
                "step": step_name,
                "asset": default_target,
                "tool": "wafw00f",
                "waf_detected": True,
                "waf_vendors": sorted(waf_vendors),
                "header_validated": True,
                "suppressed_tool": "nmap-vulscan",
                "suppressed_cve_count": len(nmap_vulscan_cve_findings),
                "reason": "target protegido por WAF/proxy (ex.: Cloudflare) com comportamento de resposta em portas/proxy que gera CVEs nao aplicaveis",
            },
        }
    )

    return filtered_findings


# ─────────────────────────────────────────────────────────────
# Core tool execution engine
# ─────────────────────────────────────────────────────────────

def _run_tools_and_collect(
    state: AgentState,
    tools: list[str],
    scan_target: str,
    step_name: str,
    log_prefix: str,
    root_domain: str = "",
    skill_context: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[int], list[str], dict[int, dict[str, str]]]:
    """Runs the given tools against `scan_target` with parallel dispatch."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from time import perf_counter
    # Import autonomy helpers lazily to avoid circular import at module level
    from app.graph.nodes.supervisor import (
        _append_action,
        _append_observation,
        _append_error,
        _update_tool_runtime_metrics,
    )

    all_findings: list[dict[str, Any]] = []
    discovered_ports: set[int] = set()
    discovered_assets: set[str] = set()
    port_evidence: dict[int, dict[str, str]] = {}
    step_success = False
    skill_context = dict(skill_context or {})
    skill_id = str(skill_context.get("skill_id") or "").strip()

    # 1) Skip tools already executed (in-state or in-DB).
    # Dedup key is `tool|target` (NOT step_name|target|tool) because the
    # supervisor rotates skills/iterations and the step_name changes each
    # iteration — using step_name as part of the key was causing wpscan to
    # re-run 3x in scan #14 against the same target with different steps.
    # Same target + same tool = identical work, regardless of which skill
    # triggered it.
    pending_tools: list[str] = []
    scan_id = state.get("scan_id")
    for tool in tools:
        run_key_global = f"{tool}|{scan_target}".lower()
        run_id_step = f"{step_name}|{scan_target}|{tool}".lower()  # kept for legacy logs
        runs_so_far = state.get("executed_tool_runs", []) or []
        already_in_state = any(
            r.lower().endswith(f"|{scan_target.lower()}|{tool.lower()}") for r in runs_so_far
        ) or run_key_global in runs_so_far
        if already_in_state:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} skipped=already_executed_this_scan")
            continue
        if scan_id and _has_tool_run_in_db(scan_id, tool, scan_target):
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} skipped=already_in_database")
            state["executed_tool_runs"].append(run_key_global)
            continue
        pending_tools.append(tool)

    if not pending_tools:
        return all_findings, sorted(discovered_ports), sorted(discovered_assets), port_evidence

    # 2) Dispatch in parallel
    state["logs_terminais"].append(
        f"{log_prefix}: dispatching {len(pending_tools)} tools in parallel: {', '.join(pending_tools)}"
    )

    # Per-tool extra_args derived from the selected technique. The supervisor
    # may have populated tactic.extra_args (e.g. `--dbms=mssql` for sqlmap on
    # ASP/MSSQL stacks) via the tech-stack auto-lock. We thread that down to
    # the Kali runner so the materialised command reflects the strategy.
    technique_extra_args_by_tool: dict[str, list[str]] = {}
    raw_tech_args = (skill_context.get("technique") or {}).get("extra_args") or {}
    if isinstance(raw_tech_args, dict):
        for key, value in raw_tech_args.items():
            if isinstance(value, list):
                technique_extra_args_by_tool[str(key).strip().lower()] = [str(v) for v in value]
    contract_extra_args = (skill_context.get("skill_contract") or {}).get("extra_args") or {}
    if isinstance(contract_extra_args, dict):
        for key, value in contract_extra_args.items():
            if isinstance(value, list):
                technique_extra_args_by_tool.setdefault(str(key).strip().lower(), [str(v) for v in value])

    def _dispatch_one(tool: str) -> tuple[str, dict, float]:
        exec_start = perf_counter()
        tool_args = technique_extra_args_by_tool.get(str(tool).strip().lower(), [])
        try:
            r = execute_tool_with_workers(
                tool,
                scan_target,
                scan_mode=state["scan_mode"],
                scan_id=scan_id if isinstance(scan_id, int) else None,
                skill_id=skill_id or None,
                skill_contract=dict(skill_context.get("skill_contract") or {}),
                technique=dict(skill_context.get("technique") or {}),
                evidence_required=list(skill_context.get("evidence_required") or []),
                constraints=list(skill_context.get("constraints") or []),
                playbook=str(skill_context.get("playbook_title") or ""),
                extra_args=tool_args,
            )
        except Exception as exc:
            r = {"status": "error", "dispatch_error": f"{type(exc).__name__}: {exc}"}
        return tool, r, perf_counter() - exec_start

    completions: list[tuple[str, dict, float]] = []
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix=f"tool-{log_prefix}") as ex:
        future_map = {ex.submit(_dispatch_one, t): t for t in pending_tools}
        for fut in as_completed(future_map):
            try:
                completions.append(fut.result())
            except Exception as exc:
                t = future_map[fut]
                completions.append((t, {"status": "error", "dispatch_error": str(exc)}, 0.0))

    # 3) Serial post-processing — mutates state safely
    for tool, result, exec_time in completions:
        run_id = f"{step_name}|{scan_target}|{tool}".lower()
        _sync_step_to_db(state, f"{step_name} · {tool}")
        _append_action(
            state,
            "tool_start",
            {
                "tool": tool,
                "target": scan_target,
                "step": step_name,
                "group": log_prefix,
                "skill_id": skill_id,
                "skill_invocation_id": skill_context.get("skill_invocation_id"),
                "technique": (skill_context.get("technique") or {}).get("name"),
            },
        )
        if skill_id:
            result.setdefault("skill_id", skill_id)
            result.setdefault("skill_invocation_id", skill_context.get("skill_invocation_id"))
            result.setdefault("technique", (skill_context.get("technique") or {}).get("name"))
        state["executed_tool_runs"].append(run_id)

        raw_command = str(result.get("command") or "").strip()
        raw_return_code = result.get("return_code")
        raw_stdout = str(result.get("stdout") or "").strip()
        raw_stderr = str(result.get("stderr") or "").strip()
        raw_dispatch_error = str(result.get("dispatch_error") or "").strip()

        execution_blob_parts: list[str] = []
        if raw_command:
            execution_blob_parts.append(f"command={raw_command}")
        if raw_return_code is not None:
            execution_blob_parts.append(f"return_code={raw_return_code}")
        if raw_dispatch_error:
            execution_blob_parts.append(f"dispatch_error={raw_dispatch_error}")
        if raw_stdout:
            execution_blob_parts.append(f"stdout:\n{raw_stdout}")
        if raw_stderr:
            execution_blob_parts.append(f"stderr:\n{raw_stderr}")
        execution_blob = "\n\n".join(execution_blob_parts)

        if scan_id:
            exec_status = result.get("status", "unknown")
            if exec_status == "executed":
                db_status = "success"
            elif exec_status == "skipped":
                db_status = "skipped"
            else:
                db_status = "failed"
            _record_tool_execution_in_db(
                scan_id=scan_id,
                tool_name=tool,
                target=scan_target,
                execution_status=db_status,
                error_msg=_truncate_log(execution_blob, 12000) if execution_blob else None,
                exec_time=exec_time,
            )

        state["logs_terminais"].append(f"{log_prefix}: tool={tool} status={result.get('status', 'unknown')}")
        if result.get("source_agent_name"):
            state["logs_terminais"].append(
                f"{log_prefix}: tool={tool} agent={result.get('source_agent_name')}"
            )
        if result.get("source_agent_id"):
            state["logs_terminais"].append(
                f"{log_prefix}: tool={tool} agent_id={result.get('source_agent_id')}"
            )
        if result.get("dispatch_task_name"):
            state["logs_terminais"].append(
                f"{log_prefix}: tool={tool} dispatch_task={result.get('dispatch_task_name')}"
            )
        if result.get("dispatch_task_id"):
            state["logs_terminais"].append(
                f"{log_prefix}: tool={tool} dispatch_id={result.get('dispatch_task_id')}"
            )
        if result.get("dispatch_error"):
            state["logs_terminais"].append(
                f"{log_prefix}: tool={tool} dispatch_error={_truncate_log(result.get('dispatch_error'), 220)}"
            )
            _append_error(
                state,
                f"tool={tool} dispatch_error={_truncate_log(result.get('dispatch_error'), 220)}",
                source=log_prefix,
            )
        _register_tool_result_metric(state, str(result.get("status") or ""))
        _update_tool_runtime_metrics(state, tool=tool, status=str(result.get("status") or ""))
        if result.get("status") == "executed":
            step_success = True
            _append_observation(
                state,
                f"tool={tool} target={scan_target} executed em {round(exec_time, 2)}s",
                source=log_prefix,
            )
        else:
            _append_error(
                state,
                f"tool={tool} target={scan_target} status={result.get('status', 'unknown')}",
                source=log_prefix,
            )

        cmd = _truncate_log(result.get("command"))
        if cmd:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} cmd={cmd}")

        rc = result.get("return_code")
        if rc is not None:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} return_code={rc}")

        preview_limit = 300

        stdout_preview = _truncate_log(result.get("stdout"), preview_limit)
        if stdout_preview:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} stdout={stdout_preview}")

        stderr_preview = _truncate_log(result.get("stderr"), preview_limit)
        if stderr_preview:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} stderr={stderr_preview}")

        tool_specific_findings = _extract_tool_output_findings(result, step_name, scan_target)
        # Backend-local tools (code-analyzer) ship findings inside the dict
        # directly — bypass the regex parsers since the analyzer already
        # produced structured items via convert_to_findings().
        extracted_local = list(result.get("findings_extracted") or [])
        if extracted_local:
            tool_specific_findings = list(tool_specific_findings or []) + extracted_local
        if tool_specific_findings:
            all_findings.extend(tool_specific_findings)
            _append_observation(
                state,
                f"tool={tool} generated_findings={len(tool_specific_findings)}",
                source=log_prefix,
            )
            state["logs_terminais"].append(
                f"{log_prefix}: tool={tool} tool_findings={len(tool_specific_findings)}"
            )
        extracted_ports = _extract_open_ports(result, step_name=step_name, tool_name=tool)
        for port in extracted_ports:
            discovered_ports.add(port)

        for port, evidence in _extract_port_service_evidence(result, tool_name=tool).items():
            if port not in port_evidence:
                port_evidence[port] = evidence
            else:
                existing = port_evidence.get(port, {})
                if not existing.get("version") and evidence.get("version"):
                    existing["version"] = evidence.get("version", "")
                if not existing.get("service") and evidence.get("service"):
                    existing["service"] = evidence.get("service", "")
                if not existing.get("evidence") and evidence.get("evidence"):
                    existing["evidence"] = evidence.get("evidence", "")
                if not existing.get("command") and evidence.get("command"):
                    existing["command"] = evidence.get("command", "")
                port_evidence[port] = existing

        for asset in _extract_assets_from_result(result, root_domain=root_domain):
            discovered_assets.add(asset)

    all_findings = _suppress_waf_proxy_false_positives(
        all_findings,
        step_name=step_name,
        default_target=scan_target,
    )
    try:
        from app.services.vulnerability_learning_service import enrich_findings_with_accepted_learning

        all_findings = enrich_findings_with_accepted_learning(all_findings)
    except Exception:
        pass

    _mark_step_metric(state, step_success)
    return all_findings, sorted(discovered_ports), sorted(discovered_assets), port_evidence


# ─────────────────────────────────────────────────────────────
# Node imports (lazy via the node modules)
# Import here so workflow.py can expose them for re-export
# ─────────────────────────────────────────────────────────────
from app.graph.nodes.supervisor import (
    _count_high_signal_findings,
    _has_verified_or_strong_evidence,
    _route_from_supervisor,
    _append_autonomy_entry,
    _append_note,
    _append_todo,
    _append_action,
    _append_observation,
    _append_error,
    _refresh_active_skills,
    _register_delegation_task,
    _complete_delegation_task,
    _update_execution_guardrails,
    _rank_tools_for_iteration,
    _default_skill_playbook,
    _build_skill_playbook_for_context,
    _invoke_skill_for_context,
    _select_tool_batch_for_iteration,
    _update_tool_runtime_metrics,
    _find_node_with_uncovered_tools,
    _select_skill_for_capability,
    supervisor_node,
)

from app.graph.nodes.skill_pipeline import (
    rag_enrichment_node,
    _bootstrap_skill_group,
    _candidate_tools_for_skill_bootstrap,
    skill_selector_node,
    skill_planner_node,
    _technique_for_selected_tool,
    tool_selector_node,
    _targets_for_tool_pipeline,
    _apply_tool_execution_findings,
    tool_executor_node,
    evidence_gate_node,
    _evaluate_evidence_gate,
)

from app.graph.nodes.reporting import (
    governance_node,
    executive_analyst_node,
    _fallback_executive_summary,
)


# ─────────────────────────────────────────────────────────────
# Graph builder
# ─────────────────────────────────────────────────────────────

def build_graph(mode: ScanMode = "unit"):
    """Single-Agent Meta-Everything (Supervisor-Centric) LangGraph."""
    graph = StateGraph(AgentState)

    graph.add_node("rag_enrichment", rag_enrichment_node)
    graph.add_node("skill_selector", skill_selector_node)
    graph.add_node("skill_planner", skill_planner_node)
    graph.add_node("tool_selector", tool_selector_node)
    graph.add_node("tool_executor", tool_executor_node)
    graph.add_node("evidence_gate", evidence_gate_node)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("governance",        governance_node)
    graph.add_node("executive_analyst", executive_analyst_node)

    graph.set_entry_point("rag_enrichment")
    graph.add_edge("rag_enrichment", "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        _route_from_supervisor,
        {
            "skill_selector": "skill_selector",
            "governance": "governance",
            "executive_analyst": "executive_analyst",
            END: END,
        },
    )
    graph.add_edge("skill_selector", "skill_planner")
    graph.add_edge("skill_planner", "tool_selector")
    graph.add_edge("tool_selector", "tool_executor")
    graph.add_edge("tool_executor", "evidence_gate")
    graph.add_edge("evidence_gate", "supervisor")

    for node_name in ["governance", "executive_analyst"]:
        graph.add_edge(node_name, "supervisor")

    return graph.compile(checkpointer=checkpointer)


def initial_state(
    scan_id: int,
    owner_id: int,
    target: str,
    scan_mode: ScanMode = "unit",
    known_vulnerability_patterns: list[str] | None = None,
    segment: str | None = None,
) -> AgentState:
    parsed_targets = _split_input_targets(target)
    primary_target = parsed_targets[0] if parsed_targets else str(target or "").strip()
    target_type = _infer_target_type(primary_target)

    mission_items = GROUP_MISSION_ITEMS.copy()
    trace_id = str(uuid4())
    initial_skills = select_mission_skills(
        target=primary_target,
        findings=[],
        target_type=target_type,
        discovered_ports=[],
        max_skills=5,
    )
    # Exhaustive sweep: each stage runs EVERY applicable tool before
    # advancing (recon ~6 batches, vuln-analysis ~3, exploitation ~4),
    # plus governance/executive. 18 was too tight and forced premature
    # finalize while RECON still had subdomain-enum pending.
    max_iterations = 45
    mission_contract = build_autonomous_mission_contract(max_iterations=max_iterations)
    return {
        "trace_id": trace_id,
        "scan_id": scan_id,
        "owner_id": owner_id,
        "target": primary_target,
        "scan_mode": scan_mode,
        "target_type": target_type,
        "easm_segment": segment or "Digital Services",
        "input_targets": parsed_targets or ([primary_target] if primary_target else []),
        "lista_ativos": [],
        "logs_terminais": [],
        "vulnerabilidades_encontradas": [],
        "proxima_ferramenta": "skill_selector",
        "discovered_ports": [],
        "pending_port_tests": [],
        "pending_asset_scans": [],
        "scanned_assets": [],
        "discovered_subdomains_persisted": [],
        "port_followup_done": False,
        "activity_metrics": [],
        "mission_metrics": {
            "steps_done": 0,
            "steps_success": 0,
            "tools_attempted": 0,
            "tools_success": 0,
        },
        "node_history": [],
        "mission_index": 0,
        "mission_items": mission_items,
        "known_vulnerability_patterns": known_vulnerability_patterns or [],
        "executed_tool_runs": [],
        "analyst_framework": {
            "name": "senior-cyber-analyst-framework",
            "version": "2026.04",
            "confidence_thresholds": ANALYST_CONFIDENCE_THRESHOLDS,
            "prompt_contract": build_supervisor_prompt_contract(
                target=primary_target,
                objective=f"Assess external attack surface and exploitable risk for {primary_target}",
                max_iterations=max_iterations,
                active_skills=initial_skills,
            ),
            "mission_contract": mission_contract,
        },
        "operation_plan": {},
        "confidence_state": {
            "global_confidence": 60,
            "reason": "initial_state",
            "last_updated": datetime.utcnow().isoformat(),
        },
        "evidence_contract": {
            "rules": EVIDENCE_RULES,
            "status_values": ["hypothesis", "unverified", "verified"],
        },
        "completed_capabilities": [],
        "loop_iteration": 0,
        "max_iterations": max_iterations,
        "objective_met": False,
        "termination_reason": "",
        "routing_next_node": "skill_selector",
        "pending_capability_node": "",
        "current_phase": "",
        "last_completed_node": "",
        "agent_validation": {},
        "active_skills": initial_skills,
        "active_skill": "",
        "current_skill": "",
        "skill_selector_ready": False,
        "skill_selector_gate": {},
        "skill_invocation": {},
        "skill_contract": {},
        "skill_plan_contract": {},
        "skill_invocations": [],
        "selected_skill": {},
        "capability_context": {},
        "tool_selection_contract": {},
        "tool_execution_results": [],
        "pentest_strategy": {},
        "pending_pentest_tactic": {},
        "pentest_tactics_completed": [],
        "delegated_tasks": [],
        "delegation_log": [],
        "autonomy_notes": [],
        "autonomy_todos": [],
        "autonomy_actions": [],
        "autonomy_observations": [],
        "autonomy_errors": [],
        "execution_control": {
            "last_findings_total": 0,
            "no_progress_iterations": 0,
            "approaching_limit": False,
            "remaining_iterations": max_iterations,
        },
        "tool_runtime": {},
        "validation_backlog": [],
        "detected_tech_stack": [],
        "tech_stack_signature": "",
        "kill_chain_stage": "RECONNAISSANCE",
        "pentest_phase_index": 0,
        "pentest_hypotheses": [],
        # Rating fields (preenchidos pelos agents 4 e 5)
        "asset_fingerprints": {},
        "fair_decomposition": {},
        "easm_rating": {},
        "executive_summary": "",
    }
