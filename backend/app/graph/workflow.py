import json
import re
from datetime import datetime
from time import perf_counter
from typing import Any, TypedDict
from urllib.parse import urlparse

from langgraph.graph import END, StateGraph

from app.graph.checkpointer import create_checkpointer
from app.services.risk_service import (
    build_fair_decomposition,
    compute_easm_rating,
    compute_asset_risk,
    METHODOLOGY_VERSION,
)
from app.services.worker_dispatcher import execute_tool_with_workers
from app.workers.worker_groups import ScanMode, get_worker_groups


def _sync_step_to_db(state: "AgentState", step_label: str) -> None:
    """Persiste current_step e mission_index no ScanJob durante execução do grafo.

    Chamado no início de cada node para que o frontend veja progresso em tempo
    real, sem depender do pulse thread.
    """
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
                # Snapshot mínimo para o frontend consultar via /status
                sd = dict(job.state_data or {})
                sd["mission_index"] = mi
                sd["mission_items"] = mission_items
                sd["burp_status"] = state.get("burp_status", "none")
                job.state_data = sd
                _db.commit()
        finally:
            _db.close()
    except Exception:
        pass  # Não pode bloquear o pipeline por falha de IO

# EASM pipeline
GROUP_MISSION_ITEMS: list[str] = [
    "1. AssetDiscovery",
    "2. ThreatIntel",
    "3. RiskAssessment",
    "4. Governance",
    "5. ExecutiveAnalysis",
]

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
    "google cloud armor",
    "google cloud app armor",
]

WAF_VENDOR_ALIASES: list[tuple[str, tuple[str, ...]]] = [
    ("Cloudflare", ("cloudflare",)),
    ("Akamai", ("akamai",)),
    ("Imperva", ("imperva", "incapsula")),
    ("ModSecurity", ("modsecurity", "mod_security")),
    ("F5", ("f5", "big-ip asm", "bigip asm")),
    ("AWS WAF", ("aws waf", "amazon waf", "amazon web application firewall")),
    ("Barracuda", ("barracuda",)),
    ("FortiWeb", ("fortiweb",)),
    ("Google Cloud Armor", ("google cloud armor", "google cloud app armor", "app armor (google cloud)", "gcp armor")),
]


def _sanitize_cli_text(value: str | None) -> str:
    if not value:
        return ""
    sanitized = str(value)
    sanitized = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", sanitized)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def _normalize_waf_vendor(value: str | None) -> str:
    blob = _sanitize_cli_text(value).lower()
    if not blob:
        return ""
    for canonical, aliases in WAF_VENDOR_ALIASES:
        if any(alias in blob for alias in aliases):
            return canonical
    for model in KNOWN_WAF_MODELS:
        if model in blob:
            return model.title()
    return ""


class AgentState(TypedDict):
    scan_id: int
    target: str
    scan_mode: str                          # "unit" | "scheduled"
    easm_segment: str                       # Segmento de mercado inferido
    input_targets: list[str]
    lista_ativos: list[str]
    logs_terminais: list[str]
    vulnerabilidades_encontradas: list[dict[str, Any]]
    proxima_ferramenta: str
    discovered_ports: list[int]
    pending_port_tests: list[int]
    pending_asset_scans: list[str]
    scanned_assets: list[str]
    port_followup_done: bool
    activity_metrics: list[dict[str, Any]]
    mission_metrics: dict[str, int]
    node_history: list[str]
    mission_index: int
    mission_items: list[str]
    known_vulnerability_patterns: list[str]
    executed_tool_runs: list[str]
    # EASM Governance fields (preenchidos pelo GovernanceNode)
    asset_fingerprints: dict[str, dict]     # asset -> {waf, tech, ports, cvss}
    fair_decomposition: dict[str, Any]      # 3-pillar FAIR breakdown
    easm_rating: dict[str, Any]             # {score, grade, factors, methodology}
    # EASM Executive fields (preenchidos pelo ExecutiveAnalystNode)
    executive_summary: str                  # Narrativa LLM gerada
    # Burp async fields (preenchidos pelo schedule_burp)
    burp_targets: list[str]                 # Alvos agendados para Burp assíncrono
    burp_status: str                        # "none" | "scheduled" | "pending" | "completed"
    burp_async_task_ids: list[str]          # Celery task IDs do chord Burp


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


def _node_for_step(step_name: str, scan_mode: str) -> str:
    step = str(step_name or "").strip().lower()
    if step in {"", "done"}:
        return "threat_intel"
    if "asset" in step or "recon" in step or "discovery" in step:
        return "asset_discovery"
    if "risk" in step or "vuln" in step or "assessment" in step:
        return "risk_assessment"
    return "threat_intel"


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


checkpointer = create_checkpointer()

# Portas comuns de superficie externa para fallback quando o scanner nao retorna
# uma lista real de portas abertas.
MAX_DISCOVERED_ASSETS = 40


STEP_TOOL_MAP: list[tuple[str, str]] = [
    ("amass", "amass"),
    ("subfinder", "subfinder"),
    ("assetfinder", "assetfinder"),
    ("dnsx", "dnsx"),
    ("naabu", "naabu"),
    ("nmap", "nmap"),
    ("httpx", "httpx"),
    ("katana", "katana"),
    ("waymore", "waymore"),
    ("ffuf", "ffuf"),
    ("gobuster", "gobuster"),
    ("wfuzz", "wfuzz"),
    ("feroxbuster", "feroxbuster"),
    ("arjun", "arjun"),
    ("dirb", "dirb"),
    ("nuclei", "nuclei"),
    ("dalfox", "dalfox"),
    ("wapiti", "wapiti"),
    ("sqlmap", "sqlmap"),
    ("commix", "commix"),
    ("tplmap", "tplmap"),
    ("wafw00f", "wafw00f"),
    ("curl", "curl-headers"),
    ("header", "curl-headers"),
    ("nikto", "nikto"),
    ("wpscan", "wpscan"),
    ("zap", "zap"),
    ("semgrep", "semgrep"),
    ("secretfinder", "secretfinder"),
    ("linkfinder", "linkfinder"),
    ("trufflehog", "trufflehog"),
    ("kiterunner", "kiterunner"),
    ("postman-to-k6", "postman-to-k6"),
    ("whatweb", "whatweb"),
    ("shodan", "shodan-cli"),
    ("theharvester", "theharvester"),
    ("h8mail", "h8mail"),
    ("metagoofil", "metagoofil"),
    ("subjack", "subjack"),
    ("urlscan", "urlscan-cli"),
]


def _tool_for_step(step_name: str) -> str | None:
    step = str(step_name or "").strip().lower()
    semantic_overrides = [
        (("score board", "administration surface"), "nuclei"),
        (("sqli",), "sqlmap"),
        (("ssti", "tplmap"), "tplmap"),
        (("command injection", "commix"), "commix"),
        (("waf",), "wafw00f"),
        (("gobuster",), "gobuster"),
        (("wfuzz",), "wfuzz"),
    ]
    for keywords, tool in semantic_overrides:
        if any(keyword in step for keyword in keywords):
            return tool
    for keyword, tool in STEP_TOOL_MAP:
        if keyword in step:
            return tool
    return None


def _tools_for_group(scan_mode: str, group_name: str) -> list[str]:
    groups = get_worker_groups(mode=scan_mode)
    group = groups.get(group_name, {})
    return list(group.get("tools", []))


def _ordered_tools_for_step(scan_mode: str, group_name: str, step_name: str) -> list[str]:
    tools = _tools_for_group(scan_mode, group_name)
    primary_tool = _tool_for_step(step_name)
    if primary_tool and primary_tool in tools:
        return [primary_tool] + [tool for tool in tools if tool != primary_tool]
    if primary_tool and primary_tool not in tools:
        # Permite executar passos explicitos da missao (ex.: naabu/nmap)
        # mesmo quando o grupo base do no nao inclui a ferramenta.
        return [primary_tool] + tools
    return tools


def _run_tools_and_collect(
    state: AgentState,
    tools: list[str],
    scan_target: str,
    step_name: str,
    log_prefix: str,
    root_domain: str = "",
) -> tuple[list[dict[str, Any]], list[int], list[str], dict[int, dict[str, str]]]:
    all_findings: list[dict[str, Any]] = []
    discovered_ports: set[int] = set()
    discovered_assets: set[str] = set()
    port_evidence: dict[int, dict[str, str]] = {}
    step_success = False

    for tool in tools:
        run_id = f"{step_name}|{scan_target}|{tool}".lower()
        if run_id in state.get("executed_tool_runs", []):
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} skipped=already_executed_for_step")
            continue

        result = execute_tool_with_workers(tool, scan_target, scan_mode=state["scan_mode"])
        state["executed_tool_runs"].append(run_id)
        state["logs_terminais"].append(f"{log_prefix}: tool={tool} status={result.get('status', 'unknown')}")
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
        _register_tool_result_metric(state, str(result.get("status") or ""))
        if result.get("status") == "executed":
            step_success = True

        cmd = _truncate_log(result.get("command"))
        if cmd:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} cmd={cmd}")

        rc = result.get("return_code")
        if rc is not None:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} return_code={rc}")

        stdout_preview = _truncate_log(result.get("stdout"), 300)
        if stdout_preview:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} stdout={stdout_preview}")

        stderr_preview = _truncate_log(result.get("stderr"), 300)
        if stderr_preview:
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} stderr={stderr_preview}")

        nuclei_findings = _extract_nuclei_findings(result, step_name, scan_target)
        if nuclei_findings:
            all_findings.extend(nuclei_findings)
            state["logs_terminais"].append(f"{log_prefix}: tool=nuclei findings_extraidas={len(nuclei_findings)}")

        tool_specific_findings = _extract_tool_output_findings(result, step_name, scan_target)
        if tool_specific_findings:
            all_findings.extend(tool_specific_findings)
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
                # Mantem o registro com mais contexto de versão/comando quando disponível.
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

    _mark_step_metric(state, step_success)
    return all_findings, sorted(discovered_ports), sorted(discovered_assets), port_evidence


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


def _target_host(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = str(parsed.hostname or "").strip().lower()
    if not host:
        host = raw.split("/")[0].split(":")[0].strip().lower()
    return host.lstrip("*.").strip(".")


def _is_local_target(target: str) -> bool:
    host = _target_host(target)
    return host in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def _adapt_recon_tools_for_target(target: str, tools: list[str]) -> list[str]:
    if not _is_local_target(target):
        return tools

    preferred = ["httpx", "katana", "gowitness", "naabu"]
    filtered = [tool for tool in preferred if tool in tools]
    return filtered or [tool for tool in tools if tool in {"httpx", "naabu"}] or tools[:1]


def _adapt_vuln_tools_for_target(target: str, tools: list[str]) -> list[str]:
    # Escopo de analise tecnica: core (Burp/Nmap/Nikto) + suporte
    # (Nuclei, WPScan, Wfuzz, WAF/Headers) quando disponivel.
    preferred_global = [
        "burp-cli", "nmap-vulscan", "nikto", "nuclei", "wpscan", "wfuzz", "wafw00f", "curl-headers",
    ]
    selected_global = [tool for tool in preferred_global if tool in tools]
    if selected_global:
        tools = selected_global

    if not _is_local_target(target):
        return tools

    preferred = [
        "burp-cli", "nmap-vulscan", "nikto", "nuclei", "wpscan", "wfuzz", "wafw00f", "curl-headers",
    ]
    filtered = [tool for tool in preferred if tool in tools]
    if filtered:
        return filtered
    if "burp-cli" in tools:
        return ["burp-cli"]
    return tools[:8]


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

    # Inclui parte da fila descoberta para ampliar cobertura em subdominios.
    for asset in list(state.get("pending_asset_scans") or []):
        host = str(asset or "").strip()
        if host and host not in candidates:
            candidates.append(host)

    return candidates[: max(1, limit)]


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

    # Sem fallback sintético: se não houver prova do scanner, não geramos porta aberta.
    return []


def _extract_port_service_evidence(result: dict[str, Any], tool_name: str = "") -> dict[int, dict[str, str]]:
    normalized_tool = str(tool_name or "").strip().lower()
    stdout = str(result.get("stdout") or "")
    command = _truncate_log(result.get("command"), 350)
    evidence: dict[int, dict[str, str]] = {}

    if normalized_tool in {"nmap", "nmap-vulscan", "vulscan"}:
        # Exemplo: 22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
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
        # Exemplo comum: host:443
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
            url_match = re.search(r"https?://[^\s\]]+", line)
            if not url_match:
                continue
            url_raw = url_match.group(0)
            parsed = urlparse(url_raw)
            if parsed.port:
                port = parsed.port
            elif parsed.scheme == "https":
                port = 443
            else:
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


def _truncate_log(value: Any, limit: int = 400) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _nuclei_risk_for_severity(severity: str) -> int:
    sev = str(severity or "").strip().lower()
    if sev == "critical":
        return 9
    if sev == "high":
        return 7
    if sev == "medium":
        return 5
    if sev == "low":
        return 3
    return 2


def _extract_nuclei_findings(result: dict[str, Any], step_name: str, default_target: str) -> list[dict[str, Any]]:
    if str(result.get("tool", "")).strip().lower() != "nuclei":
        return []

    text = str(result.get("stdout") or result.get("output") or "")
    if not text.strip():
        return []

    pattern = re.compile(
        r"^\[(?P<template>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<target>\S+)(?:\s+\[(?P<extra>.*)\])?$"
    )
    findings: list[dict[str, Any]] = []
    known_waf_tokens = {
        "cloudflare",
        "akamai",
        "imperva",
        "modsecurity",
        "f5",
        "aws waf",
        "barracuda",
        "fortiweb",
    }

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = pattern.match(line)
        if not match:
            continue

        template = str(match.group("template") or "").strip()
        severity = str(match.group("severity") or "info").strip().lower()
        target = str(match.group("target") or default_target).strip()
        proto = str(match.group("proto") or "").strip().lower()
        extra = str(match.group("extra") or "").strip()
        template_l = template.lower()

        details: dict[str, Any] = {
            "node": "scan",
            "asset": target or default_target,
            "step": step_name,
            "tool": "nuclei",
            "template": template,
            "protocol": proto,
            "raw_line": line,
        }
        if extra:
            details["evidence"] = extra

        # Ex.: [http-missing-security-headers:strict-transport-security] ...
        if template_l.startswith("http-missing-security-headers:"):
            header_name = template.split(":", 1)[1].strip().lower() if ":" in template else ""
            if header_name:
                details["header_name"] = header_name
                details["header_issue"] = "missing"
                if "evidence" not in details:
                    details["evidence"] = f"{header_name}: missing"

        # Ex.: [waf-detect:cloudflare] ...
        if template_l.startswith("waf-detect:"):
            vendor = template.split(":", 1)[1].strip().lower() if ":" in template else ""
            if vendor:
                details["waf_vendor"] = vendor
                details["waf_detected"] = True

        # Ex.: [tech-detect:cloudflare] ... (usa apenas quando token casa com WAF conhecido)
        if template_l.startswith("tech-detect:"):
            tech = template.split(":", 1)[1].strip().lower() if ":" in template else ""
            if tech and any(token in tech for token in known_waf_tokens):
                details["waf_vendor"] = tech
                details["waf_detected"] = True

        findings.append(
            {
                "title": f"Nuclei: {template}",
                "severity": severity,
                "risk_score": _nuclei_risk_for_severity(severity),
                "source_worker": "scan",
                "details": details,
            }
        )

    return findings


def _extract_asm_findings(result: dict[str, Any], step_name: str, default_target: str) -> list[dict[str, Any]]:
    raw = result.get("asm_findings")
    if not isinstance(raw, list) or not raw:
        return []

    findings: list[dict[str, Any]] = []
    tool = str(result.get("tool") or "unknown").strip().lower()
    for item in raw:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "info").strip().lower()
        rule_id = str(item.get("rule_id") or "asm-rule").strip()
        title = str(item.get("title") or f"ASM Rule Match: {rule_id}").strip()
        details: dict[str, Any] = {
            "node": "scan",
            "asset": default_target,
            "step": step_name,
            "tool": tool,
            "rule_id": rule_id,
            "tags": item.get("tags", []),
            "matches": item.get("matches", []),
            "match_count": int(item.get("match_count") or 0),
            "remediation": item.get("remediation"),
            "references": item.get("references", []),
            "description": item.get("description"),
        }
        findings.append(
            {
                "title": f"ASM Rule: {title}",
                "severity": severity,
                "risk_score": _nuclei_risk_for_severity(severity),
                "source_worker": "scan",
                "details": details,
            }
        )

    return findings


def _extract_tool_output_findings(result: dict[str, Any], step_name: str, default_target: str) -> list[dict[str, Any]]:
    tool = str(result.get("tool") or "").strip().lower()
    stdout = str(result.get("stdout") or result.get("output") or "")
    if not tool or not stdout.strip():
        return []

    if tool == "wafw00f":
        return _extract_wafw00f_findings(stdout, step_name, default_target)
    if tool == "shcheck":
        return _extract_shcheck_findings(stdout, step_name, default_target)
    if tool == "curl-headers":
        return _extract_curl_headers_findings(stdout, step_name, default_target)
    if tool == "nikto":
        return _extract_nikto_findings(stdout, step_name, default_target)
    if tool == "burp-cli":
        return _extract_burp_cli_findings(stdout, step_name, default_target)
    if tool in {"nmap-vulscan", "vulscan"}:
        return _extract_nmap_vulscan_findings(stdout, step_name, default_target)
    if tool == "sslscan":
        return _extract_sslscan_findings(stdout, step_name, default_target)
    if tool == "wapiti":
        return _extract_wapiti_findings(stdout, step_name, default_target)
    if tool == "shodan-cli":
        return _extract_shodan_findings(stdout, step_name, default_target)
    if tool == "amass":
        return _extract_amass_findings(stdout, step_name, default_target)
    if tool == "sublist3r":
        return _extract_sublist3r_findings(stdout, step_name, default_target)
    if tool == "dnsenum":
        return _extract_dnsenum_findings(stdout, step_name, default_target)
    if tool == "massdns":
        return _extract_massdns_findings(stdout, step_name, default_target)
    if tool == "subjack":
        return _extract_subjack_findings(stdout, step_name, default_target)
    if tool == "ffuf":
        return _extract_ffuf_findings(stdout, step_name, default_target)
    if tool == "gobuster":
        return _extract_gobuster_findings(stdout, step_name, default_target)
    if tool == "cloudenum":
        return _extract_cloudenum_findings(stdout, step_name, default_target)
    if tool == "whatweb":
        return _extract_whatweb_findings(stdout, step_name, default_target)
    if tool == "wappalyzer":
        return _extract_whatweb_findings(stdout, step_name, default_target)
    if tool == "katana":
        return _extract_katana_findings(stdout, step_name, default_target)
    return []


def _extract_shodan_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai CVEs e portas abertas da resposta JSON da API Shodan."""
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    matches = data.get("matches", [])
    if not matches or not isinstance(matches, list):
        return []

    findings: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    open_ports_per_ip: dict[str, list[str]] = {}

    for match in matches:
        if not isinstance(match, dict):
            continue
        ip_str = str(match.get("ip_str") or default_target)
        port = match.get("port")
        transport = str(match.get("transport") or "tcp")
        product = _sanitize_cli_text(str(match.get("product") or ""))
        version = _sanitize_cli_text(str(match.get("version") or ""))

        # Agrupa portas por IP para finding informativo consolidado
        if port:
            service_label = f"{port}/{transport}"
            if product:
                service_label += f" ({product}"
                if version:
                    service_label += f" {version}"
                service_label += ")"
            open_ports_per_ip.setdefault(ip_str, []).append(service_label)

        # CVEs reportados pelo Shodan para este host/servico
        vulns = match.get("vulns") or {}
        if not isinstance(vulns, dict):
            continue
        for cve_id, vuln_info in vulns.items():
            cve_id = str(cve_id or "").upper().strip()
            if not cve_id.startswith("CVE-"):
                continue
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            cvss = 0.0
            summary = ""
            if isinstance(vuln_info, dict):
                try:
                    cvss = float(vuln_info.get("cvss") or 0)
                except (TypeError, ValueError):
                    cvss = 0.0
                summary = _sanitize_cli_text(str(vuln_info.get("summary") or ""))

            if cvss >= 9.0:
                severity = "critical"
            elif cvss >= 7.0:
                severity = "high"
            elif cvss >= 4.0:
                severity = "medium"
            else:
                severity = "low"

            risk_score = min(10, max(1, int(round(cvss))))
            evidence = summary[:500] if summary else f"{cve_id} identificado pelo Shodan para {ip_str}"

            findings.append({
                "title": cve_id,
                "severity": severity,
                "risk_score": risk_score,
                "source_worker": "osint",
                "details": {
                    "node": "osint",
                    "step": step_name,
                    "asset": ip_str,
                    "tool": "shodan-cli",
                    "evidence": evidence,
                    "cvss": cvss,
                    "cve_id": cve_id,
                },
            })

    # Um finding informativo por IP com as portas expostas
    for ip_str, ports in open_ports_per_ip.items():
        ports_str = ", ".join(ports[:20])
        findings.append({
            "title": f"Portas expostas publicamente (Shodan): {ip_str}",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": step_name,
                "asset": ip_str,
                "tool": "shodan-cli",
                "evidence": f"Portas detectadas pelo Shodan: {ports_str}",
                "open_ports": ports,
            },
        })

    return findings


def _extract_wafw00f_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = _sanitize_cli_text(raw_line)
        if not line:
            continue
        match = re.search(r"is behind\s+(.+?)\s+WAF", line, re.IGNORECASE)
        if match:
            vendor = _sanitize_cli_text(match.group(1) or "")
            normalized_vendor = _normalize_waf_vendor(vendor or line) or vendor
            findings.append(
                {
                    "title": f"WAF detectado: {normalized_vendor}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "wafw00f",
                        "evidence": line,
                        "waf_vendor": normalized_vendor,
                        "waf_model_match": bool(_normalize_waf_vendor(normalized_vendor)),
                        "waf_detected": True,
                    },
                }
            )
            break
    return findings


def _extract_shcheck_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_missing: set[str] = set()
    seen_present: set[str] = set()
    header_pattern = re.compile(
        r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection)",
        re.IGNORECASE,
    )
    missing_tokens = ["missing", "not set", "absent", "not configured", "misconfigured"]
    present_tokens = ["present", "set", "configured", "ok", "enabled", "good"]

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        header_match = header_pattern.search(line)
        if not header_match:
            continue
        header = str(header_match.group(1) or "").strip().lower()
        lowered = line.lower()
        is_missing = any(token in lowered for token in missing_tokens)
        is_present = any(token in lowered for token in present_tokens) or (":" in line and not is_missing)

        if is_missing:
            if header in seen_missing:
                continue
            seen_missing.add(header)
            sev = "medium" if header in {"strict-transport-security", "content-security-policy", "x-frame-options"} else "low"
            findings.append(
                {
                    "title": f"Header de seguranca ausente: {header}",
                    "severity": sev,
                    "risk_score": 5 if sev == "medium" else 3,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "shcheck",
                        "header_name": header,
                        "header_issue": "missing",
                        "evidence": line,
                    },
                }
            )
            continue

        if is_present:
            if header in seen_present:
                continue
            seen_present.add(header)
            findings.append(
                {
                    "title": f"Header de seguranca configurado: {header}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "shcheck",
                        "header_name": header,
                        "header_issue": "present",
                        "evidence": line,
                    },
                }
            )
    return findings


def _extract_curl_headers_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    expected_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
    ]

    blocks: list[tuple[str, str]] = []
    current_url = default_target
    current_lines: list[str] = []

    for raw_line in stdout.splitlines():
        line = str(raw_line or "")
        if line.startswith("# URL:"):
            if current_lines:
                blocks.append((current_url, "\n".join(current_lines).strip()))
                current_lines = []
            current_url = line.replace("# URL:", "", 1).strip() or default_target
            continue
        if line.strip():
            current_lines.append(line)

    if current_lines:
        blocks.append((current_url, "\n".join(current_lines).strip()))

    if not blocks and stdout.strip():
        blocks.append((default_target, stdout.strip()))

    seen: set[tuple[str, str, str]] = set()
    high_value_headers = {"strict-transport-security", "content-security-policy", "x-frame-options"}

    for block_url, block_text in blocks:
        block_lower = block_text.lower()

        for header in expected_headers:
            present = re.search(rf"(?im)^\s*{re.escape(header)}\s*:\s*.+$", block_text) is not None
            issue = "present" if present else "missing"
            dedupe_key = (str(block_url or default_target).strip().lower(), header, issue)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            if present:
                match = re.search(rf"(?im)^\s*{re.escape(header)}\s*:\s*(.+)$", block_text)
                evidence = f"{header}: {str(match.group(1) if match else '').strip()}".strip()
                findings.append(
                    {
                        "title": f"Header de seguranca configurado: {header}",
                        "severity": "info",
                        "risk_score": 1,
                        "source_worker": "analise_vulnerabilidade",
                        "details": {
                            "node": "vuln",
                            "step": step_name,
                            "asset": block_url or default_target,
                            "tool": "curl-headers",
                            "header_name": header,
                            "header_issue": "present",
                            "evidence": evidence,
                            "http_headers_raw": block_text[:1400],
                        },
                    }
                )
            else:
                sev = "medium" if header in high_value_headers else "low"
                findings.append(
                    {
                        "title": f"Header de seguranca ausente: {header}",
                        "severity": sev,
                        "risk_score": 5 if sev == "medium" else 3,
                        "source_worker": "analise_vulnerabilidade",
                        "details": {
                            "node": "vuln",
                            "step": step_name,
                            "asset": block_url or default_target,
                            "tool": "curl-headers",
                            "header_name": header,
                            "header_issue": "missing",
                            "evidence": f"{header}: missing",
                            "http_headers_raw": block_text[:1400],
                        },
                    }
                )

        status_match = re.search(r"(?im)^\s*HTTP/\S+\s+(\d{3})\b", block_text)
        if status_match:
            status_code = str(status_match.group(1) or "").strip()
            findings.append(
                {
                    "title": f"HTTP status observado: {status_code}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": block_url or default_target,
                        "tool": "curl-headers",
                        "http_status": status_code,
                        "evidence": re.search(r"(?im)^\s*HTTP/\S+\s+\d{3}.*$", block_text).group(0),
                        "http_headers_raw": block_text[:1400],
                    },
                }
            )

    return findings


def _extract_nikto_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_headers: set[str] = set()
    
    ignore_tokens = [
        "target host",
        "target ip",
        "target port",
        "start time",
        "end time",
        "no web server found",
        "nikto installation",
        "multiple ips",
        "cloudflare detected",
        "uncommon header",
        "cgi directories",
    ]
    
    header_pattern = re.compile(
        r"Suggested security header missing:\s*(\S+)",
        re.IGNORECASE,
    )
    
    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line.startswith("+"):
            continue
        lowered = line.lower()
        
        # Extrai headers ausentes especialmente
        header_match = header_pattern.search(line)
        if header_match:
            header = str(header_match.group(1) or "").strip().lower()
            if header not in seen_headers:
                seen_headers.add(header)
                sev = "medium" if header in {"strict-transport-security", "content-security-policy", "permissions-policy"} else "low"
                findings.append(
                    {
                        "title": f"Header de seguranca ausente: {header}",
                        "severity": sev,
                        "risk_score": 5 if sev == "medium" else 3,
                        "source_worker": "analise_vulnerabilidade",
                        "details": {
                            "node": "vuln",
                            "step": step_name,
                            "asset": default_target,
                            "tool": "nikto",
                            "header_name": header,
                            "header_issue": "missing",
                            "evidence": line,
                        },
                    }
                )
            continue
        
        # Ignora linhas com tokens conhecidos
        if any(token in lowered for token in ignore_tokens):
            continue
        
        if lowered in seen:
            continue
        seen.add(lowered)
        
        # CVEs e vulnerabilidades
        sev = "high" if ("cve-" in lowered or "osvdb" in lowered) else "medium"
        findings.append(
            {
                "title": f"Nikto: {line.lstrip('+ ').strip()[:180]}",
                "severity": sev,
                "risk_score": 7 if sev == "high" else 5,
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": step_name,
                    "asset": default_target,
                    "tool": "nikto",
                    "evidence": line,
                },
            }
        )
        if len(findings) >= 30:
            break
    return findings


def _extract_nmap_vulscan_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    db_refs: list[str] = []
    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", line, re.IGNORECASE)
        if cve_match:
            cve_id = str(cve_match.group(0) or "").upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            findings.append(
                {
                    "title": cve_id,
                    "severity": "high",
                    "risk_score": 7,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "nmap-vulscan",
                        "vuln_db": "vulscan",
                        "cve": cve_id,
                        "evidence": line,
                    },
                }
            )
            continue

        lowered = line.lower()
        if any(token in lowered for token in ["exploitdb", "osvdb", "securityfocus", "packetstorm"]):
            db_refs.append(line)

    if not findings and db_refs:
        findings.append(
            {
                "title": "Referencias de vulnerabilidade identificadas (sem CVE explicito)",
                "severity": "medium",
                "risk_score": 5,
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": step_name,
                    "asset": default_target,
                    "tool": "nmap-vulscan",
                    "vuln_db": "vulscan",
                    "evidence": " | ".join(db_refs[:5]),
                },
            }
        )
    return findings


def _extract_burp_cli_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    severity_map = {
        "critical": ("critical", 10),
        "high": ("high", 8),
        "medium": ("medium", 5),
        "low": ("low", 3),
        "info": ("low", 2),
        "information": ("low", 2),
    }

    payload: dict[str, Any] = {}
    issues: list[dict[str, Any]] = []
    try:
        parsed = json.loads(stdout or "{}")
        if isinstance(parsed, dict):
            payload = parsed
        elif isinstance(parsed, list):
            issues = [item for item in parsed if isinstance(item, dict)]
    except Exception:
        payload = {}

    if not issues:
        # Alguns formatos de output imprimem logs antes do bloco JSON.
        json_block_match = re.search(r"(\[\s*\{.*\}\s*\])", stdout or "", re.DOTALL)
        if json_block_match:
            try:
                parsed_block = json.loads(json_block_match.group(1))
                if isinstance(parsed_block, list):
                    issues = [item for item in parsed_block if isinstance(item, dict)]
            except Exception:
                pass

    if not issues:
        issues = payload.get("issues") if isinstance(payload.get("issues"), list) else []
    if isinstance(payload.get("results"), list) and not issues:
        issues = payload.get("results")

    for raw_issue in issues:
        if not isinstance(raw_issue, dict):
            continue

        # Burp_export.json costuma trazer eventos no formato:
        # [{"id":..., "type":"issue_found", "issue": {...}}]
        issue = raw_issue.get("issue") if isinstance(raw_issue.get("issue"), dict) else raw_issue
        if not isinstance(issue, dict):
            continue

        name = _sanitize_cli_text(
            str(issue.get("name") or issue.get("title") or issue.get("issue_name") or "Burp finding")
        )
        sev_raw = str(issue.get("severity") or "medium").strip().lower()
        sev, risk_score = severity_map.get(sev_raw, ("medium", 5))
        evidence = _sanitize_cli_text(
            str(issue.get("evidence") or issue.get("description") or issue.get("detail") or "")
        )

        issue_url = _sanitize_cli_text(
            str(issue.get("url") or issue.get("full_url") or issue.get("endpoint") or "")
        )
        if not issue_url:
            origin = _sanitize_cli_text(str(issue.get("origin") or ""))
            path = _sanitize_cli_text(str(issue.get("path") or ""))
            if origin and path:
                issue_url = f"{origin.rstrip('/')}/{path.lstrip('/')}"
            elif origin:
                issue_url = origin
            elif path:
                issue_url = path
        if not issue_url:
            issue_url = default_target
        http_method = _sanitize_cli_text(str(issue.get("method") or issue.get("http_method") or "GET")).upper() or "GET"
        issue_parameter = _sanitize_cli_text(str(issue.get("parameter") or issue.get("param") or issue.get("field") or ""))

        # Extrai payload se disponível
        payload = _sanitize_cli_text(
            str(
                issue.get("payload")
                or issue.get("injected_payload")
                or issue.get("attack")
                or issue.get("input")
                or issue.get("vector")
                or ""
            )
        )

        if not issue_parameter and "?" in issue_url:
            try:
                query_part = issue_url.split("?", 1)[1]
                first_param = query_part.split("&", 1)[0].split("=", 1)[0].strip()
                issue_parameter = _sanitize_cli_text(first_param)
            except Exception:
                issue_parameter = ""

        cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", f"{name} {evidence}", re.IGNORECASE)
        cve_id = str(cve_match.group(0) or "").upper() if cve_match else ""
        title = cve_id or name

        dedupe = f"{title}|{sev}|{issue_url or default_target}|{issue_parameter}"
        if dedupe in seen:
            continue
        seen.add(dedupe)

        finding_details = {
            "node": "vuln",
            "step": step_name,
            "asset": default_target,
            "tool": "burp-cli",
            "cve": cve_id or None,
            "evidence": evidence,
            "url": issue_url or default_target,
            "full_url": issue_url or default_target,
            "http_method": http_method,
        }
        if issue_parameter:
            finding_details["parameter"] = issue_parameter
        if payload:
            finding_details["payload"] = payload

        if not finding_details.get("evidence"):
            finding_details["evidence"] = (
                f"Burp identificou potencial vulnerabilidade em {http_method} {issue_url or default_target}."
                + (f" Parametro: {issue_parameter}." if issue_parameter else "")
            )

        findings.append(
            {
                "title": title,
                "severity": sev,
                "risk_score": risk_score,
                "source_worker": "analise_vulnerabilidade",
                "details": finding_details,
            }
        )

    if findings:
        return findings

    # Fallback simples: extrai CVEs do stdout livre quando burp-cli nao retorna JSON estruturado.
    for match in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", stdout or "", re.IGNORECASE):
        cve_id = str(match or "").upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        findings.append(
            {
                "title": cve_id,
                "severity": "high",
                "risk_score": 7,
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": step_name,
                    "asset": default_target,
                    "tool": "burp-cli",
                    "cve": cve_id,
                    "evidence": "cve_extraida_do_stdout",
                },
            }
        )

    return findings


def _extract_sslscan_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        lowered = line.lower()
        if "tlsv1.0" in lowered or "tlsv1.1" in lowered:
            findings.append(
                {
                    "title": "TLS legado habilitado no endpoint",
                    "severity": "medium",
                    "risk_score": 5,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "sslscan",
                        "evidence": line,
                    },
                }
            )
        if "self signed" in lowered or "certificate expired" in lowered:
            findings.append(
                {
                    "title": "Problema de certificado TLS detectado",
                    "severity": "high",
                    "risk_score": 7,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "sslscan",
                        "evidence": line,
                    },
                }
            )
    return findings


def _extract_wapiti_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Parse wapiti inline warning lines (emitidos durante o scan com -v 1)."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    # (regex, severity, risk_score, title, header_name)
    _PATTERNS = [
        (
            re.compile(r"CSP is not set for URL:\s*(\S+)", re.IGNORECASE),
            "medium", 5,
            "Content Security Policy (CSP) ausente",
            "content-security-policy",
        ),
        (
            re.compile(r"X-Content-Type-Options is not set on\s*(\S+)", re.IGNORECASE),
            "low", 3,
            "X-Content-Type-Options ausente",
            "x-content-type-options",
        ),
        (
            re.compile(r"Host\s+(\S+)\s+serves HTTP content without redirecting to HTTPS", re.IGNORECASE),
            "medium", 6,
            "Canal nao cifrado: sem redirecionamento HTTPS",
            None,
        ),
        (
            re.compile(r"Strict-Transport-Security.*?not set.*?(\S+)", re.IGNORECASE),
            "medium", 5,
            "HSTS ausente",
            "strict-transport-security",
        ),
        (
            re.compile(r"X-Frame-Options.*?not set.*?(\S+)", re.IGNORECASE),
            "low", 3,
            "X-Frame-Options ausente (clickjacking)",
            "x-frame-options",
        ),
        (
            re.compile(r"\[!\].*?SQL\s+injection.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "SQL Injection detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?XSS.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "Cross-Site Scripting (XSS) detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?Path\s+Traversal.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "Path Traversal detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?SSRF.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "Server-Side Request Forgery (SSRF) detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?CRLF\s+Injection.*?(\S+)", re.IGNORECASE),
            "medium", 5,
            "CRLF Injection detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?Open\s+Redirect.*?(\S+)", re.IGNORECASE),
            "medium", 5,
            "Open Redirect detectado",
            None,
        ),
    ]

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line or line.startswith("[*]") or line.startswith("[+]"):
            continue

        for pattern, severity, risk_score, title, header_name in _PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            key = f"{title}:{default_target}"
            if key in seen:
                break
            seen.add(key)
            details: dict[str, Any] = {
                "node": "vuln",
                "step": step_name,
                "asset": default_target,
                "tool": "wapiti",
                "evidence": line[:500],
            }
            # Extrai payload se disponível na linha
            payload_match = re.search(r"payload=([^\s]+)", line)
            if payload_match:
                details["payload"] = payload_match.group(1)
            if header_name:
                details["header_name"] = header_name
                details["header_issue"] = "missing"
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "risk_score": risk_score,
                    "source_worker": "analise_vulnerabilidade",
                    "details": details,
                }
            )
            break

    return findings


# ── Parsers de ferramentas parcialmente implementadas ────────────────────────


def _extract_amass_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdomínios descobertos pelo amass enum."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        subdomain = raw_line.strip().lower()
        if not subdomain or subdomain in seen:
            continue
        if not re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", subdomain):
            continue
        seen.add(subdomain)
    if not seen:
        return []
    subdomains_list = sorted(seen)
    findings.append({
        "title": f"Subdominios descobertos (amass): {len(subdomains_list)} encontrados",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "amass",
            "evidence": ", ".join(subdomains_list[:50]),
            "subdomains": subdomains_list[:200],
            "count": len(subdomains_list),
        },
    })
    return findings


def _extract_sublist3r_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdomínios descobertos pelo sublist3r."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip().lower()
        if not line or "sublist3r" in line or line.startswith("[") or line.startswith("-"):
            continue
        if not re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", line):
            continue
        seen.add(line)
    if not seen:
        return []
    subdomains_list = sorted(seen)
    findings.append({
        "title": f"Subdominios descobertos (sublist3r): {len(subdomains_list)} encontrados",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "sublist3r",
            "evidence": ", ".join(subdomains_list[:50]),
            "subdomains": subdomains_list[:200],
            "count": len(subdomains_list),
        },
    })
    return findings


def _extract_dnsenum_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai registros DNS do dnsenum."""
    findings: list[dict[str, Any]] = []
    records: list[str] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("dnsenum") or line.startswith("--"):
            continue
        if re.search(r"\d+\.\d+\.\d+\.\d+", line) or re.search(r"(NS|MX|A|AAAA|TXT|SOA|CNAME)\s", line, re.IGNORECASE):
            records.append(line[:200])
    if not records:
        return []
    findings.append({
        "title": f"Registros DNS enumerados (dnsenum): {len(records)} registros",
        "severity": "info",
        "risk_score": 1,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "dnsenum",
            "evidence": "\n".join(records[:30]),
            "dns_records": records[:100],
            "count": len(records),
        },
    })
    # Zone Transfer detection
    if re.search(r"zone\s+transfer|AXFR", stdout, re.IGNORECASE):
        findings.append({
            "title": "Transferencia de zona DNS permitida (AXFR)",
            "severity": "high",
            "risk_score": 8,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "dnsenum",
                "evidence": "Zone transfer (AXFR) habilitado — expoe toda a estrutura DNS do dominio.",
            },
        })
    return findings


def _extract_massdns_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdomínios validados pelo massdns (formato: subdomain. A ip)."""
    findings: list[dict[str, Any]] = []
    resolved: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # formato massdns -o S: sub.domain.com. A 1.2.3.4
        parts = line.split()
        if len(parts) >= 3:
            subdomain = parts[0].rstrip(".").lower()
            record_type = parts[1].upper()
            value = parts[2]
            if subdomain not in seen and re.match(r"^[a-z0-9\-\.]+\.[a-z]{2,}$", subdomain):
                seen.add(subdomain)
                resolved.append({"subdomain": subdomain, "type": record_type, "value": value})
    if not resolved:
        return []
    findings.append({
        "title": f"Subdominios validados (massdns): {len(resolved)} resolvidos",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "massdns",
            "evidence": ", ".join(r["subdomain"] for r in resolved[:50]),
            "resolved_records": resolved[:200],
            "count": len(resolved),
        },
    })
    return findings


def _extract_subjack_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdominios vulneraveis a takeover do subjack."""
    findings: list[dict[str, Any]] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # formato subjack: [Vulnerable] sub.domain.com  [service]
        m = re.search(r"\[Vulnerable\]\s+(\S+)", line, re.IGNORECASE)
        if m:
            subdomain = m.group(1).strip().lower()
            service_m = re.search(r"\[(\w+)\]\s*$", line)
            service = service_m.group(1) if service_m else "unknown"
            findings.append({
                "title": f"Subdomain Takeover: {subdomain}",
                "severity": "high",
                "risk_score": 9,
                "source_worker": "osint",
                "details": {
                    "node": "osint",
                    "step": step_name,
                    "asset": subdomain,
                    "tool": "subjack",
                    "evidence": line[:500],
                    "takeover_service": service,
                },
            })
    return findings


def _extract_ffuf_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai paths/vhosts descobertos pelo ffuf."""
    findings: list[dict[str, Any]] = []
    paths: list[dict[str, str]] = []
    # Tenta JSON primeiro (ffuf -of json)
    try:
        data = json.loads(stdout)
        for result in (data.get("results") or []):
            url = result.get("url", "")
            status_code = result.get("status", 0)
            length = result.get("length", 0)
            paths.append({"url": url, "status": str(status_code), "length": str(length)})
    except (json.JSONDecodeError, ValueError):
        # Parse formato texto: /path [Status: 200, Size: 1234, Words: 56]
        for raw_line in (stdout or "").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("::") or line.startswith("_"):
                continue
            m = re.match(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
            if m:
                paths.append({"url": m.group(1), "status": m.group(2), "length": m.group(3)})
    if not paths:
        return []
    findings.append({
        "title": f"Paths descobertos (ffuf): {len(paths)} endpoints",
        "severity": "info",
        "risk_score": 3,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "ffuf",
            "evidence": "\n".join(f"{p['url']} [{p['status']}]" for p in paths[:30]),
            "discovered_paths": paths[:200],
            "count": len(paths),
        },
    })
    return findings


def _extract_gobuster_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai paths descobertos pelo gobuster dir."""
    findings: list[dict[str, Any]] = []
    paths: list[dict[str, str]] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("=") or line.startswith("Gobuster"):
            continue
        # formato: /path (Status: 200) [Size: 1234]
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d+)\)", line)
        if m:
            paths.append({"path": m.group(1), "status": m.group(2)})
            continue
        # formato quiet (-q): /path
        m2 = re.match(r"^(/[^\s]+)$", line)
        if m2:
            paths.append({"path": m2.group(1), "status": "200"})
    if not paths:
        return []
    sensitive_patterns = re.compile(r"(admin|backup|config|\.env|\.git|\.htaccess|wp-admin|phpmyadmin|api|debug|test|staging)", re.IGNORECASE)
    sensitive_paths = [p for p in paths if sensitive_patterns.search(p["path"])]
    if sensitive_paths:
        findings.append({
            "title": f"Paths sensiveis expostos (gobuster): {len(sensitive_paths)} encontrados",
            "severity": "medium",
            "risk_score": 6,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "gobuster",
                "evidence": "\n".join(f"{p['path']} [{p['status']}]" for p in sensitive_paths[:20]),
                "sensitive_paths": sensitive_paths[:100],
                "count": len(sensitive_paths),
            },
        })
    findings.append({
        "title": f"Content Discovery (gobuster): {len(paths)} paths",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "gobuster",
            "evidence": "\n".join(f"{p['path']} [{p['status']}]" for p in paths[:30]),
            "discovered_paths": paths[:200],
            "count": len(paths),
        },
    })
    return findings


def _extract_cloudenum_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai buckets/blobs/containers do cloud_enum."""
    findings: list[dict[str, Any]] = []
    buckets: list[str] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # cloud_enum imprime: [+] Open S3 bucket: https://bucket.s3.amazonaws.com
        # ou: OPEN S3 BUCKET: name
        if re.search(r"(OPEN|found|bucket|blob|container)", line, re.IGNORECASE):
            url_m = re.search(r"(https?://\S+)", line)
            if url_m:
                buckets.append(url_m.group(1))
            elif ":" in line:
                buckets.append(line.split(":", 1)[1].strip())
    if not buckets:
        return []
    findings.append({
        "title": f"Cloud Storage Expostos: {len(buckets)} recursos",
        "severity": "high",
        "risk_score": 8,
        "source_worker": "osint",
        "details": {
            "node": "osint",
            "step": step_name,
            "asset": default_target,
            "tool": "cloudenum",
            "evidence": "\n".join(buckets[:20]),
            "cloud_resources": buckets[:100],
            "count": len(buckets),
        },
    })
    return findings


def _extract_whatweb_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai tecnologias fingerprinted pelo whatweb/wappalyzer."""
    findings: list[dict[str, Any]] = []
    technologies: list[str] = []
    server_header = ""
    powered_by = ""
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # whatweb: http://target [200 OK] Apache[2.4], PHP[7.4], ...
        for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9\-_.]+)\[([^\]]+)\]", line):
            tech_name = m.group(1).strip()
            tech_version = m.group(2).strip()
            technologies.append(f"{tech_name}/{tech_version}")
            if tech_name.lower() in {"apache", "nginx", "iis", "lighttpd", "server"}:
                server_header = f"{tech_name}/{tech_version}"
            if tech_name.lower() in {"php", "asp.net", "x-powered-by"}:
                powered_by = f"{tech_name}/{tech_version}"
        # JSON de wappalyzer
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                for tech in data.get("technologies", []):
                    if isinstance(tech, dict):
                        name = tech.get("name", "")
                        version = tech.get("version", "")
                        technologies.append(f"{name}/{version}" if version else name)
        except (json.JSONDecodeError, ValueError):
            pass
    if not technologies:
        return []
    tech_unique = sorted(set(technologies))
    findings.append({
        "title": f"Tecnologias detectadas: {len(tech_unique)} componentes",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "osint",
        "details": {
            "node": "osint",
            "step": step_name,
            "asset": default_target,
            "tool": "whatweb",
            "evidence": ", ".join(tech_unique[:30]),
            "technologies": tech_unique[:100],
            "count": len(tech_unique),
        },
    })
    if server_header:
        findings.append({
            "title": f"Header Server Exposto: {server_header}",
            "severity": "low",
            "risk_score": 3,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": step_name,
                "asset": default_target,
                "tool": "whatweb",
                "evidence": f"Server header expoe versao: {server_header}",
                "header_name": "server",
                "header_value": server_header,
            },
        })
    if powered_by:
        findings.append({
            "title": f"Header X-Powered-By Exposto: {powered_by}",
            "severity": "low",
            "risk_score": 3,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": step_name,
                "asset": default_target,
                "tool": "whatweb",
                "evidence": f"X-Powered-By expoe tecnologia: {powered_by}",
                "header_name": "x-powered-by",
                "header_value": powered_by,
            },
        })
    return findings


def _extract_katana_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai URLs descobertas pelo katana, incluindo robots.txt e sitemap.xml."""
    findings: list[dict[str, Any]] = []
    urls: list[str] = []
    robots_entries: list[str] = []
    sitemap_entries: list[str] = []
    forms: list[str] = []
    sensitive_params: list[str] = []
    param_pattern = re.compile(r"[?&](search|user|username|password|passwd|id|token|key|api_key|secret|session|auth)=", re.IGNORECASE)

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(r"^https?://", line):
            urls.append(line)
            path_lower = line.lower()
            if "/robots.txt" in path_lower:
                robots_entries.append(line)
            if "/sitemap" in path_lower and ".xml" in path_lower:
                sitemap_entries.append(line)
            if param_pattern.search(line):
                sensitive_params.append(line)

    if robots_entries:
        findings.append({
            "title": "Robots.txt acessivel",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(robots_entries[:10]),
                "robots_urls": robots_entries[:20],
            },
        })
    if sitemap_entries:
        findings.append({
            "title": "Sitemap.xml acessivel",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(sitemap_entries[:10]),
                "sitemap_urls": sitemap_entries[:20],
            },
        })
    if sensitive_params:
        findings.append({
            "title": f"Parametros sensiveis identificados: {len(sensitive_params)} URLs",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(sensitive_params[:20]),
                "sensitive_urls": sensitive_params[:100],
                "count": len(sensitive_params),
            },
        })
    if urls:
        findings.append({
            "title": f"URLs crawled (katana): {len(urls)} endpoints",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(urls[:30]),
                "discovered_urls": urls[:200],
                "count": len(urls),
            },
        })
    return findings


def _step_name(state: AgentState) -> str:
    idx = state.get("mission_index", 0)
    items = state.get("mission_items", GROUP_MISSION_ITEMS)
    if idx >= len(items):
        return "done"
    return items[idx]


# ─────────────────────────────────────────────────────────────────────────────
# EASM Agent 1: Asset Discovery
# Descobre subdomínios, IPs, portas e tecnologias expostas.
# Ferramentas: subfinder → amass → dnsx → naabu → httpx → gowitness
# ─────────────────────────────────────────────────────────────────────────────
def asset_discovery_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    _sync_step_to_db(state, "1. AssetDiscovery")
    current = _step_name(state)
    state["proxima_ferramenta"] = "threat_intel"
    state["logs_terminais"].append(f"AssetDiscovery: {current}")
    seed_targets = list(state.get("input_targets") or [])
    if not seed_targets:
        seed_targets = _split_input_targets(state.get("target") or "") or [state["target"]]

    for seed in seed_targets:
        if seed not in state["lista_ativos"]:
            state["lista_ativos"].append(seed)
        if seed not in state["pending_asset_scans"] and seed not in state["scanned_assets"]:
            state["pending_asset_scans"].append(seed)

    # Usa asset_discovery group (que aponta para mesma fila reconhecimento)
    recon_tools = _tools_for_group(state["scan_mode"], "asset_discovery") or _tools_for_group(state["scan_mode"], "reconhecimento")
    recon_tools = _adapt_recon_tools_for_target(state["target"], recon_tools)
    if _is_local_target(state["target"]):
        state["logs_terminais"].append(
            f"AssetDiscovery: local_target detected, reduced_tools={','.join(recon_tools)}"
        )
    # Ferramentas de port scan a serem executadas também nos subdomínios descobertos
    PORT_SCAN_TOOLS = {"naabu", "nmap"}
    port_scan_tools = [t for t in recon_tools if t in PORT_SCAN_TOOLS]

    root_domain = _target_host(state["target"])
    recon_findings, recon_ports, recon_assets, recon_port_evidence = _run_tools_and_collect(
        state,
        recon_tools,
        state["target"],
        current,
        "ReconNode",
        root_domain=root_domain,
    )
    if recon_findings:
        state["vulnerabilidades_encontradas"].extend(recon_findings)
    if recon_ports:
        state["discovered_ports"] = sorted(set((state.get("discovered_ports") or []) + recon_ports))
        state["pending_port_tests"] = state["discovered_ports"].copy()
    if recon_assets:
        _register_discovered_assets(state, root_domain=root_domain, assets=recon_assets)

        # Executa port scan nos subdomínios recém-descobertos (naabu + nmap)
        if port_scan_tools:
            subdomain_targets = [
                a for a in recon_assets[:MAX_DISCOVERED_ASSETS]
                if _target_host(a) != root_domain
            ]
            if subdomain_targets:
                state["logs_terminais"].append(
                    f"ReconNode:PortScan: executando em {len(subdomain_targets)} subdominios descobertos"
                )
            for sub_asset in subdomain_targets:
                _, sub_ports, _, sub_port_ev = _run_tools_and_collect(
                    state,
                    port_scan_tools,
                    sub_asset,
                    current,
                    f"ReconNode:PortScan:{sub_asset}",
                    root_domain=root_domain,
                )
                if sub_ports:
                    state["discovered_ports"] = sorted(
                        set((state.get("discovered_ports") or []) + sub_ports)
                    )
                    for port in sub_ports:
                        technical = sub_port_ev.get(port, {})
                        service_name = str(technical.get("service") or "").strip()
                        state["vulnerabilidades_encontradas"].append(
                            {
                                "title": (
                                    f"Porta aberta em subdominio: {sub_asset}:{port}"
                                    + (f" ({service_name})" if service_name else "")
                                ),
                                "severity": "medium",
                                "risk_score": 4,
                                "source_worker": "reconhecimento",
                                "details": {
                                    "node": "recon",
                                    "step": current,
                                    "asset": sub_asset,
                                    "port": port,
                                    "service": service_name,
                                    "version": str(technical.get("version") or "").strip(),
                                    "tool": technical.get("tool") or "portscan",
                                    "evidence": technical.get("evidence") or "",
                                    "open_ports": [port],
                                },
                            }
                        )
                    state["logs_terminais"].append(
                        f"ReconNode:PortScan:{sub_asset}: portas={sorted(sub_ports)}"
                    )

        for asset in recon_assets[:MAX_DISCOVERED_ASSETS]:
            state["vulnerabilidades_encontradas"].append(
                {
                    "title": f"Ativo descoberto no reconhecimento: {asset}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "reconhecimento",
                    "details": {
                        "node": "recon",
                        "step": current,
                        "asset": asset,
                        "tool": "reconhecimento",
                    },
                }
            )

    state["vulnerabilidades_encontradas"].append(
        {
            "title": f"Ativo externo mapeado: {state['target']}",
            "severity": "low",
            "risk_score": 2,
            "source_worker": "asset_discovery",
            "details": {"node": "asset_discovery", "step": current},
        }
    )
    state["mission_index"] += 1
    _metric_end(state, "asset_discovery", started_at)
    return state


# Alias legado para backward compat
def recon_node(state: AgentState) -> AgentState:
    return asset_discovery_node(state)


def scan_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    scan_target = state["pending_asset_scans"].pop(0) if state["pending_asset_scans"] else state["target"]
    state["logs_terminais"].append(f"ScanNode: {current} [{scan_target}]")

    scan_tools = _ordered_tools_for_step(state["scan_mode"], "crawler", current)
    if state["scan_mode"] == "scheduled":
        scan_tools = scan_tools + _ordered_tools_for_step(state["scan_mode"], "fingerprint", current)

    scan_findings, scan_ports, _, scan_port_evidence = _run_tools_and_collect(state, scan_tools, scan_target, current, "ScanNode")
    if scan_findings:
        state["vulnerabilidades_encontradas"].extend(scan_findings)

    if scan_ports:
        state["discovered_ports"] = sorted(set((state.get("discovered_ports") or []) + scan_ports))
        state["pending_port_tests"] = state["discovered_ports"].copy()
    if scan_target not in state["scanned_assets"]:
        state["scanned_assets"].append(scan_target)
    state["port_followup_done"] = True

    if state["pending_port_tests"]:
        aggregated_ports: list[int] = []
        for port in state["pending_port_tests"]:
            technical = scan_port_evidence.get(port, {})
            service_name = str(technical.get("service") or "").strip()
            service_version = str(technical.get("version") or "").strip()
            title = f"Servico externo identificado na porta {port}"
            if service_name:
                title = f"Servico externo identificado na porta {port} ({service_name})"
            aggregated_ports.append(int(port))
            state["vulnerabilidades_encontradas"].append(
                {
                    "title": title,
                    "severity": "medium",
                    "risk_score": 4,
                    "source_worker": "scan",
                    "details": {
                        "node": "scan",
                        "asset": scan_target,
                        "port": port,
                        "service": service_name,
                        "version": service_version,
                        "tool": technical.get("tool") or "scan",
                        "evidence": technical.get("evidence") or "",
                        "command": technical.get("command") or "",
                        "payload": technical.get("command") or "",
                        "open_ports": [int(port)],
                        "step": current,
                    },
                }
            )
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"PortScan consolidado: {scan_target}",
                "severity": "low",
                "risk_score": 3,
                "source_worker": "scan",
                "details": {
                    "node": "scan",
                    "asset": scan_target,
                    "tool": "portscan",
                    "step": current,
                    "open_ports": sorted(set(aggregated_ports)),
                    "evidence": f"open_ports={','.join(str(p) for p in sorted(set(aggregated_ports)))}",
                    "payload": "; ".join(
                        sorted(
                            {
                                str((scan_port_evidence.get(p) or {}).get("command") or "").strip()
                                for p in aggregated_ports
                                if str((scan_port_evidence.get(p) or {}).get("command") or "").strip()
                            }
                        )
                    )[:500],
                },
            }
        )
        state["logs_terminais"].append(f"ScanNode: portas analisadas={len(state['pending_port_tests'])}")
        state["pending_port_tests"] = []

    state["mission_index"] += 1
    _metric_end(state, "scan", started_at)
    return state


def fuzzing_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["logs_terminais"].append(f"FuzzingNode: {current}")

    fuzz_tools = _ordered_tools_for_step(state["scan_mode"], "fuzzing", current)
    targets = _targets_for_deep_scan(state, limit=8)
    if len(targets) > 1:
        state["logs_terminais"].append(f"FuzzingNode: targets={len(targets)}")
    for scan_target in targets:
        fuzz_findings, _, _, _ = _run_tools_and_collect(state, fuzz_tools, scan_target, current, "FuzzingNode")
        if fuzz_findings:
            state["vulnerabilidades_encontradas"].extend(fuzz_findings)

    state["proxima_ferramenta"] = "vuln"

    state["mission_index"] += 1
    _metric_end(state, "fuzzing", started_at)
    return state


def fingerprint_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["logs_terminais"].append(f"FingerprintNode: {current}")

    fingerprint_tools = _ordered_tools_for_step(state["scan_mode"], "fingerprint", current)
    targets = _targets_for_deep_scan(state, limit=8)
    if len(targets) > 1:
        state["logs_terminais"].append(f"FingerprintNode: targets={len(targets)}")
    for scan_target in targets:
        fingerprint_findings, _, _, _ = _run_tools_and_collect(state, fingerprint_tools, scan_target, current, "FingerprintNode")
        if fingerprint_findings:
            state["vulnerabilidades_encontradas"].extend(fingerprint_findings)

    state["proxima_ferramenta"] = "fuzzing"
    state["mission_index"] += 1
    _metric_end(state, "fingerprint", started_at)
    return state


# ─────────────────────────────────────────────────────────────────────────────
# Burp Scheduling (legado)
# Mantido apenas por compatibilidade de estado/histórico.
# O fluxo principal atual executa Burp de forma síncrona no RiskAssessment.
# ─────────────────────────────────────────────────────────────────────────────
def schedule_burp(state: AgentState, targets: list[str]) -> None:
    """Compatibilidade legada.

    Esta função permanece disponível para leitura de estados antigos.
    O pipeline principal não depende mais de agendamento assíncrono do Burp.
    """
    state["burp_targets"] = list(targets)
    state["burp_status"] = "scheduled"
    state["logs_terminais"].append(
        f"RiskAssessment:Burp(legado): {len(targets)} alvos marcados em estado"
    )


# ─────────────────────────────────────────────────────────────────────────────
# EASM Agent 3: Risk Assessment
# Avalia vulnerabilidades técnicas nos ativos descobertos.
# Ferramentas ativas: burp-cli (sync) + nmap-vulscan + nikto (sync)
# ─────────────────────────────────────────────────────────────────────────────
def risk_assessment_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    _sync_step_to_db(state, "3. RiskAssessment")
    current = _step_name(state)
    vuln_tools = _tools_for_group(state["scan_mode"], "risk_assessment") or _tools_for_group(state["scan_mode"], "analise_vulnerabilidade")
    vuln_tools = _adapt_vuln_tools_for_target(state.get("target", ""), vuln_tools)
    if _is_local_target(state.get("target", "")):
        state["logs_terminais"].append(
            f"RiskAssessment: local_target detected, reduced_tools={','.join(vuln_tools)}"
        )
    primary_targets = _targets_for_deep_scan(state, limit=8)
    all_targets = _targets_for_deep_scan(state, limit=MAX_DISCOVERED_ASSETS + 1)
    all_findings: list[dict[str, Any]] = []
    if len(primary_targets) > 1:
        state["logs_terminais"].append(f"RiskAssessment: targets={len(primary_targets)}")
    
    # Burp é a ferramenta principal de vulnerabilidade e executa de forma síncrona.
    # Outras ferramentas também executam de forma síncrona.
    burp_tools = ["burp-cli"] if "burp-cli" in vuln_tools else []
    other_vuln_tools = [t for t in vuln_tools if t != "burp-cli"]

    # 1. Executar Burp CLI de forma síncrona em TODOS os alvos do escopo de análise.
    if burp_tools:
        state["logs_terminais"].append(
            f"RiskAssessment:Burp: executando de forma síncrona em {len(all_targets)} alvos"
        )
        for scan_target in all_targets:
            burp_findings, _, _, _ = _run_tools_and_collect(
                state,
                burp_tools,
                scan_target,
                current,
                "RiskAssessment:Burp",
            )
            if burp_findings:
                all_findings.extend(burp_findings)

        state["burp_targets"] = list(all_targets)
        state["burp_status"] = "completed"
        state["burp_async_task_ids"] = []

    # 2. Executar outras ferramentas de vulnerabilidade nos primary_targets.
    for scan_target in primary_targets:
        if other_vuln_tools:
            vuln_findings, _, _, _ = _run_tools_and_collect(state, other_vuln_tools, scan_target, current, "RiskAssessment")
            if vuln_findings:
                all_findings.extend(vuln_findings)
        
        all_findings.append(
            {
                "title": f"Avaliação de risco executada em {scan_target}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "risk_assessment",
                "details": {
                    "node": "risk_assessment",
                    "step": current,
                    "asset": scan_target,
                    "tool": "risk_assessment",
                },
            }
        )

    # Headers em todos os subdomínios descobertos (mesmo fora do primary_targets)
    extra_header_targets = [t for t in all_targets if t not in primary_targets]
    if "curl-headers" in vuln_tools and extra_header_targets:
        state["logs_terminais"].append(f"RiskAssessment: curl-headers extra_targets={len(extra_header_targets)}")
        for scan_target in extra_header_targets:
            header_findings, _, _, _ = _run_tools_and_collect(
                state,
                ["curl-headers"],
                scan_target,
                current,
                "RiskAssessment:Headers",
            )
            if header_findings:
                all_findings.extend(header_findings)

    state["logs_terminais"].append(f"RiskAssessment: {current}")

    if all_findings:
        state["vulnerabilidades_encontradas"].extend(all_findings)
    else:
        state["logs_terminais"].append(f"RiskAssessment: sem achados tecnicos no passo {current}")
    state["proxima_ferramenta"] = "governance"
    state["mission_index"] += 1
    _metric_end(state, "risk_assessment", started_at)
    return state


# Alias legado
def vuln_node(state: AgentState) -> AgentState:
    return risk_assessment_node(state)


def analista_ia_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["logs_terminais"].append(f"AnalistaIANode: triagem de {current}")
    if state.get("vulnerabilidades_encontradas"):
        last = state["vulnerabilidades_encontradas"][-1]
        if not last.get("source_worker"):
            last["source_worker"] = "analista_ia"
    state["proxima_ferramenta"] = "code_js"
    state["mission_index"] += 1
    _metric_end(state, "analista_ia", started_at)
    return state


def code_js_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["logs_terminais"].append(f"CodeJSNode: {current}")

    code_tools = _ordered_tools_for_step(state["scan_mode"], "code_js", current)
    targets = _targets_for_deep_scan(state, limit=6)
    if len(targets) > 1:
        state["logs_terminais"].append(f"CodeJSNode: targets={len(targets)}")
    for scan_target in targets:
        code_findings, _, _, _ = _run_tools_and_collect(state, code_tools, scan_target, current, "CodeJSNode")
        if code_findings:
            state["vulnerabilidades_encontradas"].extend(code_findings)

    state["proxima_ferramenta"] = "api"
    state["mission_index"] += 1
    _metric_end(state, "code_js", started_at)
    return state


def api_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["logs_terminais"].append(f"APINode: {current}")

    api_tools = _ordered_tools_for_step(state["scan_mode"], "api", current)
    targets = _targets_for_deep_scan(state, limit=6)
    if len(targets) > 1:
        state["logs_terminais"].append(f"APINode: targets={len(targets)}")
    for scan_target in targets:
        api_findings, _, _, _ = _run_tools_and_collect(state, api_tools, scan_target, current, "APINode")
        if api_findings:
            state["vulnerabilidades_encontradas"].extend(api_findings)

    state["proxima_ferramenta"] = "osint"
    state["mission_index"] += 1
    _metric_end(state, "api", started_at)
    return state


# ─────────────────────────────────────────────────────────────────────────────
# EASM Agent 2: Threat Intel
# Coleta inteligência externa: credenciais vazadas, reputação de IPs, OSINT.
# Ferramentas: theharvester → shodan-cli → h8mail → subjack
# ─────────────────────────────────────────────────────────────────────────────
def threat_intel_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    _sync_step_to_db(state, "2. ThreatIntel")
    current = _step_name(state)
    state["logs_terminais"].append(f"ThreatIntel: {current}")

    osint_tools = _tools_for_group(state["scan_mode"], "threat_intel") or _tools_for_group(state["scan_mode"], "osint")
    targets = _targets_for_deep_scan(state, limit=6)
    if len(targets) > 1:
        state["logs_terminais"].append(f"ThreatIntel: targets={len(targets)}")
    for scan_target in targets:
        osint_findings, _, _, _ = _run_tools_and_collect(state, osint_tools, scan_target, current, "ThreatIntel")
        if osint_findings:
            state["vulnerabilidades_encontradas"].extend(osint_findings)
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"Threat Intel executado em {scan_target}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "threat_intel",
                "details": {
                    "node": "threat_intel",
                    "step": current,
                    "asset": scan_target,
                    "tool": "threat_intel",
                },
            }
        )

    if osint_tools:
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"OSINT exposure indicators for {state['target']}",
                "severity": "low",
                "risk_score": 3,
                "source_worker": "threat_intel",
                "details": {
                    "node": "threat_intel",
                    "tools": osint_tools,
                    "step": current,
                },
            }
        )

    state["proxima_ferramenta"] = "risk_assessment"
    state["mission_index"] += 1
    _metric_end(state, "threat_intel", started_at)
    return state


# Alias legado
def osint_node(state: AgentState) -> AgentState:
    return threat_intel_node(state)


# ─────────────────────────────────────────────────────────────────────────────
# EASM Agent 4: Governance (The Rating Engine)
# Agente Python puro — sem ferramentas externas.
# Calcula FAIR+AGE por ativo e emite o rating contínuo com decomposição formal.
# ─────────────────────────────────────────────────────────────────────────────
def governance_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    _sync_step_to_db(state, "4. Governance")
    state["logs_terminais"].append("Governance: calculando FAIR+AGE rating")

    findings = state.get("vulnerabilidades_encontradas") or []
    discovered = state.get("lista_ativos") or [state["target"]]
    n_assets = max(1, len(discovered))

    # Computa Ra por finding e coleta para o rating global
    risk_per_asset: list[dict[str, Any]] = []
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        if sev in {"info"}:
            continue
        details = f.get("details") or {}
        asset = str(details.get("asset") or state["target"])
        days = int(details.get("known_in_environment_days") or details.get("age_days") or 0)
        cvss = details.get("cvss_score") or details.get("cvss")
        port = details.get("port")
        ra = compute_asset_risk(
            asset_url=asset,
            severity=sev,
            days_open=days,
            cvss=float(cvss) if cvss is not None else None,
            port=int(port) if port is not None else None,
        )
        risk_per_asset.append(ra)

    # Score global normalizado pela superfície digital
    easm_rating = compute_easm_rating(risk_per_asset, n_assets=n_assets)

    # Decomposição formal por 3 pilares FAIR
    fair_decomp = build_fair_decomposition(findings, n_assets=n_assets)

    state["easm_rating"] = {
        **easm_rating,
        "methodology": f"{METHODOLOGY_VERSION}/easm_fair_age_v1",
        "n_assets_scanned": n_assets,
    }
    state["fair_decomposition"] = fair_decomp
    state["logs_terminais"].append(
        f"Governance: score={easm_rating['score']} grade={easm_rating['grade']} "
        f"n_assets={n_assets} total_ra={easm_rating['total_ra']}"
    )
    # mission_index já foi incrementado pelos agentes paralelos (threat_intel + risk_assessment)
    _metric_end(state, "governance", started_at)
    return state


# ─────────────────────────────────────────────────────────────────────────────
# EASM Agent 5: Executive Analyst
# Usa LLM (Ollama) para gerar narrativa executiva baseada na decomposição FAIR.
# Se Ollama não estiver disponível, gera template estruturado sem LLM.
# ─────────────────────────────────────────────────────────────────────────────
def executive_analyst_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    _sync_step_to_db(state, "5. ExecutiveAnalysis")
    state["logs_terminais"].append("ExecutiveAnalyst: gerando narrativa executiva")

    easm_rating = state.get("easm_rating") or {}
    fair_decomp = state.get("fair_decomposition") or {}
    target = state.get("target", "alvo")
    score = easm_rating.get("score", 0)
    grade = easm_rating.get("grade", "F")
    pillars = fair_decomp.get("pillars") or []
    n_assets = easm_rating.get("n_assets_scanned", 1)

    # Tenta gerar narrativa via Ollama; se falhar, usa template estruturado
    try:
        import httpx
        from app.core.config import settings

        pillar_lines = ""
        for p in pillars:
            pillar_lines += (
                f"  - {p['name']} ({p['weight_pct']}): "
                f"score={p['score']}, impact=-{p['impact_pts']}pts, "
                f"{p['finding_count']} findings\n"
            )
        top_pilar = max(pillars, key=lambda x: x.get("impact_pts", 0), default={}) if pillars else {}

        prompt = (
            f"Atue como CISO. Converta os dados técnicos abaixo em uma análise executiva em português. "
            f"Seja direto, use impacto financeiro e mencione urgência de remediação.\n\n"
            f"Alvo: {target}\n"
            f"Rating: {score}/100 (Grau {grade})\n"
            f"Ativos mapeados: {n_assets}\n"
            f"Decomposição FAIR:\n{pillar_lines}"
            f"Principal detrator: {top_pilar.get('name', 'N/A')} (-{top_pilar.get('impact_pts', 0)}pts)\n\n"
            f"Gere: (1) Resumo executivo 2 frases, (2) Principal risco com impacto de negócio, "
            f"(3) Ação imediata recomendada. Máximo 150 palavras."
        )
        resp = httpx.post(
            f"{settings.ollama_base_url}/api/generate",
            json={"model": settings.ollama_model, "prompt": prompt, "stream": False},
            timeout=20.0,
        )
        if resp.status_code == 200:
            narrative = str(resp.json().get("response") or "").strip()
            state["executive_summary"] = narrative if narrative else _fallback_executive_summary(easm_rating, fair_decomp, target)
        else:
            state["executive_summary"] = _fallback_executive_summary(easm_rating, fair_decomp, target)
    except Exception as exc:
        state["logs_terminais"].append(f"ExecutiveAnalyst: ollama_unavailable ({exc.__class__.__name__}), usando template")
        state["executive_summary"] = _fallback_executive_summary(easm_rating, fair_decomp, target)

    state["logs_terminais"].append(f"ExecutiveAnalyst: narrative_length={len(state.get('executive_summary', ''))}")
    state["mission_index"] += 1
    _metric_end(state, "executive_analyst", started_at)
    return state


def _fallback_executive_summary(easm_rating: dict, fair_decomp: dict, target: str) -> str:
    """Template estruturado usado quando o Ollama não está disponível."""
    score = easm_rating.get("score", 0)
    grade = easm_rating.get("grade", "F")
    pillars = fair_decomp.get("pillars") or []
    top_pilar = max(pillars, key=lambda x: x.get("impact_pts", 0), default={}) if pillars else {}
    main_detractor = top_pilar.get("name", "vulnerabilidades não remediadas")
    main_pts = top_pilar.get("impact_pts", 0)
    finding_count = sum(p.get("finding_count", 0) for p in pillars)
    return (
        f"A postura de segurança externa de '{target}' recebeu rating {score}/100 (Grau {grade}). "
        f"Foram identificados {finding_count} issues técnicos distribuídos em {len(pillars)} dimensões de risco. "
        f"O principal detrator é '{main_detractor}', responsável por {main_pts} pontos de impacto no rating. "
        f"Ação imediata: priorizar remediação dos findings críticos/altos — a penalidade AGE "
        f"aumenta logaritmicamente a cada dia sem correção, amplificando o risco de exploração."
    )


def build_graph(mode: ScanMode = "unit"):
    """EASM 5-Agent Sequential Pipeline.

    AssetDiscovery → ThreatIntel → RiskAssessment → Governance → ExecutiveAnalyst

    - AssetDiscovery : subfinder / amass / dnsx / naabu / httpx / gowitness
    - ThreatIntel    : theharvester / shodan-cli / h8mail / subjack
    - RiskAssessment : burp-cli → nmap-vulscan → nikto
    - Governance     : FAIR+AGE rating engine (Python puro, sem ferramentas)
    - ExecutiveAnalyst: narrativa LLM via Ollama (fallback para template)
    """
    graph = StateGraph(AgentState)

    graph.add_node("asset_discovery",   asset_discovery_node)
    graph.add_node("risk_assessment",   risk_assessment_node)
    graph.add_node("threat_intel",      threat_intel_node)
    graph.add_node("governance",        governance_node)
    graph.add_node("executive_analyst", executive_analyst_node)

    # Pipeline paralelo — Asset Discovery dispara Threat Intel e Risk Assessment simultaneamente
    graph.set_entry_point("asset_discovery")
    graph.add_edge("asset_discovery",   "threat_intel")
    graph.add_edge("asset_discovery",   "risk_assessment")
    graph.add_edge("threat_intel",      "governance")
    graph.add_edge("risk_assessment",   "governance")
    graph.add_edge("governance",        "executive_analyst")
    graph.add_edge("executive_analyst", END)

    return graph.compile(checkpointer=checkpointer)


def initial_state(
    scan_id: int,
    target: str,
    scan_mode: ScanMode = "unit",
    known_vulnerability_patterns: list[str] | None = None,
    segment: str | None = None,
) -> AgentState:
    parsed_targets = _split_input_targets(target)
    primary_target = parsed_targets[0] if parsed_targets else str(target or "").strip()

    mission_items = GROUP_MISSION_ITEMS.copy()
    return {
        "scan_id": scan_id,
        "target": primary_target,
        "scan_mode": scan_mode,
        "easm_segment": segment or "Digital Services",
        "input_targets": parsed_targets or ([primary_target] if primary_target else []),
        "lista_ativos": [],
        "logs_terminais": [],
        "vulnerabilidades_encontradas": [],
        "proxima_ferramenta": "asset_discovery",
        "discovered_ports": [],
        "pending_port_tests": [],
        "pending_asset_scans": [],
        "scanned_assets": [],
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
        # EASM fields (preenchidos pelos agents 4 e 5)
        "asset_fingerprints": {},
        "fair_decomposition": {},
        "easm_rating": {},
        "executive_summary": "",
        # Burp async fields
        "burp_targets": [],
        "burp_status": "none",
        "burp_async_task_ids": [],
    }
