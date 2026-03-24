import re
from datetime import datetime
from time import perf_counter
from typing import Any, TypedDict
from urllib.parse import urlparse

from langgraph.graph import END, StateGraph

from app.graph.checkpointer import create_checkpointer
from app.services.worker_dispatcher import execute_tool_with_workers
from app.workers.worker_groups import ScanMode, get_worker_groups


GROUP_MISSION_ITEMS: list[str] = [
    "1. Reconhecimento",
    "2. AnaliseVulnerabilidade",
    "3. OSINT",
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
]


class AgentState(TypedDict):
    scan_id: int
    target: str
    scan_mode: str                          # "unit" | "scheduled"
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
        return "osint"
    if "recon" in step:
        return "recon"
    if "analisevulnerabilidade" in step or "vulnerabilidade" in step:
        return "vuln"
    return "osint"


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
        (("ssrf", "xxe", "directory traversal", "rfi", "lfi", "header injection", "crlf"), "wapiti"),
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

        asm_findings = _extract_asm_findings(result, step_name, scan_target)
        if asm_findings:
            all_findings.extend(asm_findings)
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} asm_findings={len(asm_findings)}")

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

    _mark_step_metric(state, step_success)
    return all_findings, sorted(discovered_ports), sorted(discovered_assets), port_evidence


def _target_host(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = str(parsed.hostname or "").strip().lower()
    if not host:
        host = raw.split("/")[0].split(":")[0].strip().lower()
    return host.lstrip("*.").strip(".")


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
        candidates.append(root)

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
    if tool == "nikto":
        return _extract_nikto_findings(stdout, step_name, default_target)
    if tool in {"nmap-vulscan", "vulscan"}:
        return _extract_nmap_vulscan_findings(stdout, step_name, default_target)
    if tool == "sslscan":
        return _extract_sslscan_findings(stdout, step_name, default_target)
    return []


def _extract_wafw00f_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        match = re.search(r"is behind\s+(.+?)\s+WAF", line, re.IGNORECASE)
        if match:
            vendor = str(match.group(1) or "").strip()
            lowered_vendor = vendor.lower()
            known_vendor = next((model for model in KNOWN_WAF_MODELS if model in lowered_vendor), "")
            normalized_vendor = known_vendor if known_vendor else vendor
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
                        "waf_model_match": bool(known_vendor),
                        "waf_detected": True,
                    },
                }
            )
            break
    return findings


def _extract_shcheck_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_headers: set[str] = set()
    header_pattern = re.compile(
        r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy)",
        re.IGNORECASE,
    )

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        lowered = line.lower()
        if "missing" not in lowered and "not set" not in lowered and "absent" not in lowered:
            continue
        header_match = header_pattern.search(line)
        if not header_match:
            continue
        header = str(header_match.group(1) or "").strip().lower()
        if header in seen_headers:
            continue
        seen_headers.add(header)
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
    return findings


def _extract_nikto_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    ignore_tokens = [
        "target host",
        "target ip",
        "target port",
        "start time",
        "end time",
        "no web server found",
    ]
    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line.startswith("+"):
            continue
        lowered = line.lower()
        if any(token in lowered for token in ignore_tokens):
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
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
                    "title": f"nmap-vulscan: {cve_id}",
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
                "title": "nmap-vulscan: referencias de vulnerabilidade identificadas (sem CVE explícito)",
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


def _step_name(state: AgentState) -> str:
    idx = state.get("mission_index", 0)
    items = state.get("mission_items", GROUP_MISSION_ITEMS)
    if idx >= len(items):
        return "done"
    return items[idx]


def recon_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["proxima_ferramenta"] = "scanner"
    state["logs_terminais"].append(f"ReconNode: {current}")
    if state["target"] not in state["lista_ativos"]:
        state["lista_ativos"].append(state["target"])
    if state["target"] not in state["pending_asset_scans"] and state["target"] not in state["scanned_assets"]:
        state["pending_asset_scans"].append(state["target"])

    recon_tools = _tools_for_group(state["scan_mode"], "reconhecimento")
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
            "source_worker": "recon",
            "details": {"node": "recon", "step": current},
        }
    )
    state["mission_index"] += 1
    _metric_end(state, "recon", started_at)
    return state


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


def vuln_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    vuln_tools = _tools_for_group(state["scan_mode"], "analise_vulnerabilidade")
    targets = _targets_for_deep_scan(state, limit=8)
    all_findings: list[dict[str, Any]] = []
    if len(targets) > 1:
        state["logs_terminais"].append(f"VulnNode: targets={len(targets)}")
    for scan_target in targets:
        vuln_findings, _, _, _ = _run_tools_and_collect(state, vuln_tools, scan_target, current, "VulnNode")
        if vuln_findings:
            all_findings.extend(vuln_findings)
        all_findings.append(
            {
                "title": f"Analise de vulnerabilidade executada em {scan_target}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": current,
                    "asset": scan_target,
                    "tool": "analise_vulnerabilidade",
                },
            }
        )
    state["logs_terminais"].append(f"VulnNode: {current}")

    if all_findings:
        state["vulnerabilidades_encontradas"].extend(all_findings)
    else:
        state["logs_terminais"].append(f"VulnNode: sem achados tecnicos no passo {current}")
    state["proxima_ferramenta"] = "analista_ia"
    state["mission_index"] += 1
    _metric_end(state, "vuln", started_at)
    return state


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


def osint_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["logs_terminais"].append(f"OSINTNode: {current}")

    osint_tools = _tools_for_group(state["scan_mode"], "osint")
    targets = _targets_for_deep_scan(state, limit=6)
    if len(targets) > 1:
        state["logs_terminais"].append(f"OSINTNode: targets={len(targets)}")
    for scan_target in targets:
        osint_findings, _, _, _ = _run_tools_and_collect(state, osint_tools, scan_target, current, "OSINTNode")
        if osint_findings:
            state["vulnerabilidades_encontradas"].extend(osint_findings)
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"OSINT executado em {scan_target}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "osint",
                "details": {
                    "node": "osint",
                    "step": current,
                    "asset": scan_target,
                    "tool": "osint",
                },
            }
        )

    if osint_tools:
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"OSINT exposure indicators for {state['target']}",
                "severity": "low",
                "risk_score": 3,
                "source_worker": "osint",
                "details": {
                    "node": "osint",
                    "tools": osint_tools,
                    "step": current,
                },
            }
        )

    state["proxima_ferramenta"] = "recon"
    state["mission_index"] += 1
    _metric_end(state, "osint", started_at)
    return state


def supervisor_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    nxt = state.get("proxima_ferramenta", "recon")
    state["logs_terminais"].append(f"Supervisor: step={current} -> proxima={nxt}")
    _metric_end(state, "supervisor", started_at)
    return state


def route_decision(state: AgentState) -> str:
    if state["mission_index"] >= len(state["mission_items"]):
        return END

    current = _step_name(state)
    nxt = _node_for_step(current, state.get("scan_mode", "unit"))
    if nxt == "vuln":
        return "vuln"
    if nxt == "osint":
        return "osint"
    return "recon"


def build_graph(mode: ScanMode = "unit"):
    """Constroi o grafo em 3 fases: Reconhecimento -> AnaliseVulnerabilidade -> OSINT."""
    graph = StateGraph(AgentState)

    graph.add_node("supervisor", supervisor_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("osint", osint_node)

    graph.set_entry_point("supervisor")

    graph.add_conditional_edges("supervisor", route_decision)

    graph.add_edge("recon", "supervisor")
    graph.add_edge("vuln", "supervisor")
    graph.add_edge("osint", "supervisor")

    return graph.compile(checkpointer=checkpointer)


def initial_state(
    scan_id: int,
    target: str,
    scan_mode: ScanMode = "unit",
    known_vulnerability_patterns: list[str] | None = None,
) -> AgentState:
    mission_items = GROUP_MISSION_ITEMS.copy()
    return {
        "scan_id": scan_id,
        "target": target,
        "scan_mode": scan_mode,
        "lista_ativos": [],
        "logs_terminais": [],
        "vulnerabilidades_encontradas": [],
        "proxima_ferramenta": "recon",
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
    }
