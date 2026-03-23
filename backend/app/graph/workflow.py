import re
from datetime import datetime
from time import perf_counter
from typing import Any, TypedDict
from urllib.parse import urlparse

from langgraph.graph import END, StateGraph

from app.graph.mission import MISSION_ITEMS
from app.graph.checkpointer import create_checkpointer
from app.services.tool_adapters import run_tool_execution
from app.workers.worker_groups import ScanMode, get_worker_groups


# ──────────────────────────────────────────────────────────────────────────────
# Itens de missao reduzidos para scans UNITARIOS
# Cobre os passos mais criticos: recon, ports, headers, injecoes, CVEs, relatorio
# ──────────────────────────────────────────────────────────────────────────────
UNIT_MISSION_ITEMS: list[str] = [item for item in MISSION_ITEMS if any(
    kw in item for kw in [
        "Amass", "Naabu", "Nmap", "HSTS/CSP", "Cookie Flags",
        "SQLi", "SQLMap", "IDOR", "CSRF", "SecretFinder", "Nuclei Critical",
        "Nuclei High", "Nikto", "JWT", "Command Injection", "Commix",
        "SSRF", "XXE", "SSTI", "Tplmap", "Wapiti", "Gobuster",
        "Vertical Privilege", "Horizontal Privilege", "Relatorio Final",
    ]
)]


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


def _mission_step_keywords() -> list[tuple[str, str]]:
    return [
        ("osint", "osint"),
        ("email", "osint"),
        ("theharvester", "osint"),
        ("h8mail", "osint"),
        ("metagoofil", "osint"),
        ("shodan", "osint"),
        ("urlscan", "osint"),
        ("subdomain", "recon"),
        ("dns", "recon"),
        ("asn", "recon"),
        ("ip/infra", "recon"),
        ("takeover", "recon"),
        ("naabu", "scan"),
        ("nmap", "scan"),
        ("port", "scan"),
        ("banner", "scan"),
        ("robots.txt", "scan"),
        ("sitemap.xml", "scan"),
        ("headers", "scan"),
        ("hsts", "scan"),
        ("cookie", "scan"),
        ("fingerprint", "fingerprint"),
        ("whatweb", "fingerprint"),
        ("wappalyzer", "fingerprint"),
        ("cms", "fingerprint"),
        ("ffuf", "fuzzing"),
        ("feroxbuster", "fuzzing"),
        ("wfuzz", "fuzzing"),
        ("gobuster", "fuzzing"),
        ("fuzz", "fuzzing"),
        ("linkfinder", "code_js"),
        ("secretfinder", "code_js"),
        ("trufflehog", "code_js"),
        ("javascript", "code_js"),
        ("api", "api"),
        ("kiterunner", "api"),
        ("swagger", "api"),
        ("openapi", "api"),
        ("sqli", "vuln"),
        ("sqli", "vuln"),
        ("nosql", "vuln"),
        ("idor", "vuln"),
        ("csrf", "vuln"),
        ("ssrf", "vuln"),
        ("xxe", "vuln"),
        ("lfi", "vuln"),
        ("rfi", "vuln"),
        ("ssti", "vuln"),
        ("tplmap", "vuln"),
        ("commix", "vuln"),
        ("command injection", "vuln"),
        ("jwt", "vuln"),
        ("nuclei", "vuln"),
        ("nikto", "vuln"),
        ("wpscan", "vuln"),
        ("nessus", "vuln"),
        ("shellshock", "vuln"),
        ("heartbleed", "vuln"),
        ("relatorio final", "analista_ia"),
    ]


def _node_for_step(step_name: str, scan_mode: str) -> str:
    step = str(step_name or "").strip().lower()
    if step in {"", "done"}:
        return "analista_ia"
    if scan_mode == "unit" and "relatorio final" in step:
        return "analista_ia"
    for keyword, node in _mission_step_keywords():
        if keyword in step:
            return node
    return "scan"


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
FALLBACK_PORT_CANDIDATES = [
    80,
    81,
    443,
    8080,
    8443,
    8888,
    8000,
    8008,
    3000,
    5000,
    22,
    21,
    25,
    53,
    110,
    143,
    3306,
    5432,
    6379,
    9200,
    27017,
]

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


def _tool_for_step(step_name: str) -> str:
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
    return "nmap"


def _tools_for_group(scan_mode: str, group_name: str) -> list[str]:
    groups = get_worker_groups(mode=scan_mode)
    group = groups.get(group_name, {})
    return list(group.get("tools", []))


def _ordered_tools_for_step(scan_mode: str, group_name: str, step_name: str) -> list[str]:
    tools = _tools_for_group(scan_mode, group_name)
    primary_tool = _tool_for_step(step_name)
    if primary_tool in tools:
        return [primary_tool] + [tool for tool in tools if tool != primary_tool]
    return tools


def _run_tools_and_collect(
    state: AgentState,
    tools: list[str],
    scan_target: str,
    step_name: str,
    log_prefix: str,
    root_domain: str = "",
) -> tuple[list[dict[str, Any]], list[int], list[str]]:
    all_findings: list[dict[str, Any]] = []
    discovered_ports: set[int] = set()
    discovered_assets: set[str] = set()
    step_success = False

    for tool in tools:
        run_id = f"{step_name}|{scan_target}|{tool}".lower()
        if run_id in state.get("executed_tool_runs", []):
            state["logs_terminais"].append(f"{log_prefix}: tool={tool} skipped=already_executed_for_step")
            continue

        result = run_tool_execution(tool, scan_target, scan_mode=state["scan_mode"])
        state["executed_tool_runs"].append(run_id)
        state["logs_terminais"].append(f"{log_prefix}: tool={tool} status={result.get('status', 'unknown')}")
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

        for port in _extract_open_ports(result, step_name=step_name, tool_name=tool):
            discovered_ports.add(port)

        for asset in _extract_assets_from_result(result, root_domain=root_domain):
            discovered_assets.add(asset)

    _mark_step_metric(state, step_success)
    return all_findings, sorted(discovered_ports), sorted(discovered_assets)


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

    # Fallback de portas somente em contexto explicito de mapeamento de portas.
    explicit_step = str(step_name or "").lower()
    explicit_tool = str(tool_name or "").lower()
    allow_fallback = any(token in explicit_step for token in ["port scan", "porta", "ports"]) and explicit_tool in {"naabu", "nmap"}
    if allow_fallback:
        return FALLBACK_PORT_CANDIDATES.copy()
    return []


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


def _step_name(state: AgentState) -> str:
    idx = state.get("mission_index", 0)
    items = state.get("mission_items", MISSION_ITEMS)
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

    recon_tools = _ordered_tools_for_step(state["scan_mode"], "recon", current)
    root_domain = _target_host(state["target"])
    recon_findings, recon_ports, recon_assets = _run_tools_and_collect(
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

    scan_findings, scan_ports, _ = _run_tools_and_collect(state, scan_tools, scan_target, current, "ScanNode")
    if scan_findings:
        state["vulnerabilidades_encontradas"].extend(scan_findings)

    if scan_ports:
        state["discovered_ports"] = sorted(set((state.get("discovered_ports") or []) + scan_ports))
        state["pending_port_tests"] = state["discovered_ports"].copy()
    if scan_target not in state["scanned_assets"]:
        state["scanned_assets"].append(scan_target)
    state["port_followup_done"] = True

    if state["pending_port_tests"]:
        for port in state["pending_port_tests"]:
            state["vulnerabilidades_encontradas"].append(
                {
                    "title": f"Servico externo identificado na porta {port}",
                    "severity": "medium",
                    "risk_score": 4,
                    "source_worker": "scan",
                    "details": {"node": "scan", "asset": scan_target, "port": port, "step": current},
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

    scan_target = state["target"]
    fuzz_tools = _ordered_tools_for_step(state["scan_mode"], "fuzzing", current)
    fuzz_findings, _, _ = _run_tools_and_collect(state, fuzz_tools, scan_target, current, "FuzzingNode")
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

    scan_target = state["target"]
    fingerprint_tools = _ordered_tools_for_step(state["scan_mode"], "fingerprint", current)
    fingerprint_findings, _, _ = _run_tools_and_collect(state, fingerprint_tools, scan_target, current, "FingerprintNode")
    if fingerprint_findings:
        state["vulnerabilidades_encontradas"].extend(fingerprint_findings)

    state["proxima_ferramenta"] = "fuzzing"
    state["mission_index"] += 1
    _metric_end(state, "fingerprint", started_at)
    return state


def vuln_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    scan_target = state["target"]
    vuln_tools = _ordered_tools_for_step(state["scan_mode"], "vuln", current)
    vuln_findings, _, _ = _run_tools_and_collect(state, vuln_tools, scan_target, current, "VulnNode")
    state["logs_terminais"].append(f"VulnNode: {current}")

    if vuln_findings:
        state["vulnerabilidades_encontradas"].extend(vuln_findings)
    else:
        finding = {
            "title": f"Potential issue from step: {current}",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "vuln",
        }
        known_patterns = [p.lower() for p in state.get("known_vulnerability_patterns", [])]
        title_l = finding["title"].lower()
        if any(k and (k in title_l or title_l in k) for k in known_patterns):
            finding["risk_score"] = 7
            finding["known_pattern_match"] = True
        state["vulnerabilidades_encontradas"].append(finding)
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

    scan_target = state["target"]
    code_tools = _ordered_tools_for_step(state["scan_mode"], "code_js", current)
    code_findings, _, _ = _run_tools_and_collect(state, code_tools, scan_target, current, "CodeJSNode")
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

    scan_target = state["target"]
    api_tools = _ordered_tools_for_step(state["scan_mode"], "api", current)
    api_findings, _, _ = _run_tools_and_collect(state, api_tools, scan_target, current, "APINode")
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

    # Puxa a lista de ferramentas OSINT por modo para manter alinhamento com worker groups.
    osint_tools = _ordered_tools_for_step(state["scan_mode"], "osint", current)
    osint_findings, _, _ = _run_tools_and_collect(state, osint_tools, state["target"], current, "OSINTNode")
    if osint_findings:
        state["vulnerabilidades_encontradas"].extend(osint_findings)

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
    if nxt == "scanner":
        return "scan"
    if nxt == "fuzzing":
        return "fuzzing"
    if nxt == "fingerprint":
        return "fingerprint"
    if nxt == "vuln":
        return "vuln"
    if nxt == "analista_ia":
        return "analista_ia"
    if nxt == "code_js":
        return "code_js"
    if nxt == "api":
        return "api"
    if nxt == "osint":
        return "osint"
    return "recon"


def build_graph(mode: ScanMode = "unit"):
    """
    Constroi o grafo LangGraph para o modo informado.
    - "unit": missao reduzida (UNIT_MISSION_ITEMS), comportamento focado
    - "scheduled": missao completa (100 passos), cobertura maxima
    """
    graph = StateGraph(AgentState)

    graph.add_node("supervisor", supervisor_node)
    graph.add_node("recon", recon_node)
    graph.add_node("scan", scan_node)
    graph.add_node("fingerprint", fingerprint_node)
    graph.add_node("fuzzing", fuzzing_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("analista_ia", analista_ia_node)
    graph.add_node("code_js", code_js_node)
    graph.add_node("api", api_node)
    graph.add_node("osint", osint_node)

    graph.set_entry_point("supervisor")

    graph.add_conditional_edges("supervisor", route_decision)

    graph.add_edge("recon", "supervisor")
    graph.add_edge("scan", "supervisor")
    graph.add_edge("fingerprint", "supervisor")
    graph.add_edge("fuzzing", "supervisor")
    graph.add_edge("vuln", "supervisor")
    graph.add_edge("analista_ia", "supervisor")
    graph.add_edge("code_js", "supervisor")
    graph.add_edge("api", "supervisor")
    graph.add_edge("osint", "supervisor")

    return graph.compile(checkpointer=checkpointer)


def initial_state(
    scan_id: int,
    target: str,
    scan_mode: ScanMode = "unit",
    known_vulnerability_patterns: list[str] | None = None,
) -> AgentState:
    mission_items = UNIT_MISSION_ITEMS if scan_mode == "unit" else MISSION_ITEMS
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
