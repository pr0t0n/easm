from datetime import datetime
from time import perf_counter
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from app.graph.mission import MISSION_ITEMS
from app.graph.checkpointer import create_checkpointer
from app.services.tool_adapters import run_tool_execution
from app.workers.worker_groups import ScanMode


# ──────────────────────────────────────────────────────────────────────────────
# Itens de missao reduzidos para scans UNITARIOS
# Cobre os passos mais criticos: recon, ports, headers, injecoes, CVEs, relatorio
# ──────────────────────────────────────────────────────────────────────────────
UNIT_MISSION_ITEMS: list[str] = [item for item in MISSION_ITEMS if any(
    kw in item for kw in [
        "Amass", "Naabu", "Nmap", "HSTS/CSP", "Cookie Flags",
        "SQLi", "IDOR", "CSRF", "SecretFinder", "Nuclei Critical",
        "Nuclei High", "Nikto", "JWT", "Command Injection",
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
    node_history: list[str]
    mission_index: int
    mission_items: list[str]
    known_vulnerability_patterns: list[str]


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


def _extract_open_ports(result: dict[str, Any]) -> list[int]:
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
    return FALLBACK_PORT_CANDIDATES.copy()


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

    # Sempre que houver ativo pendente, forca scanner para cobrir descoberta incremental.
    if state["pending_asset_scans"]:
        state["proxima_ferramenta"] = "scanner"
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
    result = run_tool_execution("nmap", scan_target, scan_mode=state["scan_mode"])
    state["logs_terminais"].append(f"ScanNode: {current} [{scan_target}] :: {result['status']}")

    # Reteste dinamico por portas descobertas no scan atual.
    discovered = _extract_open_ports(result)
    state["discovered_ports"] = discovered
    state["pending_port_tests"] = discovered.copy()
    if scan_target not in state["scanned_assets"]:
        state["scanned_assets"].append(scan_target)
    state["port_followup_done"] = True

    if state["pending_port_tests"]:
        port = state["pending_port_tests"].pop(0)
        state["logs_terminais"].append(f"ScanNode: reteste automatico {scan_target}:{port}")
        state["vulnerabilidades_encontradas"].append(
            {
                "title": f"Servico externo identificado na porta {port}",
                "severity": "medium",
                "risk_score": 4,
                "source_worker": "scan",
                "details": {"node": "scan", "asset": scan_target, "port": port, "step": current},
            }
        )
        state["proxima_ferramenta"] = "scanner"
    elif state["pending_asset_scans"]:
        state["proxima_ferramenta"] = "scanner"
    else:
        state["proxima_ferramenta"] = "fuzzing"

    state["mission_index"] += 1
    _metric_end(state, "scan", started_at)
    return state


def fuzzing_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    state["logs_terminais"].append(f"FuzzingNode: {current}")

    # Exemplo de ciclo: se for detectado ativo novo, retorna para scan.
    if "new-asset.local" not in state["lista_ativos"] and state["mission_index"] % 7 == 0:
        state["lista_ativos"].append("new-asset.local")
        if "new-asset.local" not in state["pending_asset_scans"] and "new-asset.local" not in state["scanned_assets"]:
            state["pending_asset_scans"].append("new-asset.local")
        state["vulnerabilidades_encontradas"].append(
            {
                "title": "Crescimento lateral detectado por fuzzing",
                "severity": "medium",
                "risk_score": 5,
                "source_worker": "fuzzing",
                "details": {"node": "fuzzing", "new_asset": "new-asset.local", "step": current},
            }
        )
        state["proxima_ferramenta"] = "scanner"
    else:
        state["proxima_ferramenta"] = "vuln"

    state["mission_index"] += 1
    _metric_end(state, "fuzzing", started_at)
    return state


def vuln_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
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
    state["logs_terminais"].append(f"VulnNode: {current}")
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
    state["proxima_ferramenta"] = "recon"
    state["mission_index"] += 1
    _metric_end(state, "analista_ia", started_at)
    return state


def route_decision(state: AgentState) -> str:
    if state["mission_index"] >= len(state["mission_items"]):
        return END

    nxt = state.get("proxima_ferramenta", "recon")
    if nxt == "scanner":
        return "scan"
    if nxt == "fuzzing":
        return "fuzzing"
    if nxt == "vuln":
        return "vuln"
    if nxt == "analista_ia":
        return "analista_ia"
    return "recon"


def build_graph(mode: ScanMode = "unit"):
    """
    Constroi o grafo LangGraph para o modo informado.
    - "unit": missao reduzida (UNIT_MISSION_ITEMS), comportamento focado
    - "scheduled": missao completa (100 passos), cobertura maxima
    """
    graph = StateGraph(AgentState)

    graph.add_node("recon", recon_node)
    graph.add_node("scan", scan_node)
    graph.add_node("fuzzing", fuzzing_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("analista_ia", analista_ia_node)

    graph.set_entry_point("recon")

    graph.add_conditional_edges("recon", route_decision)
    graph.add_conditional_edges("scan", route_decision)
    graph.add_conditional_edges("fuzzing", route_decision)
    graph.add_conditional_edges("vuln", route_decision)
    graph.add_conditional_edges("analista_ia", route_decision)

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
        "node_history": [],
        "mission_index": 0,
        "mission_items": mission_items,
        "known_vulnerability_patterns": known_vulnerability_patterns or [],
    }
