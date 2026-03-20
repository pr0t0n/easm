from datetime import datetime
from time import perf_counter
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from app.graph.mission import MISSION_ITEMS
from app.graph.checkpointer import create_checkpointer
from app.services.tool_adapters import run_tool_stub


class AgentState(TypedDict):
    scan_id: int
    target: str
    lista_ativos: list[str]
    logs_terminais: list[str]
    vulnerabilidades_encontradas: list[dict[str, Any]]
    proxima_ferramenta: str
    discovered_ports: list[int]
    pending_port_tests: list[int]
    port_followup_done: bool
    activity_metrics: list[dict[str, Any]]
    node_history: list[str]
    mission_index: int
    mission_items: list[str]


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
    state["mission_index"] += 1
    _metric_end(state, "recon", started_at)
    return state


def scan_node(state: AgentState) -> AgentState:
    started_at = _metric_start()
    current = _step_name(state)
    result = run_tool_stub("nmap", state["target"])
    state["logs_terminais"].append(f"ScanNode: {current} :: {result['status']}")

    # Simulacao defensiva: descoberta inicial de portas gera retestes direcionados.
    if not state["port_followup_done"]:
        state["discovered_ports"] = [80, 443, 8443]
        state["pending_port_tests"] = state["discovered_ports"].copy()
        state["port_followup_done"] = True

    if state["pending_port_tests"]:
        port = state["pending_port_tests"].pop(0)
        state["logs_terminais"].append(f"ScanNode: reteste automatico da porta {port}")
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
    }
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


def build_graph():
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


def initial_state(scan_id: int, target: str) -> AgentState:
    return {
        "scan_id": scan_id,
        "target": target,
        "lista_ativos": [],
        "logs_terminais": [],
        "vulnerabilidades_encontradas": [],
        "proxima_ferramenta": "recon",
        "discovered_ports": [],
        "pending_port_tests": [],
        "port_followup_done": False,
        "activity_metrics": [],
        "node_history": [],
        "mission_index": 0,
        "mission_items": MISSION_ITEMS,
    }
