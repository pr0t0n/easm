import os
from typing import Any

from app.workers.worker_groups import WORKER_GROUPS, find_group_by_tool


SAFE_TOOL_REGISTRY = {
    "recon": ["amass", "sublist3r", "cloudenum", "naabu", "massdns", "dnsenum"],
    "fuzzing": ["ffuf", "feroxbuster", "arjun", "dirb"],
    "vuln": ["nessus", "nuclei", "nikto", "wpscan", "zap"],
    "code_js": ["linkfinder", "secretfinder", "trufflehog"],
    "api": ["kiterunner", "postman-to-k6"],
}

def get_execution_mode() -> str:
    return os.getenv("TOOL_EXECUTION_MODE", "stub").strip().lower()


def resolve_worker_for_tool(tool_name: str) -> str:
    group = find_group_by_tool(tool_name)
    queue = WORKER_GROUPS.get(group, {}).get("queue", "worker.recon")
    return str(queue)


def run_tool_stub(tool_name: str, target: str) -> dict[str, Any]:
    # Adaptador seguro: apenas registra intencao de execucao para ambientes autorizados.
    worker = resolve_worker_for_tool(tool_name)
    mode = get_execution_mode()
    return {
        "tool": tool_name,
        "target": target,
        "worker": worker,
        "mode": mode,
        "status": "planned",
        "output": (
            f"{tool_name} planejado para {target} via {worker}. "
            "Integracao real deve validar escopo autorizado."
        ),
    }
