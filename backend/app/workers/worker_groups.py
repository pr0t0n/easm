from typing import Any


WORKER_GROUPS: dict[str, dict[str, Any]] = {
    "recon": {
        "queue": "worker.recon",
        "description": "Descoberta de ativos e enumeracao",
        "tools": ["amass", "sublist3r", "cloudenum", "naabu", "massdns", "dnsenum"],
    },
    "fuzzing": {
        "queue": "worker.fuzzing",
        "description": "Fuzzing de superficie web",
        "tools": ["ffuf", "feroxbuster", "arjun", "dirb"],
    },
    "vuln": {
        "queue": "worker.vuln",
        "description": "Validacao de vulnerabilidades conhecidas",
        "tools": ["nessus", "nuclei", "nikto", "wpscan", "zap"],
    },
    "code_js": {
        "queue": "worker.code_js",
        "description": "Analise de JavaScript e segredos",
        "tools": ["linkfinder", "secretfinder", "trufflehog"],
    },
    "api": {
        "queue": "worker.api",
        "description": "Mapeamento e validacao de APIs",
        "tools": ["kiterunner", "postman-to-k6"],
    },
}


def find_group_by_tool(tool_name: str) -> str:
    normalized = tool_name.strip().lower()
    for group_name, group in WORKER_GROUPS.items():
        if normalized in group["tools"]:
            return group_name
    return "recon"


def group_queue(group_name: str) -> str:
    group = WORKER_GROUPS.get(group_name, WORKER_GROUPS["recon"])
    return str(group["queue"])
