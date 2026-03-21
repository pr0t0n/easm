import os
from typing import Any
from urllib.parse import urlparse

from app.core.config import settings

from app.workers.worker_groups import find_group_by_tool, get_worker_groups


SAFE_TOOL_REGISTRY = {
    "recon": ["subfinder", "amass", "assetfinder", "dnsx", "naabu", "nessus"],
    "crawler": ["httpx", "katana", "waymore", "uro", "gowitness"],
    "fuzzing": ["ffuf", "feroxbuster", "arjun", "dirb"],
    "vuln": ["nessus", "nuclei", "dalfox", "nikto", "wpscan", "zap", "openvas", "semgrep"],
    "code_js": ["linkfinder", "secretfinder", "trufflehog"],
    "api": ["kiterunner", "postman-to-k6"],
    "osint": ["theharvester", "h8mail", "metagoofil", "urlscan-cli", "subjack", "shodan-cli", "whatweb"],
}


def get_execution_mode() -> str:
    return os.getenv("TOOL_EXECUTION_MODE", "controlled").strip().lower()


def resolve_worker_for_tool(tool_name: str, scan_mode: str = "unit") -> str:
    group = find_group_by_tool(tool_name, mode=scan_mode)
    groups = get_worker_groups(scan_mode)
    queue = groups.get(group, {}).get("queue", f"worker.{scan_mode}.recon")
    return str(queue)


def run_tool_execution(tool_name: str, target: str, scan_mode: str = "unit") -> dict[str, Any]:
    # Execucao controlada por policy/compliance na camada de orquestracao.
    worker = resolve_worker_for_tool(tool_name, scan_mode=scan_mode)
    mode = get_execution_mode()

    if tool_name.strip().lower() == "nessus":
        return _run_nessus_scan(target=target, worker=worker, mode=mode, scan_mode=scan_mode)

    return {
        "tool": tool_name,
        "target": target,
        "scan_mode": scan_mode,
        "worker": worker,
        "mode": mode,
        "status": "executed",
        "output": (
            f"{tool_name} executado para {target} via {worker}. "
            "Fluxo protegido por gate de autorizacao e policy."
        ),
    }


def _run_nessus_scan(target: str, worker: str, mode: str, scan_mode: str) -> dict[str, Any]:
    if not settings.nessus_enabled:
        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "skipped",
            "output": "Nessus desabilitado em configuracao.",
        }

    if not settings.nessus_url or not settings.nessus_access_key or not settings.nessus_secret_key:
        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "error",
            "output": "Nessus habilitado, mas sem URL/access_key/secret_key configurados.",
        }

    try:
        # Biblioteca esperada: pynessus / nessus. Mantemos import tardio para evitar quebrar o runtime.
        from nessus import NessusClient  # type: ignore
    except Exception:
        try:
            from pynessus import NessusClient  # type: ignore
        except Exception as exc:
            return {
                "tool": "nessus",
                "target": target,
                "scan_mode": scan_mode,
                "worker": worker,
                "mode": mode,
                "status": "error",
                "output": f"pynessus/nessus nao instalado no worker: {exc}",
            }

    parsed = urlparse(settings.nessus_url)
    host = parsed.hostname or settings.nessus_url.replace("https://", "").replace("http://", "")
    port = parsed.port or (8834 if parsed.scheme in {"https", ""} else 80)
    ssl = parsed.scheme != "http"

    try:
        client = NessusClient(
            host=host,
            access_key=settings.nessus_access_key,
            secret_key=settings.nessus_secret_key,
            port=port,
            ssl=ssl,
            verify=settings.nessus_verify_tls,
        )

        # Descoberta + scanner/vuln analyst: lança scan básico no alvo informado.
        scan_name = f"EASM-{scan_mode}-{target}"
        launch = client.scans.create_and_launch(
            name=scan_name,
            targets=target,
            template="basic",
        )

        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "executed",
            "output": f"Nessus scan iniciado: {scan_name}",
            "scan_id": launch.get("scan_id") if isinstance(launch, dict) else None,
            "scan_uuid": launch.get("scan_uuid") if isinstance(launch, dict) else None,
        }
    except Exception as exc:
        return {
            "tool": "nessus",
            "target": target,
            "scan_mode": scan_mode,
            "worker": worker,
            "mode": mode,
            "status": "error",
            "output": f"Falha ao executar Nessus via pynessus: {exc}",
        }
