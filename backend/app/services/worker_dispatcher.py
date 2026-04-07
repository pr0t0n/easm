import os
from typing import Any

from app.services.tool_adapters import run_tool_execution
from app.workers.celery_app import celery
from app.workers.worker_groups import find_group_by_tool, group_queue


def _tool_task_name(scan_mode: str, tool_name: str) -> str:
    mode = "scheduled" if str(scan_mode).strip().lower() == "scheduled" else "unit"
    group = find_group_by_tool(tool_name, mode=mode)
    return f"worker.{mode}.{group}.execute"


def _tool_queue_name(scan_mode: str, tool_name: str) -> str:
    mode = "scheduled" if str(scan_mode).strip().lower() == "scheduled" else "unit"
    group = find_group_by_tool(tool_name, mode=mode)
    return group_queue(group, mode=mode)


def _timeout_for_tool(tool_name: str) -> int:
    name = str(tool_name or "").strip().lower()
    if name in {"burp", "burp-cli"}:
        return 900
    if name in {"nuclei", "nessus", "nmap-vulscan", "vulscan", "zap"}:
        return 240
    if name in {"amass", "katana", "waymore", "wpscan", "nikto", "sqlmap"}:
        return 120
    return 75


def _normalize_result(tool_name: str, target: str, scan_mode: str, result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        normalized = dict(result)
        normalized.setdefault("tool", tool_name)
        normalized.setdefault("target", target)
        normalized.setdefault("scan_mode", scan_mode)
        return normalized

    return {
        "tool": tool_name,
        "target": target,
        "scan_mode": scan_mode,
        "status": "error",
        "output": f"Resultado invalido retornado pelo worker: {type(result).__name__}",
        "open_ports": [],
        "return_code": None,
        "command": "",
        "stdout": "",
        "stderr": "",
    }


def _dispatch_params_from_env() -> dict[str, str]:
    params: dict[str, str] = {}
    burp_key = str(os.getenv("BURP_LICENSE_KEY", "")).strip()
    if burp_key:
        params["burp_license_key"] = burp_key

    shodan_key = str(os.getenv("SHODAN_API_KEY", "")).strip()
    if shodan_key:
        params["shodan_api_key"] = shodan_key

    return params


def execute_tool_with_workers(tool_name: str, target: str, scan_mode: str = "unit") -> dict[str, Any]:
    execution_mode = str(os.getenv("EASM_TOOL_EXECUTION_MODE", "distributed")).strip().lower()
    if execution_mode == "local":
        return run_tool_execution(tool_name=tool_name, target=target, scan_mode=scan_mode)

    # Evita bloqueio "Never call result.get() dentro da task" quando o grafo
    # ja esta rodando dentro de um worker Celery.
    # IMPRESCINDÍVEL: grafo usa LangGraph.invoke() que roda sincrono no mesmo processo.
    in_celery_task = False
    try:
        from celery import current_task as _current_task  # type: ignore
        in_celery_task = _current_task is not None
    except Exception as ce:
        in_celery_task = False

    # SEMPRE Usar fallback local quando dentro do Celery (grafo pode estar em qualquer nó)
    if in_celery_task:
        fallback = run_tool_execution(tool_name=tool_name, target=target, scan_mode=scan_mode)
        fallback.setdefault("dispatch_task_name", _tool_task_name(scan_mode=scan_mode, tool_name=tool_name))
        fallback.setdefault("dispatch_bypassed", True)
        fallback.setdefault("dispatch_bypass_reason", "running_inside_celery_task")
        return fallback

    task_name = _tool_task_name(scan_mode=scan_mode, tool_name=tool_name)
    queue_name = _tool_queue_name(scan_mode=scan_mode, tool_name=tool_name)
    timeout = _timeout_for_tool(tool_name)
    dispatch_params = _dispatch_params_from_env()

    try:
        async_result = celery.send_task(
            task_name,
            kwargs={"tool": tool_name, "target": target, "params": dispatch_params},
            queue=queue_name,
        )
        result = async_result.get(timeout=timeout, propagate=False)
        normalized = _normalize_result(tool_name=tool_name, target=target, scan_mode=scan_mode, result=result)
        normalized.setdefault("dispatch_task_id", async_result.id)
        normalized.setdefault("dispatch_task_name", task_name)
        return normalized
    except Exception as exc:
        fallback = run_tool_execution(tool_name=tool_name, target=target, scan_mode=scan_mode)
        fallback.setdefault("dispatch_error", str(exc))
        fallback.setdefault("dispatch_task_name", task_name)
        if type(exc).__name__.lower() == "timeouterror":
            fallback.setdefault("dispatch_timeout", timeout)
        return fallback
