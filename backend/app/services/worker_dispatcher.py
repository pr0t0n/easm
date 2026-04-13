import os
from typing import Any

from celery.result import allow_join_result

from app.services.tool_adapters import run_tool_execution
from app.services.resilience import SimpleCircuitBreaker, guarded_call
from app.workers.celery_app import celery
from app.workers.worker_groups import find_group_by_tool, group_queue


_DISPATCH_BREAKER = SimpleCircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30)


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
    # 660s = 10 min de subprocess + 60s de margem para o dispatcher.
    return 660


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
    execution_mode = str(os.getenv("EASM_TOOL_EXECUTION_MODE", "local")).strip().lower()
    if execution_mode == "local":
        return run_tool_execution(tool_name=tool_name, target=target, scan_mode=scan_mode)

    in_celery_task = False
    try:
        from celery import current_task as _current_task  # type: ignore
        in_celery_task = _current_task is not None
    except Exception:
        in_celery_task = False

    task_name = _tool_task_name(scan_mode=scan_mode, tool_name=tool_name)
    queue_name = _tool_queue_name(scan_mode=scan_mode, tool_name=tool_name)
    timeout = _timeout_for_tool(tool_name)
    dispatch_params = _dispatch_params_from_env()

    try:
        async_result = guarded_call(
            _DISPATCH_BREAKER,
            lambda: celery.send_task(
                task_name,
                kwargs={"tool": tool_name, "target": target, "params": dispatch_params},
                queue=queue_name,
            ),
            on_open_error=RuntimeError("circuit_open: dispatch indisponivel temporariamente"),
        )

        if in_celery_task:
            with allow_join_result():
                result = async_result.get(timeout=timeout, propagate=False)
        else:
            result = async_result.get(timeout=timeout, propagate=False)

        normalized = _normalize_result(tool_name=tool_name, target=target, scan_mode=scan_mode, result=result)
        normalized.setdefault("dispatch_task_id", async_result.id)
        normalized.setdefault("dispatch_task_name", task_name)
        normalized.setdefault("dispatch_bypassed", False)
        return normalized
    except Exception as exc:
        fallback = run_tool_execution(tool_name=tool_name, target=target, scan_mode=scan_mode)
        fallback.setdefault("dispatch_error", str(exc))
        fallback.setdefault("dispatch_task_name", task_name)
        fallback.setdefault("dispatch_bypassed", True)
        fallback.setdefault("dispatch_bypass_reason", "dispatch_error_or_circuit_open")
        if type(exc).__name__.lower() == "timeouterror":
            fallback.setdefault("dispatch_timeout", timeout)
        return fallback
