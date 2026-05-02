"""Tool dispatcher — Kali runner is the ONLY execution path.

After the architecture refactor, every offensive tool runs inside the
Kali container. Workers no longer carry tools themselves. This module
exists only to (a) translate `tool_name → profile`, (b) post the job
to `kali_runner`, (c) poll for the result, (d) shape it back into the
dict structure the existing workflow code expects.

If the runner is unreachable, the call returns a structured `error`
result so the workflow can flag it as `attempted_failed` instead of
hanging. There is NO local fallback — that codepath has been removed.
"""
from __future__ import annotations

import logging
from typing import Any

from app.services.kali_executor import execute_via_kali, TOOL_TO_PROFILE


logger = logging.getLogger(__name__)


def execute_tool_with_workers(
    tool_name: str,
    target: str,
    scan_mode: str = "unit",
) -> dict[str, Any]:
    """Single-path tool execution: always via the Kali runner."""
    if str(tool_name or "").strip().lower() not in TOOL_TO_PROFILE:
        return {
            "tool": tool_name,
            "target": target,
            "scan_mode": scan_mode,
            "status": "error",
            "command": "",
            "stdout": "",
            "stderr": "",
            "dispatch_error": f"no_profile_mapping for tool '{tool_name}'",
            "source_agent_id": "kali_runner",
            "source_agent_name": "Kali Runner",
            "open_ports": [],
        }

    # Try to surface the current scan_id so evidence is filed under
    # /workspace/{scan_id}/{tool}/{job_id}/ on the runner.
    scan_id: int | None = None
    try:
        from celery import current_task as _ct  # type: ignore
        if _ct is not None and getattr(_ct, "request", None):
            scan_id = (_ct.request.kwargs or {}).get("scan_id")
            if not scan_id and _ct.request.args:
                scan_id = _ct.request.args[0]
    except Exception:
        scan_id = None

    return execute_via_kali(
        tool_name=tool_name,
        target=target,
        scan_id=scan_id,
        scan_mode=scan_mode,
    )
