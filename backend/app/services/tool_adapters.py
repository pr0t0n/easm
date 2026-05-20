"""Legacy module — kept ONLY as a thin compatibility shim.

In the previous architecture this file held ~900 lines of local tool wrappers
that ran offensive tools inside the backend/worker containers. Current
offensive execution goes through MCP, which proxies to the Kali runner and
returns an explicit execution contract.

The shim here exists so legacy callers in `app.workers.tasks` keep importing
without code changes:

    from app.services.tool_adapters import run_tool_execution

It dispatches the call through MCP when mandatory execution is enabled. If you
find yourself adding tool logic back into this file, extend the runner profiles
or MCP execution contract instead.
"""
from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.services.mcp_client import mcp_client
from app.services.kali_executor import execute_via_kali


def run_tool_execution(
    tool_name: str,
    target: str,
    scan_mode: str = "unit",
    **legacy_kwargs: Any,
) -> dict[str, Any]:
    """Shim: mandatory MCP -> Kali when configured.

    This legacy entrypoint used to fall back to direct Kali execution when MCP
    was unhealthy. That created false-success risk: the phase ledger could show
    a tool run while the required MCP execution contract never existed.
    """
    scan_id = legacy_kwargs.get("scan_id")
    if settings.mcp_execute_tools_via_mcp:
        if not mcp_client.kali_tools_available_sync():
            return {
                "tool": tool_name,
                "target": target,
                "scan_mode": scan_mode,
                "status": "error",
                "error": "mcp_unavailable",
                "dispatch_error": "mcp_unavailable",
                "execution_path": "mcp_required",
                "mcp_used": False,
                "stdout": "",
                "stderr": "",
                "command": "",
                "open_ports": [],
            }
        result = mcp_client.execute_kali_tool_sync(
            tool_name=tool_name,
            target=target,
            scan_id=scan_id,
        )
        result.setdefault("scan_mode", scan_mode)
        result.setdefault("target", target)
        result["mcp_used"] = True
        return result

    return execute_via_kali(
        tool_name=tool_name,
        target=target,
        scan_id=scan_id,
        scan_mode=scan_mode,
    )
