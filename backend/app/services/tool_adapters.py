"""Legacy module — kept ONLY as a thin compatibility shim.

In the previous architecture this file held ~900 lines of local tool wrappers
that ran offensive tools inside the backend/worker containers. After the Kali
runner refactor, all of that logic lives in `kali-runner/runner.py` and is
invoked over HTTP via `app.services.kali_executor.execute_via_kali`.

The shim here exists so legacy callers in `app.workers.tasks` keep importing
without code changes:

    from app.services.tool_adapters import run_tool_execution

It dispatches the call to the Kali runner. If you find yourself adding logic
back into this file, you are likely going down the wrong path — extend the
runner or its profiles instead.
"""
from __future__ import annotations

from typing import Any

from app.services.kali_executor import execute_via_kali


def run_tool_execution(
    tool_name: str,
    target: str,
    scan_mode: str = "unit",
    **legacy_kwargs: Any,
) -> dict[str, Any]:
    """Shim: every call routes to the Kali runner via HTTP."""
    return execute_via_kali(
        tool_name=tool_name,
        target=target,
        scan_id=legacy_kwargs.get("scan_id"),
        scan_mode=scan_mode,
    )
