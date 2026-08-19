"""Dispatches one BasJob to a real Kali tool, tunneled through a BasAgent.

Reuses execute_via_kali unchanged apart from one addition -- env_vars -- the
only BAS-specific thing here is which technique/profile gets resolved and
which agent's tunnel the job actually routes through. proxychains4 (wrapped
around the real tool inside kali_runner's profile) intercepts the tool's
real TCP connections via LD_PRELOAD and routes them to a per-job SOCKS5
config kali_runner's runner.py generates from the env_vars set below (see
_ensure_bas_proxychains_conf in runner.py) -- a real network hop, observable
in logs, that reaches THIS specific agent, whichever one was selected.

Whether the result on the other end is real or simulated depends entirely on
`bas_agent.kind`: "stub" (bas_agent_stub, kept in place to validate
Kali<->agent traffic) always fabricates its response content; "real" (a
genuine agent binary, cryptographically proven via a CA-signed mTLS
certificate at enroll -- see bas_ca.py) actually relays to a real
destination. See bas_scheduler.py for where this flows into Finding.details.
"""
from __future__ import annotations

import logging
from typing import Any

from app.services.bas_guardrail_policy import check_bas_authorization
from app.services.bas_technique_catalog import get_technique
from app.services.kali_executor import execute_via_kali

logger = logging.getLogger(__name__)

# Real agents in this phase are assumed to run on the same host as the dev
# stack (installed for smoke-testing, exactly like the "instale um agente na
# minha máquina" flow) -- kali_runner reaches that host via Docker's built-in
# host.docker.internal DNS name, never the agent's own self-reported OS
# hostname (which isn't resolvable from inside the kali_runner container). A
# genuinely remote, customer-network-installed agent needs a different
# addressing/registration scheme -- out of scope until the real Rust agent
# phase (see the BAS plan doc).
_REAL_AGENT_TUNNEL_HOST = "host.docker.internal"
_DEFAULT_SOCKS_PORT = 1080


def _tunnel_env_vars(bas_agent: Any) -> dict[str, str]:
    port = getattr(bas_agent, "tunnel_port", None) or _DEFAULT_SOCKS_PORT
    if getattr(bas_agent, "kind", "stub") == "real":
        host = _REAL_AGENT_TUNNEL_HOST
    else:
        host = getattr(bas_agent, "tunnel_host", None) or "bas_agent_stub"
    return {"BAS_TUNNEL_HOST": str(host), "BAS_TUNNEL_PORT": str(port)}


def dispatch_bas_technique(
    *,
    technique_key: str,
    target_hint: str,
    bas_agent: Any,
    scan_id: int,
    schedule: Any | None = None,
) -> dict[str, Any]:
    """Resolves the technique's kali tool/profile, checks authorization, and
    dispatches through execute_via_kali against the SPECIFIC bas_agent's real
    tunnel. Returns a dict with at least `dispatched: bool` and either
    `result` (execute_via_kali's normalized result) or `reason` (why it was
    refused before ever reaching Kali)."""
    technique = get_technique(technique_key)
    if technique is None:
        return {"dispatched": False, "reason": "unknown_technique"}

    if schedule is not None:
        decision = check_bas_authorization(schedule, technique_key)
        if not decision["allowed"]:
            return {"dispatched": False, "reason": decision["reason"]}
    elif technique["availability"] not in {"available", "simulated"}:
        # No schedule context (e.g. a direct call) still must never dispatch
        # a technique that isn't executable in this phase.
        return {"dispatched": False, "reason": f"technique_not_executable:{technique['availability']}"}

    kali_tool_name = technique.get("kali_tool_name")
    if not kali_tool_name:
        return {"dispatched": False, "reason": "no_kali_tool_mapped"}

    env_vars = _tunnel_env_vars(bas_agent)
    logger.info(
        "bas_dispatcher: dispatching technique=%s tool=%s agent_id=%s agent_kind=%s tunnel=%s:%s target_hint=%s scan_id=%s",
        technique_key, kali_tool_name, getattr(bas_agent, "id", None), getattr(bas_agent, "kind", "stub"),
        env_vars["BAS_TUNNEL_HOST"], env_vars["BAS_TUNNEL_PORT"], target_hint, scan_id,
    )
    result = execute_via_kali(kali_tool_name, target_hint, scan_id=scan_id, scan_mode="unit", env_vars=env_vars)
    return {"dispatched": True, "result": result, "agent_kind": getattr(bas_agent, "kind", "stub")}
