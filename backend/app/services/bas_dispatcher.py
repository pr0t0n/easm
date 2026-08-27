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

import ipaddress
import logging
from typing import Any
from urllib.parse import urlparse

from app.services.bas_guardrail_policy import check_bas_authorization
from app.services.bas_technique_catalog import get_technique
from app.services.kali_executor import execute_via_kali

logger = logging.getLogger(__name__)

# Real agents route through bas-relay's reverse tunnel (see bas-relay/main.go
# and bas-agent/relay.go): the agent dials OUT to bas-relay from wherever
# it's actually installed (solves NAT/firewall -- works for a genuinely
# remote customer network, not just this same host), and bas-relay exposes a
# per-agent forwarding port (20000 + agent_id) on the internal docker
# network that kali_runner connects to. No same-host assumption anymore --
# the agent's own tunnel_host is irrelevant here; only its id matters.
_RELAY_HOST = "bas_relay"
_RELAY_FORWARD_PORT_BASE = 20000
_DEFAULT_SOCKS_PORT = 1080


def _tunnel_env_vars(bas_agent: Any) -> dict[str, str]:
    if getattr(bas_agent, "kind", "stub") == "real":
        host = _RELAY_HOST
        port = _RELAY_FORWARD_PORT_BASE + int(getattr(bas_agent, "id"))
    else:
        host = getattr(bas_agent, "tunnel_host", None) or "bas_agent_stub"
        port = getattr(bas_agent, "tunnel_port", None) or _DEFAULT_SOCKS_PORT
    return {"BAS_TUNNEL_HOST": str(host), "BAS_TUNNEL_PORT": str(port)}


def _normalize_target(target_hint: str, target_format: str, *, accepts_range: bool = False) -> str:
    """Reshapes ONE shared target_hint (a schedule, and especially a chain,
    supplies a single string for every step) to match each step's own
    declared target_format -- confirmed live that skipping this makes a
    tool silently misinterpret its target: nmap given "192.168.1.65:8001"
    for a "host"-only step resolved to a bogus multicast address instead of
    scanning the intended IP.

    accepts_range=True (port_service_scan, firewall_segmentation_test,
    smb_enum_cme -- their underlying nmap/crackmapexec CLI natively iterates
    a CIDR in one invocation) preserves the "/nn" mask instead of the usual
    urlparse-based host extraction below, which would otherwise silently
    strip it (ipaddress.ip_network parses "10.0.0.0/24" as a network, but
    parsed.hostname/raw.split("/")[0] both discard the mask -- confirmed by
    code reading, not a guess)."""
    raw = str(target_hint or "").strip()
    if not raw:
        return raw

    if accepts_range:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            if network.num_addresses > 1:
                return str(network)
        except ValueError:
            pass  # not a CIDR -- fall through to normal single-host handling

    has_scheme = "://" in raw
    parsed = urlparse(raw if has_scheme else f"//{raw}")
    host = parsed.hostname or raw.split("/")[0].split(":")[0]
    port = parsed.port

    if target_format == "url":
        return raw if has_scheme else f"http://{raw}"
    if target_format == "host_port":
        return f"{host}:{port}" if port else host
    # "host" and "domain" both mean bare host, no scheme/port/path.
    return host


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
    normalized_target = _normalize_target(
        target_hint, technique.get("target_format", "host"),
        accepts_range=bool(technique.get("accepts_range")),
    )
    logger.info(
        "bas_dispatcher: dispatching technique=%s tool=%s agent_id=%s agent_kind=%s tunnel=%s:%s "
        "target_hint=%s target_format=%s normalized_target=%s scan_id=%s",
        technique_key, kali_tool_name, getattr(bas_agent, "id", None), getattr(bas_agent, "kind", "stub"),
        env_vars["BAS_TUNNEL_HOST"], env_vars["BAS_TUNNEL_PORT"],
        target_hint, technique.get("target_format", "host"), normalized_target, scan_id,
    )
    result = execute_via_kali(kali_tool_name, normalized_target, scan_id=scan_id, scan_mode="unit", env_vars=env_vars)
    return {"dispatched": True, "result": result, "agent_kind": getattr(bas_agent, "kind", "stub")}
