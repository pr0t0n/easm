"""Phase 1 stand-in for the real Rust BAS agent.

Enrolls for real against the platform's API (POST /api/bas/agents/enroll)
using an enrollment token generated ahead of time (see docker-compose.yml's
BAS_STUB_ENROLLMENT_CODE/USERNAME/PASSWORD env vars), sends real heartbeats,
and runs the real SOCKS5 handshake server kali_runner's proxychains-wrapped
tools connect to. Everything about enrollment/heartbeat/network protocol is
real; only the SOCKS5 tunnel's response content is a stub (socks5_stub.py).
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import time

import httpx

from socks5_stub import serve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("bas_agent_stub")

BACKEND_URL = os.environ.get("BAS_BACKEND_URL", "http://backend:8000")
ENROLLMENT_CODE = os.environ.get("BAS_STUB_ENROLLMENT_CODE", "")
ENROLLMENT_USERNAME = os.environ.get("BAS_STUB_ENROLLMENT_USERNAME", "bas-agent-stub")
ENROLLMENT_PASSWORD = os.environ.get("BAS_STUB_ENROLLMENT_PASSWORD", "")
SOCKS_HOST = os.environ.get("BAS_STUB_SOCKS_HOST", "0.0.0.0")
SOCKS_PORT = int(os.environ.get("BAS_STUB_SOCKS_PORT", "1080"))
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get("BAS_STUB_HEARTBEAT_SECONDS", "30"))


def _local_network_cidr() -> str:
    """Best-effort only, unlike bas-agent's real net.Interfaces()-based
    detection (see bas-agent/network.go) -- this container has no iproute2
    and stdlib gives no portable way to read a real configured netmask
    without one. Since this stub only ever runs inside this project's own
    docker-compose network (never a real customer network -- see this
    module's docstring), a /16 covering the container's own docker bridge
    subnet is a reasonable, clearly-labeled approximation for smoke-testing
    the enroll/heartbeat plumbing shape, not a claim of real accuracy."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
        return f"{local_ip}/16"
    except Exception:  # noqa: BLE001
        return ""


def _enroll() -> str | None:
    if not ENROLLMENT_CODE or not ENROLLMENT_PASSWORD:
        logger.warning(
            "bas_agent_stub: no enrollment code/password configured "
            "(BAS_STUB_ENROLLMENT_CODE/BAS_STUB_ENROLLMENT_PASSWORD) -- "
            "running the SOCKS5 tunnel only, without registering as a BasAgent."
        )
        return None
    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/bas/agents/enroll",
            json={
                "code": ENROLLMENT_CODE,
                "username": ENROLLMENT_USERNAME,
                "password": ENROLLMENT_PASSWORD,
                "hostname": "bas-agent-stub",
                "os": "linux",
                "os_version": "phase1-stub",
                "arch": "x86_64",
                "agent_version": "stub-0.1",
                "tunnel_host": "bas_agent_stub",
                "tunnel_port": SOCKS_PORT,
                "local_network_cidr": _local_network_cidr(),
            },
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        logger.info("bas_agent_stub: enrolled as agent_id=%s", payload.get("agent_id"))
        return payload.get("agent_jwt")
    except Exception as exc:  # noqa: BLE001
        logger.warning("bas_agent_stub: enroll failed, retrying later: %s", exc)
        return None


def _heartbeat_loop(agent_jwt: str) -> None:
    headers = {"Authorization": f"Bearer {agent_jwt}"}
    while True:
        try:
            httpx.post(
                f"{BACKEND_URL}/api/bas/agents/heartbeat", headers=headers,
                json={"local_network_cidr": _local_network_cidr()}, timeout=10,
            ).raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logger.warning("bas_agent_stub: heartbeat failed: %s", exc)
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)


async def _main() -> None:
    agent_jwt = None
    for _ in range(10):
        agent_jwt = _enroll()
        if agent_jwt:
            break
        await asyncio.sleep(5)  # backend may still be starting up

    if agent_jwt:
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, _heartbeat_loop, agent_jwt)

    await serve(SOCKS_HOST, SOCKS_PORT)


if __name__ == "__main__":
    asyncio.run(_main())
