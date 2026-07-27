#!/usr/bin/env python3
"""Run ProjectDiscovery httpx, injecting an outbound proxy when healthy.

Docker Desktop/VPN environments may allow host egress while blocking direct TCP
from bridge-network containers. In that case KALI_OUTBOUND_PROXY points at the
Docker Desktop proxy (for example http://192.168.65.7:3128). ProjectDiscovery
httpx does not reliably honor HTTP_PROXY/HTTPS_PROXY for probes, so this wrapper
passes -proxy explicitly only after a short TCP health check. A stale proxy is
worse than no proxy: it turns live web targets into empty P06 observations and
causes scan instability.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from urllib.parse import urlparse


PROXY_ENV_KEYS = ("KALI_OUTBOUND_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")


def _selected_proxy() -> str:
    proxy = (
        os.getenv("KALI_OUTBOUND_PROXY")
        or os.getenv("HTTPS_PROXY")
        or os.getenv("HTTP_PROXY")
        or os.getenv("https_proxy")
        or os.getenv("http_proxy")
        or ""
    ).strip()
    if proxy.lower() in {"0", "false", "none", "off", "direct", "disabled"}:
        return ""
    return proxy


def _proxy_reachable(proxy: str) -> tuple[bool, str]:
    parsed = urlparse(proxy)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return False, "proxy_missing_host"
    timeout = float(os.getenv("KALI_PROXY_CHECK_TIMEOUT", "2.0"))
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "ok"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _proxy_clean_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in PROXY_ENV_KEYS:
        env.pop(key, None)
    return env


def main() -> int:
    proxy = _selected_proxy()
    argv = ["/opt/tools/bin/httpx", *sys.argv[1:]]
    env = None
    if proxy and "-proxy" not in argv and "--proxy" not in argv:
        reachable, reason = _proxy_reachable(proxy)
        if reachable:
            argv.extend(["-proxy", proxy])
            print(f"httpx_proxy_wrapper proxy_enabled proxy={proxy}", file=sys.stderr, flush=True)
        else:
            env = _proxy_clean_env()
            print(
                f"httpx_proxy_wrapper proxy_unreachable proxy={proxy} reason={reason} fallback=direct",
                file=sys.stderr,
                flush=True,
            )
    return subprocess.call(argv, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
