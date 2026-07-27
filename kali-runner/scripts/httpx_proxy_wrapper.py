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
import json
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


def _truthy_env(name: str, default: str = "true") -> bool:
    return str(os.getenv(name, default)).strip().lower() not in {"0", "false", "no", "off", "disabled"}


def _json_rows(stdout: str) -> list[dict]:
    rows: list[dict] = []
    for line in str(stdout or "").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _proxy_block_rows(stdout: str) -> list[dict]:
    rows = _json_rows(stdout)
    blocked: list[dict] = []
    for row in rows:
        haystack = " ".join(
            str(row.get(key) or "")
            for key in ("title", "webserver", "content_type", "body", "server")
        ).lower()
        tech = " ".join(str(v or "") for v in (row.get("tech") or [])).lower()
        status_code = int(row.get("status_code") or 0)
        if (
            status_code in {403, 407, 502}
            and (
                "squid" in haystack
                or "proxy" in haystack
                or "access denied" in haystack
                or "request blocked" in haystack
                or "aviso" in haystack
                or "squid" in tech
            )
        ):
            blocked.append(row)
    return blocked


def _has_non_proxy_success(stdout: str) -> bool:
    for row in _json_rows(stdout):
        status_code = int(row.get("status_code") or 0)
        if 200 <= status_code < 500 and not _proxy_block_rows(json.dumps(row)):
            return True
    return False


def _emit_completed(proc: subprocess.CompletedProcess[str]) -> int:
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return int(proc.returncode or 0)


def main() -> int:
    proxy = _selected_proxy()
    argv = ["/opt/tools/bin/httpx", *sys.argv[1:]]
    env = None
    if proxy and "-proxy" not in argv and "--proxy" not in argv:
        reachable, reason = _proxy_reachable(proxy)
        if reachable:
            argv.extend(["-proxy", proxy])
            print(f"httpx_proxy_wrapper proxy_enabled proxy={proxy}", file=sys.stderr, flush=True)
            if _truthy_env("KALI_HTTPX_VALIDATE_PROXY_RESPONSE", "true"):
                proxied = subprocess.run(argv, env=env, capture_output=True, text=True)
                blocked = _proxy_block_rows(proxied.stdout)
                if blocked:
                    direct_argv = [part for part in argv if part not in {"-proxy", "--proxy", proxy}]
                    direct = subprocess.run(direct_argv, env=_proxy_clean_env(), capture_output=True, text=True)
                    if _has_non_proxy_success(direct.stdout):
                        print(
                            f"httpx_proxy_wrapper proxy_response_contaminated proxy={proxy} "
                            f"blocked_rows={len(blocked)} fallback=direct",
                            file=sys.stderr,
                            flush=True,
                        )
                        return _emit_completed(direct)
                return _emit_completed(proxied)
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
