#!/usr/bin/env python3
"""Shodan host lookup wrapper.

Usage: shodan_lookup.py <hostname-or-ip>

Reads SHODAN_API_KEY from env. Resolves hostname → IP if needed.
Outputs JSON on stdout with: ip, ports, org, hostnames, vulns, banners.
Exits 0 on success, 1 on failure (with error message on stderr).
"""
from __future__ import annotations

import json
import os
import signal
import socket
import sys
import time


class _ShodanCallTimeout(Exception):
    pass


def _alarm_handler(signum, frame):  # noqa: ANN001
    raise _ShodanCallTimeout()


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: shodan_lookup.py <host-or-ip>", file=sys.stderr)
        return 2
    raw = sys.argv[1].strip()
    if not raw:
        print("empty target", file=sys.stderr)
        return 2

    api_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not api_key:
        print("SHODAN_API_KEY not set", file=sys.stderr)
        return 3

    try:
        import shodan
    except ImportError:
        print("shodan python package not installed", file=sys.stderr)
        return 4

    # Strip URL scheme if passed
    for prefix in ("http://", "https://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):].split("/")[0]
            break

    try:
        ip = socket.gethostbyname(raw)
    except Exception as exc:
        print(f"dns resolution failed for {raw}: {exc}", file=sys.stderr)
        return 5

    # shodan.Shodan() has no timeout parameter and wraps a plain requests.Session
    # with no default timeout — a slow/unresponsive API leaves the underlying
    # HTTP call blocking indefinitely, so this script previously just hung
    # until kali_runner's outer subprocess timeout (60s) SIGKILLed it with no
    # information about why. That made "Shodan is rate-limiting us" look
    # identical to "the process is stuck" downstream. SIGALRM bounds each
    # attempt ourselves, and rate-limit errors (common: shodan's free tier is
    # 1 req/s) get one short-backoff retry plus a distinct exit code, instead
    # of being indistinguishable from a generic API error.
    PER_CALL_TIMEOUT = 20
    MAX_ATTEMPTS = 2
    api = shodan.Shodan(api_key)
    result = None
    attempt = 0
    while attempt < MAX_ATTEMPTS:
        attempt += 1
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(PER_CALL_TIMEOUT)
        try:
            result = api.host(ip)
            signal.alarm(0)
            break
        except _ShodanCallTimeout:
            print(
                f"shodan api call timed out after {PER_CALL_TIMEOUT}s "
                f"(attempt {attempt}/{MAX_ATTEMPTS})",
                file=sys.stderr,
            )
            if attempt >= MAX_ATTEMPTS:
                return 9
            time.sleep(2)
        except shodan.APIError as exc:
            signal.alarm(0)
            msg = str(exc).lower()
            if "no information" in msg or "not found" in msg:
                payload = {
                    "ip": ip,
                    "host": raw,
                    "indexed": False,
                    "message": "No Shodan data for this host (not indexed)",
                }
                print(json.dumps(payload, indent=2))
                return 0
            if "rate limit" in msg or "429" in msg:
                if attempt >= MAX_ATTEMPTS:
                    print(f"shodan rate limit exceeded after {attempt} attempt(s): {exc}", file=sys.stderr)
                    return 8
                time.sleep(3)
                continue
            print(f"shodan api error: {exc}", file=sys.stderr)
            return 6
        except Exception as exc:
            signal.alarm(0)
            print(f"shodan call failed: {exc}", file=sys.stderr)
            return 7
        finally:
            signal.signal(signal.SIGALRM, old_handler)
    if result is None:
        print(f"shodan call produced no result after {MAX_ATTEMPTS} attempt(s)", file=sys.stderr)
        return 7

    payload = {
        "ip": result.get("ip_str") or ip,
        "host": raw,
        "indexed": True,
        "org": result.get("org") or "",
        "isp": result.get("isp") or "",
        "country": result.get("country_name") or "",
        "hostnames": result.get("hostnames") or [],
        "ports": [item.get("port") for item in result.get("data") or [] if item.get("port")],
        "vulns": (list(result["vulns"].keys()) if isinstance(result.get("vulns"), dict)
                  else list(result.get("vulns") or [])),
        "banners": [
            {
                "port": item.get("port"),
                "transport": item.get("transport") or "tcp",
                "product": item.get("product") or "",
                "version": item.get("version") or "",
                "banner": str(item.get("data") or "")[:300],
            }
            for item in (result.get("data") or [])[:20]
        ],
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
