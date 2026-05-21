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
import socket
import sys


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

    try:
        api = shodan.Shodan(api_key)
        result = api.host(ip)
    except shodan.APIError as exc:
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
        print(f"shodan api error: {exc}", file=sys.stderr)
        return 6
    except Exception as exc:
        print(f"shodan call failed: {exc}", file=sys.stderr)
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
        "vulns": list((result.get("vulns") or {}).keys()),
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
