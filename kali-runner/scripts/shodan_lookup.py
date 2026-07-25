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
            # shodan.client wraps the ENTIRE request call in `except Exception:
            # raise APIError('Unable to connect to Shodan')` (confirmed by
            # reading the installed library source) — any network-level
            # failure (DNS, connection refused/reset, TLS, requests' own
            # timeout, or a connection-level rate-limit rejection that never
            # reaches a parseable HTTP response) collapses to this one generic
            # message with the real cause discarded. Live scan #6 hit this
            # exact message on 5/5 observed failures. A genuine HTTP 429 with
            # a JSON error body WOULD still carry real "rate limit" text (the
            # library only special-cases 401/403/502 explicitly, so 429 falls
            # through to `raise APIError(data['error'])` with the real
            # message) — so the text check below is still meaningful when we
            # DO get one. But since we can't tell transient-connection-failure
            # apart from rate-limit-without-a-clean-response by text alone,
            # BOTH get the same retry-with-backoff treatment; only the exit
            # code differs, as a best-effort hint for whoever reads last_error.
            is_rate_limit_text = "rate limit" in msg or "429" in msg
            if attempt >= MAX_ATTEMPTS:
                print(f"shodan api error after {attempt} attempt(s): {exc}", file=sys.stderr)
                return 8 if is_rate_limit_text else 6
            time.sleep(3)
            continue
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
