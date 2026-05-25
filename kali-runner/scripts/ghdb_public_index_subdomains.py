#!/usr/bin/env python3
"""Discover subdomains from public indexes and GHDB-style search surfaces.

This intentionally avoids browser automation against Google.  It uses public
index endpoints that are stable enough for unattended scans and emits one
in-scope hostname per line so the runner's normal parser can consume it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import Any


HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
UA = "Mozilla/5.0 (compatible; ScriptKidd.o-GHDB-Public-Index-Discovery/1.0)"


def fetch(url: str, timeout: int = 20, retries: int = 2) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    last_exc: Exception | None = None
    for attempt in range(max(1, retries + 1)):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator supplied public URLs
                return resp.read(5_000_000).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    if last_exc:
        raise last_exc
    return ""


def normalize_host(value: str, root: str) -> str | None:
    raw = str(value or "").strip().lower()
    raw = raw.replace("*.", "")
    raw = raw.split("/")[0].split(":")[0].strip(".")
    if not raw or raw == root:
        return None
    if raw.endswith("." + root) and HOST_RE.fullmatch(raw):
        return raw
    return None


def extract_hosts(text: str, root: str) -> set[str]:
    found: set[str] = set()
    for match in HOST_RE.findall(str(text or "")):
        host = normalize_host(match, root)
        if host:
            found.add(host)
    return found


def from_crtsh(root: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(root)}&output=json"
    try:
        data = json.loads(fetch(url, timeout=30) or "[]")
    except Exception:
        return set()
    found: set[str] = set()
    for item in data if isinstance(data, list) else []:
        for key in ("name_value", "common_name"):
            for value in str((item or {}).get(key) or "").splitlines():
                host = normalize_host(value, root)
                if host:
                    found.add(host)
    return found


def from_certspotter(root: str) -> set[str]:
    url = (
        "https://api.certspotter.com/v1/issuances?"
        f"domain={urllib.parse.quote(root)}&include_subdomains=true&expand=dns_names"
    )
    try:
        data = json.loads(fetch(url, timeout=30, retries=1) or "[]")
    except Exception:
        return set()
    found: set[str] = set()
    for item in data if isinstance(data, list) else []:
        for value in (item or {}).get("dns_names") or []:
            host = normalize_host(str(value), root)
            if host:
                found.add(host)
    return found


def from_urlscan(root: str) -> set[str]:
    query = urllib.parse.quote(f"domain:{root}")
    url = f"https://urlscan.io/api/v1/search/?q={query}&size=1000"
    try:
        data: Any = json.loads(fetch(url, timeout=30) or "{}")
    except Exception:
        return set()
    found: set[str] = set()
    for result in data.get("results", []) if isinstance(data, dict) else []:
        blob = json.dumps(result, ensure_ascii=False)
        found.update(extract_hosts(blob, root))
    return found


def from_otx(root: str) -> set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{urllib.parse.quote(root)}/passive_dns"
    try:
        data: Any = json.loads(fetch(url, timeout=30) or "{}")
    except Exception:
        return set()
    found: set[str] = set()
    for row in data.get("passive_dns", []) if isinstance(data, dict) else []:
        for key in ("hostname", "address"):
            host = normalize_host(str((row or {}).get(key) or ""), root)
            if host:
                found.add(host)
    return found


def from_hackertarget(root: str) -> set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(root)}"
    try:
        return extract_hosts(fetch(url, timeout=30), root)
    except Exception:
        return set()


def from_rapiddns(root: str) -> set[str]:
    url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(root)}?full=1"
    try:
        return extract_hosts(fetch(url, timeout=30), root)
    except Exception:
        return set()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("domain")
    parser.add_argument("--limit", type=int, default=5000)
    args = parser.parse_args()

    root = str(args.domain or "").strip().lower().lstrip("*.").strip(".")
    if not root:
        return 2

    found: set[str] = set()
    for collector in (from_crtsh, from_certspotter, from_urlscan, from_otx, from_hackertarget, from_rapiddns):
        try:
            found.update(collector(root))
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] {collector.__name__}: {exc}", file=sys.stderr)

    for host in sorted(found)[: max(1, int(args.limit))]:
        print(host)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
