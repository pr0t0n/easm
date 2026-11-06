#!/usr/bin/env python3
"""Passive, low-rate crawler for public assets on an approved domain scope.

The crawler intentionally avoids brute force, port scanning, WebSocket connects,
form submissions and API/business routes. It uses certificate-transparency data
as a passive source of candidate hostnames, then fetches only safe public HTTP(S)
resources (HTML, JavaScript, source maps and well-known metadata files).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import ssl
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, build_opener, urlopen


USER_AGENT = "easm-passive-domain-crawler/1.0 (authorized defensive inventory)"
MAX_BODY_BYTES = 8 * 1024 * 1024
DEFAULT_DELAY = 0.35
DEFAULT_MAX_HOSTS = 80
DEFAULT_MAX_URLS = 240

URL_RE = re.compile(r"https?://[^\s\"'`<>\\)\]}]+", re.IGNORECASE)
ASSET_RE = re.compile(
    r"(?:src|href)\s*=\s*[\"']([^\"']+)[\"']|"
    r"(?:import\s*\(|from\s*)[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)", re.IGNORECASE)


@dataclass
class FetchRecord:
    url: str
    final_url: str | None = None
    status: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    sha256: str | None = None
    tls_error: str | None = None
    error: str | None = None
    discovered_from: str | None = None
    body_file: str | None = None


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        value = urlparse(value).hostname or value
    return value


def in_scope(host: str | None, domains: set[str]) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def normalize_url(raw: str, base: str | None = None) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith(("#", "mailto:", "tel:", "data:", "javascript:", "blob:")):
        return None
    if raw.startswith("//"):
        raw = "https:" + raw
    elif base:
        raw = urljoin(base, raw)
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    # Do not crawl query variants: URLs can contain identifiers or tokens.
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", "", ""))


def is_safe_public_path(url: str) -> bool:
    path = urlparse(url).path.lower()
    # The crawler inventories public delivery assets only. API routes are
    # catalogued from source code but never requested by this tool.
    if "/api/" in path or path.startswith("/api"):
        return False
    return (
        path.endswith((".html", ".htm", ".js", ".map", ".css", ".json", ".txt", ".xml", ".webmanifest"))
        or path in {"/", "/robots.txt", "/security.txt", "/sitemap.xml", "/manifest.json", "/manifest.webmanifest"}
    )


def crt_subdomains(domain: str, timeout: float) -> set[str]:
    """Read certificate-transparency names without brute-force DNS queries."""
    endpoint = f"https://crt.sh/?q=%25.{domain}&output=json"
    request = Request(endpoint, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            data = json.loads(response.read(MAX_BODY_BYTES).decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001 - inventory should continue on source failure
        print(f"[warn] crt.sh failed for {domain}: {exc}", file=sys.stderr)
        return set()
    names: set[str] = set()
    for row in data if isinstance(data, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            name = normalize_domain(name.removeprefix("*."))
            if in_scope(name, {domain}):
                names.add(name)
    return names


def hostsearch_subdomains(domain: str, timeout: float) -> set[str]:
    """Read a public DNS index as a fallback when CT is unavailable."""
    endpoint = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    request = Request(endpoint, headers={"User-Agent": USER_AGENT, "Accept": "text/plain"})
    try:
        with urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            text = response.read(MAX_BODY_BYTES).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - inventory should continue on source failure
        print(f"[warn] hostsearch failed for {domain}: {exc}", file=sys.stderr)
        return set()
    names: set[str] = set()
    for line in text.splitlines():
        candidate = normalize_domain(line.split(",", 1)[0])
        if in_scope(candidate, {domain}):
            names.add(candidate)
    return names


def resolve_addresses(host: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    except OSError:
        return []


def fetch(url: str, output_dir: Path, timeout: float, discovered_from: str | None) -> FetchRecord:
    record = FetchRecord(url=url, discovered_from=discovered_from)
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/javascript,application/json,text/plain,*/*"})
    try:
        with urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            record.final_url = response.geturl()
            record.status = getattr(response, "status", None)
            record.content_type = response.headers.get("Content-Type")
            declared = response.headers.get("Content-Length")
            record.content_length = int(declared) if declared and declared.isdigit() else None
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                body = body[:MAX_BODY_BYTES]
            record.sha256 = hashlib.sha256(body).hexdigest()
            safe_name = hashlib.sha256(url.encode()).hexdigest()[:16]
            suffix = Path(urlparse(url).path).suffix or ".body"
            body_path = output_dir / f"{safe_name}{suffix}"
            body_path.write_bytes(body)
            record.body_file = str(body_path.name)
            if record.content_length is None:
                record.content_length = len(body)
            return record
    except HTTPError as exc:
        record.status = exc.code
        record.content_type = exc.headers.get("Content-Type") if exc.headers else None
        record.error = f"HTTP {exc.code}"
    except ssl.SSLCertVerificationError as exc:
        record.tls_error = str(exc)
        record.error = "TLS certificate verification failed"
    except (TimeoutError, URLError, OSError) as exc:
        record.error = str(exc)
    except Exception as exc:  # noqa: BLE001
        record.error = str(exc)
    return record


def extract_links(url: str, body: bytes, content_type: str | None) -> Iterable[str]:
    text = body.decode("utf-8", "replace")
    for match in URL_RE.findall(text):
        yield match.rstrip("'\"`.,;:>")
    if "html" in (content_type or "").lower() or urlparse(url).path.endswith((".html", "/")):
        for match in ASSET_RE.finditer(text):
            yield match.group(1) or match.group(2)
    for match in SOURCE_MAP_RE.findall(text):
        yield match


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domains", nargs="+", required=True, help="Approved base domains")
    parser.add_argument("--known-hosts", nargs="*", default=[], help="Known hostnames to include")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    parser.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS)
    parser.add_argument("--max-urls", type=int, default=DEFAULT_MAX_URLS)
    parser.add_argument("--root-only", action="store_true", help="Fetch only the root URL of each selected host")
    parser.add_argument("--workers", type=int, default=1, help="Parallel workers for --root-only")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    domains = {normalize_domain(x) for x in args.domains}
    known_hosts = {normalize_domain(x) for x in args.known_hosts if in_scope(normalize_domain(x), domains)}
    candidates = set(known_hosts)
    enumeration_sources: dict[str, list[str]] = {host: ["known"] for host in known_hosts}
    for domain in sorted(domains):
        candidates.add(domain)
        enumeration_sources.setdefault(domain, []).append("root")
        ct_names = crt_subdomains(domain, args.timeout)
        if ct_names:
            for host in ct_names:
                candidates.add(host)
                enumeration_sources.setdefault(host, []).append("crt.sh")
        else:
            for host in hostsearch_subdomains(domain, args.timeout):
                candidates.add(host)
                enumeration_sources.setdefault(host, []).append("hackertarget")

    # Keep explicitly supplied hosts even when the passive source returns many
    # candidates; fill the remaining slots deterministically.
    ordered_hosts = list(sorted(known_hosts | domains))
    ordered_hosts.extend(host for host in sorted(candidates) if host not in set(ordered_hosts))
    resolution: dict[str, list[str]] = {}
    for host in ordered_hosts:
        addresses = resolve_addresses(host)
        resolution[host] = addresses
    resolved_ordered_hosts = [host for host in ordered_hosts if resolution.get(host)]
    hosts = set(resolved_ordered_hosts[: args.max_hosts])

    args.out_dir.mkdir(parents=True, exist_ok=True)
    records: list[FetchRecord] = []
    queue: deque[tuple[str, str | None, int]] = deque()
    seen: set[str] = set()
    for host in sorted(hosts):
        queue.append((f"https://{host}/", None, 0))

    if args.root_only:
        root_urls = [f"https://{host}/" for host in sorted(hosts)]
        with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 16))) as executor:
            futures = []
            for url in root_urls[: args.max_urls]:
                time.sleep(max(args.delay, 0.0))
                futures.append(executor.submit(fetch, url, args.out_dir, args.timeout, None))
            records.extend(future.result() for future in futures)

    while not args.root_only and queue and len(records) < args.max_urls:
        url, source, depth = queue.popleft()
        if url in seen or not is_safe_public_path(url):
            continue
        seen.add(url)
        host = urlparse(url).hostname
        if not in_scope(host, domains):
            continue
        time.sleep(max(args.delay, 0.0))
        record = fetch(url, args.out_dir, args.timeout, source)
        records.append(record)
        if record.error == "TLS certificate verification failed" and url.startswith("https://"):
            queue.appendleft(("http://" + url.removeprefix("https://"), source, depth))
        if not record.body_file or depth >= 1:
            continue
        body = (args.out_dir / record.body_file).read_bytes()
        # Angular builds often omit a sourceMappingURL comment while still
        # publishing the predictable .map object. Inventory it explicitly.
        if urlparse(url).path.lower().endswith(".js"):
            map_url = url + ".map"
            if map_url not in seen and in_scope(urlparse(map_url).hostname, domains):
                queue.append((map_url, url, depth + 1))
        for raw_link in extract_links(url, body, record.content_type):
            child = normalize_url(raw_link, record.final_url or url)
            if not child or child in seen or not in_scope(urlparse(child).hostname, domains):
                continue
            if is_safe_public_path(child):
                queue.append((child, url, depth + 1))

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": sorted(domains),
        "candidate_hosts": sorted(candidates),
        "hosts": sorted(hosts),
        "dns": {host: resolution.get(host, []) for host in sorted(candidates)},
        "enumeration_sources": {host: enumeration_sources.get(host, []) for host in sorted(candidates)},
        "records": [asdict(record) for record in records],
        "limits": {
            "max_hosts": args.max_hosts,
            "max_urls": args.max_urls,
            "delay_seconds": args.delay,
            "root_only": args.root_only,
            "workers": args.workers,
        },
        "safety": {"passive_ct": True, "business_api_requests": False, "websocket_connections": False, "bruteforce": False},
    }
    (args.out_dir / "crawl.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    by_status: dict[str, int] = {}
    for record in records:
        key = str(record.status) if record.status is not None else (record.error or "error")
        by_status[key] = by_status.get(key, 0) + 1
    print(json.dumps({"output": str(args.out_dir), "hosts": len(hosts), "records": len(records), "status": by_status}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
