"""Resolve the authorized scope (roots) for a scan.

Used as a defense-in-depth check before the kali-runner executes a tool: the
runner used to trust the upstream ScanAuthorization gate blindly (see
kali-runner/runner.py's `_is_unsafe_target`). This gives the runner its own
list of authorized roots to validate `target` against, in case the upstream
dispatch is ever compromised or hallucinates an out-of-scope target.
"""
from __future__ import annotations

import json
import ipaddress
from typing import Any
from urllib.parse import urljoin, urlparse

from sqlalchemy.orm import Session

from app.models.models import ScanJob


def _normalize_scope_root(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        return str(urlparse(raw).hostname or "").strip().strip(".")
    try:
        network = ipaddress.ip_network(raw, strict=False)
        return str(network) if "/" in raw else str(network.network_address)
    except ValueError:
        pass
    raw = raw.split("/", 1)[0]
    try:
        return str(urlparse(f"//{raw}").hostname or raw).strip().strip(".")
    except ValueError:
        return ""


def is_host_in_scope(host: str, authorized_scope: list[str]) -> bool:
    """Same policy as kali-runner's _is_target_in_scope, backend-side.

    Exact root match or subdomain of an authorized root only — a sibling
    host under the same parent domain (ri.example.com vs www.example.com)
    is NOT in scope. This is deliberate: the operator authorized a specific
    target string, not the whole parent domain (see the endpoint_discovery
    surface_expansion incident this guards — waybackurls returned an
    archived URL on a sibling subdomain, which got reinjected as an active
    test target with no scope check at all).
    """
    host = _normalize_scope_root(host)
    if not host or not authorized_scope:
        return False
    for root in authorized_scope:
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(root, strict=False):
                return True
            continue
        except ValueError:
            pass
        normalized_root = _normalize_scope_root(root)
        if host == normalized_root or host.endswith(f".{normalized_root}"):
            return True
    return False


def authorized_scope_from_target_query(target_query: str) -> list[str]:
    """Build the exact authorized roots from a scan target query."""
    roots: set[str] = set()
    for piece in str(target_query or "").replace(",", "\n").splitlines():
        root = _normalize_scope_root(piece)
        if root:
            roots.add(root)
    return sorted(roots)


def host_from_scope_reference(value: Any) -> str:
    """Return a hostname only for values that can identify a network target."""
    raw = str(value or "").strip()
    if not raw or raw in {"__batch__", "unknown", "none", "null"}:
        return ""
    if raw.startswith(("/", "?", "#")) or any(char.isspace() for char in raw):
        return ""
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        return _normalize_scope_root(urlparse(candidate).hostname or "")
    except Exception:
        return ""


def out_of_scope_hosts_for_finding(
    details: dict[str, Any],
    domain: str,
    finding_url: str | None,
    authorized_scope: list[str],
) -> list[str]:
    """Find external network references in the identity/location of a finding."""
    references: list[Any] = [domain, finding_url]
    for key in (
        "asset", "domain", "host", "hostname", "target", "url",
        "matched_at", "matched-at", "input", "final_url", "final-url",
    ):
        references.append(details.get(key))
    network = details.get("network")
    if isinstance(network, dict):
        references.extend([network.get("host"), network.get("url")])
    outside: set[str] = set()
    for value in references:
        host = host_from_scope_reference(value)
        if host and not is_host_in_scope(host, authorized_scope):
            outside.add(host)
    return sorted(outside)


def filter_httpx_output_to_authorized_scope(
    parsed_result: Any,
    stdout: str,
    authorized_scope: list[str],
) -> tuple[Any, str, dict[str, Any]]:
    """Drop httpx rows that were generated outside the approved roots.

    This is a post-execution barrier.  It specifically guards against internal
    tool fan-out (certificate SAN probing and cross-host redirects), which is
    invisible to the pre-execution target-file validation.
    """
    if not authorized_scope:
        return [], "", {"rejected_count": 0, "rejected_hosts": [], "fail_closed": True}

    rejected_hosts: set[str] = set()
    allowed_redirects: list[dict[str, str]] = []
    blocked_redirects: list[dict[str, str]] = []

    def _row_allowed(row: dict[str, Any]) -> bool:
        references: list[Any] = [
            row.get("input"), row.get("url"), row.get("host"),
            row.get("final_url"), row.get("final-url"),
        ]
        chain = row.get("chain") or row.get("redirect_chain")
        if isinstance(chain, list):
            references.extend(chain)
        observed = [host_from_scope_reference(v) for v in references if v]
        observed = [host for host in observed if host]
        outside = [host for host in observed if not is_host_in_scope(host, authorized_scope)]
        rejected_hosts.update(outside)
        allowed = bool(observed) and not outside
        if allowed and row.get("location"):
            source = str(row.get("url") or row.get("input") or "").strip()
            destination = urljoin(source, str(row.get("location") or "").strip())
            destination_host = host_from_scope_reference(destination)
            redirect = {"source": source, "destination": destination}
            if destination_host and is_host_in_scope(destination_host, authorized_scope):
                if redirect not in allowed_redirects:
                    allowed_redirects.append(redirect)
            else:
                if redirect not in blocked_redirects:
                    blocked_redirects.append(redirect)
                if destination_host:
                    rejected_hosts.add(destination_host)
        return allowed

    rows: list[dict[str, Any]] = []
    if isinstance(parsed_result, list):
        rows = [row for row in parsed_result if isinstance(row, dict)]
    elif isinstance(parsed_result, dict):
        rows = [parsed_result]
    kept = [row for row in rows if _row_allowed(row)]
    if isinstance(parsed_result, dict):
        clean_parsed: Any = kept[0] if kept else {}
    elif isinstance(parsed_result, list):
        clean_parsed = kept
    else:
        clean_parsed = []

    clean_lines: list[str] = []
    for line in str(stdout or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except (TypeError, ValueError, json.JSONDecodeError):
            # httpx JSONL should be structured; fail closed for unparseable rows.
            continue
        if isinstance(row, dict) and _row_allowed(row):
            clean_lines.append(line)

    return clean_parsed, "\n".join(clean_lines), {
        "rejected_count": max(0, len(rows) - len(kept)),
        "rejected_hosts": sorted(rejected_hosts),
        "allowed_redirects": allowed_redirects[:100],
        "blocked_redirects": blocked_redirects[:100],
        "fail_closed": False,
    }


def authorized_scope_for_scan(db: Session, scan_id: int) -> list[str]:
    """Roots (domains/IPs/CIDRs) a scan is authorized to touch.

    Source of truth is `ScanJob.target_query` — the value the scan was
    actually created against — mirroring the root used elsewhere for
    subdomain-scope checks (scan_intelligence._canonical_in_scope_host).
    `target_query` may hold more than one target (comma or newline
    separated), so every piece is normalized and returned.
    """
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return []
    return authorized_scope_from_target_query(str(job.target_query or ""))
