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
import re
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


# Common two-label public suffixes. Not a full public-suffix-list — deliberately
# conservative: covers the ccTLDs this platform actually targets (.com.br and
# common English-speaking ccTLDs) so P01 subdomain-enum tools (amass/subfinder,
# designed to find children of a zone apex) aren't wastefully re-run at full
# strength every time a target is already a specific leaf host, e.g.
# df.si.valid.com.br. Getting this wrong only ever costs an extra P01 pass on
# an apex domain misclassified as a subdomain — never a scope-narrowing error,
# since the actual authorization/scope check (is_host_in_scope) is unaffected.
_TWO_LABEL_PUBLIC_SUFFIXES = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "adv.br", "art.br",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr",
    "co.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "co.in", "org.in", "gov.in", "net.in",
    "com.mx", "com.ar", "com.co", "com.pe", "com.cn", "com.sg", "com.hk", "com.tw",
}


def is_already_specific_subdomain(target: str) -> bool:
    """True when `target` already has more labels than its registrable/apex domain.

    Used to skip P01's subdomain-enumeration fan-out when the operator already
    supplied a specific leaf host (e.g. df.si.valid.com.br) rather than a zone
    apex (e.g. valid.com.br) — amass/subfinder/etc. enumerate *children of a
    zone*, and structurally cannot find anything beyond the given name when
    it's already a leaf. See `_TWO_LABEL_PUBLIC_SUFFIXES` for the heuristic's
    known limitation (not a full public-suffix list).
    """
    host = _normalize_scope_root(target)
    if not host or _looks_like_ip(host):
        return False
    labels = host.split(".")
    if len(labels) < 3:
        return False  # can't be deeper than a 2-label apex (e.g. valid.com)
    two_label_suffix = ".".join(labels[-2:])
    suffix_label_count = 2 if two_label_suffix in _TWO_LABEL_PUBLIC_SUFFIXES else 1
    apex_label_count = suffix_label_count + 1
    return len(labels) > apex_label_count


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


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
    for piece in re.split(r"[,;\n]+", str(target_query or "")):
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

    def _sanitize_row(row: dict[str, Any]) -> dict[str, Any] | None:
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
        clean_row = dict(row)
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
                # The source response is valid evidence, but the external
                # destination is not part of this scan and must not survive in
                # parsed/stdout data consumed by downstream inventory code.
                clean_row.pop("location", None)
        return clean_row if allowed else None

    rows: list[dict[str, Any]] = []
    if isinstance(parsed_result, list):
        rows = [row for row in parsed_result if isinstance(row, dict)]
    elif isinstance(parsed_result, dict):
        rows = [parsed_result]
    kept = [clean for row in rows if (clean := _sanitize_row(row)) is not None]
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
        if isinstance(row, dict) and (clean_row := _sanitize_row(row)) is not None:
            clean_lines.append(json.dumps(clean_row, ensure_ascii=False, separators=(",", ":")))

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
