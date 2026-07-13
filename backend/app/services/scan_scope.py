"""Resolve the authorized scope (roots) for a scan.

Used as a defense-in-depth check before the kali-runner executes a tool: the
runner used to trust the upstream ScanAuthorization gate blindly (see
kali-runner/runner.py's `_is_unsafe_target`). This gives the runner its own
list of authorized roots to validate `target` against, in case the upstream
dispatch is ever compromised or hallucinates an out-of-scope target.
"""
from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.models import ScanJob


def _normalize_scope_root(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).hostname or raw
    raw = raw.split("/")[0].split(":")[0]
    return raw.strip().strip(".")


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
        if host == root or host.endswith(f".{root}"):
            return True
    return False


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
    roots: set[str] = set()
    for piece in str(job.target_query or "").replace(",", "\n").splitlines():
        root = _normalize_scope_root(piece)
        if root:
            roots.add(root)
    return sorted(roots)
