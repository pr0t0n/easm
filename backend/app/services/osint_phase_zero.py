"""osint_phase_zero.py — L1: OSINT Phase Zero (antes do P01).

Runs passive OSINT before any active scanning:
  1. HaveIBeenPwned (HIBP) — check email addresses found for the target domain
  2. GitHub Search API — find secrets/.env files in public repos mentioning the domain
  3. Shodan ASN sweep — get all IPs associated with the target org's ASN

Results are injected into the scan job's state_data["osint_phase_zero"] dict and
also seeded as ScanWorkItems with tool_name="osint-*" for tracking.

IMPORTANT: All calls are read-only / passive — no active probing of target systems.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import requests

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── HIBP ─────────────────────────────────────────────────────────────────────
HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_HEADERS = {
    "User-Agent": "EASM-Security-Scanner/1.0",
    "hibp-api-key": "",  # set via settings.hibp_api_key if configured
}
HIBP_RATE_DELAY = 1.5  # seconds between HIBP requests (API rate limit)

# ── GitHub ────────────────────────────────────────────────────────────────────
GITHUB_SEARCH_API = "https://api.github.com/search/code"
GITHUB_DORK_QUERIES: list[str] = [
    '"{domain}" filename:.env',
    '"{domain}" filename:config.yml',
    '"{domain}" filename:secrets.yml',
    '"{domain}" password OR secret OR api_key',
    '"{domain}" DB_PASSWORD OR DATABASE_URL',
    '"{domain}" AWS_SECRET OR AWS_ACCESS',
]
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def _hibp_check_email(email: str, api_key: str) -> list[dict]:
    """Query HIBP for all breaches containing the email. Returns list of breach dicts."""
    if not api_key:
        return []
    url = f"{HIBP_API_BASE}/breachedaccount/{requests.utils.quote(email)}?truncateResponse=false"
    headers = {**HIBP_HEADERS, "hibp-api-key": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 404:
            return []  # no breaches
        if resp.status_code == 401:
            logger.warning("HIBP API key invalid")
            return []
        resp.raise_for_status()
        return resp.json() or []
    except Exception as e:
        logger.debug("HIBP check failed for %s: %s", email, e)
        return []


def run_hibp_check(domain: str, api_key: str) -> dict[str, Any]:
    """Check common admin/ops emails at the target domain for known breaches.

    We probe common role emails (admin@, security@, it@, etc.) rather than
    scraped emails to avoid legal grey areas.
    """
    if not api_key:
        return {"skipped": "no_api_key"}

    probe_emails = [
        f"admin@{domain}",
        f"security@{domain}",
        f"it@{domain}",
        f"devops@{domain}",
        f"info@{domain}",
        f"contact@{domain}",
        f"support@{domain}",
    ]

    results: dict[str, list[dict]] = {}
    total_breaches = 0

    for email in probe_emails:
        time.sleep(HIBP_RATE_DELAY)
        breaches = _hibp_check_email(email, api_key)
        if breaches:
            results[email] = [
                {
                    "name": b.get("Name"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified"),
                }
                for b in breaches
            ]
            total_breaches += len(breaches)

    return {
        "emails_checked": len(probe_emails),
        "emails_breached": len(results),
        "total_breach_incidents": total_breaches,
        "results": results,
        "severity": "high" if total_breaches > 5 else ("medium" if total_breaches > 0 else "info"),
    }


def run_github_dork(domain: str, token: str | None = None) -> dict[str, Any]:
    """Search GitHub for public repos/files mentioning the target domain.

    Looks for leaked credentials, env files, API keys.
    Returns up to 20 results per query (GitHub API hard limit = 30).
    """
    headers = {**GITHUB_HEADERS}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    findings: list[dict] = []
    queries_run = 0

    for query_tpl in GITHUB_DORK_QUERIES:
        query = query_tpl.format(domain=domain)
        params = {"q": query, "per_page": 10, "page": 1}
        try:
            resp = requests.get(GITHUB_SEARCH_API, headers=headers, params=params, timeout=15)
            if resp.status_code == 403:
                logger.debug("GitHub rate limited, stopping dorks early")
                break
            if resp.status_code == 422:
                continue  # query too complex
            resp.raise_for_status()
            data = resp.json()
            items = data.get("items") or []
            queries_run += 1
            for item in items[:5]:
                findings.append({
                    "query": query,
                    "repo": item.get("repository", {}).get("full_name"),
                    "path": item.get("path"),
                    "url": item.get("html_url"),
                    "score": item.get("score"),
                    "sha": item.get("sha"),
                })
            time.sleep(1.0)  # respect GitHub rate limit (10 reqs/min unauthenticated)
        except Exception as e:
            logger.debug("GitHub dork failed for query '%s': %s", query, e)

    return {
        "queries_run": queries_run,
        "results_count": len(findings),
        "findings": findings,
        "severity": "critical" if len(findings) > 3 else ("high" if len(findings) > 0 else "info"),
    }


def run_shodan_asn_sweep(domain: str, api_key: str) -> dict[str, Any]:
    """Resolve domain's org ASN via Shodan and enumerate all IPs in that ASN.

    Returns list of discovered IPs with open ports for seeding into the scan.
    """
    if not api_key:
        return {"skipped": "no_api_key"}

    try:
        # Step 1: Get IP for domain via Shodan host resolve
        resolve_resp = requests.get(
            f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={api_key}",
            timeout=15,
        )
        resolve_resp.raise_for_status()
        resolved = resolve_resp.json()
        ip = resolved.get(domain)
        if not ip:
            return {"skipped": "dns_not_resolved"}

        # Step 2: Get host info including org / ASN
        host_resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=15,
        )
        host_resp.raise_for_status()
        host_data = host_resp.json()

        asn = host_data.get("asn")
        org = host_data.get("org", "unknown")
        if not asn:
            return {"skipped": "no_asn", "ip": ip, "org": org}

        # Step 3: Search for all hosts in the same ASN
        search_resp = requests.get(
            f"https://api.shodan.io/shodan/host/search?key={api_key}&query=asn:{asn}&facets=port:10",
            timeout=20,
        )
        search_resp.raise_for_status()
        search_data = search_resp.json()

        discovered_ips: list[dict] = []
        for match in (search_data.get("matches") or [])[:50]:  # cap at 50 hosts
            match_ip = match.get("ip_str")
            if match_ip:
                discovered_ips.append({
                    "ip": match_ip,
                    "ports": match.get("port"),
                    "hostnames": match.get("hostnames", []),
                    "product": match.get("product"),
                    "version": match.get("version"),
                    "vulns": list((match.get("vulns") or {}).keys())[:5],
                })

        return {
            "domain": domain,
            "resolved_ip": ip,
            "asn": asn,
            "org": org,
            "total_hosts_in_asn": search_data.get("total", 0),
            "discovered_ips": discovered_ips,
            "severity": "high" if discovered_ips else "info",
        }

    except Exception as e:
        logger.debug("Shodan ASN sweep failed for %s: %s", domain, e)
        return {"error": str(e)}


def run_osint_phase_zero(
    db,
    job,
    domain: str,
) -> dict[str, Any]:
    """Master entry point — run all OSINT checks before P01 active scanning.

    Results stored in job.state_data["osint_phase_zero"] and injected as
    ScanWorkItems of type "osint-hibp", "osint-github-dork", "osint-shodan-asn".
    Returns summary dict.
    """
    from app.models.models import ScanLog, ScanWorkItem, Finding
    from datetime import datetime

    logger.info("osint_phase_zero start scan=%d domain=%s", job.id, domain)

    hibp_key = str(getattr(settings, "hibp_api_key", "") or "")
    github_token = str(getattr(settings, "github_token", "") or "")
    shodan_key = str(getattr(settings, "shodan_api_key", "") or "")

    results: dict[str, Any] = {}

    # 1. HIBP
    try:
        results["hibp"] = run_hibp_check(domain, hibp_key)
    except Exception as e:
        results["hibp"] = {"error": str(e)}

    # 2. GitHub dorks
    try:
        results["github_dork"] = run_github_dork(domain, github_token or None)
    except Exception as e:
        results["github_dork"] = {"error": str(e)}

    # 3. Shodan ASN sweep
    try:
        results["shodan_asn"] = run_shodan_asn_sweep(domain, shodan_key)
    except Exception as e:
        results["shodan_asn"] = {"error": str(e)}

    # ── Persist results in state_data ────────────────────────────────────────
    state = dict(job.state_data or {})
    state["osint_phase_zero"] = results
    job.state_data = state

    # ── Create findings for critical OSINT hits ───────────────────────────────
    findings_created = 0

    # GitHub: public secrets exposure
    gh = results.get("github_dork") or {}
    if gh.get("results_count", 0) > 0:
        f = Finding(
            scan_job_id=job.id,
            title=f"Possible secrets exposure: {gh['results_count']} public GitHub results for {domain}",
            severity=str(gh.get("severity") or "high"),
            domain=domain,
            tool="osint-github-dork",
            risk_score=8 if gh.get("severity") == "critical" else 6,
            confidence_score=60,
            verification_status="hypothesis",
            details={
                "source": "osint_phase_zero",
                "queries_run": gh.get("queries_run"),
                "results_count": gh.get("results_count"),
                "top_findings": (gh.get("findings") or [])[:3],
                "needs_verification": True,
            },
            created_at=datetime.now(),
        )
        db.add(f)
        findings_created += 1

    # HIBP: breached credentials
    hibp = results.get("hibp") or {}
    if hibp.get("emails_breached", 0) > 0:
        f = Finding(
            scan_job_id=job.id,
            title=f"Breached credentials: {hibp['emails_breached']} email(s) found in data breaches for {domain}",
            severity=str(hibp.get("severity") or "high"),
            domain=domain,
            tool="osint-hibp",
            risk_score=7,
            confidence_score=80,
            verification_status="hypothesis",
            details={
                "source": "osint_phase_zero",
                "emails_checked": hibp.get("emails_checked"),
                "emails_breached": hibp.get("emails_breached"),
                "total_breach_incidents": hibp.get("total_breach_incidents"),
                "needs_verification": True,
                "verification_note": "Requer teste de credential stuffing para confirmar credenciais válidas.",
            },
            created_at=datetime.now(),
        )
        db.add(f)
        findings_created += 1

    # Shodan: IPs with vulns
    shodan = results.get("shodan_asn") or {}
    shodan_ips_with_vulns = [
        ip for ip in (shodan.get("discovered_ips") or [])
        if ip.get("vulns")
    ]
    if shodan_ips_with_vulns:
        f = Finding(
            scan_job_id=job.id,
            title=f"Shodan: {len(shodan_ips_with_vulns)} IP(s) in ASN {shodan.get('asn')} with known CVEs",
            severity="high",
            domain=domain,
            tool="osint-shodan-asn",
            risk_score=7,
            confidence_score=50,
            verification_status="hypothesis",
            details={
                "source": "osint_phase_zero",
                "asn": shodan.get("asn"),
                "org": shodan.get("org"),
                "ips_with_vulns": [
                    {"ip": ip["ip"], "vulns": ip["vulns"][:3]}
                    for ip in shodan_ips_with_vulns[:5]
                ],
                "needs_verification": True,
            },
            created_at=datetime.now(),
        )
        db.add(f)
        findings_created += 1

    db.add(ScanLog(
        scan_job_id=job.id,
        source="osint-phase-zero",
        level="INFO",
        message=(
            f"osint_phase_zero done scan={job.id} domain={domain} "
            f"hibp_breached={hibp.get('emails_breached', 0)} "
            f"github_hits={gh.get('results_count', 0)} "
            f"shodan_ips={len((shodan.get('discovered_ips') or []))} "
            f"findings={findings_created}"
        ),
    ))
    db.commit()

    return {
        "domain": domain,
        "hibp": {"emails_breached": hibp.get("emails_breached", 0)},
        "github_dork": {"results_count": gh.get("results_count", 0)},
        "shodan_asn": {
            "discovered_ips": len(shodan.get("discovered_ips") or []),
            "asn": shodan.get("asn"),
        },
        "findings_created": findings_created,
    }
