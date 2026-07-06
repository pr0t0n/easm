"""Deterministic offensive operator contracts.

This module is intentionally dependency-light so it can be exercised by unit
tests without a running LangGraph, Celery worker, MCP server, or Kali runner.
Runtime integrations should call these contracts instead of letting an LLM,
worker, or phase node mark progress directly.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised in minimal local envs
    yaml = None


PHASE_STATUSES = {
    "pending",
    "running",
    "completed",
    "partial",
    "blocked",
    "failed",
    "skipped_with_justification",
}
HYPOTHESIS_STATUSES = {"open", "testing", "validated", "discarded", "inconclusive", "escalated"}
ATTACK_PATH_STATUSES = {"candidate", "testing", "validated", "broken", "discarded"}
EVIDENCE_STRENGTHS = ("none", "weak", "medium", "strong", "conclusive")
EXECUTION_MODES = {
    "learning_only",
    "passive_recon",
    "safe_validation",
    "controlled_pentest",
    "full_authorized_pentest",
}
BACKEND_LOCAL_TOOL_NAMES = {"bl-test", "code-analyzer", "semgrep"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, payload: Any) -> str:
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


def tool_execution_key(phase_id: str, skill_id: str, tool: dict[str, Any]) -> str:
    return stable_id(
        "TR",
        {
            "phase_id": phase_id,
            "skill_id": skill_id,
            "tool_name": tool.get("tool_name"),
            "profile": tool.get("profile"),
            "arguments": tool.get("arguments") or {},
        },
    )


def tool_execution_signature(phase_id: str, tool: dict[str, Any]) -> str:
    """Operational dedupe key independent of skill attribution.

    Multiple approved skills can request the same runner profile for the same
    target. Executing it once is enough; the richer execution_key still records
    skill-specific attribution for planned coverage.
    """
    return stable_id(
        "TS",
        {
            "phase_id": phase_id,
            "profile": tool.get("profile"),
            "target": (tool.get("arguments") or {}).get("target"),
            "arguments": tool.get("arguments") or {},
            "execution_backend": tool.get("execution_backend"),
        },
    )


def _load_skill_tool_map(skills_root: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Read every skill .md and return skill_id → {required_tools, optional_tools, fallback_tools}.

    Tries common relative paths when skills_root is not given; returns {} if the directory
    is absent so callers fall back to hardcoded lists gracefully.
    """
    roots: list[Path] = []
    if skills_root is not None:
        roots = [Path(skills_root)]
    else:
        for candidate in ["skills", "../skills", "../../skills"]:
            p = Path(candidate)
            if p.is_dir() and any(p.rglob("*.md")):
                roots.append(p)
                break

    skill_map: dict[str, dict[str, Any]] = {}
    for root in roots:
        for path in sorted(root.rglob("*.md")):
            try:
                if is_dataless_file(path):
                    continue
                parsed = parse_skill_markdown(path)
                meta = parsed["metadata"]
                skill_id = str(meta.get("skill_id") or "")
                if not skill_id:
                    continue
                skill_map[skill_id] = {
                    "required_tools": list(meta.get("required_tools") or []),
                    "optional_tools": list(meta.get("optional_tools") or []),
                    "fallback_tools": list(meta.get("fallback_tools") or []),
                }
            except Exception:  # noqa: BLE001
                pass
    return skill_map


def _resolve_phase_tools(
    skill_ids: list[str],
    skill_map: dict[str, dict[str, Any]],
    fallback_required: list[str],
    fallback_optional: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Resolve phase tools without letting multi-phase skill metadata bleed across phases.

    Skill frontmatter is skill-wide today, while these rows are phase-specific. The
    row's required tools therefore remain authoritative for the phase; skill
    metadata is used only when no row fallback is available.
    """
    fallback_required = list(fallback_required or [])
    fallback_optional = list(fallback_optional or [])

    if not skill_map:
        return fallback_required, fallback_optional

    required: list[str] = []
    optional: list[str] = []
    for skill_id in skill_ids:
        tools = skill_map.get(skill_id) or {}
        required.extend(tools.get("required_tools") or [])
        optional.extend(tools.get("optional_tools") or [])
        optional.extend(tools.get("fallback_tools") or [])

    # Phase rows are deliberately narrower than multi-phase skill metadata. If a
    # row declares a phase primary, keep that primary; otherwise use the skill's
    # own required tools as the best available source.
    required_source = fallback_required or required
    optional_source = fallback_optional or optional

    req_seen: set[str] = set()
    req_deduped: list[str] = []
    for t in required_source:
        if t and t not in req_seen:
            req_seen.add(t)
            req_deduped.append(t)
    opt_seen: set[str] = set(req_seen)
    opt_deduped: list[str] = []
    for t in optional_source:
        if t and t not in opt_seen:
            opt_seen.add(t)
            opt_deduped.append(t)
    return req_deduped, opt_deduped


def default_phase_contracts(skills_root: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Return P01-P22 contracts with tools resolved from skill metadata.

    Tool lists are read from the skill markdown frontmatter (required_tools /
    optional_tools / fallback_tools). The hardcoded tuples serve as fallbacks
    when the skills directory is not mounted (e.g. unit tests without Docker).
    """
    skill_map = _load_skill_tool_map(skills_root)

    # (phase_id, name, description, skill_ids, fb_required, fb_optional)
    # Optional tools include HackerOne-derived nuclei profiles segregated by vuln class.
    rows = [
        ("P01", "Subdomain Enumeration", "Collect passive domains, subdomains and assets via OSINT + active brute-force",
         ["skill.recon.subdomain_enumeration"], ["subfinder"],
         ["amass", "amass-brute", "amass-intel", "theharvester", "dnsx", "assetfinder",
          "ghdb-public-indexes",
          "sublist3r", "findomain", "dnsrecon-brt", "dnsrecon-zt", "dnsenum", "shuffledns", "alterx",
          "nuclei-takeover"]),  # HackerOne: 49 subdomain takeover reports
        ("P02", "Port Service Discovery", "Discover exposed ports and services; enrich with OSINT banners",
         ["skill.recon.port_service_discovery"], ["naabu"],
         ["shodan-cli", "nmap", "nmap-vuln", "nmap-ssl", "nmap-ssh", "nmap-smb", "nmap-dns",
          "masscan", "sslscan", "testssl"]),
        ("P03", "Endpoint Discovery", "Discover routes, content and JavaScript surfaces",
         ["skill.discovery.endpoint_discovery"], ["ffuf"],
         # gobuster REPLACED by feroxbuster: gobuster had 0/95 completions (broken tool in Kali).
         # feroxbuster is Rust-based, 10x faster, smart status filtering, automatic recursion.
         # ffuf remains as primary (most flexible); feroxbuster as fast fallback.
         ["feroxbuster", "katana", "hakrawler", "gospider", "dirsearch",
          "gau", "waybackurls", "nmap-http",
          "nuclei-lfi"]),  # HackerOne: 13 path traversal reports — scan dirs for exposed paths
        ("P04", "Parameter Discovery", "Discover input points and parameters",
         ["skill.discovery.parameter_discovery"], ["arjun"],
         # ffuf: use fingerprint-first gate — P07 tech_stack selects wordlist before ffuf runs.
         # Generic 220k wordlist replaced by stack-specific 500-1200 entry lists.
         # This reduces ffuf avg from 497s → ~45s per target.
         ["paramspider", "ffuf", "ffuf-params", "ffuf-content", "gau", "waybackurls"]),
        ("P05", "Surface Expansion", "Expand hidden routes and crawlable content via HTTP headers + OWASP fingerprint",
         ["skill.discovery.endpoint_discovery"], ["ffuf"],
         # gobuster REPLACED by feroxbuster (same reason as P03: 0 completions, broken).
         # nikto KEPT for banner-grabbing but findings auto-tagged as candidate (high FP rate).
         ["feroxbuster", "katana", "httpx", "whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"]),
        ("P06", "HTTP Fingerprinting & WAF Detection", "Fingerprint HTTP behavior, headers, WAF profile and evasion clues",
         ["skill.recon.port_service_discovery"], ["httpx"],
         ["wafw00f", "curl-headers", "nmap-http", "whatweb",
          "nuclei-headers",      # HackerOne: 27 missing security headers reports (CSP, HSTS, X-Content-Type)
          "nuclei-cors",         # HackerOne: 8 CORS misconfiguration reports
          "nuclei-clickjacking", # HackerOne: 19 clickjacking / X-Frame-Options reports
          "nuclei-spoofing",     # HackerOne: 53 spoofing/email-spoofing reports (SPF/DMARC/DKIM)
          "nuclei-crlf"]),       # HackerOne: CRLF/header injection — detected via HTTP response
        ("P07", "Technology Detection", "Identify services and technology versions",
         ["skill.recon.port_service_discovery"], ["whatweb"],
         ["httpx", "whatweb-basic", "nmap-http", "wpscan"]),
        ("P08", "JavaScript Endpoint Analysis", "Analyze JS bundles, API routes, and SPA endpoints",
         ["skill.discovery.endpoint_discovery"], ["linkfinder"],
         # katana-js/hakrawler/gospider removed: no DOM rendering, captures less than P03
         # linkfinder: AST/regex over JS bundles discovers hidden API routes (pentest staple)
         # nuclei-js-secrets: finds API keys, JWT tokens hardcoded in production bundles
         # nuclei-js-analysis: source maps, debug endpoints, webpack chunk enumeration
         # gau: historical JS URLs from AlienVault/Wayback (catches removed but cached endpoints)
         # Output feeds P04 (parameter discovery) and P16 (API review) with discovered endpoints
         ["nuclei-js-secrets", "nuclei-js-analysis", "gau", "nuclei-exposure", "katana"]),
        ("P09", "Vulnerability Template Scan", "Nuclei CVE/misconfiguration templates + content discovery",
         ["skill.discovery.endpoint_discovery"], ["nuclei"],
         ["ffuf", "gobuster", "nikto", "nmap-vuln", "wpscan",
          "nuclei-rce",           # HackerOne: injection class (135 reports) — RCE/command injection
          "nuclei-auth",          # HackerOne: 119 auth bypass / default credentials reports
          "nuclei-deserialization"]),  # HackerOne: 13 insecure deserialization reports
        ("P10", "Injection Testing", "Test injection hypotheses with controls",
         ["skill.sqli_testing"], ["wapiti"],
         ["sqlmap", "dalfox", "nikto",
          "nuclei-sqli",   # HackerOne: 46 SQL injection reports — template-based detection
          "nuclei-ssti",   # HackerOne: injection class (135 reports) — SSTI patterns
          "nuclei-xxe",    # HackerOne: 9 XXE reports
          "nuclei-crlf"]), # HackerOne: CRLF injection → header injection
        ("P11", "SSRF Testing", "Validate SSRF and callback hypotheses",
         ["skill.vuln.ssrf"], ["nuclei"],
         ["interactsh-client", "ffuf", "wapiti",
          "nuclei-ssrf"]),  # HackerOne: 68 SSRF reports — blind SSRF, EC2 metadata, webhook
        ("P12", "XSS Testing", "Validate reflected or stored XSS safely",
         ["skill.stored_xss_testing"], ["dalfox"],
         ["wapiti", "nikto",
          "nuclei-xss",   # HackerOne: #1 class (652 reports) — reflected, stored, DOM, blind
          "nuclei-csrf"]), # HackerOne: 110 CSRF reports — login CSRF, OAuth CSRF
        ("P13", "Access Control & Business Logic", "Validate object/authorization boundaries and business-logic flows",
         # FIAÇÃO: skills antes ÓRFÃS agora ligadas à fase — business_logic (chromium-capture),
         # bola_bfla, csrf, mass-assignment (api_security).
         # bl-test é REQUIRED da fase: a P13 escolhe só UMA skill via RAG, mas o
         # teste de business logic (valor/IDOR-BOLA/mass-assignment/dados sensíveis)
         # precisa rodar SEMPRE — então entra como required do contrato, não via .md.
         # bl-test já faz a captura chromium internamente (não duplicar como required).
         ["skill.idor_object_authorization", "skill.vuln.business_logic",
          "skill.vuln.bola_bfla", "skill.vuln.csrf", "skill.vuln.api_security"], ["bl-test"],
         ["ffuf", "arjun", "chromium-capture", "curl",
          "nuclei-idor",     # HackerOne: 73 IDOR/broken access control reports
          "nuclei-redirect"]), # HackerOne: 69 open redirect reports — auth flow redirects
        ("P14", "Auth Boundary Testing", "Test authentication and session boundaries without brute-force",
         ["skill.vuln.auth_bypass"], ["nuclei-auth-bypass"],
         # hydra/medusa REMOVED: they were being skipped (noisy brute-force, blocked by WAF/rate-limit)
         # Replaced with template-based auth testing — deterministic, not brute-force:
         # nuclei-auth-bypass: 400+ ProjectDiscovery templates for auth bypass patterns
         # nuclei-default-credentials: tests known default passwords per detected technology
         # jwt_tool: JWT alg:none, RS256→HS256 confusion, weak HMAC key, expired token acceptance
         # nuclei-jwt: JWT/OAuth misconfig templates (alg:none, token leak via referrer/log)
         # nuclei-oauth: OAuth open redirect, PKCE bypass, implicit flow token leakage
         # crackmapexec KEPT for internal network scope only (AD/SMB testing)
         ["jwt_tool", "crackmapexec", "ffuf",
          "nuclei-auth",            # HackerOne: 119 auth bypass reports — default creds, 2FA bypass
          "nuclei-jwt",             # HackerOne: 19 JWT/OAuth reports — alg:none, token leak
          "nuclei-default-credentials",  # Known default passwords by technology stack
          "nuclei-oauth"]),         # OAuth misconfig: open redirect, PKCE, implicit flow
        ("P15", "File Handling Testing", "Validate exposed files, git/secret leaks, supply chain and upload risks",
         ["skill.chain.exposed_git_to_credential_leak"], ["gitleaks"],
         ["trufflehog", "gau", "waybackurls",
          "nuclei-lfi",             # HackerOne: 13 path traversal/LFI reports
          "nuclei-exposure",        # HackerOne: 78 info/secret exposure — .env, config files
          "nuclei-misconfiguration",# .env, .git, .DS_Store, backup files, CI/CD artifacts
          "semgrep",                # SAST: secrets in JS bundles, exposed config
          "nuclei-file-upload",     # Unrestricted file upload → WebShell chain
          "trivy"]),                # Supply chain: CVEs in Docker images, npm/pip packages
        ("P16", "API Input Surface Review", "Validate API, GraphQL, and parameterized endpoint coverage",
         ["skill.discovery.parameter_discovery"], ["arjun"],
         ["paramspider", "ffuf", "wfuzz", "gau", "waybackurls",
          "nuclei-graphql",         # HackerOne: 25 GraphQL introspection / API disclosure reports
          "nuclei-exposure",        # HackerOne: hardcoded API keys, token leaks in API responses
          "nuclei-swagger"]),       # Swagger/OpenAPI exposure → API schema dump for auth bypass
        ("P17", "Exploit Validation", "Reproduce validated exploit paths safely via nuclei + manual",
         ["skill.vuln.sqli"], ["nuclei"],
         ["sqlmap", "wapiti", "nikto", "wpscan",
          "nuclei-rce",    # HackerOne: critical RCE validation
          "nuclei-lfi",    # HackerOne: path traversal exploit confirmation
          "nuclei-sqli",   # HackerOne: SQL injection exploit confirmation
          "nuclei-ssti"]), # HackerOne: template injection → RCE confirmation
        ("P18", "Credential Exposure Boundary", "Validate credential exposure via OSINT and secret scanning",
         ["skill.chain.exposed_git_to_credential_leak"], ["theharvester"],
         ["gitleaks", "trufflehog", "h8mail", "bandit", "semgrep", "trivy",
          "nuclei-exposure", # HackerOne: 78 info/secret exposure reports — API keys, debug endpoints
          "nuclei-cloud"]),   # HackerOne: 15 cloud/S3 exposure reports — open buckets, AWS metadata
        ("P19", "Post Exploitation Boundary", "Validate post-exploitation scope controls",
         ["skill.idor_object_authorization"], ["nuclei"],
         ["ffuf", "arjun",
          "nuclei-csrf",    # HackerOne: 110 CSRF reports — post-auth CSRF on sensitive actions
          "nuclei-cors",    # HackerOne: 8 CORS misconfig — cross-origin credential access
          "nuclei-idor"]),  # HackerOne: 73 IDOR — post-auth object boundary testing
        ("P20", "Attack Path Correlation", "Build offensive chains from evidence",
         ["skill.chain.exposed_git_to_credential_leak"], ["nuclei"],
         ["gitleaks", "trufflehog",
          "nuclei-race"]),  # HackerOne: 20 race condition reports — coupon/invitation bypass chains
        ("P21", "Evidence Quality Review", "Score evidence and false positive controls",
         ["skill.reporting.evidence_quality"], ["manual_review"], []),
        ("P22", "Campaign Reporting", "Build offensive campaign narrative",
         ["skill.technical_report"], ["report-builder"], ["manual_review"]),
    ]

    contracts: dict[str, dict[str, Any]] = {}
    for phase_id, name, description, skills, fb_required, fb_optional in rows:
        required_tools, optional_tools = _resolve_phase_tools(skills, skill_map, fb_required, fb_optional)
        contracts[phase_id] = {
            "phase_id": phase_id,
            "name": name,
            "description": description,
            "required_skills": skills,
            "optional_skills": [],
            "required_tools": required_tools,
            "optional_tools": optional_tools,
            "minimum_evidence": ["tool_output", "raw_tool_output", "parsed_result"],
            "exit_criteria": {
                "minimum_required_tools_attempted": 1,
                "evidence_required": True,
                "validator_required": True,
                "allow_partial": True,
                "allow_skip": phase_id in {"P18", "P19"},
                "minimum_evidence_strength": "medium" if phase_id not in {"P01", "P21", "P22"} else "weak",
            },
            "retry_policy": {"max_retries": 2, "fallback_allowed": True, "rag_reconsult_allowed": True},
        }
    return contracts


PHASE_CONTRACTS = default_phase_contracts()
PHASE_ORDER = list(PHASE_CONTRACTS)


# Liga uma tool REQUIRED da fase a skills ESPECÍFICAS — evita FALSA cobertura.
# Ex.: bl-test cobre business logic / BOLA / mass-assignment, mas NÃO prova CSRF
# nem IDOR genérico. Uma tool sem binding aqui é phase-global (entra em toda skill).
PHASE_TOOL_BINDINGS: dict[str, dict[str, list[str]]] = {
    "P13": {
        "bl-test": [
            "skill.vuln.business_logic",
            "skill.vuln.bola_bfla",
            "skill.vuln.api_security",
        ],
    },
}


def route_next_required_phase(completed_phases: list[str] | None, current_phase: str | None = None) -> str | None:
    completed = set(completed_phases or [])
    if current_phase and current_phase not in completed:
        return current_phase
    for phase_id in PHASE_ORDER:
        if phase_id not in completed:
            return phase_id
    return None


@dataclass
class ToolCatalogEntry:
    tool_name: str
    profile: str
    available: bool
    target_types: list[str]
    capabilities: list[str]
    accepted_arguments: list[str]
    required_arguments: list[str]
    output_format: str
    parser: str
    timeout_policy: dict[str, Any]
    risk_level: str
    noise_level: str


# Capabilities that require real external DNS resolution — useless against
# localhost / host.docker.internal / RFC-1918 targets.
_DNS_BRUTE_CAPABILITIES = {"dns_brute", "dns_zone_transfer"}

# Tools that rely on OSINT/certificate-transparency databases and yield nothing
# for internal hosts even when they don't do DNS brute-force.
# Also includes protocol-specific scanners (DNS/SMB/SSH) that are irrelevant
# when the target is an internal HTTP service.
_OSINT_ONLY_TOOLS = {
    # DNS enumeration / brute-force
    "amass", "amass-brute", "amass-intel",
    "shuffledns", "dnsrecon-brt", "dnsrecon-zt", "dnsenum",
    "sublist3r", "findomain", "alterx", "assetfinder", "theharvester",
    # Protocol-specific scanners irrelevant for localhost/internal HTTP targets
    "nmap-dns",   # scans UDP/53 for DNS vulns — no DNS server on localhost web apps
    "nmap-smb",   # SMB vuln scripts — not relevant for web apps
    "nmap-ssh",   # SSH audit — not relevant for web apps
    # Vulnerability scan scripts that hammer every port/service — too slow and irrelevant
    # against internal HTTP-only targets (JuiceShop, dev apps, etc.)
    "nmap-vuln", "nmap-vulscan",   # nmap --script vuln: 300+ s against internal hosts
    "masscan",   # mass internet scanner — useless / dangerous for localhost
    # Fuzzing fallbacks that duplicate ffuf but have no --maxtime flag
    "wfuzz",
}

_INTERNAL_HOST_RE = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0"
    r"|10\.\d+\.\d+\.\d+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|host\.docker\.internal)$",
    re.IGNORECASE,
)


def _is_internal_host(target: str) -> bool:
    """Return True when *target* is localhost, a private IP, or a Docker-internal name."""
    try:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).lower().split(":")[0]
    except Exception:
        host = target.lower()
    return bool(_INTERNAL_HOST_RE.match(host))


class ToolCatalog:
    def __init__(self, entries: list[ToolCatalogEntry] | None = None) -> None:
        self.entries = {entry.tool_name: entry for entry in (entries or default_tool_catalog())}

    def get(self, tool_name: str) -> ToolCatalogEntry | None:
        return self.entries.get(tool_name)

    def require(self, tool_name: str) -> ToolCatalogEntry:
        entry = self.get(tool_name)
        if not entry or not entry.available:
            raise ValueError(f"tool_not_found:{tool_name}")
        return entry


def default_tool_catalog() -> list[ToolCatalogEntry]:
    def entry(name: str, profile: str, capabilities: list[str], parser: str = "generic_json_parser", default_timeout: int = 300) -> ToolCatalogEntry:
        return ToolCatalogEntry(
            tool_name=name,
            profile=profile,
            available=True,
            target_types=["url", "domain", "api_endpoint", "parameterized_endpoint"],
            capabilities=capabilities,
            accepted_arguments=["target", "wordlist", "rate", "timeout", "headers", "payload"],
            required_arguments=["target"],
            output_format="json",
            parser=parser,
            timeout_policy={"default_timeout": default_timeout, "max_timeout": max(default_timeout * 2, 1800)},
            risk_level="medium",
            noise_level="medium",
        )

    return [
        entry("manual_scope_review", "manual_scope_review", ["scope_validation"], "manual_parser"),
        entry("manual_review", "manual_review", ["evidence_review"], "manual_parser"),
        entry("manual_correlation", "manual_review", ["attack_path_correlation"], "manual_parser"),
        entry("manual_http_probe", "curl_probe", ["http_validation"], "http_parser"),
        # Análise client-side (CDP) + teste ATIVO de business logic (backend-local).
        # chromium-capture roda no kali (profile chromium_capture); bl-test é
        # backend-local (curto-circuitado em _call_mcp_execution, profile sentinela).
        entry("chromium-capture", "chromium_capture", ["client_side_analysis", "dom_xss", "api_capture"], "generic_json_parser"),
        entry("bl-test", "business_logic_backend", ["business_logic", "idor_bola", "mass_assignment", "sensitive_data_exposure"], "generic_json_parser"),
        entry("report-builder", "report_builder", ["reporting"], "report_parser"),
        entry("subfinder", "subfinder_passive", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("subfinder-passive", "subfinder_passive", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("assetfinder", "assetfinder_passive", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("naabu", "naabu_top1000", ["port_service_discovery"], "naabu_parser"),
        entry("nmap-top-ports", "nmap_service_detect", ["port_service_discovery"], "nmap_parser"),
        entry("nmap", "nmap_service_detect", ["port_service_discovery"], "nmap_parser"),
        entry("arjun", "arjun_param_discover", ["parameter_discovery"], "arjun_parser"),
        entry("paramspider", "paramspider_mining", ["parameter_discovery"], "param_parser"),
        entry("ffuf", "ffuf_dirs", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("ffuf-params", "ffuf_param_names", ["parameter_discovery", "fuzzing"], "ffuf_parser"),
        entry("ffuf-content", "ffuf_dirs", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("katana", "katana_crawl", ["endpoint_discovery", "crawling"], "katana_parser"),
        entry("gobuster", "gobuster_dir", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("katana-crawl", "katana_crawl", ["endpoint_discovery", "crawling"], "katana_parser"),
        entry("katana-js", "katana_crawl", ["js_analysis"], "katana_parser"),
        entry("linkfinder", "linkfinder_js", ["js_analysis", "endpoint_discovery"], "katana_parser"),
        entry("httpx-fingerprint", "httpx_probe", ["http_fingerprinting"], "httpx_parser"),
        entry("whatweb-basic", "whatweb_fingerprint", ["technology_detection"], "whatweb_parser"),
        entry("curl", "curl_probe", ["http_validation", "request_response_pair"], "http_parser"),
        entry("curl-headers", "curl_headers", ["http_validation", "headers"], "http_parser"),
        entry("sqlmap", "sqlmap_basic", ["sqli_validation"], "sqlmap_parser"),
        entry("wapiti", "wapiti_scan", ["web_validation"], "generic_json_parser"),
        entry("dalfox", "dalfox_xss", ["xss_validation"], "dalfox_parser"),
        entry("interactsh", "interactsh_oob", ["ssrf_oob"], "interactsh_parser"),
        entry("interactsh-client", "interactsh_oob", ["ssrf_oob"], "interactsh_parser"),
        entry("nuclei", "nuclei_cves", ["template_validation", "vuln_scanning"], "nuclei_parser"),
        entry("hydra", "hydra_wordlist_auth", ["auth_validation"], "generic_json_parser"),
        entry("git", "curl_probe", ["git_exposure_review"], "http_parser"),
        entry("gitleaks", "gitleaks_secrets", ["secret_detection"], "secret_parser"),
        entry("trufflehog-filesystem", "trufflehog_secrets", ["secret_detection"], "secret_parser"),
        entry("amass", "amass_brute", ["subdomain_enumeration", "passive_recon", "osint"], "subfinder_parser"),
        entry("shodan-cli", "shodan_lookup", ["port_service_discovery", "osint", "banner_grabbing"], "generic_json_parser"),
        entry("theharvester", "theharvester_passive", ["osint", "email_harvesting"], "generic_json_parser"),
        # === Expanded catalog — Kali tools now reachable from offensive operator ===
        # Subdomain enumeration variants
        entry("amass-brute", "amass_brute", ["subdomain_enumeration", "active_recon", "dns_brute"], "subfinder_parser"),
        entry("amass-intel", "amass_intel", ["subdomain_enumeration", "osint", "whois"], "subfinder_parser"),
        entry("ghdb-public-indexes", "ghdb_public_indexes", ["subdomain_enumeration", "passive_recon", "osint"], "subfinder_parser"),
        entry("sublist3r", "sublist3r_basic", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("findomain", "findomain_passive", ["subdomain_enumeration", "passive_recon"], "subfinder_parser"),
        entry("dnsrecon-brt", "dnsrecon_brute", ["subdomain_enumeration", "dns_brute"], "subfinder_parser"),
        entry("dnsrecon-zt", "dnsrecon_zone_transfer", ["subdomain_enumeration", "dns_zone_transfer"], "subfinder_parser"),
        entry("dnsenum", "dnsenum_basic", ["subdomain_enumeration", "dns_brute"], "subfinder_parser"),
        entry("dnsx", "dnsx_resolve", ["dns_resolution", "passive_recon"], "subfinder_parser"),
        entry("shuffledns", "shuffledns_brute", ["subdomain_enumeration", "dns_brute"], "subfinder_parser"),
        entry("alterx", "alterx_permutations", ["subdomain_enumeration", "permutation"], "subfinder_parser"),
        # Port & service discovery
        entry("masscan", "masscan_full", ["port_service_discovery", "internet_scale"], "naabu_parser"),
        entry("httpx", "httpx_probe", ["http_fingerprinting", "tech_detection"], "httpx_parser"),
        entry("whatweb", "whatweb_fingerprint", ["technology_detection", "fingerprinting"], "whatweb_parser"),
        entry("wafw00f", "wafw00f_detect", ["waf_detection", "fingerprinting"], "generic_json_parser"),
        entry("sslscan", "sslscan_audit", ["tls_audit", "cipher_review"], "generic_json_parser"),
        entry("testssl", "testssl_audit", ["tls_audit", "vulnerability_scan"], "generic_json_parser"),
        # Nmap NSE variants
        entry("nmap-vuln", "nmap_vuln_scripts", ["vulnerability_scan", "nse_scripts"], "nmap_parser"),
        entry("nmap-http", "nmap_http_enum", ["http_enumeration", "nse_scripts"], "nmap_parser"),
        entry("nmap-smb", "nmap_smb_vuln", ["smb_audit", "nse_scripts"], "nmap_parser"),
        entry("nmap-ssh", "nmap_ssh_audit", ["ssh_audit", "nse_scripts"], "nmap_parser"),
        entry("nmap-ssl", "nmap_ssl_vuln", ["tls_audit", "nse_scripts"], "nmap_parser"),
        entry("nmap-dns", "nmap_dns_vuln", ["dns_audit", "nse_scripts"], "nmap_parser"),
        # Crawling / endpoint extraction
        entry("hakrawler", "hakrawler_crawl", ["endpoint_discovery", "crawling"], "katana_parser"),
        entry("gospider", "gospider_crawl", ["endpoint_discovery", "crawling"], "katana_parser"),
        entry("gau", "gau_archives", ["url_mining", "archive_recon"], "katana_parser"),
        entry("waybackurls", "waybackurls_archives", ["url_mining", "archive_recon"], "katana_parser"),
        # Content / parameter fuzzing
        entry("feroxbuster", "feroxbuster_recursive", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("dirsearch", "dirsearch_paths", ["content_discovery", "fuzzing"], "ffuf_parser"),
        entry("wfuzz", "wfuzz_param_names", ["parameter_discovery", "fuzzing"], "ffuf_parser"),
        # Vulnerability scanning
        entry("nikto", "nikto_basic", ["web_validation", "vuln_scanning"], "generic_json_parser", default_timeout=1800),
        entry("wpscan", "wpscan_basic", ["cms_audit", "vuln_scanning"], "generic_json_parser", default_timeout=900),
        # Credential / brute-force
        entry("crackmapexec", "crackmapexec_smb", ["smb_enumeration", "auth_validation"], "generic_json_parser"),
        entry("medusa", "medusa_smb", ["auth_validation", "credential_test"], "generic_json_parser"),
        entry("jwt_tool", "jwt_tool_audit", ["jwt_audit", "auth_validation"], "generic_json_parser"),
        entry("h8mail", "h8mail_breach", ["osint", "credential_exposure"], "generic_json_parser"),
        # Secret scanning / SAST
        entry("trufflehog", "trufflehog_secrets", ["secret_detection"], "secret_parser"),
        entry("bandit", "bandit_python", ["sast", "secret_detection"], "generic_json_parser"),
        entry("semgrep", "semgrep_backend", ["sast", "code_analysis"], "generic_json_parser"),
        entry("trivy", "trivy_fs", ["sca", "vuln_scanning"], "generic_json_parser"),
        entry("retire", "retire_js", ["sca", "js_audit"], "generic_json_parser"),
        # Takeover detection
        entry("subjack", "subjack_takeover", ["subdomain_takeover", "passive_recon"], "generic_json_parser"),
        # === HackerOne-derived nuclei profiles (23 vulnerability classes) ===
        # Maps to kali-runner profile keys; each targets a specific vuln class via nuclei tags.
        # XSS — #1 HackerOne class (652 reports): reflected, stored, DOM, blind, HTML inject
        entry("nuclei-xss", "nuclei_xss", ["xss_validation", "template_validation"], "nuclei_parser"),
        # SQL Injection — 46 reports: error-based, time-based, blind, NoSQL
        entry("nuclei-sqli", "nuclei_sqli", ["sqli_validation", "template_validation"], "nuclei_parser"),
        # SSRF — 68 reports: blind SSRF, EC2 metadata, webhook, bypass patterns
        entry("nuclei-ssrf", "nuclei_ssrf", ["ssrf_validation", "template_validation"], "nuclei_parser"),
        # LFI/Path Traversal — 13 reports: directory traversal, local/remote file inclusion
        entry("nuclei-lfi", "nuclei_lfi", ["lfi_validation", "path_traversal"], "nuclei_parser"),
        # SSTI — injection class (135 reports): template injection leading to RCE
        entry("nuclei-ssti", "nuclei_ssti", ["ssti_validation", "template_injection"], "nuclei_parser"),
        # XXE — 9 reports: blind OOB, SOAP XXE, XML parser injection
        entry("nuclei-xxe", "nuclei_xxe", ["xxe_validation", "template_validation"], "nuclei_parser"),
        # CORS misconfiguration — 8 reports: wildcard, credentials, allow-origin bypass
        entry("nuclei-cors", "nuclei_cors", ["cors_misconfiguration", "header_audit"], "nuclei_parser"),
        # Open Redirect — 69 reports: login redirect, OAuth redirect_uri, host header
        entry("nuclei-redirect", "nuclei_open_redirect", ["open_redirect", "template_validation"], "nuclei_parser"),
        # IDOR/Access Control — 73 reports: broken access control, unauthorized data access
        entry("nuclei-idor", "nuclei_idor", ["idor_validation", "access_control"], "nuclei_parser"),
        # CSRF — 110 reports: login CSRF, OAuth CSRF, missing token checks
        entry("nuclei-csrf", "nuclei_csrf", ["csrf_validation", "template_validation"], "nuclei_parser"),
        # CRLF/Header Injection — injection class: response splitting, log injection
        entry("nuclei-crlf", "nuclei_crlf", ["crlf_injection", "header_injection"], "nuclei_parser"),
        # GraphQL/API — 25 of 28 API reports: introspection enabled, field disclosure
        entry("nuclei-graphql", "nuclei_graphql", ["graphql_exposure", "api_validation"], "nuclei_parser"),
        # Race Condition — 20 reports: coupon/invitation bypass, resource exhaustion
        entry("nuclei-race", "nuclei_race", ["race_condition", "business_logic"], "nuclei_parser"),
        # RCE/Command Injection — critical severity, injection class (135 reports)
        entry("nuclei-rce", "nuclei_rce", ["rce_validation", "command_injection"], "nuclei_parser"),
        # Auth/Default Credentials — 119 reports: broken auth, default logins, 2FA bypass
        entry("nuclei-auth", "nuclei_auth", ["auth_validation", "default_credentials"], "nuclei_parser"),
        entry("nuclei-auth-bypass", "nuclei_auth", ["auth_validation", "auth_bypass"], "nuclei_parser"),
        entry("nuclei-default-credentials", "nuclei_auth", ["auth_validation", "default_credentials"], "nuclei_parser"),
        # JWT/OAuth — 19 reports: alg:none, weak HS256, token leak, OAuth state bypass
        entry("nuclei-jwt", "nuclei_jwt", ["jwt_audit", "oauth_validation"], "nuclei_parser"),
        entry("nuclei-oauth", "nuclei_jwt", ["oauth_validation"], "nuclei_parser"),
        # Information/Secret Exposure — 78 reports: API keys, tokens, stack traces, debug
        entry("nuclei-exposure", "nuclei_exposure", ["information_disclosure", "secret_detection"], "nuclei_parser"),
        # Cloud/S3 Exposure — 15 reports: open buckets, AWS metadata, GCP/Azure
        entry("nuclei-cloud", "nuclei_cloud", ["cloud_exposure", "s3_audit"], "nuclei_parser"),
        # Deserialization — 13 reports: Java, PHP, Python unsafe deserialize
        entry("nuclei-deserialization", "nuclei_deserialization", ["deserialization_audit", "template_validation"], "nuclei_parser"),
        # Clickjacking — 19 reports: missing X-Frame-Options, CSP frame-ancestors
        entry("nuclei-clickjacking", "nuclei_clickjacking", ["clickjacking", "header_audit"], "nuclei_parser"),
        # Security Headers — 27 reports: CSP, HSTS, X-Content-Type-Options, DMARC/SPF/DKIM
        entry("nuclei-headers", "nuclei_headers", ["security_headers", "header_audit"], "nuclei_parser"),
        # Spoofing/Impersonation — 53 reports: email spoofing, SPF/DMARC/DKIM missing
        entry("nuclei-spoofing", "nuclei_spoofing", ["email_spoofing", "dns_security"], "nuclei_parser"),
        # Subdomain Takeover (nuclei templates) — 49 reports: complement subjack
        entry("nuclei-takeover", "nuclei_takeover", ["subdomain_takeover", "passive_recon"], "nuclei_parser"),
        # === OWASP ZAP — web application scanner ===
        # ZAP Baseline: passive scan + quick spider (no active attacks), low noise, fast
        entry("zap-baseline", "zap_baseline", ["web_validation", "passive_scan", "header_audit"], "zap_parser"),
        # ZAP AJAX Spider: headless browser crawl for SPAs (React/Vue/Angular) — discovers routes
        entry("zap-ajax", "zap_ajax_spider", ["endpoint_discovery", "crawling", "spa_crawl"], "zap_parser"),
        # ZAP Active Scan: active fuzzing for OWASP Top 10 (SQLi, XSS, command injection, etc.)
        entry("zap-active", "zap_active_scan", ["web_validation", "vuln_scanning", "active_scan"], "zap_parser"),
        # ZAP API Scan: scans all endpoints discovered via OpenAPI/Swagger schema
        entry("zap-api", "zap_api_scan", ["api_validation", "openapi_scan", "vuln_scanning"], "zap_parser"),
    ]


@dataclass
class Scope:
    scope_id: str
    allowed_domains: list[str] = field(default_factory=list)
    allowed_subdomains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    allowed_protocols: list[str] = field(default_factory=lambda: ["http", "https"])
    disallowed_targets: list[str] = field(default_factory=list)
    allowed_techniques: list[str] = field(default_factory=list)
    disallowed_techniques: list[str] = field(default_factory=list)
    max_noise_level: str = "medium"
    allow_authenticated_testing: bool = True
    allow_post_exploitation: bool = False
    allow_credential_testing: bool = False
    allow_data_access_validation: bool = False
    execution_windows: list[dict[str, Any]] = field(default_factory=list)


class ScopeGuard:
    NOISE_ORDER = {"low": 1, "medium": 2, "high": 3}

    def validate(self, target: str, scope: Scope, technique: str | None = None, noise_level: str = "medium") -> dict[str, Any]:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        protocol = parsed.scheme or "https"
        port = parsed.port
        if target in scope.disallowed_targets or host in scope.disallowed_targets:
            return {"allowed": False, "reason": "target_explicitly_disallowed"}
        if scope.allowed_protocols and protocol not in scope.allowed_protocols:
            return {"allowed": False, "reason": "protocol_not_allowed"}
        if scope.allowed_ports and port is not None and port not in scope.allowed_ports:
            return {"allowed": False, "reason": "port_not_allowed"}
        allowed_hosts = set(scope.allowed_domains + scope.allowed_subdomains + scope.allowed_ips)
        if allowed_hosts and host not in allowed_hosts and not any(host.endswith(f".{domain}") for domain in scope.allowed_domains):
            return {"allowed": False, "reason": "target_out_of_scope"}
        if technique and technique in scope.disallowed_techniques:
            return {"allowed": False, "reason": "technique_disallowed"}
        if scope.allowed_techniques and technique and technique not in scope.allowed_techniques:
            return {"allowed": False, "reason": "technique_not_allowed"}
        if self.NOISE_ORDER.get(noise_level, 2) > self.NOISE_ORDER.get(scope.max_noise_level, 2):
            return {"allowed": False, "reason": "noise_level_exceeds_scope"}
        return {"allowed": True, "reason": "scope_approved"}


class ExecutionPolicyEngine:
    def __init__(self, catalog: ToolCatalog | None = None, scope_guard: ScopeGuard | None = None) -> None:
        self.catalog = catalog or ToolCatalog()
        self.scope_guard = scope_guard or ScopeGuard()

    def decide(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("execution_mode") not in EXECUTION_MODES:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "invalid_execution_mode"}
        if request["execution_mode"] == "learning_only":
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "learning_only_no_tool_execution"}
        tool = self.catalog.get(str(request.get("tool_name") or ""))
        if not tool or not tool.available:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "tool_without_profile"}
        if not tool.profile:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "tool_without_profile"}
        if not tool.parser:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "execution_without_parser"}
        if not tool.timeout_policy.get("default_timeout"):
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "execution_without_timeout"}
        if not request.get("expected_evidence"):
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "execution_without_evidence_expected"}
        scope_decision = self.scope_guard.validate(
            target=str(request.get("target") or ""),
            scope=request["scope"],
            technique=str(request.get("payload_family") or request.get("skill_id") or ""),
            noise_level=str(request.get("noise_level") or tool.noise_level),
        )
        if not scope_decision["allowed"]:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": scope_decision["reason"]}
        if tool.tool_name in BACKEND_LOCAL_TOOL_NAMES:
            return {
                "allowed": True,
                "reason": "policy_approved_backend_local",
                "required_controls": ["scope_guard", "backend_local", "evidence"],
                "blocked_reason": None,
            }
        if request.get("mcp_available") is False:
            return {"allowed": False, "reason": "", "required_controls": [], "blocked_reason": "mcp_unavailable"}
        return {"allowed": True, "reason": "policy_approved", "required_controls": ["scope_guard", "mcp", "evidence"], "blocked_reason": None}


def parse_skill_markdown(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", text, re.S)
    if not match:
        raise ValueError("missing_frontmatter")
    metadata = safe_yaml_load(match.group(1)) or {}
    if not isinstance(metadata, dict):
        raise ValueError("invalid_frontmatter")
    return {"metadata": metadata, "body": match.group(2), "path": str(path)}


def safe_yaml_load(text: str) -> dict[str, Any]:
    if yaml is not None:
        return yaml.safe_load(text) or {}
    def _next_content(start: int) -> tuple[int, int, str] | None:
        for idx in range(start, len(lines)):
            raw = lines[idx]
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            return idx, indent, raw.strip()
        return None

    data: dict[str, Any] = {}
    lines = text.splitlines()
    line_index = 0
    while line_index < len(lines):
        raw_line = lines[line_index]
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            line_index += 1
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent != 0:
            line_index += 1
            continue
        line = raw_line.strip()
        if ":" not in line:
            line_index += 1
            continue

        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if raw_value:
            data[key] = _parse_scalar(raw_value)
            line_index += 1
            continue

        next_content = _next_content(line_index + 1)
        if not next_content:
            data[key] = {}
            line_index += 1
            continue

        next_index, _next_indent, next_line = next_content
        if next_line.startswith("- "):
            values: list[Any] = []
            cursor = next_index
            while cursor < len(lines):
                item_raw = lines[cursor]
                if not item_raw.strip() or item_raw.lstrip().startswith("#"):
                    cursor += 1
                    continue
                item_indent = len(item_raw) - len(item_raw.lstrip(" "))
                item_line = item_raw.strip()
                if item_indent < indent or not item_line.startswith("- "):
                    break
                values.append(_parse_scalar(item_line[2:].strip()))
                cursor += 1
            data[key] = values
            line_index = cursor
            continue

        nested: dict[str, Any] = {}
        cursor = next_index
        while cursor < len(lines):
            nested_raw = lines[cursor]
            if not nested_raw.strip() or nested_raw.lstrip().startswith("#"):
                cursor += 1
                continue
            nested_indent = len(nested_raw) - len(nested_raw.lstrip(" "))
            if nested_indent <= indent:
                break
            nested_line = nested_raw.strip()
            if ":" in nested_line:
                nested_key, nested_value = nested_line.split(":", 1)
                nested[nested_key.strip()] = _parse_scalar(nested_value.strip()) if nested_value.strip() else {}
            cursor += 1
        data[key] = nested
        line_index = cursor
    return data


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def is_dataless_file(path: Path) -> bool:
    """Detect macOS/iCloud dataless files without opening file content."""
    try:
        flags = getattr(os.stat(path), "st_flags", 0)
    except OSError:
        return False
    return bool(flags & 0x40000000)


class SkillRegistry:
    REQUIRED_FRONTMATTER = {
        "skill_id",
        "name",
        "version",
        "category",
        "phase_ids",
        "supported_target_types",
        "risk_level",
        "noise_level",
        "requires_authorization",
        "required_tools",
        "evidence_required",
        "exit_criteria",
        "retry_policy",
        "allowed_execution_modes",
        "safety_rules",
    }

    REQUIRED_SECTIONS = ["# Objective", "# Offensive Reasoning", "# Execution Strategy", "# Tool Mapping", "# Expected Evidence", "## Changelog"]

    def __init__(self, skills_root: str | Path = "skills", catalog: ToolCatalog | None = None) -> None:
        self.skills_root = Path(skills_root)
        self.catalog = catalog or ToolCatalog()
        self._skills: dict[str, dict[str, Any]] | None = None

    def load(self) -> dict[str, dict[str, Any]]:
        skills: dict[str, dict[str, Any]] = {}
        if not self.skills_root.exists():
            self._skills = self._with_contract_fallback_skills(skills)
            return self._skills
        for path in sorted(self.skills_root.rglob("*.md")):
            try:
                if is_dataless_file(path):
                    skills[str(path)] = {
                        "skill_id": "",
                        "path": str(path),
                        "status": "review",
                        "quality_gate_status": "failed",
                        "quality_gate_errors": ["file_dataless_unavailable_offline"],
                        "metadata": {},
                        "body": "",
                    }
                    continue
                parsed = parse_skill_markdown(path)
                metadata = parsed["metadata"]
                from app.services.vulnerability_catalog_config import is_vulnerability_skill_enabled

                if not is_vulnerability_skill_enabled(path, metadata):
                    continue
                skill_id = str(metadata.get("skill_id") or "")
                gate = self.validate(parsed)
                skills[skill_id or str(path)] = {
                    "skill_id": skill_id,
                    "path": str(path),
                    "version": metadata.get("version"),
                    "status": metadata.get("status", "approved" if gate["valid"] else "review"),
                    "category": metadata.get("category"),
                    "phase_ids": metadata.get("phase_ids") or [],
                    "source_report_ids": metadata.get("source_report_ids") or [],
                    "allowed_execution_modes": metadata.get("allowed_execution_modes") or [],
                    "required_tools": metadata.get("required_tools") or [],
                    "quality_gate_status": "passed" if gate["valid"] else "failed",
                    "quality_gate_errors": gate["errors"],
                    "metadata": metadata,
                    "body": parsed["body"],
                }
            except Exception as exc:  # noqa: BLE001
                skills[str(path)] = {
                    "skill_id": "",
                    "path": str(path),
                    "status": "review",
                    "quality_gate_status": "failed",
                    "quality_gate_errors": [str(exc)],
                    "metadata": {},
                    "body": "",
                }
        self._skills = self._with_contract_fallback_skills(skills)
        return self._skills

    def _with_contract_fallback_skills(self, skills: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Ensure deterministic phase contracts can run when markdown skills are not mounted.

        The Docker backend mounts `./backend` at `/app` in development, while the
        markdown skill library lives at the repository root. Without this fallback
        the offensive operator blocks at P01 before attempting any tool.
        """
        result = dict(skills)
        for contract in PHASE_CONTRACTS.values():
            for skill_id in contract.get("required_skills") or []:
                existing = result.get(skill_id)
                if existing and existing.get("quality_gate_status") == "passed":
                    phase_ids = list(dict.fromkeys(list(existing.get("phase_ids") or []) + [contract["phase_id"]]))
                    modes = list(dict.fromkeys(list(existing.get("allowed_execution_modes") or []) + sorted(EXECUTION_MODES - {"learning_only"})))
                    tools = list(dict.fromkeys(list(existing.get("required_tools") or []) + list(contract.get("required_tools") or [])))
                    metadata = dict(existing.get("metadata") or {})
                    metadata["phase_ids"] = phase_ids
                    metadata["allowed_execution_modes"] = modes
                    metadata["required_tools"] = tools
                    existing.update(
                        phase_ids=phase_ids,
                        allowed_execution_modes=modes,
                        required_tools=tools,
                        metadata=metadata,
                    )
                    continue
                metadata = {
                    "skill_id": skill_id,
                    "name": contract["name"],
                    "version": "contract-fallback",
                    "status": "approved",
                    "category": "contract",
                    "phase_ids": [contract["phase_id"]],
                    "supported_target_types": ["domain", "url"],
                    "risk_level": "medium",
                    "noise_level": "medium",
                    "requires_authorization": True,
                    "required_tools": list(contract.get("required_tools") or []),
                    "fallback_tools": list(contract.get("optional_tools") or []),
                    "evidence_required": list(contract.get("minimum_evidence") or ["tool_output"]),
                    "exit_criteria": dict(contract.get("exit_criteria") or {}),
                    "retry_policy": dict(contract.get("retry_policy") or {}),
                    "allowed_execution_modes": sorted(EXECUTION_MODES - {"learning_only"}),
                    "safety_rules": ["scope_guard_required", "authorized_targets_only"],
                }
                result[skill_id] = {
                    "skill_id": skill_id,
                    "path": f"<contract:{contract['phase_id']}>",
                    "version": metadata["version"],
                    "status": "approved",
                    "category": metadata["category"],
                    "phase_ids": metadata["phase_ids"],
                    "source_report_ids": [],
                    "allowed_execution_modes": metadata["allowed_execution_modes"],
                    "required_tools": metadata["required_tools"],
                    "quality_gate_status": "passed",
                    "quality_gate_errors": [],
                    "metadata": metadata,
                    "body": (
                        f"# Objective\n{contract['description']}\n\n"
                        "# Offensive Reasoning\nUse the phase contract safely inside authorized scope.\n\n"
                        "# Execution Strategy\nRun the required tools and collect evidence.\n\n"
                        "# Tool Mapping\nContract required tools define the tool plan.\n\n"
                        "# Expected Evidence\nPersist raw and parsed tool output.\n\n"
                        "## Changelog\n- contract fallback\n"
                    ),
                }
        return result

    def validate(self, parsed: dict[str, Any]) -> dict[str, Any]:
        metadata = parsed["metadata"]
        body = parsed["body"]
        errors: list[str] = []
        missing = sorted(self.REQUIRED_FRONTMATTER - set(metadata))
        errors.extend([f"missing_frontmatter:{field}" for field in missing])
        if not metadata.get("required_tools"):
            errors.append("missing_required_tools")
        for tool in list(metadata.get("required_tools") or []) + list(metadata.get("fallback_tools") or []):
            if not self.catalog.get(str(tool)):
                errors.append(f"tool_not_found:{tool}")
        if not metadata.get("evidence_required"):
            errors.append("missing_evidence_required")
        if not metadata.get("exit_criteria"):
            errors.append("missing_exit_criteria")
        if not metadata.get("retry_policy"):
            errors.append("missing_retry_policy")
        for section in self.REQUIRED_SECTIONS:
            if section not in body:
                errors.append(f"missing_section:{section}")
        if metadata.get("learning_source") == "hackerone" and not metadata.get("source_report_ids"):
            errors.append("missing_source_report_ids")
        return {"valid": not errors, "errors": errors}

    def approved_for_phase(self, phase_id: str, execution_mode: str) -> list[dict[str, Any]]:
        skills = self._skills if self._skills is not None else self.load()
        return [
            skill
            for skill in skills.values()
            if skill.get("quality_gate_status") == "passed"
            and skill.get("status", "approved") == "approved"
            and phase_id in (skill.get("phase_ids") or [])
            and execution_mode in (skill.get("allowed_execution_modes") or [])
        ]


class SkillRagIndex:
    def __init__(self, registry: SkillRegistry) -> None:
        self.registry = registry
        self.chunks: list[dict[str, Any]] = []

    def rebuild(self) -> list[dict[str, Any]]:
        skills = self.registry.load()
        chunks: list[dict[str, Any]] = []
        for skill in skills.values():
            if skill.get("quality_gate_status") != "passed":
                continue
            metadata = skill["metadata"]
            sections = re.split(r"\n(?=# )", skill.get("body") or "")
            for index, section in enumerate([part.strip() for part in sections if part.strip()]):
                chunks.append(
                    {
                        "chunk_id": stable_id("chunk", {"skill": skill["skill_id"], "index": index, "section": section[:80]}),
                        "skill_id": skill["skill_id"],
                        "skill_version": metadata.get("version"),
                        "skill_path": skill["path"],
                        "section": section.splitlines()[0].lstrip("# ").strip(),
                        "category": metadata.get("category"),
                        "phase_ids": metadata.get("phase_ids") or [],
                        "vulnerability_class": metadata.get("vulnerability_class", ""),
                        "source_report_ids": metadata.get("source_report_ids") or [],
                        "execution_modes": metadata.get("allowed_execution_modes") or [],
                        "required_tools": metadata.get("required_tools") or [],
                        "status": metadata.get("status", "approved"),
                        "tags": metadata.get("tags") or [],
                        "content": section,
                    }
                )
        self.chunks = chunks
        return chunks

    def retrieve(self, query: str, filters: dict[str, Any] | None = None, top_k: int = 5) -> dict[str, Any]:
        filters = filters or {}
        if not self.chunks:
            self.rebuild()
        query_tokens = set(re.findall(r"[a-z0-9_\\-]{3,}", query.lower()))
        scored: dict[str, dict[str, Any]] = {}
        for chunk in self.chunks:
            if not self._matches(chunk, filters):
                continue
            tokens = set(re.findall(r"[a-z0-9_\\-]{3,}", json.dumps(chunk, default=str).lower()))
            score = len(query_tokens & tokens) / max(1, len(query_tokens))
            if score <= 0 and filters:
                score = 0.25
            current = scored.get(chunk["skill_id"])
            if not current or score > current["relevance"]:
                scored[chunk["skill_id"]] = {
                    "skill_id": chunk["skill_id"],
                    "path": chunk["skill_path"],
                    "relevance": round(score, 4),
                    "matched_reasons": self._reasons(chunk, filters),
                }
        return {
            "retrieved_skills": sorted(scored.values(), key=lambda item: item["relevance"], reverse=True)[:top_k],
            "retrieved_context": [],
            "recommended_execution_focus": [],
        }

    @staticmethod
    def _matches(chunk: dict[str, Any], filters: dict[str, Any]) -> bool:
        for key, value in filters.items():
            if value in (None, "", []):
                continue
            if key == "phase_id":
                if value not in (chunk.get("phase_ids") or []):
                    return False
                continue
            if key == "execution_mode":
                if value not in (chunk.get("execution_modes") or []):
                    return False
                continue
            actual = chunk.get(key)
            if isinstance(actual, list):
                if value not in actual:
                    return False
            elif actual != value:
                return False
        return True

    @staticmethod
    def _reasons(chunk: dict[str, Any], filters: dict[str, Any]) -> list[str]:
        reasons = []
        if filters.get("phase_id") in chunk.get("phase_ids", []):
            reasons.append(f"Phase {filters['phase_id']} active")
        if filters.get("execution_mode") in chunk.get("execution_modes", []):
            reasons.append(f"Execution mode {filters['execution_mode']} allowed")
        if filters.get("vulnerability_class") == chunk.get("vulnerability_class"):
            reasons.append(f"Vulnerability class {filters['vulnerability_class']} matched")
        return reasons or ["Lexical skill match"]


class SkillToToolPlanCompiler:
    def __init__(self, catalog: ToolCatalog | None = None, policy: ExecutionPolicyEngine | None = None) -> None:
        self.catalog = catalog or ToolCatalog()
        self.policy = policy or ExecutionPolicyEngine(self.catalog)

    def compile(
        self,
        skill: dict[str, Any],
        phase_contract: dict[str, Any],
        target: str,
        scope: Scope,
        execution_mode: str,
        mcp_available: bool = True,
    ) -> dict[str, Any]:
        if skill.get("quality_gate_status") != "passed":
            raise ValueError("skill_quality_gate_failed")
        tools: list[dict[str, Any]] = []
        _skip_dns_tools = _is_internal_host(target)

        def _add_tool(name: str, is_required: bool) -> None:
            # Skip DNS brute-force and OSINT-only tools for internal/local targets —
            # they block indefinitely without producing any results.
            if _skip_dns_tools and str(name) in _OSINT_ONLY_TOOLS:
                return
            catalog_entry = self.catalog.get(str(name))
            if not catalog_entry:
                if is_required:
                    tool_record = {
                        "tool_name": str(name),
                        "profile": "",
                        "required": True,
                        "arguments": {},
                        "reason": f"tool_not_in_catalog:{name}",
                        "expected_evidence": [],
                        "timeout": 0,
                        "rate_limit": 0,
                        "noise_level": "low",
                        "policy_decision": {"allowed": False, "blocked_reason": f"tool_not_in_catalog:{name}"},
                        "execution_backend": "unknown",
                    }
                    tool_record["execution_key"] = tool_execution_key(
                        phase_contract["phase_id"],
                        skill["skill_id"],
                        tool_record,
                    )
                    tools.append(tool_record)
                return
            expected_evidence = skill["metadata"].get("evidence_required") or phase_contract.get("minimum_evidence") or []
            policy_decision = self.policy.decide(
                {
                    "phase_id": phase_contract["phase_id"],
                    "skill_id": skill["skill_id"],
                    "tool_name": catalog_entry.tool_name,
                    "target": target,
                    "payload_family": skill["metadata"].get("vulnerability_class", skill["skill_id"]),
                    "execution_mode": execution_mode,
                    "scope": scope,
                    "risk_level": skill["metadata"].get("risk_level"),
                    "noise_level": skill["metadata"].get("noise_level"),
                    "expected_evidence": expected_evidence,
                    "mcp_available": mcp_available,
                }
            )
            tool_record = {
                "tool_name": catalog_entry.tool_name,
                "profile": catalog_entry.profile,
                "required": is_required,
                "arguments": {"target": target, "timeout": catalog_entry.timeout_policy["default_timeout"]},
                "reason": f"{'Required' if is_required else 'Optional'} by {skill['skill_id']}",
                "expected_evidence": expected_evidence,
                "timeout": catalog_entry.timeout_policy["default_timeout"],
                "rate_limit": 50,
                "noise_level": catalog_entry.noise_level,
                "policy_decision": policy_decision,
                "execution_backend": "backend_local" if catalog_entry.tool_name in BACKEND_LOCAL_TOOL_NAMES else "mcp",
            }
            tool_record["execution_key"] = tool_execution_key(phase_contract["phase_id"], skill["skill_id"], tool_record)
            tools.append(tool_record)

        # A tool is REQUIRED only if the *phase contract* requires it. A skill
        # shared across phases (e.g. port_service_discovery → P02/P06/P07)
        # can accumulate tools from every phase; using that list directly would
        # run unrelated tools and create noisy or false coverage.
        phase_required = set(phase_contract.get("required_tools") or [])
        phase_optional = set(phase_contract.get("optional_tools") or [])
        phase_tool_names = phase_required | phase_optional
        skill_required = list(skill["metadata"].get("required_tools") or [])
        skill_optional = list(skill["metadata"].get("optional_tools") or []) + \
                         list(skill["metadata"].get("fallback_tools") or [])
        # Fallback: if the contract declares no required tools, treat the
        # skill's first required tool as required so the phase still gates.
        if not phase_required and skill_required:
            phase_required = {skill_required[0]}
            phase_tool_names.update(phase_required)

        _bindings = PHASE_TOOL_BINDINGS.get(phase_contract["phase_id"], {})

        def _tool_belongs_to_skill(name: str) -> bool:
            bound_to = _bindings.get(name)
            return bound_to is None or skill["skill_id"] in bound_to

        seen_tools: set[str] = set()
        for name in skill_required + skill_optional:
            if phase_tool_names and name not in phase_tool_names:
                continue
            if not _tool_belongs_to_skill(name):
                continue
            if name not in seen_tools:
                seen_tools.add(name)
                _add_tool(name, is_required=(name in phase_required))
        # Tools REQUERIDAS PELA FASE entram mesmo que a skill do RAG não as liste —
        # mas RESPEITANDO os bindings: uma tool ligada a skills específicas (ex.:
        # bl-test → business_logic/bola_bfla/api_security) NÃO entra em skills não
        # ligadas (csrf/idor), p/ não gerar FALSA cobertura. Tool sem binding é
        # phase-global (entra em toda skill).
        for name in (phase_contract.get("required_tools") or []):
            if not _tool_belongs_to_skill(name):
                continue  # tool ligada a outras skills — não conta cobertura aqui
            if name not in seen_tools:
                seen_tools.add(name)
                _add_tool(name, is_required=True)
        return {
            "tool_plan_id": stable_id("TP", {"phase_id": phase_contract["phase_id"], "skill_id": skill["skill_id"], "target": target}),
            "phase_id": phase_contract["phase_id"],
            "skill_id": skill["skill_id"],
            "objective": skill["metadata"].get("name") or phase_contract["name"],
            "tools": tools,
            "fallbacks": skill["metadata"].get("fallback_tools") or [],
            "validation_plan": skill["metadata"].get("exit_criteria") or {},
            "retry_plan": skill["metadata"].get("retry_policy") or {},
            "policy_decision": {"allowed": all(tool["policy_decision"]["allowed"] for tool in tools)},
        }


class MCPToolExecutor:
    def __init__(self, call_tool: Callable[[dict[str, Any]], dict[str, Any]] | None = None, available: bool = True) -> None:
        self.call_tool = call_tool
        self.available = available

    def _build_execution_record(self, tool: dict[str, Any], tool_plan: dict[str, Any], target: str) -> dict[str, Any]:
        execution_key = tool.get("execution_key") or tool_execution_key(tool_plan["phase_id"], tool_plan["skill_id"], tool)
        return {
            "mcp_execution_id": stable_id("MCP", {"tool_plan_id": tool_plan["tool_plan_id"], "execution_key": execution_key}),
            "mcp_request_id": stable_id("mcp", {"tool_plan_id": tool_plan["tool_plan_id"], "execution_key": execution_key}),
            "tool_plan_id": tool_plan["tool_plan_id"],
            "execution_key": execution_key,
            "execution_backend": tool.get("execution_backend") or "mcp",
            "phase_id": tool_plan["phase_id"],
            "skill_id": tool_plan["skill_id"],
            "tool_name": tool["tool_name"],
            "profile": tool["profile"],
            "arguments_hash": stable_id("ARG", tool.get("arguments") or {}),
            "arguments": dict(tool.get("arguments") or {}),
            "target": target,
            "status": "blocked",
            "stdout_path": "",
            "stderr_path": "",
            "artifacts": [],
            "exit_code": None,
            "timeout": tool.get("timeout"),
            "started_at": utc_now(),
            "finished_at": "",
            "error": None,
        }

    def _run_one_tool(self, execution: dict[str, Any]) -> dict[str, Any]:
        try:
            raw = self.call_tool(execution) if self.call_tool else {"status": "success", "exit_code": 0, "stdout_path": ""}
            status = raw.get("status") or "failed"
            if status == "done":
                status = "success"
            execution.update(
                status=status if status in {"queued", "running", "success", "failed", "timeout", "blocked"} else "failed",
                stdout_path=raw.get("stdout_path") or "",
                stderr_path=raw.get("stderr_path") or raw.get("stderr") or "",
                artifacts=raw.get("artifact_paths") or raw.get("artifacts") or [],
                exit_code=raw.get("exit_code", raw.get("return_code")),
                finished_at=utc_now(),
                error=raw.get("error"),
                stdout=raw.get("stdout") or "",
                parsed_result=raw.get("parsed_result") or raw.get("parsed"),
                command=raw.get("command") or "",
                duration_seconds=raw.get("duration_seconds"),
            )
        except Exception as exc:  # noqa: BLE001
            execution.update(status="failed", error=str(exc), finished_at=utc_now())
        return execution

    def execute(self, tool_plan: dict[str, Any], target: str) -> list[dict[str, Any]]:
        from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed

        tools = tool_plan.get("tools") or []
        if not tools:
            return []

        # Split into immediately-blocked (no I/O) and runnable (need kali call)
        blocked: list[tuple[int, dict[str, Any]]] = []
        runnable: list[tuple[int, dict[str, Any]]] = []
        for idx, tool in enumerate(tools):
            execution = self._build_execution_record(tool, tool_plan, target)
            backend_local = (
                tool.get("execution_backend") == "backend_local"
                or str(tool.get("tool_name") or "") in BACKEND_LOCAL_TOOL_NAMES
            )
            if (not self.available or tool["policy_decision"].get("blocked_reason") == "mcp_unavailable") and not backend_local:
                execution.update(status="blocked", error="mcp_unavailable", finished_at=utc_now())
                blocked.append((idx, execution))
            elif not tool["policy_decision"]["allowed"]:
                execution.update(status="blocked", error=tool["policy_decision"].get("blocked_reason"), finished_at=utc_now())
                blocked.append((idx, execution))
            else:
                runnable.append((idx, execution))

        ordered: dict[int, dict[str, Any]] = {idx: ex for idx, ex in blocked}

        # Run all kali-dispatched tools concurrently — each is an independent
        # HTTP POST to kali runner; there are no ordering dependencies within a phase.
        if runnable:
            max_workers = min(len(runnable), 8)
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(self._run_one_tool, ex): idx for idx, ex in runnable}
                for fut in _as_completed(futures):
                    idx = futures[fut]
                    try:
                        ordered[idx] = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        _, ex = runnable[next(i for i, (ri, _) in enumerate(runnable) if ri == idx)]
                        ex.update(status="failed", error=str(exc), finished_at=utc_now())
                        ordered[idx] = ex

        return [ordered[i] for i in range(len(tools))]


class EvidenceCollector:
    def create(self, execution: dict[str, Any], parsed_json: Any | None = None, payloads: list[str] | None = None) -> dict[str, Any]:
        strength = self.classify(execution, parsed_json)
        return {
            "evidence_id": stable_id("EV", execution),
            "phase_id": execution["phase_id"],
            "skill_id": execution["skill_id"],
            "tool_name": execution["tool_name"],
            "execution_key": execution.get("execution_key") or "",
            "execution_backend": execution.get("execution_backend") or "",
            "mcp_request_id": execution.get("mcp_request_id") or execution["mcp_execution_id"],
            "target": execution["target"],
            "evidence_type": "tool_output",
            "raw_stdout_path": execution.get("stdout_path") or "",
            "raw_stderr_path": execution.get("stderr_path") or "",
            "parsed_json": parsed_json or {},
            "request": {},
            "response": {},
            "payloads": payloads or [],
            "artifacts": execution.get("artifacts") or [],
            "created_at": utc_now(),
            "confidence": {"none": 0.0, "weak": 0.35, "medium": 0.6, "strong": 0.85, "conclusive": 1.0}[strength],
            "evidence_strength": strength,
        }

    @staticmethod
    def classify(execution: dict[str, Any], parsed_json: Any) -> str:
        if execution.get("status") != "success":
            return "none"
        parsed_dict = parsed_json if isinstance(parsed_json, dict) else {}
        if parsed_dict.get("impact_demonstrated") and parsed_dict.get("false_positive_controls_passed"):
            return "conclusive"
        if parsed_dict.get("reproducible") and parsed_dict.get("request_response_pair"):
            return "strong"
        if execution.get("stdout_path") or execution.get("stdout") or parsed_json:
            return "medium"
        return "weak"


class PhaseValidator:
    def validate(
        self,
        phase_contract: dict[str, Any],
        skill_plan: dict[str, Any],
        mcp_results: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]] | None,
        offensive_state: dict[str, Any],
        skill_coverage: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        required_tools = {
            str(tool.get("tool_name") or "")
            for tool in (skill_plan.get("tools") or [])
            if tool.get("required")
        }
        if not required_tools:
            required_tools = set(phase_contract.get("required_tools") or [])
        attempted = {result["tool_name"] for result in mcp_results}
        missing = sorted(required_tools - attempted)
        if missing:
            return self._decision(phase_contract["phase_id"], "blocked", False, "required_tool_not_attempted", missing)
        # Only block if a REQUIRED tool was blocked/timed-out.
        # Optional tools (not in required_tools) being blocked must not block the phase.
        required_blocked = [
            r for r in mcp_results
            if r["status"] in {"blocked", "timeout"} and r["tool_name"] in required_tools
        ]
        if required_blocked:
            reason = "required_tool_blocked_or_timeout"
            # MCP infrastructure down is a soft block — mark partial so the campaign advances.
            if all(r.get("error") in {"mcp_unavailable", None} for r in required_blocked):
                return self._decision(phase_contract["phase_id"], "partial", True, "mcp_unavailable_tool_skipped", [])
            coverage_decision = self._skill_coverage_decision(phase_contract, skill_coverage)
            if coverage_decision:
                return coverage_decision
            # Recon/discovery phases run many redundant tools. If the nominally
            # 'required' tool timed out (common behind a WAF) but other tools
            # in the phase still succeeded, the phase produced value — mark it
            # 'partial' and advance instead of hard-blocking.
            other_success = [r for r in mcp_results
                             if r["status"] == "success" and r["tool_name"] not in required_tools]
            if other_success:
                return self._decision(phase_contract["phase_id"], "partial", True,
                                      "required_tool_degraded_other_tools_succeeded", [])
            return self._decision(phase_contract["phase_id"], "blocked", False, reason, [r["tool_name"] for r in required_blocked])
        if any(result["status"] == "failed" for result in mcp_results if result["tool_name"] in required_tools):
            return self._decision(phase_contract["phase_id"], "partial", True, "mcp_execution_failed", [])
        # Phases that tolerate missing evidence still advance as partial.
        _PARTIAL_OK = {"P05", "P06", "P07", "P08", "P09", "P10",
                       "P11", "P15", "P16", "P17", "P18", "P19", "P20", "P21", "P22"}
        if phase_contract["exit_criteria"].get("evidence_required") and not evidence:
            if phase_contract["phase_id"] in _PARTIAL_OK:
                return self._decision(phase_contract["phase_id"], "partial", True, "no_evidence_partial_ok", [])
            return self._decision(phase_contract["phase_id"], "blocked", False, "missing_evidence", [])
        min_strength = phase_contract["exit_criteria"].get("minimum_evidence_strength", "medium")
        strongest = max((EVIDENCE_STRENGTHS.index(ev.get("evidence_strength", "none")) for ev in evidence), default=0)
        if strongest < EVIDENCE_STRENGTHS.index(min_strength):
            return self._decision(phase_contract["phase_id"], "partial", True, "evidence_strength_too_weak", [])
        # COBERTURA POR SKILL (vale p/ TODAS as fases multi-skill): a fase só é
        # 'completed' quando TODAS as required_skills estão completed. Se alguma
        # ficou blocked/partial mas houve execução útil → partial. Se NENHUMA
        # required skill foi coberta → blocked. Sem isso, uma fase virava
        # 'completed' por evidência agregada mesmo com skills required descobertas.
        coverage_decision = self._skill_coverage_decision(phase_contract, skill_coverage)
        if coverage_decision:
            return coverage_decision
        return {
            "phase_id": phase_contract["phase_id"],
            "status": "completed",
            "can_advance": True,
            "reason": "exit_criteria_satisfied",
            "missing_requirements": [],
            "required_retries": [],
            "generated_hypotheses": hypotheses or [],
            "updated_attack_paths": offensive_state.get("attack_paths", []),
        }

    @classmethod
    def _skill_coverage_decision(cls, phase_contract: dict[str, Any], skill_coverage: dict[str, Any] | None) -> dict[str, Any] | None:
        required_skills = phase_contract.get("required_skills") or []
        if not skill_coverage or not required_skills:
            return None
        cov = {s: (skill_coverage.get(s) or {}).get("status") for s in required_skills}
        blocked = [s for s, st in cov.items() if st in (None, "blocked")]
        partial = [s for s, st in cov.items() if st == "partial"]
        completed = [s for s, st in cov.items() if st == "completed"]
        if blocked and not completed and not partial:
            return cls._decision(phase_contract["phase_id"], "blocked", False, "no_required_skill_covered", blocked)
        if blocked or partial:
            return cls._decision(phase_contract["phase_id"], "partial", True, "partial_skill_coverage", blocked + partial)
        return None

    @staticmethod
    def _decision(phase_id: str, status: str, can_advance: bool, reason: str, missing: list[str]) -> dict[str, Any]:
        return {
            "phase_id": phase_id,
            "status": status,
            "can_advance": can_advance,
            "reason": reason,
            "missing_requirements": missing,
            "required_retries": [],
            "generated_hypotheses": [],
            "updated_attack_paths": [],
        }


class HypothesisEngine:
    def update_from_evidence(self, phase_id: str, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        hypotheses: list[dict[str, Any]] = []
        for ev in evidence:
            parsed = ev.get("parsed_json") if isinstance(ev.get("parsed_json"), dict) else {}
            for parameter in parsed.get("parameters", []):
                lower = str(parameter).lower()
                skills = ["skill.idor_object_authorization"]
                title = f"Parameter {parameter} may alter authorization or object access"
                if any(token in lower for token in ["redirect", "callback", "url", "uri"]):
                    skills = ["skill.ssr_basic_discovery", "skill.open_redirect_testing"]
                    title = f"Potential SSRF or redirect behavior in {parameter}"
                hypotheses.append(
                    {
                        "hypothesis_id": stable_id("H", {"phase_id": phase_id, "parameter": parameter}),
                        "title": title,
                        "description": "",
                        "source_phase": phase_id,
                        "source_evidence_ids": [ev["evidence_id"]],
                        "confidence": 0.74,
                        "status": "open",
                        "required_skills": skills,
                        "required_tools": ["curl"],
                        "payload_candidates": [],
                        "test_plan": {},
                        "result": None,
                        "created_at": utc_now(),
                        "updated_at": utc_now(),
                    }
                )
        return hypotheses


class AttackPathEngine:
    def correlate(self, evidence: list[dict[str, Any]], hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
        paths: list[dict[str, Any]] = []
        for ev in evidence:
            parsed = ev.get("parsed_json") if isinstance(ev.get("parsed_json"), dict) else {}
            if parsed.get("exposed_git") or "git" in json.dumps(parsed).lower():
                paths.append(
                    {
                        "attack_path_id": stable_id("AP", {"evidence": ev["evidence_id"], "chain": "exposed_git"}),
                        "title": "Exposed Git to Credential Reuse",
                        "status": "candidate",
                        "confidence": 0.82,
                        "steps": [{"step": 1, "description": "Exposed .git found", "evidence_id": ev["evidence_id"]}],
                        "required_conditions": ["credentials_present", "authenticated_access_allowed"],
                        "impact": "",
                        "next_actions": ["extract controlled test credential candidates", "request human review before credential testing"],
                    }
                )
        return paths


class OperationLearningEngine:
    def learn(self, phase_id: str, tool_plan: dict[str, Any], mcp_results: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> dict[str, Any]:
        effective_skills = sorted({
            str(ev.get("skill_id") or "")
            for ev in evidence
            if ev.get("evidence_strength") in {"medium", "strong", "conclusive"} and ev.get("skill_id")
        })
        return {
            "lesson_id": stable_id("TL", {"phase": phase_id, "tool_plan": tool_plan.get("tool_plan_id")}),
            "phase_id": phase_id,
            "skills_effective": effective_skills,
            "tools_effective": [res["tool_name"] for res in mcp_results if res.get("status") == "success"],
            "tool_errors": [res for res in mcp_results if res.get("status") != "success"],
            "created_at": utc_now(),
        }


class AdaptiveRetryEngine:
    def plan_retry(self, reason: str, previous_attempt: dict[str, Any], retry_count: int = 0) -> dict[str, Any]:
        changes = {
            "403": "reduced_rate_and_changed_headers",
            "waf": "changed_headers_and_payload_encoding",
            "timeout": "increased_timeout_and_reduced_rate",
            "parser": "fallback_parser_and_raw_evidence_review",
            "inconclusive": "changed_payload_family_and_added_negative_control",
        }
        key = next((token for token in changes if token in reason.lower()), "inconclusive")
        new_attempt = dict(previous_attempt)
        new_attempt["retry_count"] = retry_count + 1
        new_attempt["strategy_change"] = changes[key]
        if "timeout" in changes[key]:
            new_attempt["timeout"] = int(previous_attempt.get("timeout") or 120) * 2
        if "rate" in changes[key]:
            new_attempt["rate_limit"] = max(1, int(previous_attempt.get("rate_limit") or 50) // 2)
        if "headers" in changes[key]:
            new_attempt["headers"] = {"User-Agent": "authorized-security-validation"}
        return {
            "retry_id": stable_id("R", {"reason": reason, "previous": previous_attempt, "retry_count": retry_count}),
            "reason": reason,
            "previous_attempt": previous_attempt,
            "change_applied": changes[key],
            "new_attempt": new_attempt,
            "result": "",
        }


class ReportBuilder:
    def build(self, campaign: dict[str, Any]) -> dict[str, Any]:
        ledgers = campaign.get("phase_ledger", [])
        return {
            "title": "Offensive Campaign Report",
            "executive_summary": {
                "target": campaign.get("target"),
                "execution_mode": campaign.get("execution_mode"),
                "completed": len([l for l in ledgers if l.get("status") == "completed"]),
                "partial": len([l for l in ledgers if l.get("status") == "partial"]),
                "blocked": len([l for l in ledgers if l.get("status") == "blocked"]),
            },
            "offensive_campaign_timeline": [
                {
                    "phase_id": ledger.get("phase_id"),
                    "status": ledger.get("status"),
                    "skills": ledger.get("selected_skills", []),
                    "mcp_executions": ledger.get("mcp_executions", []),
                    "evidence_ids": ledger.get("evidence_ids", []),
                }
                for ledger in ledgers
            ],
            "hypotheses": campaign.get("offensive_state", {}).get("open_hypotheses", []),
            "attack_paths": campaign.get("offensive_state", {}).get("attack_paths", []),
            "findings_validated": campaign.get("findings_validated", []),
            "findings_inconclusive": campaign.get("findings_inconclusive", []),
            "coverage_gaps": [ledger for ledger in ledgers if ledger.get("status") in {"partial", "blocked", "failed"}],
        }


class OffensiveSkillRuntime:
    def __init__(
        self,
        registry: SkillRegistry | None = None,
        rag: SkillRagIndex | None = None,
        compiler: SkillToToolPlanCompiler | None = None,
        executor: MCPToolExecutor | None = None,
        validator: PhaseValidator | None = None,
    ) -> None:
        self.registry = registry or SkillRegistry()
        self.rag = rag or SkillRagIndex(self.registry)
        self.compiler = compiler or SkillToToolPlanCompiler()
        self.executor = executor or MCPToolExecutor()
        self.validator = validator or PhaseValidator()
        self.collector = EvidenceCollector()
        self.hypotheses = HypothesisEngine()
        self.attack_paths = AttackPathEngine()
        self.learning = OperationLearningEngine()

    def run_phase(
        self,
        phase_id: str,
        target: str,
        scope: Scope,
        execution_mode: str,
        offensive_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        state = offensive_state or create_offensive_state(target)
        contract = PHASE_CONTRACTS[phase_id]
        retrieved = self.rag.retrieve(
            f"{contract['name']} {target} {' '.join(contract['required_skills'])}",
            filters={"phase_id": phase_id, "execution_mode": execution_mode, "status": "approved"},
            top_k=max(5, len(contract.get("required_skills") or [])),
        )
        selected_skills = [skill["skill_id"] for skill in retrieved["retrieved_skills"]]
        registry_skills = {skill["skill_id"]: skill for skill in self.registry.approved_for_phase(phase_id, execution_mode)}
        # Composite phase execution: every approved skill for the phase gets a
        # tool plan. Dedup uses the rich execution_key, not just tool_name, so a
        # curl/ffuf/nuclei run for one skill cannot create false coverage for
        # another skill that needs different arguments or reasoning.
        ordered_sids = list(dict.fromkeys(
            [sid for sid in selected_skills if sid in registry_skills]
            + [sid for sid in (contract.get("required_skills") or []) if sid in registry_skills]
            + list(registry_skills.keys())
        ))
        if not ordered_sids:
            ledger = create_phase_ledger(contract)
            ledger.update(status="blocked", blocking_reason="no_approved_skill_resolved", retrieved_rag_context=retrieved["retrieved_skills"])
            return {"phase_ledger": ledger, "offensive_state": state, "validator_decision": {"status": "blocked", "can_advance": False}}

        mcp_results: list[dict[str, Any]] = []
        executed_tool_keys: set[str] = set()
        ran_skills: list[str] = []
        tool_plans: list[dict[str, Any]] = []
        required_skill_set = set(contract.get("required_skills") or [])
        for sid in ordered_sids:
            skill = registry_skills[sid]
            try:
                tp = self.compiler.compile(skill, contract, target, scope, execution_mode, mcp_available=self.executor.available)
            except Exception:  # noqa: BLE001 — skill que falha quality gate é pulada, não derruba a fase
                continue
            if not tp.get("tools") and sid not in required_skill_set:
                continue
            tool_plans.append(tp)
            ran_skills.append(sid)
            new_tools: list[dict[str, Any]] = []
            for t in tp["tools"]:
                execution_key = str(t.get("execution_key") or "")
                if execution_key in executed_tool_keys:
                    continue
                executed_tool_keys.add(execution_key)
                new_tools.append(t)
            if not new_tools:
                continue
            mcp_results.extend(self.executor.execute({**tp, "tools": new_tools}, target))
        if not tool_plans:
            ledger = create_phase_ledger(contract)
            ledger.update(status="blocked", blocking_reason="no_skill_compiled", retrieved_rag_context=retrieved["retrieved_skills"])
            return {"phase_ledger": ledger, "offensive_state": state, "validator_decision": {"status": "blocked", "can_advance": False}}

        # Combined tool plan for validator/ledger: union by execution_key.
        _combined_tools: list[dict[str, Any]] = []
        _seen_tk: set[str] = set()
        for tp in tool_plans:
            for t in tp["tools"]:
                key = str(t.get("execution_key") or tool_execution_key(tp["phase_id"], tp["skill_id"], t))
                if key not in _seen_tk:
                    _seen_tk.add(key); _combined_tools.append(t)
        tool_plan = {**tool_plans[0], "tools": _combined_tools}

        # Skill coverage is attributed by execution_key. This keeps coverage
        # honest for every phase, including phases with multiple skills.
        _ok = {"success", "done"}
        _status_by_key = {str(r.get("execution_key") or ""): r.get("status") for r in mcp_results}
        _bindings = PHASE_TOOL_BINDINGS.get(phase_id, {})

        def _counts_for(_sid: str, _tool: dict[str, Any]) -> bool:
            # tool com binding só conta cobertura p/ skills ligadas (anti-FP):
            # bl-test não prova csrf/idor mesmo se estiver no plano por herança.
            b = _bindings.get(str(_tool.get("tool_name") or ""))
            return b is None or _sid in b

        skill_coverage: dict[str, Any] = {}
        for sid, tp in zip(ran_skills, tool_plans):
            allt = [t for t in tp["tools"] if _counts_for(sid, t)]
            req = [t for t in tp["tools"] if t.get("required") and _counts_for(sid, t)]
            attempted_items = [t for t in allt if str(t.get("execution_key") or "") in _status_by_key]
            succ_items = [t for t in attempted_items if _status_by_key.get(str(t.get("execution_key") or "")) in _ok]
            fail_items = [t for t in attempted_items if _status_by_key.get(str(t.get("execution_key") or "")) not in _ok]
            req_ok = all(_status_by_key.get(str(t.get("execution_key") or "")) in _ok for t in req) if req else bool(succ_items)
            s_status = "completed" if (succ_items and req_ok) else ("partial" if succ_items else "blocked")
            attempted = [str(t.get("tool_name") or "") for t in attempted_items]
            succ = [str(t.get("tool_name") or "") for t in succ_items]
            fail = [str(t.get("tool_name") or "") for t in fail_items]
            skill_coverage[sid] = {
                "status": s_status,
                "tools_required": [str(t.get("tool_name") or "") for t in req],
                "tools_attempted": attempted,
                "tools_success": succ,
                "tools_failed": fail,
                "tool_execution_keys_required": [str(t.get("execution_key") or "") for t in req],
                "tool_execution_keys_attempted": [str(t.get("execution_key") or "") for t in attempted_items],
                "tool_execution_keys_success": [str(t.get("execution_key") or "") for t in succ_items],
                "tool_execution_keys_failed": [str(t.get("execution_key") or "") for t in fail_items],
                "evidence_ids": [],
                "blocking_reason": None if s_status != "blocked" else "tools_not_executed_or_blocked",
            }
        # required skills do contrato SEMPRE aparecem no plano — uma ausente/reprovada
        # vira blocked com motivo (não some silenciosamente = não mascara cobertura).
        required_sids = list(contract.get("required_skills") or [])
        skills_planned = list(dict.fromkeys(required_sids + list(ordered_sids)))
        for sid in required_sids:
            if sid not in skill_coverage:
                reason = ("required_skill_quality_gate_failed" if sid in registry_skills
                          else "required_skill_not_available")
                skill_coverage[sid] = {
                    "status": "blocked", "tools_required": [], "tools_attempted": [],
                    "tools_success": [], "tools_failed": [],
                    "tool_execution_keys_required": [],
                    "tool_execution_keys_attempted": [],
                    "tool_execution_keys_success": [],
                    "tool_execution_keys_failed": [],
                    "evidence_ids": [],
                    "blocking_reason": reason,
                }
        skills_success = [s for s, c in skill_coverage.items() if c["status"] == "completed"]
        skills_partial = [s for s, c in skill_coverage.items() if c["status"] == "partial"]
        skills_blocked = [s for s, c in skill_coverage.items() if c["status"] == "blocked"]

        evidence = [
            self.collector.create(result, parsed_json=result.get("parsed_result"))
            for result in mcp_results
            if result.get("status") == "success"
        ]
        # atribui evidência por skill (cada evidência carrega skill_id da execução)
        for ev in evidence:
            _sid = ev.get("skill_id")
            if _sid in skill_coverage:
                skill_coverage[_sid]["evidence_ids"].append(ev["evidence_id"])
        generated_hypotheses = self.hypotheses.update_from_evidence(phase_id, evidence)
        attack_paths = self.attack_paths.correlate(evidence, generated_hypotheses)
        state["current_phase"] = phase_id
        state["open_hypotheses"].extend(generated_hypotheses)
        state["attack_paths"].extend(attack_paths)
        state["next_objectives"] = [item["title"] for item in generated_hypotheses[:3]]
        decision = self.validator.validate(contract, tool_plan, mcp_results, evidence, generated_hypotheses, state, skill_coverage=skill_coverage)
        lesson = self.learning.learn(phase_id, tool_plan, mcp_results, evidence)
        ledger = create_phase_ledger(contract)
        ledger.update(
            status=decision["status"],
            finished_at=utc_now(),
            selected_skills=ran_skills,
            skills_planned=skills_planned,
            skills_attempted=ran_skills,
            skills_success=skills_success,
            skills_partial=skills_partial,
            skills_blocked=skills_blocked,
            skill_coverage=skill_coverage,
            retrieved_rag_context=retrieved["retrieved_skills"],
            tools_required=contract["required_tools"],
            tools_attempted=[result["tool_name"] for result in mcp_results],
            tools_success=[result["tool_name"] for result in mcp_results if result["status"] == "success"],
            tools_failed=[result["tool_name"] for result in mcp_results if result["status"] not in {"success"}],
            tool_execution_keys_attempted=[str(result.get("execution_key") or "") for result in mcp_results],
            tool_execution_keys_success=[str(result.get("execution_key") or "") for result in mcp_results if result["status"] == "success"],
            tool_execution_keys_failed=[str(result.get("execution_key") or "") for result in mcp_results if result["status"] not in {"success"}],
            mcp_executions=[result["mcp_execution_id"] for result in mcp_results],
            evidence_ids=[ev["evidence_id"] for ev in evidence],
            hypotheses_created=[h["hypothesis_id"] for h in generated_hypotheses],
            attack_paths_updated=[ap["attack_path_id"] for ap in attack_paths],
            validation_result=decision,
            blocking_reason=None if decision["status"] != "blocked" else decision["reason"],
        )
        return {
            "phase_ledger": ledger,
            "offensive_state": state,
            "skill_plan": {
                "phase_id": phase_id,
                "target": target,
                "selected_skills": ran_skills,
                "skill_plan": {
                    "objective": tool_plan["objective"],
                    "offensive_questions": [],
                    "tool_requirements": [
                        {
                            "tool": tool["tool_name"],
                            "profile": tool.get("profile"),
                            "required": tool["required"],
                            "reason": tool["reason"],
                            "execution_key": tool.get("execution_key"),
                            "execution_backend": tool.get("execution_backend"),
                        }
                        for tool in tool_plan["tools"]
                    ],
                    "payload_strategy": {},
                    "retry_strategy": tool_plan["retry_plan"],
                    "expected_evidence": [e for tool in tool_plan["tools"] for e in tool["expected_evidence"]],
                },
            },
            "tool_plan": tool_plan,
            "mcp_results": mcp_results,
            "evidence": evidence,
            "validator_decision": decision,
            "operation_lesson": lesson,
        }


def create_phase_ledger(contract: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase_id": contract["phase_id"],
        "phase_name": contract["name"],
        "status": "running",
        "started_at": utc_now(),
        "finished_at": "",
        "selected_skills": [],
        "skills_planned": [],
        "skills_attempted": [],
        "skills_success": [],
        "skills_partial": [],
        "skills_blocked": [],
        "skill_coverage": {},
        "retrieved_rag_context": [],
        "tools_required": [],
        "tools_attempted": [],
        "tools_success": [],
        "tools_failed": [],
        "tool_execution_keys_attempted": [],
        "tool_execution_keys_success": [],
        "tool_execution_keys_failed": [],
        "mcp_executions": [],
        "evidence_ids": [],
        "hypotheses_created": [],
        "hypotheses_tested": [],
        "attack_paths_updated": [],
        "retry_count": 0,
        "fallback_used": False,
        "validation_result": {},
        "skip_reason": None,
        "blocking_reason": None,
    }


def create_offensive_state(target: str, campaign_id: str | None = None) -> dict[str, Any]:
    return {
        "campaign_id": campaign_id or str(uuid.uuid4()),
        "target": target,
        "current_phase": "P01",
        "current_stage": "scope",
        "known_assets": [],
        "known_endpoints": [],
        "known_parameters": [],
        "technologies": [],
        "credentials": [],
        "sessions": [],
        "tokens": [],
        "interesting_files": [],
        "waf_fingerprints": [],
        "open_hypotheses": [],
        "validated_hypotheses": [],
        "discarded_hypotheses": [],
        "attack_paths": [],
        "compromised_assets": [],
        "next_objectives": [],
    }


def create_operation_event(
    event_type: str,
    campaign_id: str,
    scan_job_id: str,
    phase_id: str = "",
    skill_id: str = "",
    status: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "campaign_id": campaign_id,
        "scan_job_id": scan_job_id,
        "phase_id": phase_id,
        "skill_id": skill_id,
        "event_type": event_type,
        "timestamp": utc_now(),
        "status": status,
        "details": details or {},
    }


def create_human_review_item(item_type: str, reason: str, risk: str, related_skill_id: str = "", evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return {
        "review_item_id": stable_id("HR", {"type": item_type, "reason": reason, "skill": related_skill_id}),
        "type": item_type,
        "status": "pending",
        "reason": reason,
        "risk": risk,
        "related_skill_id": related_skill_id,
        "related_evidence_ids": evidence_ids or [],
        "created_at": utc_now(),
    }


def create_report_learning_profile(report_id: str, source_url: str, text: str) -> dict[str, Any]:
    steps_match = re.search(r"(steps to reproduce|reproduction steps|steps)(.*?)(impact|summary|$)", text, re.I | re.S)
    steps_text = steps_match.group(2).strip() if steps_match else ""
    steps = [line.strip(" -\t") for line in steps_text.splitlines() if line.strip(" -\t")]
    statements = [
        {
            "statement": step,
            "type": "fact",
            "confidence": 0.9,
            "source_section": "steps_to_reproduce",
            "source_report_id": report_id,
        }
        for step in steps
    ]
    vulnerability_class = "unknown"
    lowered = text.lower()
    if "idor" in lowered or "object" in lowered and "authorization" in lowered:
        vulnerability_class = "idor"
    elif "sql injection" in lowered or "sqli" in lowered:
        vulnerability_class = "sqli"
    elif "xss" in lowered:
        vulnerability_class = "xss"
    return {
        "report_id": report_id,
        "source_url": source_url,
        "vulnerability_class": vulnerability_class,
        "affected_asset_type": "unknown",
        "researcher_goal": "",
        "discovery_method": "",
        "attack_steps": steps,
        "validation_steps": steps,
        "impact_demonstration": "",
        "technical_signals": statements,
        "preconditions": [],
        "payload_families": [],
        "tool_candidates": ["curl"],
        "evidence_model": ["request_response_pair"],
        "generalized_technique": "",
        "skill_candidates": [],
        "limitations": [],
        "unknowns": [] if steps else ["steps_to_reproduce_not_found"],
    }
