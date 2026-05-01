"""Autonomous agent registry with skill validation and tool selection.

Each agent is a specialized, independent entity that can validate its own
prerequisites, select tools, and report execution results.
"""
from __future__ import annotations

from typing import Any
from datetime import datetime


class AgentManifest:
    """Defines an autonomous agent with skills, tools, and validation rules."""

    def __init__(
        self,
        agent_id: str,
        name: str,
        category: str,
        description: str,
        tools: list[str],
        required_skills: list[str],
        when_to_activate: str,
        phase_ids: list[str],
        priority: int = 5,
        timeout_seconds: int = 300,
    ):
        self.agent_id = agent_id
        self.name = name
        self.category = category
        self.description = description
        self.tools = tools
        self.required_skills = required_skills
        self.when_to_activate = when_to_activate
        self.phase_ids = phase_ids
        self.priority = priority
        self.timeout_seconds = timeout_seconds
        self.created_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "tools": self.tools,
            "required_skills": self.required_skills,
            "when_to_activate": self.when_to_activate,
            "phase_ids": self.phase_ids,
            "priority": self.priority,
            "timeout_seconds": self.timeout_seconds,
        }


# ─────────────────────────────────────────────────────────────────────────────
# RECON AGENTS (P01-P06: Subdomain, Port, Web, Fingerprint, WAF)
# ─────────────────────────────────────────────────────────────────────────────

AGENT_RECON_SUBDOMAIN = AgentManifest(
    agent_id="agent-recon-subdomain",
    name="Subdomain Enumeration Agent",
    category="reconnaissance",
    description="Passive + active subdomain enumeration, DNS validation, surface expansion.",
    tools=["subfinder", "amass", "massdns", "dnsx", "shuffledns", "assetfinder", "alterx"],
    required_skills=["passive_dns", "active_dns", "dns_validation"],
    when_to_activate="Begin every recon pass; expand authorized domain scope cheaply.",
    phase_ids=["P01"],
    priority=9,
    timeout_seconds=600,
)

AGENT_RECON_PORT = AgentManifest(
    agent_id="agent-recon-port",
    name="Port & Service Agent",
    category="reconnaissance",
    description="High-throughput port scanning, service banner grabbing, fingerprinting.",
    tools=["naabu", "nmap", "masscan", "httpx"],
    required_skills=["port_scan", "service_detection", "banner_grab"],
    when_to_activate="After subdomain enum; map exposed services and protocols.",
    phase_ids=["P02"],
    priority=9,
    timeout_seconds=900,
)

AGENT_RECON_WEB = AgentManifest(
    agent_id="agent-recon-web",
    name="Web Content & Parameter Agent",
    category="reconnaissance",
    description="Web crawling, JS extraction, parameter discovery, endpoint mapping.",
    tools=["katana", "hakrawler", "gau", "waybackurls", "gospider", "arjun", "paramspider", "ffuf"],
    required_skills=["web_crawl", "js_analysis", "parameter_discovery"],
    when_to_activate="Map web surface, extract JavaScript, find hidden endpoints.",
    phase_ids=["P03", "P04"],
    priority=8,
    timeout_seconds=900,
)

AGENT_RECON_FINGERPRINT = AgentManifest(
    agent_id="agent-recon-fingerprint",
    name="HTTP/TLS Fingerprint Agent",
    category="reconnaissance",
    description="HTTP headers, TLS ciphers, WAF detection, tech stack identification.",
    tools=["httpx", "whatweb", "nikto", "curl-headers", "sslscan", "wafw00f"],
    required_skills=["http_fingerprint", "tls_analysis", "waf_detection"],
    when_to_activate="Characterize tech stack and defense posture.",
    phase_ids=["P05", "P06"],
    priority=8,
    timeout_seconds=600,
)

# ─────────────────────────────────────────────────────────────────────────────
# OSINT AGENTS (P07-P10: Leaks, Email, Takeover, Cloud)
# ─────────────────────────────────────────────────────────────────────────────

AGENT_OSINT_EXPOSURE = AgentManifest(
    agent_id="agent-osint-exposure",
    name="Exposure Intelligence Agent",
    category="osint",
    description="Shodan queries, public leaks, email enumeration, credential exposure.",
    tools=["shodan-cli", "theHarvester", "h8mail", "trufflehog", "gitleaks"],
    required_skills=["osint_search", "leak_intel", "credential_hunting"],
    when_to_activate="Discover publicly exposed assets and leaked credentials.",
    phase_ids=["P07", "P08", "P21"],
    priority=8,
    timeout_seconds=600,
)

AGENT_OSINT_TAKEOVER = AgentManifest(
    agent_id="agent-osint-takeover",
    name="Subdomain Takeover Agent",
    category="osint",
    description="CNAME dangling detection, subdomain takeover validation.",
    tools=["subjack", "nuclei"],
    required_skills=["dns_cname_check", "takeover_detection"],
    when_to_activate="Validate reachable but unowned subdomains after enum.",
    phase_ids=["P09"],
    priority=7,
    timeout_seconds=300,
)

AGENT_OSINT_CLOUD = AgentManifest(
    agent_id="agent-osint-cloud",
    name="Cloud Asset Exposure Agent",
    category="osint",
    description="S3 bucket, GCP, Azure misconfiguration detection, public cloud storage.",
    tools=["nuclei", "shodan-cli", "trufflehog"],
    required_skills=["cloud_storage_enum", "cloud_misconfiguration"],
    when_to_activate="Hunt misconfigured cloud storage and public buckets.",
    phase_ids=["P10"],
    priority=7,
    timeout_seconds=400,
)

# ─────────────────────────────────────────────────────────────────────────────
# VULN AGENTS (P11-P20: CVE, Injection, SSRF, Auth, API, CMS, etc.)
# ─────────────────────────────────────────────────────────────────────────────

AGENT_VULN_CVE = AgentManifest(
    agent_id="agent-vuln-cve",
    name="CVE & Misconfiguration Agent",
    category="vulnerability",
    description="Known vulnerability scanning via Nuclei, version-based matching.",
    tools=["nuclei", "nmap-vulscan"],
    required_skills=["cve_matching", "nuclei_template_selection"],
    when_to_activate="Run after fingerprinting to catch known issues quickly.",
    phase_ids=["P11"],
    priority=9,
    timeout_seconds=900,
)

AGENT_VULN_INJECTION = AgentManifest(
    agent_id="agent-vuln-injection",
    name="Web Injection Agent",
    category="vulnerability",
    description="SQLi, XSS, SSTI, XXE validation with reproducible proof.",
    tools=["sqlmap", "dalfox", "wapiti", "burp-cli", "nikto"],
    required_skills=["injection_testing", "payload_crafting", "result_validation"],
    when_to_activate="Test discovered parameters for injection flaws.",
    phase_ids=["P12"],
    priority=9,
    timeout_seconds=1200,
)

AGENT_VULN_SSRF = AgentManifest(
    agent_id="agent-vuln-ssrf",
    name="SSRF & Open Redirect Agent",
    category="vulnerability",
    description="Server-side request forgery, open redirect detection, OOB interaction.",
    tools=["nuclei", "burp-cli", "interactsh-client"],
    required_skills=["ssrf_detection", "oob_callback", "redirect_validation"],
    when_to_activate="Test URL-based parameters for SSRF/redirect flaws.",
    phase_ids=["P13"],
    priority=8,
    timeout_seconds=600,
)

AGENT_VULN_AUTH = AgentManifest(
    agent_id="agent-vuln-auth",
    name="Authentication Bypass Agent",
    category="vulnerability",
    description="Credential brute-force, JWT attacks, OAuth bypass, MFA weaknesses.",
    tools=["hydra", "jwt_tool", "nuclei", "burp-cli"],
    required_skills=["auth_testing", "jwt_analysis", "brute_force_tuning"],
    when_to_activate="Attack login endpoints, tokens, and session management.",
    phase_ids=["P14"],
    priority=8,
    timeout_seconds=1800,
)

AGENT_VULN_DIRECTORY = AgentManifest(
    agent_id="agent-vuln-directory",
    name="Directory Enumeration Agent",
    category="vulnerability",
    description="Hidden directory/file discovery, backup files, admin panels.",
    tools=["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    required_skills=["path_enumeration", "wordlist_selection", "rate_limiting"],
    when_to_activate="Enumerate web directories on each discovered host.",
    phase_ids=["P15"],
    priority=8,
    timeout_seconds=900,
)

AGENT_VULN_API = AgentManifest(
    agent_id="agent-vuln-api",
    name="API Security Agent",
    category="vulnerability",
    description="REST/GraphQL/API endpoint testing, rate limit evasion, schema mapping.",
    tools=["nuclei", "burp-cli", "arjun", "wapiti"],
    required_skills=["api_testing", "endpoint_discovery", "rate_limit_bypass"],
    when_to_activate="Test API endpoints for common flaws and authentication gaps.",
    phase_ids=["P16"],
    priority=8,
    timeout_seconds=900,
)

AGENT_VULN_UPLOAD = AgentManifest(
    agent_id="agent-vuln-upload",
    name="Upload & WebShell Agent",
    category="vulnerability",
    description="File upload bypass, webshell injection, execution validation.",
    tools=["nuclei", "burp-cli"],
    required_skills=["upload_bypass", "webshell_testing"],
    when_to_activate="Test file upload functionality for shell injection.",
    phase_ids=["P17"],
    priority=7,
    timeout_seconds=600,
)

AGENT_VULN_SSL = AgentManifest(
    agent_id="agent-vuln-ssl",
    name="SSL/TLS Audit Agent",
    category="vulnerability",
    description="Cipher suite analysis, certificate validation, protocol weakness detection.",
    tools=["sslscan", "nmap", "testssl"],
    required_skills=["ssl_analysis", "cipher_grading", "cert_validation"],
    when_to_activate="Audit TLS configuration and certificate chain.",
    phase_ids=["P18"],
    priority=7,
    timeout_seconds=600,
)

AGENT_VULN_IDOR = AgentManifest(
    agent_id="agent-vuln-idor",
    name="IDOR & Access Control Agent",
    category="vulnerability",
    description="Insecure direct object reference, authorization bypass testing.",
    tools=["burp-cli", "nuclei"],
    required_skills=["idor_detection", "authorization_testing"],
    when_to_activate="Test ID/resource access controls after endpoint discovery.",
    phase_ids=["P19"],
    priority=8,
    timeout_seconds=600,
)

AGENT_VULN_CMS = AgentManifest(
    agent_id="agent-vuln-cms",
    name="CMS-Specific Agent",
    category="vulnerability",
    description="WordPress, Joomla, Drupal vulnerability scanning and enumeration.",
    tools=["wpscan", "nuclei", "nikto"],
    required_skills=["cms_detection", "plugin_enumeration", "cms_vuln_matching"],
    when_to_activate="Scan detected CMS platforms for known vulnerabilities.",
    phase_ids=["P20"],
    priority=7,
    timeout_seconds=900,
)

# ─────────────────────────────────────────────────────────────────────────────
# CODE/SUPPLY CHAIN AGENTS (P21-P22)
# ─────────────────────────────────────────────────────────────────────────────

AGENT_CODE_SECRETS = AgentManifest(
    agent_id="agent-code-secrets",
    name="Secrets & Credential Exposure Agent",
    category="code",
    description="GitHub secret scanning, credential patterns, API key exposure.",
    tools=["trufflehog", "gitleaks", "semgrep"],
    required_skills=["secret_detection", "credential_pattern_matching"],
    when_to_activate="Hunt exposed credentials in git history and code repos.",
    phase_ids=["P21"],
    priority=8,
    timeout_seconds=600,
)

AGENT_CODE_SUPPLY_CHAIN = AgentManifest(
    agent_id="agent-code-supply-chain",
    name="Supply Chain & Dependencies Agent",
    category="code",
    description="Dependency scanning, CVE matching, SBOM generation.",
    tools=["retire", "trivy", "semgrep", "bandit"],
    required_skills=["dependency_scanning", "cve_matching", "sbom_generation"],
    when_to_activate="Scan application dependencies for known vulnerabilities.",
    phase_ids=["P22"],
    priority=7,
    timeout_seconds=900,
)

# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

AGENT_REGISTRY: list[AgentManifest] = [
    # Recon
    AGENT_RECON_SUBDOMAIN,
    AGENT_RECON_PORT,
    AGENT_RECON_WEB,
    AGENT_RECON_FINGERPRINT,
    # OSINT
    AGENT_OSINT_EXPOSURE,
    AGENT_OSINT_TAKEOVER,
    AGENT_OSINT_CLOUD,
    # Vulnerability
    AGENT_VULN_CVE,
    AGENT_VULN_INJECTION,
    AGENT_VULN_SSRF,
    AGENT_VULN_AUTH,
    AGENT_VULN_DIRECTORY,
    AGENT_VULN_API,
    AGENT_VULN_UPLOAD,
    AGENT_VULN_SSL,
    AGENT_VULN_IDOR,
    AGENT_VULN_CMS,
    # Code/Supply Chain
    AGENT_CODE_SECRETS,
    AGENT_CODE_SUPPLY_CHAIN,
]


def get_agent_by_id(agent_id: str) -> AgentManifest | None:
    for agent in AGENT_REGISTRY:
        if agent.agent_id == agent_id:
            return agent
    return None


def get_agents_for_phase(phase_id: str) -> list[AgentManifest]:
    """Return all agents that handle a specific phase."""
    return [agent for agent in AGENT_REGISTRY if phase_id in agent.phase_ids]


def get_agents_by_category(category: str) -> list[AgentManifest]:
    """Return all agents in a specific category."""
    return [agent for agent in AGENT_REGISTRY if agent.category == category]
