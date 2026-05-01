"""Rich, agent-readable catalog of pentest tools.

Each entry teaches the autonomous agent:
  - what the tool does (description)
  - when to use it (when_to_use, prerequisites)
  - inputs/outputs (so the agent can plan I/O wiring)
  - category, phase, weight
The catalog is injected into the supervisor prompt so the agent can pick
tools by role rather than name-matching.
"""
from __future__ import annotations

import shutil
from typing import Any

# (binary_name, …) — list of CLI binaries that signal the tool is installed.
# If multiple alternatives exist, any present is enough.
_TOOL_BINARIES: dict[str, list[str]] = {
    "subfinder": ["subfinder"],
    "amass": ["amass"],
    "massdns": ["massdns"],
    "dnsx": ["dnsx"],
    "shuffledns": ["shuffledns"],
    "assetfinder": ["assetfinder"],
    "alterx": ["alterx"],
    "naabu": ["naabu"],
    "nmap": ["nmap"],
    "masscan": ["masscan"],
    "httpx": ["httpx"],
    "whatweb": ["whatweb"],
    "wafw00f": ["wafw00f"],
    "curl-headers": ["curl"],
    "sslscan": ["sslscan"],
    "testssl": ["testssl", "testssl.sh"],
    "katana": ["katana"],
    "hakrawler": ["hakrawler"],
    "gau": ["gau"],
    "waybackurls": ["waybackurls"],
    "gospider": ["gospider"],
    "arjun": ["arjun"],
    "paramspider": ["paramspider"],
    "ffuf": ["ffuf"],
    "gobuster": ["gobuster"],
    "feroxbuster": ["feroxbuster"],
    "dirsearch": ["dirsearch"],
    "shodan-cli": ["shodan"],
    "theHarvester": ["theHarvester", "theharvester"],
    "h8mail": ["h8mail"],
    "subjack": ["subjack"],
    "metagoofil": ["metagoofil"],
    "nuclei": ["nuclei"],
    "nmap-vulscan": ["nmap"],
    "nikto": ["nikto"],
    "wapiti": ["wapiti"],
    "wfuzz": ["wfuzz"],
    "burp-cli": ["burp-cli"],
    "sqlmap": ["sqlmap"],
    "dalfox": ["dalfox"],
    "wpscan": ["wpscan"],
    "interactsh-client": ["interactsh-client"],
    "hydra": ["hydra"],
    "medusa": ["medusa"],
    "jwt_tool": ["jwt_tool"],
    "crackmapexec": ["crackmapexec", "netexec", "nxc"],
    "impacket": ["impacket-smbexec", "impacket-secretsdump"],
    "evilwinrm": ["evil-winrm"],
    "semgrep": ["semgrep"],
    "bandit": ["bandit"],
    "trufflehog": ["trufflehog"],
    "gitleaks": ["gitleaks"],
    "retire": ["retire"],
    "trivy": ["trivy"],
    "eslint": ["eslint"],
    "jshint": ["jshint"],
    "ast-grep": ["ast-grep"],
    "js-snooper": ["js-snooper"],
    "jsniper": ["jsniper"],
}


# Rich tool catalog. Keep entries narrative — these go straight into the agent prompt.
TOOL_CATALOG: dict[str, dict[str, Any]] = {
    # ── RECON / DNS ─────────────────────────────────────────────────────────
    "subfinder": {
        "category": "recon", "phase": "P01",
        "description": "Passive subdomain enumeration via 30+ data sources (CT logs, DNS-DB).",
        "when_to_use": "Begin every recon to expand authorized scope; cheap, no traffic to target.",
        "inputs": "domain", "outputs": "subdomain list",
        "prerequisites": "none",
    },
    "amass": {
        "category": "recon", "phase": "P01",
        "description": "Active+passive subdomain enumeration with brute force, ASN, and graph DB.",
        "when_to_use": "Deep enum after subfinder when more breadth is needed; takes minutes.",
        "inputs": "domain", "outputs": "subdomain+IP graph",
        "prerequisites": "subfinder run first to seed",
    },
    "massdns": {
        "category": "recon", "phase": "P01",
        "description": "High-throughput DNS resolver — validates which subdomains resolve.",
        "when_to_use": "After subfinder/amass to filter live subdomains; pairs with shuffledns.",
        "inputs": "subdomain list, resolvers.txt", "outputs": "live subdomains",
        "prerequisites": "subdomain list",
    },
    "dnsx": {
        "category": "recon", "phase": "P01",
        "description": "Multi-purpose DNS toolkit (A, AAAA, CNAME, NS, MX, AXFR, wildcard detection).",
        "when_to_use": "Validate live records, detect wildcard DNS, fingerprint nameservers.",
        "inputs": "domain/subdomain list", "outputs": "DNS records JSON",
        "prerequisites": "none",
    },
    "shuffledns": {
        "category": "recon", "phase": "P01",
        "description": "Active subdomain bruteforce with massdns backend + wildcard filtering.",
        "when_to_use": "When passive enum gives little (small org); requires good resolvers.txt.",
        "inputs": "domain, wordlist, resolvers", "outputs": "bruteforced subdomains",
        "prerequisites": "resolvers.txt available",
    },
    "assetfinder": {
        "category": "recon", "phase": "P01",
        "description": "Quick passive subdomain finder (CT logs + Wayback).",
        "when_to_use": "Fast pre-flight; complement subfinder.",
        "inputs": "domain", "outputs": "subdomains",
        "prerequisites": "none",
    },
    "alterx": {
        "category": "recon", "phase": "P01",
        "description": "Pattern-based subdomain permutation generator (e.g. dev-X, X-stage).",
        "when_to_use": "After base enum to discover stealth subdomains by mutating known ones.",
        "inputs": "subdomain seed list", "outputs": "candidate subdomains",
        "prerequisites": "seed list of known subdomains",
    },

    # ── RECON / PORT & TLS ───────────────────────────────────────────────────
    "naabu": {
        "category": "recon", "phase": "P02",
        "description": "Fast TCP SYN/CONNECT scanner with rate limit and exclude lists.",
        "when_to_use": "Pre-screen open ports before launching nmap deep scan.",
        "inputs": "host list, port range", "outputs": "open ports",
        "prerequisites": "live host list (httpx/dnsx)",
    },
    "nmap": {
        "category": "recon", "phase": "P02",
        "description": "Service/version detection, scripting engine (NSE).",
        "when_to_use": "Deep scan on ports surfaced by naabu; or full --top-ports for prod.",
        "inputs": "host:port list", "outputs": "service banners + NSE findings",
        "prerequisites": "open port list",
    },
    "masscan": {
        "category": "recon", "phase": "P02",
        "description": "Internet-scale stateless TCP scanner; fastest port discovery.",
        "when_to_use": "Massive netblocks (>1000 hosts) where naabu would be slow.",
        "inputs": "CIDR + ports", "outputs": "host:port pairs",
        "prerequisites": "raw socket capability",
    },
    "httpx": {
        "category": "recon", "phase": "P02|P05",
        "description": "Fast HTTP/HTTPS prober — status, title, tech, TLS, redirects.",
        "when_to_use": "Right after subdomain enum to find live web targets and fingerprint.",
        "inputs": "host list", "outputs": "live URLs + HTTP metadata",
        "prerequisites": "subdomain list",
    },
    "whatweb": {
        "category": "recon", "phase": "P05",
        "description": "Web technology fingerprint (CMS, frameworks, JS libs, headers).",
        "when_to_use": "After httpx to enrich tech stack for skill selection.",
        "inputs": "URL", "outputs": "tech list",
        "prerequisites": "live URL",
    },
    "curl-headers": {
        "category": "recon", "phase": "P05|P06",
        "description": "HTTP header analysis via curl — inspect security headers, WAF signatures.",
        "when_to_use": "Lightweight header inspection for security posture and WAF fingerprinting.",
        "inputs": "URL", "outputs": "HTTP headers + analysis",
        "prerequisites": "curl installed",
    },
    "wafw00f": {
        "category": "recon", "phase": "P06",
        "description": "Detects 100+ WAFs by signature/headers.",
        "when_to_use": "Before any active scan to choose evasion profile.",
        "inputs": "URL", "outputs": "WAF vendor",
        "prerequisites": "live URL",
    },
    "sslscan": {
        "category": "recon", "phase": "P18",
        "description": "TLS cipher/protocol/cert audit (heartbleed, weak ciphers, expired certs).",
        "when_to_use": "Every HTTPS host; cheap and feeds compliance scoring.",
        "inputs": "host:port", "outputs": "TLS report",
        "prerequisites": "443/HTTPS reachable",
    },
    "testssl": {
        "category": "recon", "phase": "P18",
        "description": "Comprehensive TLS auditor (vulns, ciphers, HSTS, OCSP).",
        "when_to_use": "Deeper than sslscan when compliance/PCI evidence is needed.",
        "inputs": "host:port", "outputs": "JSON TLS report",
        "prerequisites": "HTTPS endpoint",
    },

    # ── RECON / WEB CRAWL ────────────────────────────────────────────────────
    "katana": {
        "category": "recon", "phase": "P03",
        "description": "Headless+passive web crawler with JS parser; finds endpoints/forms.",
        "when_to_use": "Surface endpoints + parameters for injection testing.",
        "inputs": "URL", "outputs": "URL list, JS files",
        "prerequisites": "live URL",
    },
    "hakrawler": {
        "category": "recon", "phase": "P03",
        "description": "Fast Go web crawler; pulls links from JS, robots, sitemaps.",
        "when_to_use": "Quick endpoint discovery; pairs with katana.",
        "inputs": "URL", "outputs": "URL list",
        "prerequisites": "live URL",
    },
    "gau": {
        "category": "recon", "phase": "P03",
        "description": "GetAllUrls — fetches archived URLs from Wayback/CommonCrawl/AlienVault.",
        "when_to_use": "Discover historical endpoints/parameters not visible in current site.",
        "inputs": "domain", "outputs": "historical URLs",
        "prerequisites": "internet egress",
    },
    "waybackurls": {
        "category": "recon", "phase": "P03",
        "description": "Wayback Machine URL extractor (subset of gau).",
        "when_to_use": "Light passive endpoint expansion.",
        "inputs": "domain", "outputs": "URLs",
        "prerequisites": "internet egress",
    },
    "gospider": {
        "category": "recon", "phase": "P03",
        "description": "Web spider with form/sitemap detection; respects robots.",
        "when_to_use": "Crawl + form discovery for fuzzing inputs.",
        "inputs": "URL", "outputs": "URLs + forms",
        "prerequisites": "live URL",
    },
    "arjun": {
        "category": "recon", "phase": "P04",
        "description": "Hidden HTTP parameter discoverer (GET/POST/JSON).",
        "when_to_use": "Before injection scans — many bugs require unknown params.",
        "inputs": "URL, wordlist", "outputs": "valid params",
        "prerequisites": "endpoint accepts requests",
    },
    "paramspider": {
        "category": "recon", "phase": "P04",
        "description": "Mines URLs from Wayback to extract param names.",
        "when_to_use": "Seed arjun with realistic param names.",
        "inputs": "domain", "outputs": "param list",
        "prerequisites": "internet egress",
    },
    "ffuf": {
        "category": "recon", "phase": "P15",
        "description": "Fast HTTP fuzzer for paths, parameters, virtual hosts, headers.",
        "when_to_use": "Directory/file enum; vhost brute; parameter brute.",
        "inputs": "URL, wordlist", "outputs": "found paths",
        "prerequisites": "wordlist",
    },
    "gobuster": {
        "category": "recon", "phase": "P15",
        "description": "Directory/DNS/vhost brute-force with extension filtering.",
        "when_to_use": "Alternative to ffuf when SSL/proxy issues; simpler output.",
        "inputs": "URL, wordlist", "outputs": "found paths",
        "prerequisites": "wordlist",
    },
    "feroxbuster": {
        "category": "recon", "phase": "P15",
        "description": "Recursive content discovery in Rust — fast, follows redirects.",
        "when_to_use": "Deep recursive directory bruteforce.",
        "inputs": "URL, wordlist", "outputs": "found paths",
        "prerequisites": "wordlist",
    },
    "dirsearch": {
        "category": "recon", "phase": "P15",
        "description": "Web path scanner with smart wordlists per technology.",
        "when_to_use": "When tech stack known (whatweb) and tailored wordlist exists.",
        "inputs": "URL", "outputs": "found paths",
        "prerequisites": "live URL",
    },

    # ── OSINT ────────────────────────────────────────────────────────────────
    "shodan-cli": {
        "category": "osint", "phase": "P07|P10",
        "description": "Shodan API client — banners, exposed services, IoT, cloud assets.",
        "when_to_use": "Discover external exposures from internet-wide scans (ICS, RDP, dbs).",
        "inputs": "domain/IP/query", "outputs": "exposed services",
        "prerequisites": "SHODAN_API_KEY",
    },
    "theHarvester": {
        "category": "osint", "phase": "P07|P08",
        "description": "Email/host/employee gathering from public sources (LinkedIn, certs).",
        "when_to_use": "OSINT phase to seed credential testing and SPF/DMARC checks.",
        "inputs": "domain", "outputs": "emails + hosts",
        "prerequisites": "internet egress",
    },
    "h8mail": {
        "category": "osint", "phase": "P07",
        "description": "Email leak hunter (HIBP, Snusbase integration).",
        "when_to_use": "After theHarvester; flag exposed corporate emails for credential reuse.",
        "inputs": "email list", "outputs": "leak matches",
        "prerequisites": "API keys for premium sources (optional)",
    },
    "subjack": {
        "category": "osint", "phase": "P09",
        "description": "Subdomain takeover scanner — detects dangling CNAMEs to abandoned services.",
        "when_to_use": "After subdomain enum to find takeover candidates (S3, Heroku, GitHub).",
        "inputs": "subdomain list", "outputs": "takeover candidates",
        "prerequisites": "subdomain list",
    },
    "metagoofil": {
        "category": "osint", "phase": "P07",
        "description": "Metadata extractor from public docs (PDFs, DOC).",
        "when_to_use": "Find usernames/software versions leaked in public files.",
        "inputs": "domain, file types", "outputs": "metadata",
        "prerequisites": "domain serves docs",
    },

    # ── VULNERABILITY ASSESSMENT ────────────────────────────────────────────
    "nuclei": {
        "category": "vuln", "phase": "P11|P13|P14|P16|P17|P19|P20",
        "description": "Template-driven scanner — 8000+ checks for CVEs, misconfigs, exposures.",
        "when_to_use": "Primary vuln scanner — run on every live URL after recon.",
        "inputs": "URL list, template tags", "outputs": "findings JSON",
        "prerequisites": "live URL list, templates updated",
    },
    "nmap-vulscan": {
        "category": "vuln", "phase": "P11",
        "description": "Nmap NSE script that maps services to known CVEs (vulscan/vulners DBs).",
        "when_to_use": "Network-level CVE matching from banner data.",
        "inputs": "host:port", "outputs": "CVE list",
        "prerequisites": "nmap service detection done",
    },
    "nikto": {
        "category": "vuln", "phase": "P12",
        "description": "Legacy web server scanner (6700+ tests for misconfigs, default files).",
        "when_to_use": "Quick coverage of common web server flaws; complements nuclei.",
        "inputs": "URL", "outputs": "vulnerability list",
        "prerequisites": "live URL",
    },
    "wapiti": {
        "category": "vuln", "phase": "P12|P16",
        "description": "Black-box web scanner — SQLi, XSS, file disclosure, SSRF, XXE.",
        "when_to_use": "Active injection scanning when crawler has built URL map.",
        "inputs": "URL", "outputs": "findings",
        "prerequisites": "katana/hakrawler crawl done",
    },
    "wfuzz": {
        "category": "vuln", "phase": "P15",
        "description": "Web app fuzzer for parameters, headers, paths, methods.",
        "when_to_use": "Custom payload fuzzing where ffuf grammar isn't expressive enough.",
        "inputs": "URL template, wordlist", "outputs": "responses ranked by anomaly",
        "prerequisites": "URL with FUZZ marker",
    },
    "burp-cli": {
        "category": "vuln", "phase": "P12|P13|P14|P16|P17|P19",
        "description": "Burp Pro REST API for crawl + active scan with extended issue rules.",
        "when_to_use": "Authoritative web vuln coverage when Burp Pro is configured.",
        "inputs": "URL", "outputs": "Burp issues JSON",
        "prerequisites": "burp_rest service healthy + license",
    },
    "sqlmap": {
        "category": "vuln", "phase": "P12",
        "description": "Automatic SQL injection + DB takeover (extracts schema, dumps tables).",
        "when_to_use": "When recon flags suspect parameters or arjun finds reflective inputs.",
        "inputs": "URL with params", "outputs": "injection points + DB extracts",
        "prerequisites": "URL with parameter",
    },
    "dalfox": {
        "category": "vuln", "phase": "P12",
        "description": "Modern XSS scanner (DOM, reflected, stored) with payload mutation.",
        "when_to_use": "After parameter discovery (arjun) on dynamic endpoints.",
        "inputs": "URL", "outputs": "XSS findings + PoC",
        "prerequisites": "live URL",
    },
    "wpscan": {
        "category": "vuln", "phase": "P20",
        "description": "WordPress scanner — plugins, themes, users, weak auth, known CVEs.",
        "when_to_use": "Only when whatweb identifies WordPress.",
        "inputs": "WP URL", "outputs": "WP findings",
        "prerequisites": "WP-DETECTED, WPSCAN_API_TOKEN (for CVE intel)",
    },
    "interactsh-client": {
        "category": "vuln", "phase": "P13",
        "description": "OOB interaction server — proves blind SSRF/RCE/XSS via DNS callbacks.",
        "when_to_use": "Validate blind vulnerabilities found by nuclei/burp.",
        "inputs": "registered hostname", "outputs": "callback log",
        "prerequisites": "egress DNS works",
    },

    # ── EXPLOIT / AUTH ──────────────────────────────────────────────────────
    "hydra": {
        "category": "exploit", "phase": "P14",
        "description": "Network login bruteforcer (SSH, FTP, RDP, HTTP-POST, SMB).",
        "when_to_use": "When exposed login services found; only with explicit authorization.",
        "inputs": "service URI, userlist, passlist", "outputs": "valid creds",
        "prerequisites": "AUTH_TO_BRUTE_FORCE granted, lists",
    },
    "medusa": {
        "category": "exploit", "phase": "P14",
        "description": "Parallel modular login bruteforcer (alternative to hydra).",
        "when_to_use": "Higher concurrency than hydra for batch logins.",
        "inputs": "service URI, lists", "outputs": "creds",
        "prerequisites": "explicit authorization",
    },
    "jwt_tool": {
        "category": "exploit", "phase": "P14",
        "description": "JWT analyzer — alg none, weak HS256 secret, kid injection.",
        "when_to_use": "Whenever HTTP responses contain JWT (Authorization, cookies).",
        "inputs": "JWT string", "outputs": "vulnerabilities + forged tokens",
        "prerequisites": "captured JWT",
    },
    "crackmapexec": {
        "category": "exploit", "phase": "P14",
        "description": "Swiss-army for SMB/AD: enumerate, spray, dump SAM, lateral move.",
        "when_to_use": "Internal/exposed SMB/AD only; needs authorization.",
        "inputs": "host list, creds", "outputs": "hosts + privileges",
        "prerequisites": "SMB exposed, credentials or null session",
    },
    "impacket": {
        "category": "exploit", "phase": "P14",
        "description": "Suite for Windows protocols (psexec, smbexec, secretsdump, GetNPUsers).",
        "when_to_use": "Post-credential pivoting and Kerberos abuse.",
        "inputs": "creds, host", "outputs": "shells/secrets",
        "prerequisites": "valid creds",
    },
    "evilwinrm": {
        "category": "exploit", "phase": "P14",
        "description": "Interactive WinRM shell with auto-loaders and pass-the-hash.",
        "when_to_use": "Post-exploit shell on Windows when WinRM is exposed.",
        "inputs": "host, creds", "outputs": "shell session",
        "prerequisites": "WinRM 5985/5986 reachable",
    },

    # ── CODE / SUPPLY-CHAIN ─────────────────────────────────────────────────
    "semgrep": {
        "category": "code", "phase": "P22",
        "description": "Pattern-based SAST across 30+ languages with curated rules.",
        "when_to_use": "When source code or git URL provided.",
        "inputs": "code path/repo", "outputs": "findings + lines",
        "prerequisites": "source code",
    },
    "bandit": {
        "category": "code", "phase": "P22",
        "description": "Python security linter (asserts, weak crypto, sql injection patterns).",
        "when_to_use": "Python codebases.",
        "inputs": "code dir", "outputs": "findings",
        "prerequisites": "Python source",
    },
    "trufflehog": {
        "category": "code", "phase": "P21",
        "description": "Verified secret scanner across git history, S3, GCS, GitHub orgs.",
        "when_to_use": "Always — even live URL secrets via JS bundles.",
        "inputs": "repo/dir/URL", "outputs": "verified secrets",
        "prerequisites": "git URL or S3 path",
    },
    "gitleaks": {
        "category": "code", "phase": "P21",
        "description": "Pattern-based secret scanner for git history.",
        "when_to_use": "Faster pre-flight than trufflehog; good for branch CI.",
        "inputs": "repo path", "outputs": "secret findings",
        "prerequisites": "git repo",
    },
    "retire": {
        "category": "code", "phase": "P22",
        "description": "JS dependency CVE scanner (jQuery, Angular, Vue legacy).",
        "when_to_use": "After JS extraction (katana/js-snooper) on live targets.",
        "inputs": "JS file/URL", "outputs": "vulnerable libs",
        "prerequisites": "JS files or live URL",
    },
    "trivy": {
        "category": "code", "phase": "P22",
        "description": "Container/IaC/dependency scanner (CVEs, misconfigs, secrets).",
        "when_to_use": "Container images, K8s manifests, Terraform, lockfiles.",
        "inputs": "image/dir", "outputs": "findings JSON",
        "prerequisites": "image or repo path",
    },
    "eslint": {
        "category": "code", "phase": "P22",
        "description": "JavaScript/TS linter — security plugins available.",
        "when_to_use": "JS/TS codebases.",
        "inputs": "code dir", "outputs": "issues",
        "prerequisites": "node_modules + config",
    },
    "jshint": {
        "category": "code", "phase": "P22",
        "description": "Legacy JS linter — quick pass for syntax/security smells.",
        "when_to_use": "JS-only code.",
        "inputs": "JS file/dir", "outputs": "issues",
        "prerequisites": "JS code",
    },
}


def is_tool_installed(tool_name: str) -> bool:
    candidates = _TOOL_BINARIES.get(tool_name, [tool_name])
    return any(shutil.which(c) for c in candidates)


def installed_tools() -> dict[str, bool]:
    return {tool: is_tool_installed(tool) for tool in TOOL_CATALOG.keys()}


def tool_summary_for_agent(category: str | None = None, only_installed: bool = True) -> list[dict[str, Any]]:
    """Returns compact tool descriptors suitable for LLM prompt injection."""
    out: list[dict[str, Any]] = []
    for name, meta in TOOL_CATALOG.items():
        if category and category not in str(meta.get("category", "")).split("|"):
            continue
        installed = is_tool_installed(name)
        if only_installed and not installed:
            continue
        out.append({
            "tool": name,
            "category": meta["category"],
            "phase": meta["phase"],
            "description": meta["description"],
            "when_to_use": meta["when_to_use"],
            "inputs": meta["inputs"],
            "outputs": meta["outputs"],
            "prerequisites": meta["prerequisites"],
            "installed": installed,
        })
    return out


def render_tool_catalog_for_prompt(category: str | None = None, only_installed: bool = True) -> str:
    """Markdown-rendered catalog for direct injection into the system prompt."""
    rows = tool_summary_for_agent(category=category, only_installed=only_installed)
    if not rows:
        return "(no tools available in this category)"
    lines: list[str] = []
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_cat.setdefault(r["category"], []).append(r)
    for cat in sorted(by_cat.keys()):
        lines.append(f"### {cat.upper()}")
        for r in by_cat[cat]:
            lines.append(
                f"- **{r['tool']}** ({r['phase']}) — {r['description']}\n"
                f"    · USE WHEN: {r['when_to_use']}\n"
                f"    · INPUTS: {r['inputs']} → OUTPUTS: {r['outputs']}\n"
                f"    · NEEDS: {r['prerequisites']}"
            )
    return "\n".join(lines)


def installation_report() -> dict[str, Any]:
    """Dict with installed/missing breakdown for the phase-monitor endpoint."""
    installed: list[str] = []
    missing: list[str] = []
    for tool in TOOL_CATALOG.keys():
        (installed if is_tool_installed(tool) else missing).append(tool)
    return {
        "total": len(TOOL_CATALOG),
        "installed": sorted(installed),
        "missing": sorted(missing),
        "coverage_ratio": round(len(installed) / max(1, len(TOOL_CATALOG)), 3),
    }
