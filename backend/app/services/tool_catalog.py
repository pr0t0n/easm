"""Rich, agent-readable catalog of vulnerability analysis tools.

Each entry teaches the autonomous agent:
  - what the tool does (description)
  - when to use it (when_to_use, prerequisites)
  - inputs/outputs (so the agent can plan I/O wiring)
  - category, phase, weight
The catalog is injected into the supervisor prompt so the agent can pick
tools by role rather than name-matching.
"""
from __future__ import annotations

from typing import Any


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
        "description": "Fast HTTP/HTTPS prober — status, title, tech, TLS metadata, redirects.",
        "when_to_use": "Right after subdomain enum to find live web targets, HTTPS posture and fingerprint.",
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
        "category": "recon", "phase": "P05|P06|P12",
        "description": "OWASP Top 10 security-header analysis via curl — HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, server disclosure and WAF hints.",
        "when_to_use": "Every live web target before active validation; maps A05 Security Misconfiguration, A01 access-control UI hardening, A02 HTTPS downgrade risk and A03 header injection context.",
        "inputs": "URL", "outputs": "HTTP headers, missing/present security-header findings, OWASP category hints",
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
        "description": "TLS certificate/protocol/cipher audit: chain, expiry, self-signed certs, TLS 1.0/1.1, SSLv2/v3, weak ciphers and server-preferred suites.",
        "when_to_use": "Every HTTPS host; cheap first-pass certificate and cipher evidence.",
        "inputs": "host:port", "outputs": "TLS certificate and cipher report",
        "prerequisites": "443/HTTPS reachable",
    },
    "testssl": {
        "category": "recon", "phase": "P18",
        "description": "Comprehensive TLS/certificate auditor: protocols, ciphers, certificate trust/validity, OCSP, HSTS, compression, known TLS vulns.",
        "when_to_use": "Deeper than sslscan when compliance/PCI or strong evidence is needed.",
        "inputs": "host:port", "outputs": "TLS report with certificate/protocol/cipher findings",
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
        "when_to_use": "Directory/file enum with Kali Seclists; default profiles use raft-small-directories and raft-small-files.",
        "inputs": "URL, wordlist", "outputs": "found paths",
        "prerequisites": "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt and raft-small-files.txt inside kali_runner",
    },
    "ffuf-files": {
        "category": "recon", "phase": "P15",
        "description": "FFUF profile alias for non-indexed file discovery using raft-small-files.",
        "when_to_use": "After directory fuzzing to catch backups, old files, configs and exposed static artifacts.",
        "inputs": "URL", "outputs": "found files",
        "prerequisites": "ffuf binary and /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt in kali_runner",
    },
    "ffuf-params": {
        "category": "recon", "phase": "P04|P15|P16",
        "description": "FFUF profile alias for GET parameter-name fuzzing using burp-parameter-names.",
        "when_to_use": "When a page/API endpoint may have hidden URL variables; feeds SQLi, XSS, IDOR, SSRF and auth tests.",
        "inputs": "URL", "outputs": "candidate parameter names",
        "prerequisites": "ffuf binary and /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt in kali_runner",
    },
    "ffuf-values": {
        "category": "recon", "phase": "P04|P16",
        "description": "FFUF profile alias for fuzzing values of an operator-selected URL parameter.",
        "when_to_use": "When a parameter name is known and the agent needs value discovery or anomaly comparison.",
        "inputs": "URL, SCAN_FUZZ_PARAM", "outputs": "interesting parameter values",
        "prerequisites": "SCAN_FUZZ_PARAM; ffuf binary and raft-small-words in kali_runner",
    },
    "ffuf-post": {
        "category": "recon", "phase": "P16",
        "description": "FFUF profile alias for POST/form/dialog-box fuzzing. Request body must contain FUZZ.",
        "when_to_use": "For login/search/dialog form fields and API bodies where fuzzing the URL alone is insufficient.",
        "inputs": "URL, SCAN_FUZZ_POST_DATA, optional SCAN_FUZZ_CONTENT_TYPE", "outputs": "interesting form/API responses",
        "prerequisites": "SCAN_FUZZ_POST_DATA containing FUZZ; defaults to application/x-www-form-urlencoded",
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
        "category": "vuln", "phase": "P04|P15|P16",
        "description": "Web app fuzzer for parameters, headers, paths, methods.",
        "when_to_use": "Alternative anomaly-based parameter fuzzing where ffuf filters are not expressive enough.",
        "inputs": "URL template, wordlist", "outputs": "responses ranked by anomaly",
        "prerequisites": "wfuzz binary and Seclists in kali_runner",
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
        "when_to_use": "Validate blind vulnerabilities found by nuclei or active web scanners.",
        "inputs": "registered hostname", "outputs": "callback log",
        "prerequisites": "egress DNS works",
    },

    # ── EXPLOIT / AUTH ──────────────────────────────────────────────────────
    "hydra": {
        "category": "exploit", "phase": "P14",
        "description": "Network login bruteforcer (SSH, FTP, RDP, HTTP-POST, SMB).",
        "when_to_use": "Credential fuzzing when exposed login services or dialog boxes are found; only with explicit authorization and operator-provided user/pass lists.",
        "inputs": "service URI, userlist, passlist", "outputs": "valid creds",
        "prerequisites": "SCAN_AUTH_USERLIST, SCAN_AUTH_PASSLIST and SCAN_AUTH_PROTOCOL; Kali profile runs hydra -L users.txt -P passlist.txt <target> <protocol>",
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
    "ast-grep": {
        "category": "code", "phase": "P22",
        "description": "AST-aware structural code search for insecure patterns.",
        "when_to_use": "Fast custom SAST rules across source trees and extracted JS.",
        "inputs": "code dir, AST pattern", "outputs": "matched files + lines",
        "prerequisites": "source code or extracted JS",
    },
    "js-snooper": {
        "category": "recon|code", "phase": "P03",
        "description": "JavaScript endpoint and secret discovery from bundles.",
        "when_to_use": "After crawling live apps to inspect JS assets.",
        "inputs": "JS URLs/files", "outputs": "endpoints, keys, interesting strings",
        "prerequisites": "JS files from crawler",
    },
    "jsniper": {
        "category": "recon|code", "phase": "P03",
        "description": "JavaScript recon helper for endpoints and sensitive patterns.",
        "when_to_use": "Complement js-snooper on large SPAs and static bundles.",
        "inputs": "JS URLs/files", "outputs": "endpoints + candidate secrets",
        "prerequisites": "JS files from crawler",
    },
}


def is_tool_installed(tool_name: str) -> bool:
    """Back-compat name for "available in the Kali runner".

    The backend never checks local binaries. Availability requires both a Kali
    profile mapping and a live executable inside the Kali container.
    """
    try:
        from app.services.kali_catalog import is_kali_tool_available
    except Exception:
        return False
    return is_kali_tool_available(tool_name)


def installed_tools() -> dict[str, bool]:
    return {tool: is_tool_installed(tool) for tool in TOOL_CATALOG.keys()}


def ensure_tool_installed(tool_name: str) -> bool:
    """Back-compat alias. Runtime tool installation is not supported.

    Adding tools means adding them to the Kali image and creating a safe
    profile; the backend image stays tool-free.
    """
    return is_tool_installed(tool_name)


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
    """Kali-runner availability breakdown for the phase-monitor endpoint."""
    try:
        from app.services.kali_catalog import kali_installation_report
    except Exception:
        return {
            "source": "kali_runner",
            "runner_reachable": False,
            "total": len(TOOL_CATALOG),
            "installed": [],
            "missing": sorted(TOOL_CATALOG.keys()),
            "coverage_ratio": 0,
        }
    return kali_installation_report(expected_tools=list(TOOL_CATALOG.keys()))
