"""Scan Intelligence Layer.

Adds the "smart" parts to the offensive operator workflow:

  1. Multi-target propagation — subdomains discovered in P01 expand the scope
     for subsequent phases (P02 port scan, P03 endpoint discovery, etc.)
  2. Tech-stack detection — pulls signals from HTTP fingerprinting / whatweb /
     nuclei to set state["tech_stack"] which downstream tools consume.
  3. Evidence validation — re-runs lightweight probes (curl) to confirm
     critical findings (nuclei "exposed .git", credential exposure, etc.).
  4. Defense evasion — WAF detection downshifts rate limits / threads.
  5. MITRE ATT&CK + OWASP mapping — every Finding is enriched with TTP
     identifiers and OWASP categories.
  6. Auth context — credentials/JWT/cookies are propagated to tools that
     accept them (curl, ffuf, sqlmap).
  7. Learning extraction — turn completed scans into VulnerabilityLearning
     candidates without manual seeding.

All functions are stateless: they receive a `state` dict and return enriched
state OR a list of artifacts. The runner calls them at well-defined hooks.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable


# ─────────────────────────────────────────────────────────────────────────────
# 1. Multi-target propagation
# ─────────────────────────────────────────────────────────────────────────────

_SUBDOMAIN_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_\-\.]{0,253}[A-Za-z0-9_\-])?$")


def extract_discovered_subdomains(mcp_results: list[dict[str, Any]], root_domain: str) -> list[str]:
    """Parse subfinder/amass/assetfinder/etc stdout to extract subdomains in scope."""
    if not root_domain:
        return []
    root = root_domain.lstrip("*.").strip().lower()
    found: set[str] = set()
    for mcp in mcp_results or []:
        if not isinstance(mcp, dict):
            continue
        stdout = str(mcp.get("stdout") or "")
        if not stdout:
            continue
        for line in stdout.splitlines():
            token = line.strip().split()[0] if line.strip() else ""
            if not token:
                continue
            # strip optional URL prefix
            for prefix in ("http://", "https://"):
                if token.startswith(prefix):
                    token = token[len(prefix):].split("/")[0]
                    break
            token = token.lower()
            if not _SUBDOMAIN_RE.match(token):
                continue
            # in-scope check: must end with root domain
            if token == root or token.endswith("." + root):
                found.add(token)
    return sorted(found)


def expand_targets_after_p01(state: dict[str, Any], root_target: str, mcp_results: list[dict[str, Any]]) -> list[str]:
    """Return the expanded target list — root + every in-scope subdomain found.

    Stored in state["expanded_targets"] so later phases can iterate.
    Capped at 50 by default to avoid runaway scans.
    """
    cap = int(state.get("expanded_targets_cap") or 50)
    subs = extract_discovered_subdomains(mcp_results, root_target)
    # Always keep the root first.
    expanded = [root_target]
    for s in subs:
        if s not in expanded:
            expanded.append(s)
        if len(expanded) >= cap:
            break
    state["expanded_targets"] = expanded
    return expanded


# ─────────────────────────────────────────────────────────────────────────────
# 2. Tech-stack detection
# ─────────────────────────────────────────────────────────────────────────────

_TECH_SIGNATURES: dict[str, list[str]] = {
    # marker substrings (case-insensitive) → tech name
    "wordpress": ["wp-content", "wp-json", "wp-admin", "wordpress", "woocommerce"],
    "joomla": ["joomla", "/components/com_"],
    "drupal": ["drupal", "sites/default/files", "sites/all/modules"],
    "laravel": ["laravel_session", "x-powered-by: laravel", "/storage/", "phpdebugbar"],
    "django": ["csrftoken", "django", "wsgi"],
    "rails": ["x-runtime", "_session_id", "ruby on rails"],
    "spring": ["spring", "jsessionid", "actuator"],
    "express": ["x-powered-by: express", "connect.sid"],
    "nextjs": ["__next", "_next/data", "nextjs"],
    "react": ["react-helmet", "react", "_reactroot"],
    "magento": ["magento", "mage/cookies", "x-magento"],
    "shopify": ["shopify", "x-shopify"],
    "iis": ["server: microsoft-iis", "x-aspnet-version", "x-aspnetmvc-version"],
    "apache": ["server: apache"],
    "nginx": ["server: nginx"],
    "cloudflare": ["server: cloudflare", "cf-ray", "cf-cache-status"],
    "akamai": ["x-akamai", "akamai", "akamaighost"],
    "incapsula": ["incap_ses", "visid_incap", "x-iinfo", "incapsula", "imperva"],
    "sucuri": ["x-sucuri", "sucuri/cloudproxy", "sucuri"],
    "f5-bigip": ["bigipserver", "f5-", "x-waf-status", "ts01"],
    "barracuda": ["barra_counter", "barracuda"],
    "fortinet": ["fortiwafsid", "fortigate", "fortiweb"],
    "aws-waf": ["awselb", "x-amzn-waf", "aws-waf"],
    "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
    "wordfence": ["wordfence", "wfwaf"],
    "aws": ["x-amz-cf-id", "x-amz-request-id"],
    "graphql": ["/graphql", "graphql"],
    "swagger": ["/swagger", "swagger-ui", "openapi.json"],
    "tomcat": ["apache-coyote", "jsessionid", "tomcat"],
    "php": ["x-powered-by: php", "phpsessid"],
}

# WAF/CDN vendors — when one of these fronts the target, recon results
# (open ports, "vulnerabilities", banners) are frequently the WAF edge
# rather than the origin, and must be treated with skepticism.
_WAF_VENDORS = {
    "cloudflare", "akamai", "incapsula", "sucuri", "f5-bigip",
    "barracuda", "fortinet", "aws-waf", "modsecurity", "wordfence",
}


def detect_tech_stack(state: dict[str, Any], mcp_results: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Scan tool stdout for tech-stack markers and merge into state["tech_stack"]."""
    existing = state.get("tech_stack") or {}
    detected: set[str] = set(existing.get("detected") or [])
    cms: set[str] = set(existing.get("cms") or [])
    servers: set[str] = set(existing.get("servers") or [])
    waf: set[str] = set(existing.get("waf") or [])

    for mcp in mcp_results or []:
        if not isinstance(mcp, dict):
            continue
        body = (str(mcp.get("stdout") or "") + " " + str(mcp.get("command") or "")).lower()
        if not body.strip():
            continue
        for tech, markers in _TECH_SIGNATURES.items():
            if any(m in body for m in markers):
                detected.add(tech)
                if tech in {"wordpress", "joomla", "drupal", "magento", "shopify"}:
                    cms.add(tech)
                if tech in {"apache", "nginx", "iis", "tomcat"}:
                    servers.add(tech)
                if tech in _WAF_VENDORS:
                    waf.add(tech)

    tech_stack = {
        "detected": sorted(detected),
        "cms": sorted(cms),
        "servers": sorted(servers),
        "waf": sorted(waf),
    }
    state["tech_stack"] = tech_stack
    return tech_stack


def tools_to_inject_for_tech(tech_stack: dict[str, list[str]]) -> dict[str, list[str]]:
    """Suggest additional tools per phase based on detected tech stack."""
    extra: dict[str, list[str]] = {}
    cms = tech_stack.get("cms") or []
    detected = tech_stack.get("detected") or []
    if "wordpress" in cms:
        extra.setdefault("P09", []).append("wpscan")
        extra.setdefault("P17", []).append("wpscan")
    if "graphql" in detected or "swagger" in detected:
        extra.setdefault("P04", []).extend(["arjun", "ffuf"])
        extra.setdefault("P16", []).extend(["arjun", "ffuf"])
    return extra


def wordlist_for_tech(tech_stack: dict[str, list[str]]) -> str | None:
    """Return a tech-specific wordlist path if one is preferable to the default."""
    detected = set(tech_stack.get("detected") or [])
    cms = set(tech_stack.get("cms") or [])
    if "wordpress" in cms:
        return "/usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt"
    if "joomla" in cms:
        return "/usr/share/seclists/Discovery/Web-Content/CMS/joomla.txt"
    if "drupal" in cms:
        return "/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt"
    if "laravel" in detected:
        return "/usr/share/seclists/Discovery/Web-Content/Laravel.fuzz.txt"
    if "graphql" in detected or "swagger" in detected:
        return "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Evidence validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_critical_findings(state: dict[str, Any], mcp_results: list[dict[str, Any]], call_curl: callable | None = None) -> list[dict[str, Any]]:
    """For each critical finding (nuclei high/critical, exposed-file, leaked-secret),
    re-run a curl probe to confirm. Returns list of confirmation entries.

    Skipped when call_curl is None (validation disabled).
    """
    confirmations: list[dict[str, Any]] = []
    if not call_curl:
        return confirmations
    candidates: list[dict[str, Any]] = []
    for mcp in mcp_results or []:
        if not isinstance(mcp, dict):
            continue
        tool = str(mcp.get("tool_name") or "").lower()
        parsed = mcp.get("parsed_result")
        if tool == "nuclei" and isinstance(parsed, list):
            for item in parsed[:20]:
                if not isinstance(item, dict):
                    continue
                sev = str((item.get("info") or {}).get("severity") or item.get("severity") or "").lower()
                url = item.get("matched-at") or item.get("url")
                if sev in {"critical", "high"} and url:
                    candidates.append({"tool": "nuclei", "url": str(url), "severity": sev, "template": item.get("template-id")})
    # de-dup
    seen_urls: set[str] = set()
    unique = []
    for c in candidates:
        if c["url"] not in seen_urls:
            seen_urls.add(c["url"])
            unique.append(c)
    for c in unique[:10]:
        try:
            raw = call_curl(c["url"])
            confirmations.append({
                **c,
                "validation_status": "confirmed" if raw.get("status_code", 0) > 0 else "unconfirmed",
                "validation_code": raw.get("status_code"),
                "validation_preview": str(raw.get("body") or "")[:300],
            })
        except Exception as exc:  # noqa: BLE001
            confirmations.append({**c, "validation_status": "error", "validation_error": str(exc)})
    if confirmations:
        state["finding_validations"] = (state.get("finding_validations") or []) + confirmations
    return confirmations


# ─────────────────────────────────────────────────────────────────────────────
# 4. Defense evasion
# ─────────────────────────────────────────────────────────────────────────────

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


def evasion_profile_for(tech_stack: dict[str, list[str]]) -> dict[str, Any]:
    """Pick rate-limits and user-agent strategy based on detected WAF / CDN."""
    waf = set(tech_stack.get("waf") or [])
    if waf:  # any WAF/CDN vendor → reduced-noise profile
        return {
            "rate_limit": 10,
            "threads": 5,
            "delay_ms": 300,
            "user_agents": _USER_AGENTS,
            "rotate_ua": True,
            "respect_robots": True,
            "rationale": f"WAF detected: {', '.join(sorted(waf))} — reduced noise profile",
        }
    return {
        "rate_limit": 100,
        "threads": 25,
        "delay_ms": 0,
        "user_agents": _USER_AGENTS[:1],
        "rotate_ua": False,
        "respect_robots": False,
        "rationale": "No WAF detected — normal scan profile",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4b. WAF deception analysis + environment learning
# ─────────────────────────────────────────────────────────────────────────────

def analyze_waf_behavior(state: dict[str, Any], mcp_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect WAF deception and build a learned environment profile.

    A WAF/CDN in front of the origin actively lies to a scanner:
      - reports many 'open' ports that are just the CDN edge listener
      - returns 200/302 for paths that don't exist on the origin
      - serves generic challenge pages that fuzzers count as 'findings'
      - emits HTTP 429 when it decides the access pattern is abusive

    This records those behaviours in state['environment_profile'] so the
    current scan AND future scans of the same target know how to interpret
    results. Returns the updated environment profile.
    """
    tech = state.get("tech_stack") or {}
    waf_vendors = list(tech.get("waf") or [])
    env = dict(state.get("environment_profile") or {})
    env.setdefault("target", state.get("target") or "")
    env["waf_present"] = bool(waf_vendors)
    env["waf_vendors"] = waf_vendors

    rate_limited = 0
    challenge_responses = 0
    suspicious_port_runs = 0
    observed_behaviors: set[str] = set(env.get("observed_behaviors") or [])

    for mcp in mcp_results or []:
        if not isinstance(mcp, dict):
            continue
        tool = str(mcp.get("tool_name") or "").lower()
        stdout = str(mcp.get("stdout") or "")
        low = stdout.lower()
        # HTTP 429 — WAF rate-limiting / abuse blocking, NOT a finding
        if " 429" in low or "429 too many" in low or "too many requests" in low:
            rate_limited += 1
            observed_behaviors.add("waf_returns_429_on_abuse")
        # WAF challenge / block pages
        if any(m in low for m in ("incap_ses", "_incapsula_", "attention required",
                                  "access denied", "request blocked", "ray id",
                                  "challenge-platform", "captcha")):
            challenge_responses += 1
            observed_behaviors.add("waf_serves_challenge_pages")
        # Port scanners against a WAF/CDN edge — many "open" ports are the edge
        if tool in {"naabu", "masscan", "nmap", "shodan-cli"} and waf_vendors:
            ports = []
            for line in stdout.splitlines():
                if ":" in line:
                    tail = line.rsplit(":", 1)[-1].strip()
                    if tail.isdigit():
                        ports.append(int(tail))
            if len(set(ports)) >= 6:
                suspicious_port_runs += 1
                observed_behaviors.add("waf_edge_reports_many_ports")

    env["observed_behaviors"] = sorted(observed_behaviors)
    env["rate_limit_hits"] = int(env.get("rate_limit_hits", 0)) + rate_limited
    env["challenge_page_hits"] = int(env.get("challenge_page_hits", 0)) + challenge_responses
    # Confidence penalty applied to findings when the WAF is actively deceiving
    penalty = 0
    if waf_vendors:
        penalty = 25
    if rate_limited:
        penalty += 20
    if challenge_responses:
        penalty += 15
    if suspicious_port_runs:
        penalty += 10
    env["finding_confidence_penalty"] = min(70, penalty)
    env["interpretation_notes"] = _waf_interpretation_notes(env)
    state["environment_profile"] = env
    return env


def _waf_interpretation_notes(env: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if not env.get("waf_present"):
        return notes
    vendors = ", ".join(env.get("waf_vendors") or []) or "WAF"
    notes.append(f"{vendors} fronts this target — origin responses are mediated by the WAF.")
    behaviors = set(env.get("observed_behaviors") or [])
    if "waf_edge_reports_many_ports" in behaviors:
        notes.append("Open-port results likely reflect the WAF/CDN edge, not the origin host — "
                     "treat port findings as low-confidence until origin IP is confirmed.")
    if "waf_returns_429_on_abuse" in behaviors:
        notes.append("Target returned HTTP 429 — the WAF rate-limited the scan; "
                     "affected results are incomplete, not negative. Re-test with reduced rate.")
    if "waf_serves_challenge_pages" in behaviors:
        notes.append("WAF served challenge/block pages — fuzzer 'discovered paths' and some "
                     "nuclei matches may be the challenge page, not real origin content.")
    notes.append("Recommendation: confirm the origin IP (DNS history, SPF, certificate SANs) "
                 "and re-validate findings directly against the origin where authorized.")
    return notes


def apply_waf_confidence_adjustment(env: dict[str, Any], severity: str, confidence: int,
                                    phase_id: str, signal: str) -> tuple[str, int, str | None]:
    """Discount a finding's severity/confidence when the WAF is known to deceive.

    Returns (severity, confidence, caveat). caveat is a human-readable note
    appended to the finding when the WAF likely manufactured the result.
    """
    if not env or not env.get("waf_present"):
        return severity, confidence, None
    penalty = int(env.get("finding_confidence_penalty", 0) or 0)
    caveat = None
    adjusted = max(5, confidence - penalty)
    # Port/recon findings behind a WAF are the least trustworthy
    if signal in {"ports_open"} and "waf_edge_reports_many_ports" in (env.get("observed_behaviors") or []):
        severity = "info"
        caveat = "Portas reportadas atrás de WAF/CDN — provavelmente o edge, não a origem."
    # nuclei / path findings behind a WAF need manual confirmation
    elif signal in {"nuclei_finding", "sensitive_path", "path_discovered"}:
        if severity in {"critical", "high"}:
            severity = "medium"
        caveat = "WAF presente — finding requer confirmação manual contra a origem (possível falso-positivo do WAF)."
    return severity, adjusted, caveat


# ─────────────────────────────────────────────────────────────────────────────
# 5. MITRE ATT&CK + OWASP mapping
# ─────────────────────────────────────────────────────────────────────────────

PHASE_MITRE_MAP: dict[str, list[dict[str, str]]] = {
    "P01": [{"id": "T1590.005", "name": "Gather Victim Network Information: IP Addresses"},
            {"id": "T1596.002", "name": "Search Open Technical Databases: WHOIS"}],
    "P02": [{"id": "T1046", "name": "Network Service Discovery"}],
    "P03": [{"id": "T1595.003", "name": "Active Scanning: Wordlist Scanning"}],
    "P04": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "P05": [{"id": "T1595.003", "name": "Active Scanning: Wordlist Scanning"}],
    "P06": [{"id": "T1592.004", "name": "Gather Victim Host Information: Client Configurations"}],
    "P07": [{"id": "T1592.002", "name": "Gather Victim Host Information: Software"}],
    "P08": [{"id": "T1593.001", "name": "Search Open Websites/Domains: Social Media"}],
    "P09": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "P10": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"}],
    "P11": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1090", "name": "Proxy"}],
    "P12": [{"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"}],
    "P13": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1078", "name": "Valid Accounts"}],
    "P14": [{"id": "T1110", "name": "Brute Force"},
            {"id": "T1078", "name": "Valid Accounts"}],
    "P15": [{"id": "T1213", "name": "Data from Information Repositories"}],
    "P16": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "P17": [{"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1059", "name": "Command and Scripting Interpreter"}],
    "P18": [{"id": "T1552", "name": "Unsecured Credentials"},
            {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"}],
    "P19": [{"id": "T1078", "name": "Valid Accounts"}],
    "P20": [{"id": "T1583", "name": "Acquire Infrastructure"}],
    "P21": [{"id": "T1530", "name": "Data from Cloud Storage Object"}],
    "P22": [{"id": "TA0009", "name": "Collection"}],
}

PHASE_OWASP_MAP: dict[str, list[str]] = {
    "P01": ["A05:2021 Security Misconfiguration"],
    "P02": ["A05:2021 Security Misconfiguration"],
    "P03": ["A01:2021 Broken Access Control"],
    "P04": ["A03:2021 Injection"],
    "P05": ["A05:2021 Security Misconfiguration"],
    "P06": ["A05:2021 Security Misconfiguration"],
    "P07": ["A06:2021 Vulnerable and Outdated Components"],
    "P08": ["A07:2021 Identification and Authentication Failures"],
    "P09": ["A06:2021 Vulnerable and Outdated Components"],
    "P10": ["A03:2021 Injection"],
    "P11": ["A10:2021 Server-Side Request Forgery (SSRF)"],
    "P12": ["A03:2021 Injection", "A07:2021 Identification and Authentication Failures"],
    "P13": ["A01:2021 Broken Access Control"],
    "P14": ["A07:2021 Identification and Authentication Failures"],
    "P15": ["A04:2021 Insecure Design", "A08:2021 Software and Data Integrity Failures"],
    "P16": ["A03:2021 Injection", "A04:2021 Insecure Design"],
    "P17": ["A03:2021 Injection", "A06:2021 Vulnerable and Outdated Components"],
    "P18": ["A02:2021 Cryptographic Failures", "A07:2021 Identification and Authentication Failures"],
    "P19": ["A01:2021 Broken Access Control"],
    "P20": ["A05:2021 Security Misconfiguration"],
    "P21": ["A09:2021 Security Logging and Monitoring Failures"],
    "P22": [],
}


def enrich_finding_with_mappings(phase_id: str, details: dict[str, Any]) -> dict[str, Any]:
    """Add MITRE ATT&CK and OWASP Top 10 mapping to finding details."""
    details["mitre_attack"] = PHASE_MITRE_MAP.get(phase_id, [])
    details["owasp_top10"] = PHASE_OWASP_MAP.get(phase_id, [])
    details["kill_chain_stage"] = _phase_kill_chain(phase_id)
    return details


def _phase_kill_chain(phase_id: str) -> str:
    if phase_id in {"P01"}: return "Reconnaissance"
    if phase_id in {"P02", "P05", "P06", "P07", "P08"}: return "Resource Development"
    if phase_id in {"P03", "P04"}: return "Discovery"
    if phase_id in {"P09", "P14"}: return "Initial Access"
    if phase_id in {"P10", "P11", "P12", "P13", "P15", "P16", "P17"}: return "Execution / Exploitation"
    if phase_id in {"P18"}: return "Credential Access"
    if phase_id in {"P19", "P20"}: return "Lateral Movement"
    if phase_id in {"P21", "P22"}: return "Exfiltration / Reporting"
    return "Unclassified"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Auth context
# ─────────────────────────────────────────────────────────────────────────────

def auth_headers_from_state(state: dict[str, Any]) -> dict[str, str]:
    """Extract authentication headers from scan state_data.auth_config.

    auth_config example:
      {"type": "bearer", "token": "..."}
      {"type": "cookie", "cookie": "PHPSESSID=..."}
      {"type": "basic", "username": "...", "password": "..."}
      {"type": "header", "headers": {"X-API-Key": "..."}}
    """
    cfg = (state.get("auth_config") or {}) if isinstance(state.get("auth_config"), dict) else {}
    headers: dict[str, str] = {}
    auth_type = str(cfg.get("type") or "").lower()
    if auth_type == "bearer" and cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"
    elif auth_type == "cookie" and cfg.get("cookie"):
        headers["Cookie"] = cfg["cookie"]
    elif auth_type == "basic":
        import base64
        pair = f"{cfg.get('username', '')}:{cfg.get('password', '')}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(pair).decode()
    elif auth_type == "header" and isinstance(cfg.get("headers"), dict):
        for k, v in cfg["headers"].items():
            headers[str(k)] = str(v)
    return headers


def has_auth(state: dict[str, Any]) -> bool:
    cfg = state.get("auth_config")
    return isinstance(cfg, dict) and bool(cfg.get("type"))


# ─────────────────────────────────────────────────────────────────────────────
# 7. EASM scan level
# ─────────────────────────────────────────────────────────────────────────────

# ASM mode: only run passive recon and surface mapping. Skips exploitation.
ASM_PHASES = {"P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08", "P18", "P21", "P22"}
FULL_PHASES = set()  # empty = run all


def phases_for_scan_level(scan_level: str | None) -> set[str] | None:
    """Return phase IDs to execute. None means 'all phases'."""
    level = str(scan_level or "full").lower().strip()
    if level == "asm":
        return ASM_PHASES
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 8. Learning extraction (post-scan)
# ─────────────────────────────────────────────────────────────────────────────

def extract_learning_signals(state: dict[str, Any], phase_ledgers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build VulnerabilityLearning candidates from scan results.

    Returns rows suitable for create_vulnerability_learning-style persistence.
    """
    learnings: list[dict[str, Any]] = []
    tech = state.get("tech_stack") or {}
    for ledger in phase_ledgers:
        if not isinstance(ledger, dict):
            continue
        if ledger.get("status") != "completed":
            continue
        for mcp in (ledger.get("mcp_results") or []):
            if not isinstance(mcp, dict):
                continue
            tool = str(mcp.get("tool_name") or "")
            parsed = mcp.get("parsed_result")
            if tool == "nuclei" and isinstance(parsed, list):
                for item in parsed[:5]:
                    if not isinstance(item, dict):
                        continue
                    info = item.get("info") or {}
                    sev = str(info.get("severity") or "").lower()
                    if sev not in {"critical", "high", "medium"}:
                        continue
                    template = item.get("template-id") or info.get("name") or "nuclei-finding"
                    learnings.append({
                        "tool": tool,
                        "template": template,
                        "severity": sev,
                        "title": info.get("name") or template,
                        "description": info.get("description") or "",
                        "cve": (info.get("classification") or {}).get("cve-id"),
                        "phase_id": ledger.get("phase_id"),
                        "tech_stack": tech.get("detected") or [],
                        "evidence_url": item.get("matched-at") or "",
                    })
    return learnings
