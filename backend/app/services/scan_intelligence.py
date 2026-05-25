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
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlparse


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
    Uses lista_ativos (raw tool stdout, uncapped) when available so ALL
    discovered subdomains enter the pipeline. Falls back to MCP extraction.
    By default there is no cap: every discovered subdomain enters the pipeline.
    Set expanded_targets_cap explicitly when an operator wants a safety limit.
    """
    raw_cap = state.get("expanded_targets_cap")
    cap = int(raw_cap) if raw_cap not in (None, "", 0, "0") else None
    # lista_ativos is populated from raw P01 stdout before this function is called.
    # It contains ALL discovered subdomains without a cap, so prefer it.
    lista = list(state.get("lista_ativos") or [])
    if lista:
        subs = [h for h in lista if h and h != root_target]
    else:
        subs = extract_discovered_subdomains(mcp_results, root_target)
    # Always keep the root first.
    expanded = [root_target]
    for s in subs:
        if s not in expanded:
            expanded.append(s)
        if cap is not None and len(expanded) >= cap:
            break
    state["expanded_targets"] = expanded
    return expanded


# Phases whose result is bound to the host's IP, not the hostname — running
# them once per unique IP avoids redundant scans of a shared WAF/CDN edge
# (and the 429s that 50 identical port scans of one IP would trigger).
NETWORK_PHASES = {"P02"}
WEB_HEAVY_PHASES = {
    "P03", "P04", "P05", "P06", "P07", "P08", "P09", "P10",
    "P11", "P12", "P13", "P14", "P15", "P16", "P17", "P19",
}
DEFAULT_PREFLIGHT_PORTS = (80, 443, 8080, 8081, 8443, 8000, 8008, 8888, 9000, 9443, 10443, 3000, 5000, 5001)


def _normalize_host(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = parsed.hostname or ""
    except Exception:  # noqa: BLE001
        host = ""
    if not host:
        host = raw.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    return host.strip().strip(".")


def _resolve_host(host: str) -> str | None:
    """Resolve a hostname to its primary IPv4. None = does not resolve (dead)."""
    import socket
    h = _normalize_host(host)
    if not h:
        return None
    try:
        return socket.gethostbyname(h)
    except Exception:  # noqa: BLE001
        return None


def _tcp_connects(host: str, port: int, timeout: float = 1.5) -> bool:
    import socket

    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


def _http_probe(host: str, port: int, timeout: float = 3.0) -> dict[str, Any] | None:
    import requests

    scheme = "https" if int(port) in {443, 8443} else "http"
    default_port = (scheme == "http" and int(port) == 80) or (scheme == "https" and int(port) == 443)
    url = f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{int(port)}"
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "ScriptKidd.o-preflight/1.0"},
        )
        return {
            "url": url,
            "status_code": int(response.status_code),
            "server": response.headers.get("server"),
            "content_type": response.headers.get("content-type"),
            "final_url": response.url,
        }
    except Exception:  # noqa: BLE001
        return None


def classify_target_preflight(
    target: str,
    ports: Iterable[int] | None = None,
    tcp_timeout: float = 1.5,
    http_timeout: float = 3.0,
) -> dict[str, Any]:
    """Classify a host before expensive phases.

    This is intentionally lightweight: DNS, a small TCP connect set and a tiny
    HTTP request. It does not replace P02; it prevents obvious dead/non-HTTP
    targets from consuming the full P03-P19 web-testing budget.
    """
    host = _normalize_host(target)
    checked_at = datetime.now(timezone.utc).isoformat()
    if not host:
        return {
            "target": target,
            "host": "",
            "status": "invalid",
            "reason": "target vazio ou inválido",
            "dns_resolves": False,
            "ip": None,
            "open_ports": [],
            "http": [],
            "checked_at": checked_at,
        }

    ip = _resolve_host(host)
    if not ip:
        return {
            "target": target,
            "host": host,
            "status": "dns_dead",
            "reason": "host não resolve em DNS",
            "dns_resolves": False,
            "ip": None,
            "open_ports": [],
            "http": [],
            "checked_at": checked_at,
        }

    port_list = []
    for port in (ports or DEFAULT_PREFLIGHT_PORTS):
        try:
            port_list.append(int(port))
        except (TypeError, ValueError):
            continue

    # Probe all ports in parallel — 14 sequential socket calls would add ~20s
    # of latency at 1.5s timeout each; ThreadPoolExecutor cuts this to ~1-2s.
    open_ports: list[int] = []
    http_signals: list[dict[str, Any]] = []
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _probe_port(p: int) -> tuple[int, dict | None] | None:
        if _tcp_connects(host, p, timeout=tcp_timeout):
            return p, _http_probe(host, p, timeout=http_timeout)
        return None

    with ThreadPoolExecutor(max_workers=min(len(port_list), 20)) as pool:
        futures = {pool.submit(_probe_port, p): p for p in port_list}
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                p, probe = result
                open_ports.append(p)
                if probe:
                    http_signals.append(probe)

    if http_signals:
        status = "http_live"
        reason = f"HTTP respondeu em {len(http_signals)} porta(s)"
    elif open_ports:
        status = "tcp_live"
        reason = f"TCP aberto sem resposta HTTP clara em {len(open_ports)} porta(s)"
    else:
        status = "tcp_closed"
        reason = "DNS resolve, mas portas web comuns não aceitaram conexão"

    return {
        "target": target,
        "host": host,
        "status": status,
        "reason": reason,
        "dns_resolves": True,
        "ip": ip,
        "open_ports": open_ports,
        "http": http_signals,
        "checked_at": checked_at,
    }


def preflight_skip_reason(phase_id: str, profile: dict[str, Any] | None) -> str | None:
    """Return a skip reason for a phase/target according to Tier 1 preflight."""
    if phase_id == "P01" or not profile:
        return None
    status = str(profile.get("status") or "").lower()
    # Dead hosts: skip ALL phases — no point port-scanning an unresolvable host.
    if status in {"invalid", "dns_dead"}:
        return profile.get("reason") or "preflight sem DNS válido"
    # tcp_closed (DNS resolves, no open web ports): skip web-heavy phases but
    # still run P02 (port scan) — P02 itself may find non-web open ports.
    if phase_id in WEB_HEAVY_PHASES and status == "tcp_closed":
        return profile.get("reason") or "preflight sem superfície HTTP ativa"
    return None


def refine_target_set(root: str, subdomains: list[str], cap: int | None = None) -> dict[str, Any]:
    """Liveness-filter + IP-group the discovered subdomains before Stage 2.

    - Liveness: a host that does not resolve in DNS is 'dead' — it gets no
      P02-P22 phases, only a report entry 'discovered but inactive'.
    - IP-grouping: hosts are mapped to their resolved IP so the runner can
      run network phases (port scan) once per unique IP.

    By default NO cap — every alive subdomain enters the queue. The 'cap'
    parameter is an explicit operator safety ceiling only.

    Returns:
      live_targets: hosts that resolve (root always first)
      dead_targets: hosts that do not resolve
      host_ip:      host → resolved IP
      ip_groups:    IP → [hosts sharing it]
    """
    host_ip: dict[str, str] = {}
    live: list[str] = []
    dead: list[str] = []
    ordered = [root] + [s for s in subdomains if s and s != root]
    for host in ordered:
        if cap is not None and len(live) >= cap:
            break
        ip = _resolve_host(host)
        if ip:
            host_ip[host] = ip
            live.append(host)
        elif host != root:  # root stays even if resolution hiccups
            dead.append(host)
        else:
            live.append(host)
    ip_groups: dict[str, list[str]] = {}
    for host, ip in host_ip.items():
        ip_groups.setdefault(ip, []).append(host)
    return {
        "live_targets": live,
        "dead_targets": dead,
        "host_ip": host_ip,
        "ip_groups": ip_groups,
    }


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

# Markers that mean the response is a WAF challenge/block page — NOT the
# real origin content. A finding "confirmed" by such a page is a false lead.
_WAF_CHALLENGE_MARKERS = (
    "incap_ses", "_incapsula_", "visid_incap", "captcha", "challenge-platform",
    "attention required", "request blocked", "access denied", "request unsuccessful",
    "ray id", "cf-error", "akamai reference", "support id", "this request was blocked",
)

# Expected response-body content per finding class — used to confirm a finding
# is REAL (the body actually contains what the finding claims) vs a 200 from a
# generic page or a WAF challenge.
_CONTENT_SIGNATURES: dict[str, list[str]] = {
    "git": ["ref:", "[core]", "repositoryformatversion", "x-pack", "objects/pack"],
    "env": ["app_key", "db_password", "db_host", "db_username", "api_key", "secret_key", "aws_"],
    "phpinfo": ["php version", "phpinfo()", "php credits", "configuration php core"],
    "config": ["password", "secret", "connectionstring", "<?php", "datasource"],
    "backup": ["sql dump", "create table", "insert into", "<?php", "mysqldump"],
    "swagger": ["swagger", "openapi", '"paths"', "basepath"],
    "listing": ["index of /", "directory listing", "<title>index of"],
}


def _finding_class_for(template_id: str, url: str) -> str | None:
    """Map a nuclei template / URL to a content-signature class."""
    t = (str(template_id or "") + " " + str(url or "")).lower()
    if ".git" in t or "git-config" in t or "git-exposure" in t or "git/head" in t:
        return "git"
    if ".env" in t or "env-file" in t or "dotenv" in t:
        return "env"
    if "phpinfo" in t:
        return "phpinfo"
    if "swagger" in t or "openapi" in t or "api-docs" in t:
        return "swagger"
    if "backup" in t or ".sql" in t or ".bak" in t or "dump" in t:
        return "backup"
    if "config" in t or ".conf" in t or "settings" in t:
        return "config"
    if "listing" in t or "directory" in t:
        return "listing"
    return None


def validate_critical_findings(state: dict[str, Any], mcp_results: list[dict[str, Any]],
                                call_curl: callable | None = None) -> list[dict[str, Any]]:
    """Deep, content-based validation of critical findings.

    For each nuclei critical/high finding, re-fetch the URL and classify:
      - confirmed       : response body actually contains the expected content
      - false_positive  : 404/403, or 200 whose body does NOT match the claim
      - waf_blocked     : response is a WAF challenge/block page (inconclusive)
      - unconfirmed     : reachable 200 but no signature to check against
      - error           : the probe itself failed

    This stops a WAF challenge page or a generic 200 from "confirming" a vuln.
    Skipped when call_curl is None.
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
            for item in parsed[:25]:
                if not isinstance(item, dict):
                    continue
                info = item.get("info") or {}
                sev = str(info.get("severity") or item.get("severity") or "").lower()
                url = item.get("matched-at") or item.get("url")
                if sev in {"critical", "high", "medium"} and url:
                    candidates.append({
                        "tool": "nuclei", "url": str(url), "severity": sev,
                        "template": item.get("template-id"),
                        "name": info.get("name"),
                    })
    seen_urls: set[str] = set()
    unique = [c for c in candidates if not (c["url"] in seen_urls or seen_urls.add(c["url"]))]

    for c in unique[:15]:
        try:
            raw = call_curl(c["url"])
            code = int(raw.get("status_code") or 0)
            body = str(raw.get("body") or "")
            low = body.lower()
            if any(m in low for m in _WAF_CHALLENGE_MARKERS):
                status, reason = "waf_blocked", "response is a WAF challenge/block page — inconclusive"
            elif code in (0, 404, 403, 503):
                status, reason = "false_positive", f"resource not actually reachable (HTTP {code})"
            else:
                cls = _finding_class_for(c.get("template"), c["url"])
                if cls:
                    expected = _CONTENT_SIGNATURES.get(cls, [])
                    if any(e in low for e in expected):
                        status, reason = "confirmed", f"body matches {cls} signature"
                    else:
                        status, reason = "false_positive", f"HTTP {code} but body lacks {cls} content"
                else:
                    status = "confirmed" if (code == 200 and body.strip()) else "unconfirmed"
                    reason = f"HTTP {code}, {len(body)} bytes (no class signature to verify)"
            confirmations.append({
                **c,
                "validation_status": status,
                "validation_reason": reason,
                "validation_code": code,
                "validation_preview": body[:300],
            })
        except Exception as exc:  # noqa: BLE001
            confirmations.append({**c, "validation_status": "error", "validation_reason": str(exc)})

    if confirmations:
        state["finding_validations"] = (state.get("finding_validations") or []) + confirmations
    return confirmations


def detect_rate_limit_signals(mcp_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Inspect tool output for HTTP 429 / WAF-throttling signatures.

    Returns {hit: bool, tools_throttled: [tool_name], evidence: [snippet]}.
    The runner uses this to decide whether to re-run the phase with the
    reduced-rate evasion profile.
    """
    throttled: list[str] = []
    evidence: list[str] = []
    for mcp in mcp_results or []:
        if not isinstance(mcp, dict):
            continue
        out = (str(mcp.get("stdout") or "") + " " + str(mcp.get("stderr_path") or "")).lower()
        if (" 429" in out or "429 too many" in out or "too many requests" in out
                or "rate limit" in out or "throttled" in out or "retry-after" in out):
            t = str(mcp.get("tool_name") or "?")
            if t not in throttled:
                throttled.append(t)
                evidence.append(out[:200])
    return {"hit": bool(throttled), "tools_throttled": throttled, "evidence": evidence}


# ─────────────────────────────────────────────────────────────────────────────
# 5b. Cross-target finding deduplication
# ─────────────────────────────────────────────────────────────────────────────

def dedup_findings_by_signature(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge findings of the same kind across multiple targets/subdomains.

    The same vuln template firing on 30 subdomains should be ONE finding with
    30 instances, not 30 copies polluting the report. Signature = (phase_id,
    nuclei_template OR finding_kind OR signal_class). Distinct targets are
    rolled into 'instances'.
    """
    groups: dict[tuple, dict[str, Any]] = {}
    for f in findings:
        details = f.get("details") or {}
        # Build a dedup signature
        sig_parts: list[str] = [str(details.get("phase_id") or "")]
        kind = details.get("finding_kind")
        if kind:
            sig_parts.append(str(kind))
        else:
            # Use the first nuclei template ID found in tool_evidence, else title
            tmpl = ""
            for te in (details.get("tool_evidence") or []):
                for nf in (te.get("nuclei_findings") or []):
                    tmpl = nf.get("template") or ""
                    if tmpl:
                        break
                if tmpl:
                    break
            sig_parts.append(tmpl or str(f.get("title") or "")[:80])
        signature = tuple(sig_parts)
        target = details.get("target") or f.get("domain") or ""
        if signature not in groups:
            f = dict(f)
            f["instances"] = [target] if target else []
            f["instance_count"] = len(f["instances"])
            groups[signature] = f
        else:
            existing = groups[signature]
            insts = existing.get("instances") or []
            if target and target not in insts:
                insts.append(target)
            existing["instances"] = insts
            existing["instance_count"] = len(insts)
            # Promote severity to the highest seen across instances
            sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if sev_rank.get(str(f.get("severity")), 0) > sev_rank.get(str(existing.get("severity")), 0):
                existing["severity"] = f.get("severity")
    return list(groups.values())


# ─────────────────────────────────────────────────────────────────────────────
# 5c. CVSS auto-derivation (rule-based, no NVD lookup)
# ─────────────────────────────────────────────────────────────────────────────

def derive_cvss(severity: str, signal: str, waf_present: bool = False) -> float:
    """Map evidence-derived severity + finding signal to a CVSS-style score.

    Not a real NVD lookup — a rule-based base score so the report has a
    consistent numeric next to qualitative severity. Adjusts down when a
    WAF is present (less directly exploitable).
    """
    base: dict[str, float] = {
        "critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.5, "info": 1.5,
    }.copy()
    # signal-class bumps
    bumps: dict[str, float] = {
        "secret_exposed": 1.0, "injection_confirmed": 1.5,
        "cve_identified": 0.8, "sensitive_path": 0.5,
        "missing_headers": -0.5, "ports_open": -1.0,
    }
    score = base.get((severity or "info").lower(), 1.5) + bumps.get(signal or "", 0.0)
    if waf_present:
        score -= 1.0  # WAF reduces direct exploitability
    return round(max(0.1, min(10.0, score)), 1)


# ─────────────────────────────────────────────────────────────────────────────
# 5d. Executive narrative
# ─────────────────────────────────────────────────────────────────────────────

def build_executive_narrative(scan_id: int, target: str, findings: list[dict[str, Any]],
                              env_profile: dict[str, Any] | None = None,
                              origin: dict[str, Any] | None = None) -> dict[str, Any]:
    """Generate an executive-level summary of the scan.

    Returns a dict with: headline, key_findings, attack_surface, environment,
    recommendation_priority, full narrative text. Intended for the report PDF
    and the dashboard.
    """
    by_sev: dict[str, int] = {}
    top: list[dict[str, Any]] = []
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if sev in {"critical", "high", "medium"}:
            top.append(f)
    top.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2}.get(x.get("severity", "info"), 9))
    top = top[:5]

    waf = (env_profile or {}).get("waf_vendors") or []
    origin_cands = (origin or {}).get("candidate_origins") or []

    headline_parts: list[str] = []
    if by_sev.get("critical", 0) + by_sev.get("high", 0) > 0:
        headline_parts.append(f"{by_sev.get('critical', 0)} crítico(s), {by_sev.get('high', 0)} alto(s)")
    if origin_cands:
        headline_parts.append(f"WAF bypass possível ({len(origin_cands)} IPs candidatos a origem)")
    if waf:
        headline_parts.append(f"perímetro {', '.join(waf)}")
    headline = " · ".join(headline_parts) if headline_parts else "Superfície mapeada, sem achados críticos confirmados"

    return {
        "scan_id": scan_id,
        "target": target,
        "headline": headline,
        "severity_distribution": by_sev,
        "total_findings": sum(by_sev.values()),
        "top_findings": [
            {"id": f.get("id"), "title": f.get("title"), "severity": f.get("severity"),
             "instances": f.get("instance_count", 1)}
            for f in top
        ],
        "environment": {
            "waf_vendors": waf,
            "waf_present": bool(waf),
            "origin_candidates": len(origin_cands),
        },
        "narrative": (
            f"Avaliação ofensiva do alvo {target}. " +
            (f"O perímetro é defendido por {', '.join(waf)}; " if waf else "") +
            (f"foram identificados {len(origin_cands)} candidatos a IP de origem fora dos ranges do WAF — "
             f"a confirmação habilita bypass total da proteção. " if origin_cands else "") +
            f"Total de {sum(by_sev.values())} achado(s): " +
            ", ".join(f"{c} {s}" for s, c in sorted(by_sev.items(),
                key=lambda kv: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(kv[0], 9)) if c) + "."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5e. Asset / finding diff vs previous scan of same target
# ─────────────────────────────────────────────────────────────────────────────

def diff_against_previous(current_findings: list[dict[str, Any]],
                          previous_findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare current scan to the previous scan of the same target.

    Returns: new_findings, fixed_findings (in previous, not in current),
    persistent_findings (in both), regression candidates.
    """
    def _sig(f: dict[str, Any]) -> str:
        d = f.get("details") or {}
        return f"{d.get('phase_id', '')}:{d.get('finding_kind') or f.get('title', '')[:80]}"

    cur_sigs = {_sig(f): f for f in current_findings}
    prev_sigs = {_sig(f): f for f in previous_findings}
    new = [f for sig, f in cur_sigs.items() if sig not in prev_sigs]
    fixed = [f for sig, f in prev_sigs.items() if sig not in cur_sigs]
    persistent = [cur_sigs[sig] for sig in cur_sigs if sig in prev_sigs]
    return {
        "new_findings": new,
        "fixed_findings": fixed,
        "persistent_findings": persistent,
        "new_count": len(new),
        "fixed_count": len(fixed),
        "persistent_count": len(persistent),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5f. Attack-path chaining — link findings into kill chains
# ─────────────────────────────────────────────────────────────────────────────

# Rules: each rule lists trigger conditions (finding_kinds OR phase_ids) that,
# when present together, materialise into a named attack chain.
_CHAIN_RULES: list[dict[str, Any]] = [
    {
        "name": "WAF Bypass → Direct Origin Exposure",
        "severity": "critical",
        "triggers": {"finding_kinds": ["waf_origin_discovery"], "phase_ids": []},
        "second": {"phase_ids": ["P09", "P10", "P11", "P12", "P13", "P15", "P17", "P18"]},
        "story": (
            "O atacante descobre o IP da origem fora do WAF e usa para acessar "
            "diretamente os endpoints vulneráveis identificados em P09-P18, "
            "contornando completamente toda proteção do perímetro."
        ),
        "mitre": ["T1133", "T1190"],
    },
    {
        "name": "Credential Leak Chain",
        "severity": "critical",
        "triggers": {"phase_ids": ["P15", "P18"], "title_markers": ["secret", "credential", ".git", ".env"]},
        "second": {"phase_ids": ["P14"], "title_markers": ["auth"]},
        "story": (
            "Credencial vazada (P15/P18) habilita autenticação direta (P14), "
            "convertendo um vazamento de informação em acesso autenticado."
        ),
        "mitre": ["T1552", "T1078"],
    },
    {
        "name": "Subdomain Takeover → Brand Hijack",
        "severity": "high",
        "triggers": {"title_markers": ["takeover", "subjack"]},
        "second": {"phase_ids": ["P01"]},
        "story": (
            "Subdomínio com referência DNS pendente pode ser tomado pelo atacante, "
            "permitindo hospedar conteúdo malicioso sob a marca do alvo."
        ),
        "mitre": ["T1583.001"],
    },
    {
        "name": "Injection → Data Exfiltration",
        "severity": "critical",
        "triggers": {"phase_ids": ["P10", "P12"], "title_markers": ["sql", "xss", "inject"]},
        "second": {"phase_ids": ["P13", "P19"]},
        "story": (
            "Injection confirmada (P10/P12) combinada com falha de access control "
            "(P13/P19) permite extração de dados de outros usuários/contas."
        ),
        "mitre": ["T1190", "T1213"],
    },
    {
        "name": "Exposed API → IDOR",
        "severity": "high",
        "triggers": {"phase_ids": ["P04", "P16"], "title_markers": ["parameter", "api"]},
        "second": {"phase_ids": ["P13"]},
        "story": (
            "Parâmetros descobertos em APIs (P04/P16) sem controle adequado de "
            "autorização (P13) permitem IDOR — acesso a recursos de outros usuários."
        ),
        "mitre": ["T1213"],
    },
]


def _finding_matches(finding: dict[str, Any], cond: dict[str, Any]) -> bool:
    details = finding.get("details") or {}
    phase = str(details.get("phase_id") or "")
    kind = str(details.get("finding_kind") or "")
    title = str(finding.get("title") or "").lower()
    if cond.get("finding_kinds") and kind in cond["finding_kinds"]:
        return True
    if cond.get("phase_ids") and phase in cond["phase_ids"]:
        markers = cond.get("title_markers") or []
        if not markers or any(m in title for m in markers):
            return True
    return False


def chain_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate findings into attack chains.

    For each rule, collect findings matching the trigger and findings matching
    the second link. If both sets are non-empty, materialise the chain.
    """
    chains: list[dict[str, Any]] = []
    for rule in _CHAIN_RULES:
        primary = [f for f in findings if _finding_matches(f, rule["triggers"])]
        if not primary:
            continue
        secondary = [f for f in findings if _finding_matches(f, rule["second"])]
        if not secondary:
            continue
        chains.append({
            "name": rule["name"],
            "severity": rule["severity"],
            "story": rule["story"],
            "mitre_attack": rule["mitre"],
            "trigger_findings": [{"id": f.get("id"), "title": f.get("title")} for f in primary[:5]],
            "exploit_findings": [{"id": f.get("id"), "title": f.get("title")} for f in secondary[:5]],
            "trigger_count": len(primary),
            "exploit_count": len(secondary),
        })
    return chains


# ─────────────────────────────────────────────────────────────────────────────
# 5g. False-positive feedback loop — learn from analyst FP markings
# ─────────────────────────────────────────────────────────────────────────────

def build_fp_signature(finding: Any) -> str:
    """Stable signature for an FP-blocklist entry. Same across scans."""
    details = (finding.details if hasattr(finding, "details") else finding.get("details")) or {}
    phase = str(details.get("phase_id") or "")
    kind = str(details.get("finding_kind") or "")
    # Pull a nuclei template if present, else title
    tmpl = ""
    for te in (details.get("tool_evidence") or []):
        for nf in (te.get("nuclei_findings") or []):
            tmpl = nf.get("template") or ""
            if tmpl:
                break
        if tmpl:
            break
    title = str(finding.title if hasattr(finding, "title") else finding.get("title") or "")[:80]
    return f"{phase}|{kind}|{tmpl}|{title}"


def load_fp_blocklist(db, owner_id: int | None = None) -> set[str]:
    """Read all findings marked as false positive and return their signatures.

    The runner uses this to downgrade matching findings on new scans.
    """
    from app.models.models import Finding as _F
    q = db.query(_F).filter(_F.is_false_positive == True)  # noqa: E712
    if owner_id is not None:
        from app.models.models import ScanJob as _SJ
        q = q.join(_SJ, _F.scan_job_id == _SJ.id).filter(_SJ.owner_id == owner_id)
    sigs: set[str] = set()
    for f in q.all():
        sigs.add(build_fp_signature(f))
    return sigs


def apply_fp_blocklist(finding_dict: dict[str, Any], blocklist: set[str]) -> bool:
    """If the finding matches a known FP, downgrade it to info + flag.

    Returns True if downgraded.
    """
    sig = build_fp_signature(finding_dict)
    if sig in blocklist:
        finding_dict["severity"] = "info"
        details = finding_dict.get("details") or {}
        details["fp_downgraded"] = True
        details["fp_signature"] = sig
        finding_dict["details"] = details
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 5h. LLM-driven phase reasoning — adapt next-phase plan from evidence
# ─────────────────────────────────────────────────────────────────────────────

def llm_phase_reasoning(state: dict[str, Any], phase_id: str, target: str,
                        tool_evidences: list[dict[str, Any]],
                        tech_stack: dict[str, list[str]],
                        env_profile: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Ask the LLM to suggest payload/tool adjustments for downstream phases
    based on the evidence collected so far.

    Returns a dict like:
      {"injected_tools": {"P09": ["wpscan"]},
       "payloads_hint": ["..."],
       "reasoning": "..."}
    or None when the LLM is unreachable or disabled.

    Disabled with state["llm_reasoning_disabled"] = True or env LLM_REASONING=0.
    """
    import os
    if state.get("llm_reasoning_disabled") or os.environ.get("LLM_REASONING") == "0":
        return None
    # Only call the LLM after phases that produce actionable signal
    if phase_id not in {"P01", "P03", "P06", "P07", "P09", "P15", "P18"}:
        return None
    try:
        from app.services.vulnerability_learning_service import _call_learning_llm, _extract_json_object
    except Exception:
        return None

    # Compact context the LLM can reason about
    findings_summary: list[str] = []
    for ev in (tool_evidences or [])[:8]:
        s = ev.get("finding_summary") or ""
        if s and not s.lower().startswith(("no ", "nenhum", "sem ")):
            findings_summary.append(f"- {ev.get('tool')}: {s[:120]}")
    if not findings_summary:
        return None

    prompt = f"""Você é um operador RedTeam.
Analise as evidências coletadas até agora e sugira como ajustar o teste das próximas fases.

Alvo: {target}
Fase recém-concluída: {phase_id}
Stack detectado: {tech_stack.get('detected', [])} (CMS: {tech_stack.get('cms', [])}, WAF: {tech_stack.get('waf', [])})
WAF presente: {bool((env_profile or {}).get('waf_present'))}

Evidências:
{chr(10).join(findings_summary)}

Responda em JSON estrito:
{{
  "injected_tools": {{"PXX": ["tool1"]}},   // ferramentas extras por fase futura, baseadas nas evidências
  "payloads_hint": ["payload sugerido 1", "..."],
  "reasoning": "1-2 frases explicando seu raciocínio"
}}

Apenas JSON. Sem texto adicional."""
    try:
        _model, raw = _call_learning_llm(prompt)
        if not raw:
            return None
        parsed = _extract_json_object(raw) if hasattr(_extract_json_object, "__call__") else {}
        if not isinstance(parsed, dict):
            return None
        # Sanitize
        injected = parsed.get("injected_tools") if isinstance(parsed.get("injected_tools"), dict) else {}
        payloads = parsed.get("payloads_hint") if isinstance(parsed.get("payloads_hint"), list) else []
        reasoning = str(parsed.get("reasoning") or "")[:300]
        return {
            "injected_tools": {str(k): [str(t) for t in (v or [])] for k, v in injected.items()},
            "payloads_hint": [str(p) for p in payloads[:8]],
            "reasoning": reasoning,
            "source_phase": phase_id,
        }
    except Exception:  # noqa: BLE001
        return None


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
    elif auth_type == "login_flow":
        # Execute the login flow once; cached headers stored in state
        # under '_login_flow_cache' so we don't re-login every phase.
        cached = state.get("_login_flow_cache") or {}
        if cached.get("ok") and cached.get("headers"):
            return dict(cached["headers"])
        try:
            from app.services.login_flow import execute_login_flow
            result = execute_login_flow(cfg.get("login_flow") or {})
            state["_login_flow_cache"] = result
            if result.get("ok"):
                return dict(result.get("headers") or {})
        except Exception:  # noqa: BLE001
            return {}
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


# ─────────────────────────────────────────────────────────────────────────────
# 9. Tier 4 — Asset DAG, incremental state, continuous reporting
# ─────────────────────────────────────────────────────────────────────────────

# Phase dependency graph: which phases must complete before each phase can start.
# Used by build_asset_dag to mark phases as "ready" vs "pending" (blocked by deps).
_PHASE_DEPS: dict[str, list[str]] = {
    "P01": [],
    "P02": ["P01"],
    "P03": ["P02"],
    "P04": ["P03"],
    "P05": ["P03"],
    "P06": ["P03"],
    "P07": ["P02"],
    "P08": ["P05", "P06"],
    "P09": ["P07", "P08"],
    "P10": ["P09"],
    "P11": ["P10"],
    "P12": ["P10", "P11"],
    "P13": ["P12"],
    "P14": ["P12"],
    "P15": ["P04"],
    "P16": ["P15"],
    "P17": ["P16"],
    "P18": ["P06"],
    "P19": ["P17", "P18"],
    "P20": ["P19"],
    "P21": ["P20"],
    "P22": ["P21"],
}

# Re-trigger policy: which downstream phases should be re-queued when a class
# of new evidence appears.  Used by detect_incremental_changes.
_NEW_TARGET_TRIGGERS = ["P02", "P03", "P04", "P05", "P06", "P07", "P08", "P09"]
_NEW_PORT_TRIGGERS = ["P03", "P05", "P07", "P09"]
_NEW_TECH_TRIGGERS = ["P07", "P08", "P09"]


def build_asset_dag(
    state: dict[str, Any],
    targets: list[str],
    phase_order: list[str],
) -> dict[str, Any]:
    """Build or update the per-asset phase DAG stored in state["asset_dag"].

    Each target gets an entry with per-phase status (completed / skipped / ready /
    pending) and coverage metrics.  Calling this incrementally merges new targets
    into the existing DAG without resetting already-completed entries.
    """
    completed = set(state.get("completed_work") or [])
    skipped_keys = {
        f"{s['phase_id']}:{s['target']}"
        for s in (state.get("skipped_work") or [])
        if isinstance(s, dict) and s.get("phase_id") and s.get("target")
    }
    host_ip = dict(state.get("host_ip_map") or {})
    tech_stack = state.get("tech_stack") or {}
    existing_dag = dict(state.get("asset_dag") or {})

    dag: dict[str, Any] = dict(existing_dag)
    for target in targets:
        phases: dict[str, dict[str, Any]] = {}
        for phase_id in phase_order:
            key = f"{phase_id}:{target}"
            if key in completed:
                status = "skipped" if key in skipped_keys else "completed"
            else:
                deps = _PHASE_DEPS.get(phase_id, [])
                deps_done = all(f"{d}:{target}" in completed for d in deps)
                status = "ready" if deps_done else "pending"
            phases[phase_id] = {"status": status, "deps": _PHASE_DEPS.get(phase_id, [])}

        n_done = sum(1 for p in phases.values() if p["status"] in ("completed", "skipped"))
        n_total = len(phase_order)
        asset_status = (
            "completed" if n_done == n_total
            else "in_progress" if n_done > 0
            else "pending"
        )
        dag[target] = {
            "status": asset_status,
            "phases": phases,
            "phases_completed": n_done,
            "phases_total": n_total,
            "coverage_pct": round(n_done / max(1, n_total) * 100, 1),
            "ip": host_ip.get(target),
            "open_ports": list(state.get("discovered_ports") or [])[:20],
            "tech_detected": list(tech_stack.get("detected") or [])[:10],
            "discovered_by": existing_dag.get(target, {}).get("discovered_by", "root"),
        }
    return dag


def detect_incremental_changes(
    prev_targets: list[str],
    curr_targets: list[str],
    prev_ports: list[int],
    curr_ports: list[int],
    prev_tech: list[str],
    curr_tech: list[str],
    source_phase: str,
) -> dict[str, Any]:
    """Detect new assets / ports / technologies that appeared after a phase.

    Returns a change record suitable for appending to state["incremental_changes"].
    The triggered_phases field indicates which phases the runner should re-queue
    for new assets (the actual re-queuing is handled by the existing fanout).
    """
    new_targets = [t for t in curr_targets if t and t not in set(prev_targets)]
    new_ports = [p for p in curr_ports if p not in set(prev_ports)]
    new_tech = [t for t in curr_tech if t and t not in set(prev_tech)]

    if new_targets:
        triggered = list(_NEW_TARGET_TRIGGERS)
    elif new_ports:
        triggered = list(_NEW_PORT_TRIGGERS)
    elif new_tech:
        triggered = list(_NEW_TECH_TRIGGERS)
    else:
        triggered = []

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_phase": source_phase,
        "new_targets": new_targets[:50],
        "new_ports": new_ports[:50],
        "new_tech": new_tech[:20],
        "triggered_phases": triggered,
        "has_changes": bool(new_targets or new_ports or new_tech),
    }


def emit_partial_report(
    state: dict[str, Any],
    phase_ledgers: list[dict[str, Any]],
    all_targets: list[str],
    phase_order: list[str],
) -> dict[str, Any]:
    """Build a lightweight scan snapshot for continuous / incremental reporting.

    Appended to state["scan_reports"] so the frontend can poll for live progress
    without waiting for scan completion.
    """
    completed = set(state.get("completed_work") or [])
    total_units = max(1, len(all_targets) * len(phase_order))
    done_units = len(completed)

    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    tools_used: set[str] = set()
    for ledger in phase_ledgers:
        if not isinstance(ledger, dict):
            continue
        for tool in (ledger.get("tools_success") or []):
            tools_used.add(str(tool))
        for mcp in (ledger.get("mcp_results") or []):
            if not isinstance(mcp, dict):
                continue
            parsed = mcp.get("parsed_result")
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    info = item.get("info") or {}
                    sev = str(
                        info.get("severity") or item.get("severity") or "info"
                    ).lower()
                    if sev in sev_counts:
                        sev_counts[sev] += 1

    # Count targets that have at least one completed non-P01 phase
    active_targets = len({
        wk.split(":")[1]
        for wk in completed
        if ":" in wk and not wk.startswith("P01:")
    })

    dag = state.get("asset_dag") or {}
    dag_summary = {
        t: {
            "coverage_pct": dag[t]["coverage_pct"],
            "status": dag[t]["status"],
            "phases_completed": dag[t]["phases_completed"],
        }
        for t in list(dag.keys())[:20]
    }

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phases_completed": done_units,
        "phases_total": total_units,
        "coverage_pct": round(done_units / total_units * 100, 1),
        "targets_active": active_targets,
        "targets_total": len(all_targets),
        "findings": dict(sev_counts),
        "tools_used": sorted(tools_used)[:30],
        "asset_dag_summary": dag_summary,
        "tech_detected": list((state.get("tech_stack") or {}).get("detected") or [])[:10],
        "incremental_changes_count": len(state.get("incremental_changes") or []),
    }
