"""
findings_extractor.py — bridge between work-queue tool results and Finding records.

The work queue (scan_work_items) runs tools through Kali but never called the
tool parsers in graph/tool_parsers.py, so 0 findings were created from whatweb,
curl-headers, shodan-cli, httpx, nmap, nuclei, etc.

This module provides:
  persist_findings_from_work_item(db, item, job) — called by poll_scan_work_item
  when a work item reaches terminal status "completed".

Architecture
────────────
  ScanWorkItem.result = {
      "stdout_preview": "<up to 3 000 chars of raw tool output>",
      "parsed_result":  <structured JSON from Kali runner, or null>,
      "exit_code":      0 | non-zero,
      ...
  }

  For each tool we prefer `parsed_result` when it carries structured data
  (httpx, shodan-cli, nuclei*), otherwise we fall back to `stdout_preview`.
  The existing parsers in graph/tool_parsers.py are reused for text-output tools.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

# ─────────────────────────────────────────────────────────────────────────────
# Re-use existing parsers from the LangGraph path
# ─────────────────────────────────────────────────────────────────────────────
from app.graph.tool_parsers import (
    _extract_curl_headers_findings,
    _extract_wafw00f_findings,
    _extract_whatweb_findings,
    _extract_nikto_findings,
    _extract_ffuf_findings,
    _extract_gobuster_findings,
    _extract_dalfox_findings,
    _extract_wapiti_findings,
    _extract_sqlmap_findings,
    _extract_katana_findings,
    _extract_amass_findings,
    _extract_dnsenum_findings,
    _extract_nmap_vulscan_findings,
    _extract_shodan_findings,
)

# ─────────────────────────────────────────────────────────────────────────────
# New parsers for structured Kali-runner outputs
# ─────────────────────────────────────────────────────────────────────────────


def _extract_httpx_findings(
    parsed_result: Any, stdout: str, target: str
) -> list[dict[str, Any]]:
    """
    Parse httpx JSON output.  The Kali runner returns a list of dicts like:
    [{
        "url": "http://example.com", "status_code": 200, "title": "...",
        "tech": ["Cloudflare"], "cdn": true,
        "tls": {"cipher": "TLS_AES_128_GCM_SHA256", "issuer_cn": "...", ...},
        "a": ["172.66.147.243"], ...
    }]
    """
    findings: list[dict[str, Any]] = []
    rows: list[dict] = []
    if isinstance(parsed_result, list):
        rows = [r for r in parsed_result if isinstance(r, dict)]
    elif isinstance(parsed_result, dict):
        rows = [parsed_result]
    else:
        # try stdout as JSON-lines
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except (json.JSONDecodeError, ValueError):
                pass

    for row in rows:
        url = str(row.get("url") or target)
        status_code = row.get("status_code") or row.get("status")
        title = str(row.get("title") or "").strip()
        tech = list(row.get("tech") or row.get("technologies") or [])
        cdn = bool(row.get("cdn"))
        tls = dict(row.get("tls") or {})
        a_records = list(row.get("a") or row.get("ips") or [])
        scheme = url.split("://")[0] if "://" in url else "http"

        # Technology stack finding
        if tech:
            tech_str = ", ".join(str(t) for t in tech)
            findings.append({
                "title": f"Stack tecnológico detectado: {tech_str}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "recon",
                "details": {
                    "node": "recon",
                    "step": "httpx_probe",
                    "asset": url,
                    "tool": "httpx",
                    "evidence": f"httpx -tech-detect: {tech_str}",
                    "technologies": tech,
                    "http_title": title,
                    "http_status": status_code,
                    "cdn_detected": cdn,
                    "ip_addresses": a_records,
                },
            })

        # CDN / WAF detection
        if cdn or any("cloudflare" in str(t).lower() for t in tech):
            waf_tech = next((t for t in tech if "cloudflare" in str(t).lower()), "CDN/WAF")
            findings.append({
                "title": f"CDN/WAF detectado: {waf_tech}",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "recon",
                "details": {
                    "node": "recon",
                    "step": "httpx_probe",
                    "asset": url,
                    "tool": "httpx",
                    "evidence": f"CDN presente: {waf_tech}",
                    "waf_vendor": str(waf_tech),
                    "cdn_detected": True,
                },
            })

        # TLS info
        if tls and scheme in ("https", "http"):
            cipher = str(tls.get("cipher") or "")
            issuer = str(tls.get("issuer_cn") or tls.get("issuer_dn") or "")
            serial = str(tls.get("serial") or "")
            weak = any(w in cipher.upper() for w in ("RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"))
            findings.append({
                "title": f"TLS configurado em {url}",
                "severity": "medium" if weak else "info",
                "risk_score": 5 if weak else 1,
                "source_worker": "recon",
                "details": {
                    "node": "recon",
                    "step": "httpx_probe",
                    "asset": url,
                    "tool": "httpx",
                    "evidence": f"Cipher: {cipher} | Issuer: {issuer}",
                    "tls_cipher": cipher,
                    "tls_issuer": issuer,
                    "tls_serial": serial,
                    "weak_cipher": weak,
                    "owasp_category": "A02:2021 Cryptographic Failures" if weak else "",
                },
            })

        # HTTP response
        if status_code:
            findings.append({
                "title": f"Host HTTP ativo: {url} [{status_code}]",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "recon",
                "details": {
                    "node": "recon",
                    "step": "httpx_probe",
                    "asset": url,
                    "tool": "httpx",
                    "evidence": f"{url} respondeu {status_code} — {title}",
                    "http_status": status_code,
                    "http_title": title,
                    "ip_addresses": a_records,
                },
            })

    return findings


def _extract_shodan_kali_findings(
    parsed_result: Any, stdout: str, target: str
) -> list[dict[str, Any]]:
    """
    Parse the Kali runner's shodan_lookup.py output format:
    {
        "ip": "...", "isp": "...", "org": "...", "host": "...",
        "ports": [80, 443, ...],
        "vulns": ["CVE-2021-xxxx", ...],  # or []
        "banners": [{"port": 80, "banner": "..."}]
    }
    """
    findings: list[dict[str, Any]] = []
    data: dict = {}

    if isinstance(parsed_result, dict):
        data = parsed_result
    elif isinstance(parsed_result, list) and parsed_result:
        data = parsed_result[0] if isinstance(parsed_result[0], dict) else {}
    else:
        # Try the legacy Shodan API format via existing parser
        return _extract_shodan_findings(stdout, "shodan_lookup", target)

    if not data:
        return findings

    ip = str(data.get("ip") or "")
    isp = str(data.get("isp") or "")
    org = str(data.get("org") or "")
    host = str(data.get("host") or target)
    ports = list(data.get("ports") or [])
    vulns = list(data.get("vulns") or [])
    banners = list(data.get("banners") or [])

    # Open ports finding
    if ports:
        ports_str = ", ".join(str(p) for p in sorted(ports))
        # Flag interesting ports
        interesting = [p for p in ports if p not in (80, 443)]
        severity = "medium" if interesting else "info"
        risk_score = 4 if interesting else 1
        notes = ""
        if interesting:
            notes = f" — portas não-padrão expostas: {', '.join(str(p) for p in interesting)}"
        findings.append({
            "title": f"Portas expostas (Shodan): {host} — {len(ports)} portas",
            "severity": severity,
            "risk_score": risk_score,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": "shodan_lookup",
                "asset": host,
                "tool": "shodan-cli",
                "evidence": f"IP {ip} ({org}/{isp}): ports {ports_str}{notes}",
                "ip_address": ip,
                "isp": isp,
                "org": org,
                "open_ports": ports,
                "interesting_ports": interesting,
                "owasp_category": "A05:2021 Security Misconfiguration" if interesting else "",
            },
        })

    # Banners — look for server/version info
    server_banners: list[str] = []
    for b in banners:
        if not isinstance(b, dict):
            continue
        banner_text = str(b.get("banner") or "")
        port = b.get("port", "")
        # Extract Server header
        match = re.search(r"(?i)^Server:\s*(.+)$", banner_text, re.MULTILINE)
        if match:
            server_val = match.group(1).strip()
            server_banners.append(f"Port {port}: {server_val}")
    if server_banners:
        findings.append({
            "title": f"Informação de servidor exposta em cabeçalhos HTTP (Shodan)",
            "severity": "low",
            "risk_score": 2,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": "shodan_lookup",
                "asset": host,
                "tool": "shodan-cli",
                "evidence": " | ".join(server_banners[:5]),
                "server_headers": server_banners[:20],
                "owasp_category": "A05:2021 Security Misconfiguration",
            },
        })

    # CVEs from Shodan
    for vuln_entry in vulns:
        cve_id = str(vuln_entry or "").upper().strip()
        if not cve_id.startswith("CVE-"):
            continue
        findings.append({
            "title": cve_id,
            "severity": "high",  # conservative default; enrichment will refine
            "risk_score": 7,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": "shodan_lookup",
                "asset": host,
                "tool": "shodan-cli",
                "evidence": f"{cve_id} reportado pelo Shodan para {ip}",
                "cve_id": cve_id,
                "ip_address": ip,
            },
        })

    return findings


def _extract_nmap_findings(
    stdout: str, step_name: str, target: str
) -> list[dict[str, Any]]:
    """Parse nmap text output — open ports, service versions, NSE vuln results."""
    findings: list[dict[str, Any]] = []
    if not stdout:
        return findings

    # Extract open ports — match PORT/PROTO  STATE  SERVICE [VERSION]
    # Stop version at any trailing NSE script output (e.g., |_http-server-header:...)
    port_pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open)\s+(\S+)(?:\s+([^\n|]+?))?(?:\s*\|.*)?$",
        re.MULTILINE,
    )
    open_ports: list[dict] = []
    seen_ports: set[int] = set()
    for m in port_pattern.finditer(stdout):
        port_num = int(m.group(1))
        if port_num in seen_ports:
            continue
        seen_ports.add(port_num)
        proto = m.group(2)
        service = m.group(4).strip()
        version = (m.group(5) or "").strip()
        # Skip generic placeholders as "versions"
        if version.lower() in ("", "tcpwrapped", "unknown", service.lower()):
            version = ""
        open_ports.append({
            "port": port_num,
            "proto": proto,
            "service": service,
            "version": version,
        })

    if open_ports:
        ports_summary = ", ".join(
            f"{p['port']}/{p['proto']} ({p['service']})" for p in open_ports
        )
        interesting = [p for p in open_ports if p["port"] not in (80, 443)]
        severity = "medium" if interesting else "info"

        # Server version disclosure
        version_disclosures = [p for p in open_ports if p["version"]]
        if version_disclosures:
            for p in version_disclosures:
                findings.append({
                    "title": f"Versão de serviço exposta: {p['service']} {p['version']} (porta {p['port']})",
                    "severity": "low",
                    "risk_score": 3,
                    "source_worker": "recon",
                    "details": {
                        "node": "recon",
                        "step": step_name,
                        "asset": target,
                        "tool": "nmap",
                        "evidence": f"Port {p['port']}/{p['proto']}: {p['service']} {p['version']}",
                        "port": p["port"],
                        "protocol": p["proto"],
                        "service": p["service"],
                        "version": p["version"],
                        "owasp_category": "A05:2021 Security Misconfiguration",
                    },
                })

        findings.append({
            "title": f"Portas abertas detectadas: {target} ({len(open_ports)} porta{'s' if len(open_ports) > 1 else ''})",
            "severity": severity,
            "risk_score": 4 if interesting else 1,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": target,
                "tool": "nmap",
                "evidence": ports_summary,
                "open_ports": open_ports,
                "interesting_ports": interesting,
                "owasp_category": "A05:2021 Security Misconfiguration" if interesting else "",
            },
        })

    # NSE vuln script results (|_ lines with CVE patterns)
    cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    nse_vulns = cve_pattern.findall(stdout)
    for cve_id in set(nse_vulns):
        findings.append({
            "title": cve_id.upper(),
            "severity": "high",
            "risk_score": 7,
            "source_worker": "vuln",
            "details": {
                "node": "vuln",
                "step": step_name,
                "asset": target,
                "tool": "nmap",
                "evidence": f"{cve_id.upper()} encontrado em output nmap",
                "cve_id": cve_id.upper(),
                "owasp_category": "A06:2021 Vulnerable and Outdated Components",
            },
        })

    return findings


def _extract_nuclei_findings(
    parsed_result: Any, stdout: str, target: str, tool_name: str = "nuclei"
) -> list[dict[str, Any]]:
    """
    Parse nuclei JSON-lines output.
    Each line: {"template-id": "...", "info": {"name":..., "severity":..., "tags":[...]},
                "matched-at": "https://...", "type": "http", ...}
    """
    findings: list[dict[str, Any]] = []
    rows: list[dict] = []

    if isinstance(parsed_result, list):
        rows = [r for r in parsed_result if isinstance(r, dict)]
    elif isinstance(parsed_result, dict):
        rows = [parsed_result]

    # Also parse stdout as JSON-lines (handles cases where parsed_result is empty)
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "template-id" in obj:
                rows.append(obj)
        except (json.JSONDecodeError, ValueError):
            pass

    for row in rows:
        template_id = str(row.get("template-id") or row.get("template") or "")
        info = dict(row.get("info") or {})
        name = str(info.get("name") or template_id)
        severity_raw = str(info.get("severity") or "info").lower()
        tags = list(info.get("tags") or [])
        matched_at = str(row.get("matched-at") or row.get("url") or target)
        result_type = str(row.get("type") or "")
        description = str(info.get("description") or "").strip()
        remediation = str(info.get("remediation") or "").strip()

        # Map nuclei severity
        severity_map = {
            "critical": "critical", "high": "high",
            "medium": "medium", "low": "low", "info": "info"
        }
        severity = severity_map.get(severity_raw, "info")
        risk_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
        risk_score = risk_map.get(severity, 1)

        # CVE in tags or template-id
        cve_match = re.search(r"CVE-\d{4}-\d+", template_id + " " + " ".join(tags), re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        findings.append({
            "title": name or template_id,
            "severity": severity,
            "risk_score": risk_score,
            "source_worker": "vuln",
            "details": {
                "node": "vuln",
                "step": tool_name,
                "asset": matched_at,
                "tool": tool_name,
                "evidence": f"Nuclei template {template_id} matched at {matched_at}",
                "template_id": template_id,
                "nuclei_tags": tags,
                "result_type": result_type,
                "description": description,
                "remediation": remediation,
                "cve_id": cve_id,
                "matched_at": matched_at,
                "owasp_category": _nuclei_tags_to_owasp(tags),
            },
        })

    return findings


def _nuclei_tags_to_owasp(tags: list[str]) -> str:
    tag_str = " ".join(str(t) for t in tags).lower()
    if "sqli" in tag_str or "sql" in tag_str:
        return "A03:2021 Injection"
    if "xss" in tag_str:
        return "A03:2021 Injection"
    if "lfi" in tag_str or "traversal" in tag_str:
        return "A01:2021 Broken Access Control"
    if "ssrf" in tag_str:
        return "A10:2021 Server-Side Request Forgery"
    if "exposure" in tag_str or "disclosure" in tag_str:
        return "A05:2021 Security Misconfiguration"
    if "auth" in tag_str or "bypass" in tag_str:
        return "A07:2021 Identification and Authentication Failures"
    if "cve" in tag_str:
        return "A06:2021 Vulnerable and Outdated Components"
    if "takeover" in tag_str:
        return "A05:2021 Security Misconfiguration"
    if "cors" in tag_str:
        return "A01:2021 Broken Access Control"
    return "A05:2021 Security Misconfiguration"


def _extract_theharvester_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse theHarvester text output — emails, hosts, IPs discovered."""
    findings: list[dict[str, Any]] = []
    if not stdout:
        return findings

    emails: list[str] = []
    hosts: list[str] = []
    ips: list[str] = []

    in_emails = in_hosts = in_ips = False
    for line in stdout.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if "[*] emails found" in lower or "emails found" in lower:
            in_emails, in_hosts, in_ips = True, False, False
            continue
        if "[*] hosts found" in lower or "ips found" in lower or "interesting" in lower:
            in_hosts, in_emails = True, False
            if "ips" in lower:
                in_ips, in_hosts = True, False
            continue
        if stripped.startswith("[") and not stripped.startswith("[*]"):
            in_emails = in_hosts = in_ips = False

        if in_emails and "@" in stripped and len(stripped) < 200:
            emails.append(stripped)
        elif in_hosts and "." in stripped and stripped and not stripped.startswith("---"):
            if not any(c in stripped for c in (" ", "/")):
                hosts.append(stripped)
        elif in_ips and re.match(r"^\d+\.\d+\.\d+\.\d+$", stripped):
            ips.append(stripped)

    if emails:
        findings.append({
            "title": f"E-mails corporativos expostos publicamente: {len(emails)} encontrados",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": "theharvester",
                "asset": target,
                "tool": "theharvester",
                "evidence": "\n".join(emails[:20]),
                "discovered_emails": emails[:50],
                "count": len(emails),
                "owasp_category": "A01:2021 Broken Access Control",
                "impact": "Emails corporativos expostos facilitam phishing dirigido, credential stuffing e engenharia social.",
                "remediation": "Avaliar exposição via OSINT periódico, treinar colaboradores e monitorar uso indevido de identidade.",
            },
        })

    if hosts:
        findings.append({
            "title": f"Hosts adicionais descobertos via OSINT: {len(hosts)} hospeito(s)",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": "theharvester",
                "asset": target,
                "tool": "theharvester",
                "evidence": "\n".join(hosts[:20]),
                "discovered_hosts": hosts[:100],
                "count": len(hosts),
            },
        })

    return findings


def _extract_gospider_hakrawler_findings(
    stdout: str, target: str, tool_name: str
) -> list[dict[str, Any]]:
    """Parse gospider/hakrawler URL output."""
    findings: list[dict[str, Any]] = []
    urls: list[str] = []
    sensitive: list[str] = []
    admin_paths: list[str] = []

    sensitive_patterns = re.compile(
        r"(password|passwd|secret|api.key|token|access_key|aws|s3|\.env|\.bak|\.sql|config|backup)",
        re.IGNORECASE,
    )
    admin_patterns = re.compile(
        r"(/admin|/api/|/internal|/manage|/dashboard|/login|/auth|/graphql|/wp-admin)",
        re.IGNORECASE,
    )

    for line in (stdout or "").splitlines():
        url = line.strip()
        if not url or not url.startswith("http"):
            # gospider adds prefixes like "[url]" or "[javascript]"
            m = re.search(r"https?://\S+", url)
            if m:
                url = m.group(0)
            else:
                continue
        urls.append(url)
        if sensitive_patterns.search(url):
            sensitive.append(url)
        if admin_patterns.search(url):
            admin_paths.append(url)

    if urls:
        findings.append({
            "title": f"URLs descobertas pelo crawler ({tool_name}): {len(urls)} endpoints",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": "\n".join(urls[:20]),
                "discovered_urls": urls[:200],
                "count": len(urls),
            },
        })
    if sensitive:
        findings.append({
            "title": f"Parâmetros/caminhos sensíveis detectados no crawl: {len(sensitive)} URLs",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": "\n".join(sensitive[:10]),
                "sensitive_urls": sensitive[:50],
                "owasp_category": "A05:2021 Security Misconfiguration",
            },
        })
    if admin_paths:
        findings.append({
            "title": f"Endpoints administrativos/API expostos: {len(admin_paths)} caminhos",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": "\n".join(admin_paths[:10]),
                "admin_paths": admin_paths[:50],
                "owasp_category": "A01:2021 Broken Access Control",
            },
        })

    return findings


def _extract_gitleaks_trufflehog_findings(
    stdout: str, target: str, tool_name: str
) -> list[dict[str, Any]]:
    """Parse gitleaks/trufflehog secret findings."""
    findings: list[dict[str, Any]] = []
    secrets: list[str] = []

    for line in (stdout or "").splitlines():
        lower = line.lower()
        if any(kw in lower for kw in (
            "secret", "token", "password", "api_key", "aws_access", "private_key",
            "credential", "auth", "leak", "found", "match"
        )):
            secrets.append(line.strip()[:300])

    if secrets:
        findings.append({
            "title": f"Possível vazamento de segredos detectado ({tool_name}): {len(secrets)} ocorrência(s)",
            "severity": "critical",
            "risk_score": 10,
            "source_worker": "vuln",
            "details": {
                "node": "vuln",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": "\n".join(secrets[:10]),
                "matches": secrets[:30],
                "owasp_category": "A02:2021 Cryptographic Failures / A07:2021 Identification and Authentication Failures",
                "impact": "Chaves de API, tokens e senhas expostos permitem acesso não autorizado imediato a sistemas internos.",
                "remediation": "Revogar imediatamente credenciais expostas, implementar git-secrets/pre-commit hooks e varredura periódica de repositórios.",
            },
        })

    return findings


def _extract_waybackurls_gau_findings(
    stdout: str, target: str, tool_name: str
) -> list[dict[str, Any]]:
    """Parse waybackurls / gau URL discovery output."""
    findings: list[dict[str, Any]] = []
    urls: list[str] = []
    interesting: list[str] = []

    interesting_patterns = re.compile(
        r"(\?|&)(id=|user=|pass|token|key|admin|redirect|debug|test|secret|api)",
        re.IGNORECASE,
    )

    for line in (stdout or "").splitlines():
        url = line.strip()
        if url.startswith("http"):
            urls.append(url)
            if interesting_patterns.search(url):
                interesting.append(url)

    if urls:
        findings.append({
            "title": f"URLs históricas descobertas ({tool_name}): {len(urls)} endpoints",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": f"{len(urls)} URLs encontradas no histórico",
                "discovered_urls": urls[:200],
                "count": len(urls),
            },
        })
    if interesting:
        findings.append({
            "title": f"Parâmetros sensíveis em URLs históricas ({tool_name}): {len(interesting)} URLs",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": "\n".join(interesting[:10]),
                "sensitive_urls": interesting[:50],
                "owasp_category": "A01:2021 Broken Access Control",
                "impact": "URLs históricas com parâmetros sensíveis podem indicar endpoints legados com controles mais fracos.",
            },
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Main dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def extract_findings_from_work_item(
    tool_name: str,
    target: str,
    phase_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Route a completed work item result to the appropriate parser.
    Returns a list of finding dicts (not yet persisted to DB).
    """
    stdout = str(result.get("stdout_preview") or "").strip()
    parsed = result.get("parsed_result")
    step = f"{phase_id}.{tool_name}"
    tool = tool_name.lower().strip()

    findings: list[dict[str, Any]] = []

    try:
        # ── Structured-output tools (prefer parsed_result) ──────────────────
        if tool == "httpx":
            findings = _extract_httpx_findings(parsed, stdout, target)

        elif tool == "shodan-cli":
            findings = _extract_shodan_kali_findings(parsed, stdout, target)

        elif tool in ("nuclei",) or tool.startswith("nuclei-"):
            findings = _extract_nuclei_findings(parsed, stdout, target, tool_name=tool)

        # ── Text-output tools (stdout_preview) ──────────────────────────────
        elif tool == "whatweb" or tool == "whatweb-basic":
            findings = _extract_whatweb_findings(stdout, step, target)

        elif tool == "curl-headers":
            findings = _extract_curl_headers_findings(stdout, step, target)

        elif tool == "wafw00f":
            findings = _extract_wafw00f_findings(stdout, step, target)

        elif tool in ("nmap", "nmap-http", "nmap-smb", "nmap-ssh", "nmap-dns"):
            findings = _extract_nmap_findings(stdout, step, target)

        elif tool == "nmap-vuln":
            # nmap-vuln can have CVE output — try vulscan parser first, then plain nmap
            vf = _extract_nmap_vulscan_findings(stdout, step, target)
            nf = _extract_nmap_findings(stdout, step, target)
            findings = vf + nf

        elif tool == "nmap-ssl":
            # SSL-specific nmap — check for weak ciphers / cert issues
            findings = _extract_nmap_findings(stdout, step, target)

        elif tool == "nikto":
            findings = _extract_nikto_findings(stdout, step, target)

        elif tool in ("ffuf", "ffuf-params", "ffuf-content"):
            findings = _extract_ffuf_findings(stdout, step, target)

        elif tool in ("gobuster", "feroxbuster", "dirsearch"):
            findings = _extract_gobuster_findings(stdout, step, target)

        elif tool == "dalfox":
            findings = _extract_dalfox_findings(stdout, step, target)

        elif tool == "wapiti":
            findings = _extract_wapiti_findings(stdout, step, target)

        elif tool == "sqlmap":
            findings = _extract_sqlmap_findings(stdout, step, target)

        elif tool in ("katana", "katana-js"):
            findings = _extract_katana_findings(stdout, step, target)

        elif tool in ("amass", "amass-brute", "amass-intel"):
            findings = _extract_amass_findings(stdout, step, target)

        elif tool in ("dnsenum", "dnsrecon-brt", "dnsrecon-zt"):
            findings = _extract_dnsenum_findings(stdout, step, target)

        elif tool == "theharvester":
            findings = _extract_theharvester_findings(stdout, target)

        elif tool in ("gospider", "hakrawler"):
            findings = _extract_gospider_hakrawler_findings(stdout, target, tool)

        elif tool in ("gitleaks", "trufflehog"):
            findings = _extract_gitleaks_trufflehog_findings(stdout, target, tool)

        elif tool in ("waybackurls", "gau"):
            findings = _extract_waybackurls_gau_findings(stdout, target, tool)

    except Exception as exc:  # noqa: BLE001
        # Never let parser failure crash the work queue
        import logging
        logging.getLogger(__name__).warning(
            "findings_extractor: parser error tool=%s target=%s: %s", tool, target, exc
        )

    # Inject standard fields missing from some parsers
    for f in findings:
        details = dict(f.get("details") or {})
        if not details.get("tool"):
            details["tool"] = tool
        if not details.get("asset"):
            details["asset"] = target
        if not details.get("phase_id"):
            details["phase_id"] = phase_id
        f["details"] = details

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# DB persistence
# ─────────────────────────────────────────────────────────────────────────────

def persist_findings_from_work_item(
    db: Session,
    item: Any,  # ScanWorkItem
    job: Any,   # ScanJob
) -> int:
    """
    Extract findings from a completed work item and persist them to the DB.
    Deduplicates by (scan_job_id, title, domain, tool).
    Returns the number of new findings created.
    """
    from app.models.models import Finding

    result = dict(item.result or {})
    tool = str(item.tool_name or "")
    target = str(item.target or "")
    phase_id = str(item.phase_id or "")

    raw_findings = extract_findings_from_work_item(tool, target, phase_id, result)
    if not raw_findings:
        return 0

    created = 0
    for f in raw_findings:
        title = str(f.get("title") or "").strip()[:500]
        severity = str(f.get("severity") or "info").lower()
        risk_score = int(f.get("risk_score") or 1)
        details = dict(f.get("details") or {})
        tool_col = str(details.get("tool") or tool)[:100]
        domain_col = str(details.get("asset") or target)[:255]

        if not title:
            continue

        # CVE-level dedup: one CVE per target domain, regardless of tool
        if cve_id:
            cve_exists = (
                db.query(Finding.id)
                .filter(
                    Finding.scan_job_id == job.id,
                    Finding.cve == cve_id,
                    Finding.domain == domain_col,
                )
                .first()
            )
            if cve_exists:
                continue

        # Generic dedup: skip if (scan_job_id, title, domain, tool) already exists
        exists = (
            db.query(Finding.id)
            .filter(
                Finding.scan_job_id == job.id,
                Finding.title == title,
                Finding.domain == domain_col,
                Finding.tool == tool_col,
            )
            .first()
        )
        if exists:
            continue

        cve_id: str | None = None
        cve_raw = str(details.get("cve_id") or "").strip().upper()
        if cve_raw.startswith("CVE-"):
            cve_id = cve_raw

        try:
            cvss_val: float | None = float(details["cvss"])
        except (KeyError, TypeError, ValueError):
            cvss_val = None

        finding = Finding(
            scan_job_id=job.id,
            title=title,
            severity=severity,
            cve=cve_id,
            cvss=cvss_val,
            domain=domain_col,
            tool=tool_col,
            risk_score=risk_score,
            confidence_score=50,
            details=details,
            created_at=datetime.utcnow(),
        )
        db.add(finding)
        try:
            db.flush()
            created += 1
        except Exception:
            db.rollback()

    if created:
        db.commit()

    return created
