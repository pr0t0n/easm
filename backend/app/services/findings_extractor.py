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
            tls_version = str(tls.get("tls_version") or "").lower()
            mismatched = bool(tls.get("mismatched"))
            subject_cn = str(tls.get("subject_cn") or "")
            weak = any(w in cipher.upper() for w in ("RC4", "DES", "3DES", "EXPORT", "NULL", "MD5"))

            # TLS version risk
            old_tls = tls_version in ("tls10", "tls1.0", "tls 1.0") or "tls10" in tls_version
            very_old_tls = tls_version in ("ssl2", "ssl3", "ssl30", "sslv2", "sslv3")
            tls_sev = "high" if very_old_tls else ("medium" if old_tls or weak else "info")
            tls_risk = 7 if very_old_tls else (5 if old_tls or weak else 1)

            if old_tls or very_old_tls:
                findings.append({
                    "title": f"Protocolo TLS obsoleto em uso: {tls_version.upper()} em {url}",
                    "severity": tls_sev,
                    "risk_score": tls_risk,
                    "source_worker": "recon",
                    "details": {
                        "node": "recon",
                        "step": "httpx_probe",
                        "asset": url,
                        "tool": "httpx",
                        "evidence": f"Versão TLS detectada: {tls_version} — vulnerável a ataques BEAST/POODLE",
                        "tls_version": tls_version,
                        "tls_cipher": cipher,
                        "tls_issuer": issuer,
                        "owasp_category": "A02:2021 Cryptographic Failures",
                        "remediation": "Desabilitar TLS 1.0/1.1/SSL e configurar apenas TLS 1.2+",
                    },
                })
            elif weak:
                findings.append({
                    "title": f"Cipher TLS fraco detectado em {url}",
                    "severity": "medium",
                    "risk_score": 5,
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
                        "weak_cipher": True,
                        "owasp_category": "A02:2021 Cryptographic Failures",
                        "remediation": "Desabilitar ciphers fracos (RC4, DES, 3DES, EXPORT, NULL, MD5)",
                    },
                })
            else:
                findings.append({
                    "title": f"TLS configurado em {url}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "recon",
                    "details": {
                        "node": "recon",
                        "step": "httpx_probe",
                        "asset": url,
                        "tool": "httpx",
                        "evidence": f"Cipher: {cipher} | Issuer: {issuer} | Version: {tls_version}",
                        "tls_cipher": cipher,
                        "tls_version": tls_version,
                        "tls_issuer": issuer,
                        "tls_serial": serial,
                    },
                })

            # Certificate mismatch — subdomain takeover candidate or misconfiguration
            if mismatched and subject_cn and subject_cn != url.split("://")[-1].split("/")[0]:
                findings.append({
                    "title": f"Certificado TLS divergente (mismatch) em {url}",
                    "severity": "medium",
                    "risk_score": 5,
                    "source_worker": "recon",
                    "details": {
                        "node": "recon",
                        "step": "httpx_probe",
                        "asset": url,
                        "tool": "httpx",
                        "evidence": (
                            f"Domínio '{url}' apresenta cert emitido para '{subject_cn}' "
                            f"(issuer: {issuer}) — possível subdomain takeover ou misconfiguration"
                        ),
                        "cert_subject": subject_cn,
                        "cert_issuer": issuer,
                        "cert_mismatched": True,
                        "owasp_category": "A05:2021 Security Misconfiguration",
                        "remediation": (
                            "Verificar se o subdomínio está apontando para serviço de terceiro "
                            "sem controle do certificado. Possível candidate de subdomain takeover."
                        ),
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

    # Cloudflare proxy ports — estas são portas do proxy Cloudflare, não do servidor de origem.
    # Quando o IP pertence à Cloudflare, essas portas não representam superfície real do alvo.
    CLOUDFLARE_PROXY_PORTS = {2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880}
    is_cloudflare = any(kw in (org + isp).lower() for kw in ("cloudflare", "cloud flare"))

    # Open ports finding
    if ports:
        # Filter out Cloudflare-owned proxy ports when behind Cloudflare
        real_ports = ports
        cloudflare_filtered: list[int] = []
        if is_cloudflare:
            cloudflare_filtered = [p for p in ports if int(p) in CLOUDFLARE_PROXY_PORTS]
            real_ports = [p for p in ports if int(p) not in CLOUDFLARE_PROXY_PORTS]

        ports_str = ", ".join(str(p) for p in sorted(real_ports or ports))
        interesting = [p for p in real_ports if p not in (80, 443)]

        if real_ports:
            severity = "medium" if interesting else "info"
            risk_score = 4 if interesting else 1
            notes = ""
            if interesting:
                notes = f" — portas não-padrão expostas: {', '.join(str(p) for p in interesting)}"
            if cloudflare_filtered:
                notes += f" (Cloudflare proxy: {len(cloudflare_filtered)} portas excluídas)"
            findings.append({
                "title": f"Portas expostas (Shodan): {host} — {len(real_ports)} portas",
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
                    "open_ports": real_ports,
                    "interesting_ports": interesting,
                    "cloudflare_filtered_ports": cloudflare_filtered,
                    "is_cloudflare_proxy": is_cloudflare,
                    "owasp_category": "A05:2021 Security Misconfiguration" if interesting else "",
                },
            })
        elif cloudflare_filtered:
            # All ports were Cloudflare proxy — report as info with context
            findings.append({
                "title": f"Host atrás de Cloudflare (Shodan): {host} — apenas portas do proxy Cloudflare visíveis",
                "severity": "info",
                "risk_score": 1,
                "source_worker": "osint",
                "details": {
                    "node": "osint",
                    "step": "shodan_lookup",
                    "asset": host,
                    "tool": "shodan-cli",
                    "evidence": f"IP {ip} ({org}): todas as {len(ports)} portas são do proxy Cloudflare — origem real oculta",
                    "ip_address": ip,
                    "cloudflare_proxy_ports": cloudflare_filtered,
                    "is_cloudflare_proxy": True,
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

    # NSE vuln script results — parse port-contextual CVE blocks
    # Split output into per-port blocks so each CVE is linked to its port/service
    cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

    # Build a map: port_info → [cve_ids found in its NSE block]
    # Strategy: split output on port header lines, then scan each block for CVEs
    port_block_pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+([^\n|]+))?",
        re.MULTILINE,
    )

    # Find all port header positions
    port_blocks: list[tuple[int, int, str, str, str]] = []  # (start, port, proto, service, version)
    for m in port_block_pattern.finditer(stdout):
        port_blocks.append((m.start(), int(m.group(1)), m.group(2), m.group(3).strip(), (m.group(4) or "").strip()))

    # For each CVE in the full output, determine which port block it belongs to
    cve_port_map: dict[str, dict] = {}  # cve_id → port context dict
    for cve_m in cve_pattern.finditer(stdout):
        cve_id = cve_m.group(0).upper()
        cve_pos = cve_m.start()
        # Find the last port block that started before this CVE position
        port_ctx = {"port": None, "proto": "tcp", "service": "unknown", "version": ""}
        for (blk_start, port_num, proto, service, version) in reversed(port_blocks):
            if blk_start <= cve_pos:
                port_ctx = {"port": port_num, "proto": proto, "service": service, "version": version}
                break
        # Keep highest-context match (prefer port-linked over generic)
        if cve_id not in cve_port_map or port_ctx["port"] is not None:
            cve_port_map[cve_id] = port_ctx

    for cve_id, port_ctx in cve_port_map.items():
        port_num = port_ctx.get("port")
        service = port_ctx.get("service", "unknown")
        version = port_ctx.get("version", "")
        proto = port_ctx.get("proto", "tcp")

        # Build contextual evidence
        if port_num:
            port_label = f"porta {port_num}/{proto}"
            service_label = f"{service} {version}".strip() if version else service
            evidence = f"{cve_id} — {port_label} ({service_label}) em {target}"
        else:
            evidence = f"{cve_id} encontrado em output nmap para {target}"

        findings.append({
            "title": cve_id,
            "severity": "high",
            "risk_score": 7,
            "source_worker": "vuln",
            "details": {
                "node": "vuln",
                "step": step_name,
                "asset": target,
                "tool": "nmap",
                "evidence": evidence,
                "cve_id": cve_id,
                "port": port_num,
                "protocol": proto,
                "service": service,
                "service_version": version,
                "port_context": f"{port_num}/{proto} ({service_label})" if port_num else None,
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

        # ── CVSS score from nuclei classification block ────────────────────────
        # Nuclei templates include CVSS in info.classification.cvss-score
        # Example: {"info": {"classification": {"cvss-score": 9.8, "cvss-metrics": "CVSS:3.1/AV:N/..."}}}
        cvss_score: float | None = None
        try:
            _cls = dict(info.get("classification") or {})
            _cs_raw = (
                _cls.get("cvss-score")
                or _cls.get("cvss_score")
                or info.get("cvss-score")
                or info.get("cvss_score")
            )
            if _cs_raw is not None:
                cvss_score = float(_cs_raw)
        except (ValueError, TypeError):
            pass

        # ── Extracted result fields (matched content, curl output, etc.) ──────
        extracted_results = dict(row.get("extracted-results") or row.get("extracted_results") or {})
        curl_command = str(row.get("curl-command") or row.get("curl_command") or "").strip()

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
                "cvss": cvss_score,
                "curl_command": curl_command or None,
                "extracted_results": extracted_results or None,
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
# ZAP parser — converts ZAP JSON alerts to platform findings
# ─────────────────────────────────────────────────────────────────────────────

def _extract_zap_findings(
    parsed: Any,
    stdout: str,
    target: str,
    tool_name: str = "zap_baseline",
) -> list[dict[str, Any]]:
    """
    Convert ZAP Automation Framework JSON report to platform Finding dicts.

    ZAP JSON report format (json-plus template):
    {
      "site": [
        {"alerts": [
          {
            "name": "...",
            "riskdesc": "High (Confirmed)",
            "confidence": "High",
            "desc": "...",
            "solution": "...",
            "reference": "...",
            "cweid": "79",
            "wascid": "8",
            "instances": [{"uri": "...", "evidence": "..."}],
            "count": 3
          }
        ]}
      ]
    }
    """
    findings: list[dict[str, Any]] = []

    # parsed_result might be the full JSON dict or just the alerts list
    alerts_data = None
    if isinstance(parsed, dict):
        if "alerts" in parsed:
            # Direct alerts dict from our zap_json parser
            alerts_data = parsed.get("alerts", [])
        elif "site" in parsed:
            # Full ZAP report format
            for site in (parsed.get("site") or []):
                if isinstance(site, list):
                    for s in site:
                        alerts_data = (alerts_data or []) + (s.get("alerts") or [])
                elif isinstance(site, dict):
                    alerts_data = (alerts_data or []) + (site.get("alerts") or [])

    # Fallback: try to parse stdout for JSON block
    if alerts_data is None and stdout:
        start = stdout.find("[ZAP-REPORT-START]")
        end = stdout.find("[ZAP-REPORT-END]")
        if start != -1 and end != -1:
            try:
                block = stdout[start + len("[ZAP-REPORT-START]"):end].strip()
                data = json.loads(block)
                alerts_data = data.get("alerts", [])
            except (json.JSONDecodeError, AttributeError):
                pass

    if not alerts_data:
        return findings

    severity_map = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
        "info": "info",
        "false positive": "info",
    }
    risk_score_map = {"high": 7, "medium": 5, "low": 2, "info": 1}

    for alert in alerts_data:
        if not isinstance(alert, dict):
            continue

        name = str(alert.get("title") or alert.get("name") or "").strip()
        if not name:
            continue

        risk_desc = str(alert.get("riskdesc") or alert.get("risk") or "Informational")
        risk_level = risk_desc.split(" ")[0].lower()
        severity = severity_map.get(risk_level, "low")
        risk_score = risk_score_map.get(severity, 2)

        evidence = str(alert.get("evidence") or "")[:1000]
        uri = str(alert.get("uri") or target)
        description = str(alert.get("description") or alert.get("desc") or "")
        solution = str(alert.get("solution") or "")
        reference = str(alert.get("reference") or "")
        cwe = str(alert.get("cwe") or alert.get("cweid") or "")
        count = int(alert.get("count") or 1)

        # Compute domain from target or URI
        domain = target
        if uri and uri.startswith("http"):
            from urllib.parse import urlparse as _urlparse
            try:
                domain = _urlparse(uri).hostname or target
            except Exception:
                pass

        title = f"[ZAP] {name}"

        findings.append({
            "title": title[:500],
            "severity": severity,
            "risk_score": risk_score,
            "details": {
                "tool": tool_name,
                "asset": target,
                "zap_alert_name": name,
                "risk": risk_desc,
                "confidence": str(alert.get("confidence") or "Medium"),
                "description": description[:2000],
                "solution": solution[:1000],
                "reference": reference[:500],
                "cwe_id": cwe,
                "evidence": evidence,
                "uri": uri[:500],
                "instance_count": count,
                "owasp_category": _zap_cwe_to_owasp(cwe),
                "source": "zap",
            },
        })

    return findings


def _zap_cwe_to_owasp(cwe_id: str) -> str:
    """Map CWE ID to OWASP Top 10 2021 category."""
    mapping = {
        "79": "A03:2021 Injection (XSS)",
        "89": "A03:2021 Injection (SQLi)",
        "78": "A03:2021 Injection (Command Injection)",
        "22": "A01:2021 Broken Access Control (Path Traversal)",
        "352": "A01:2021 Broken Access Control (CSRF)",
        "601": "A01:2021 Broken Access Control (Open Redirect)",
        "200": "A02:2021 Cryptographic Failures (Information Exposure)",
        "319": "A02:2021 Cryptographic Failures (Cleartext Transmission)",
        "16": "A05:2021 Security Misconfiguration",
        "693": "A05:2021 Security Misconfiguration (Missing Security Headers)",
        "1021": "A04:2021 Insecure Design (Clickjacking/X-Frame-Options)",
        "614": "A02:2021 Cryptographic Failures (Insecure Cookie)",
        "1004": "A02:2021 Cryptographic Failures (Cookie without HttpOnly)",
    }
    return mapping.get(str(cwe_id).strip(), f"CWE-{cwe_id}" if cwe_id else "")


# ─────────────────────────────────────────────────────────────────────────────
# LinkFinder parser — JS endpoint extractor
# ─────────────────────────────────────────────────────────────────────────────

def _extract_linkfinder_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse linkfinder output — extracts API endpoints from JS bundles.

    LinkFinder outputs one URL/path per line, with optional context:
      /api/v1/users
      /api/v2/admin/config
      https://internal.example.com/api/token
    """
    findings: list[dict[str, Any]] = []
    if not stdout:
        return findings

    endpoints: list[str] = []
    sensitive_endpoints: list[str] = []
    api_endpoints: list[str] = []

    _sensitive_patterns = re.compile(
        r"(admin|config|secret|token|key|auth|login|password|internal|private|debug|test|upload|webhook|graphql)",
        re.IGNORECASE,
    )
    _api_patterns = re.compile(r"/api/|/v\d+/|/rest/|/graphql|/swagger|/openapi", re.IGNORECASE)

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Accept paths (/api/...) and full URLs
        if line.startswith("/") or line.startswith("http"):
            endpoints.append(line)
            if _sensitive_patterns.search(line):
                sensitive_endpoints.append(line)
            if _api_patterns.search(line):
                api_endpoints.append(line)

    if endpoints:
        findings.append({
            "title": f"JS Endpoint Analysis: {len(endpoints)} endpoints extraídos de bundles JS",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": "linkfinder",
                "asset": target,
                "tool": "linkfinder",
                "evidence": f"{len(endpoints)} endpoints encontrados em bundles JS do target",
                "discovered_endpoints": endpoints[:200],
                "count": len(endpoints),
                "owasp_category": "A01:2021 Broken Access Control",
            },
        })

    if sensitive_endpoints:
        findings.append({
            "title": f"Endpoints Sensíveis em JS: {len(sensitive_endpoints)} rotas com padrões críticos",
            "severity": "medium",
            "risk_score": 6,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": "linkfinder",
                "asset": target,
                "tool": "linkfinder",
                "evidence": "\n".join(sensitive_endpoints[:10]),
                "sensitive_endpoints": sensitive_endpoints[:50],
                "impact": (
                    "Endpoints com padrões sensíveis (admin, token, key, secret) descobertos em "
                    "bundles JS de produção — podem revelar rotas não documentadas ou "
                    "endpoints de administração acessíveis sem autenticação."
                ),
                "owasp_category": "A05:2021 Security Misconfiguration",
                "remediation": (
                    "Remover rotas sensíveis de bundles JS de produção. "
                    "Verificar se endpoints /api/admin/* exigem autenticação. "
                    "Considerar split code loading para ocultar rotas administrativas."
                ),
            },
        })

    if api_endpoints:
        findings.append({
            "title": f"API Endpoints Descobertos em JS: {len(api_endpoints)} rotas de API",
            "severity": "low",
            "risk_score": 3,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": "linkfinder",
                "asset": target,
                "tool": "linkfinder",
                "evidence": "\n".join(api_endpoints[:10]),
                "api_endpoints": api_endpoints[:100],
                "impact": "Mapa de superfície de API extraído — usar como input para P16 (API Input Review).",
                "owasp_category": "A01:2021 Broken Access Control",
            },
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain discovery tools (subfinder / findomain / assetfinder / alterx / shuffledns / dnsx)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_subdomain_discovery_findings(
    stdout: str, target: str, tool_name: str
) -> list[dict[str, Any]]:
    """Parse one-subdomain-per-line output from subfinder, findomain, assetfinder, alterx, dnsx, shuffledns."""
    findings: list[dict[str, Any]] = []
    subdomains: list[str] = []
    for line in (stdout or "").splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#") or " " in s:
            continue
        # Accept hostnames and IPs; reject URLs (have ://)
        if "://" in s:
            try:
                from urllib.parse import urlparse as _up
                s = _up(s).hostname or ""
            except Exception:
                continue
        if s and "." in s and len(s) < 255:
            subdomains.append(s)

    if not subdomains:
        return findings

    root = target.lower().lstrip("*.")
    new_subs = [s for s in subdomains if s != root and s.endswith(f".{root}")]

    if subdomains:
        findings.append({
            "title": f"Subdomínios descobertos ({tool_name}): {len(subdomains)} host(s)",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": "\n".join(subdomains[:30]),
                "discovered_subdomains": subdomains[:500],
                "count": len(subdomains),
                "new_subdomains": new_subs[:100],
            },
        })

    # High-value subdomain patterns — admin, dev, staging, API surfaces
    _HV_PATTERNS = re.compile(
        r"(admin|api|dev|staging|hml|test|internal|intranet|auth|sso|jenkins|"
        r"gitlab|grafana|kibana|portainer|rancher|vault|consul|redis|mongo|"
        r"elastic|kafka|rabbitmq|flower|harbor|registry|nexus|jira|confluence)",
        re.IGNORECASE,
    )
    hv = [s for s in subdomains if _HV_PATTERNS.search(s)]
    if hv:
        findings.append({
            "title": f"Subdomínios de alto valor descobertos ({tool_name}): {len(hv)} host(s)",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": "\n".join(hv[:20]),
                "high_value_subdomains": hv[:100],
                "owasp_category": "A05:2021 Security Misconfiguration",
                "impact": "Subdomínios de infraestrutura expostos podem conter painéis administrativos, serviços internos e interfaces de gestão sem autenticação forte.",
            },
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Parameter discovery (arjun / paramspider)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_param_discovery_findings(
    stdout: str, target: str, tool_name: str
) -> list[dict[str, Any]]:
    """Parse arjun JSON output or paramspider one-URL-per-line output."""
    findings: list[dict[str, Any]] = []

    # arjun JSON: {"https://target.com/path": ["param1", "param2", ...], ...}
    # or list of {url, params} dicts
    parsed_json = None
    try:
        parsed_json = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        pass

    params_by_url: dict[str, list[str]] = {}

    if isinstance(parsed_json, dict):
        for url, params in parsed_json.items():
            if isinstance(params, list):
                params_by_url[str(url)] = [str(p) for p in params]
    elif isinstance(parsed_json, list):
        for item in parsed_json:
            if isinstance(item, dict):
                url = str(item.get("url") or item.get("endpoint") or "")
                params = list(item.get("params") or item.get("parameters") or [])
                if url and params:
                    params_by_url[url] = [str(p) for p in params]

    # paramspider / text fallback: one URL-with-params per line
    if not params_by_url:
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            if "?" in line or "&" in line:
                from urllib.parse import urlparse as _up2, parse_qs as _pq
                try:
                    _p = _up2(line)
                    _params = list(_pq(_p.query).keys())
                    if _params:
                        base = f"{_p.scheme}://{_p.netloc}{_p.path}"
                        params_by_url.setdefault(base, []).extend(_params)
                except Exception:
                    pass

    if not params_by_url:
        return findings

    all_params: list[str] = []
    for ps in params_by_url.values():
        all_params.extend(ps)
    unique_params = list(dict.fromkeys(all_params))

    # Flag injection-relevant parameters
    _INJECT_PATTERNS = re.compile(
        r"^(id|user|uid|username|email|name|search|q|query|url|redirect|"
        r"file|path|page|lang|locale|callback|return|next|ref|token|key|"
        r"debug|admin|cmd|exec|input|data|payload|format|type|action|"
        r"order|sort|filter|limit|offset|start|end|from|to|cat|category)$",
        re.IGNORECASE,
    )
    injectable = [p for p in unique_params if _INJECT_PATTERNS.match(p)]

    findings.append({
        "title": f"Parâmetros HTTP descobertos ({tool_name}): {len(unique_params)} parâmetros em {len(params_by_url)} endpoints",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": tool_name,
            "asset": target,
            "tool": tool_name,
            "evidence": f"{len(unique_params)} parâmetros: {', '.join(unique_params[:20])}",
            "parameters_by_url": {k: v for k, v in list(params_by_url.items())[:50]},
            "all_parameters": unique_params[:200],
            "count": len(unique_params),
        },
    })

    if injectable:
        findings.append({
            "title": f"Parâmetros injetáveis detectados ({tool_name}): {len(injectable)} candidatos a SQLi/XSS/SSRF",
            "severity": "medium",
            "risk_score": 6,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": tool_name,
                "asset": target,
                "tool": tool_name,
                "evidence": f"Parâmetros de alto risco: {', '.join(injectable[:15])}",
                "injectable_parameters": injectable[:50],
                "owasp_category": "A03:2021 Injection",
                "impact": "Parâmetros como id, user, url, redirect, file, cmd são vetores primários de injeção. Requerem testes ativos (sqlmap, dalfox) nas fases P10/P12.",
                "remediation": "Validar e sanitizar todos os parâmetros de entrada. Usar prepared statements para SQL. Implementar allowlist de valores para parâmetros de redirecionamento.",
            },
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# WPScan — WordPress vulnerability scanner
# ─────────────────────────────────────────────────────────────────────────────

def _extract_wpscan_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse wpscan JSON output (wpscan --format json).

    wpscan JSON structure:
    {
      "target_url": "https://...",
      "version": {"number": "6.4.1", "vulnerabilities": [...]},
      "plugins": {"plugin-slug": {"vulnerabilities": [...], "version": {...}}},
      "themes": {"theme-slug": {"vulnerabilities": [...]}},
      "users": [{"username": "admin", ...}],
      "interesting_findings": [{"type": "...", "url": "...", "interesting_entries": [...]}]
    }
    """
    findings: list[dict[str, Any]] = []

    data: dict = {}
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        # Try to find JSON block in mixed output
        m = re.search(r"\{.*\}", stdout or "", re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(0))
            except Exception:
                pass

    if not data:
        return findings

    target_url = str(data.get("target_url") or target)

    # WordPress version
    version_info = dict(data.get("version") or {})
    wp_version = str(version_info.get("number") or "")
    if wp_version:
        wp_vulns = list(version_info.get("vulnerabilities") or [])
        sev = "high" if wp_vulns else "info"
        findings.append({
            "title": f"WordPress {wp_version} detectado{f' ({len(wp_vulns)} CVE(s))' if wp_vulns else ''}",
            "severity": sev,
            "risk_score": 7 if wp_vulns else 1,
            "source_worker": "vuln",
            "details": {
                "node": "vuln", "step": "wpscan", "asset": target_url, "tool": "wpscan",
                "evidence": f"WP {wp_version}" + (f" — {len(wp_vulns)} vulnerabilidades" if wp_vulns else ""),
                "wordpress_version": wp_version,
                "version_vulnerabilities": wp_vulns[:10],
                "owasp_category": "A06:2021 Vulnerable and Outdated Components",
            },
        })
        for vuln in wp_vulns[:20]:
            cve = str(vuln.get("references", {}).get("cve", [""]) or [""])[0] if isinstance(vuln.get("references", {}).get("cve"), list) else ""
            findings.append({
                "title": str(vuln.get("title") or f"WP Core CVE {cve}")[:300],
                "severity": "high",
                "risk_score": 8,
                "source_worker": "vuln",
                "details": {
                    "node": "vuln", "step": "wpscan", "asset": target_url, "tool": "wpscan",
                    "evidence": str(vuln.get("title") or ""),
                    "cve_id": f"CVE-{cve}" if cve else None,
                    "fixed_in": str(vuln.get("fixed_in") or ""),
                    "owasp_category": "A06:2021 Vulnerable and Outdated Components",
                },
            })

    # Plugins with vulnerabilities
    plugins = dict(data.get("plugins") or {})
    for slug, plug_data in list(plugins.items())[:50]:
        if not isinstance(plug_data, dict):
            continue
        plug_vulns = list(plug_data.get("vulnerabilities") or [])
        if not plug_vulns:
            continue
        plug_version = str((plug_data.get("version") or {}).get("number") or "")
        for vuln in plug_vulns[:10]:
            cve_list = (vuln.get("references") or {}).get("cve") or []
            cve = f"CVE-{cve_list[0]}" if cve_list else None
            findings.append({
                "title": str(vuln.get("title") or f"Plugin {slug} vulnerável")[:300],
                "severity": "high",
                "risk_score": 8,
                "source_worker": "vuln",
                "details": {
                    "node": "vuln", "step": "wpscan", "asset": target_url, "tool": "wpscan",
                    "evidence": f"Plugin {slug} {plug_version}: {vuln.get('title', '')}",
                    "plugin_slug": slug, "plugin_version": plug_version,
                    "cve_id": cve, "fixed_in": str(vuln.get("fixed_in") or ""),
                    "owasp_category": "A06:2021 Vulnerable and Outdated Components",
                },
            })

    # Usernames (enumeration)
    users = list(data.get("users") or {})
    if users:
        usernames = [str(u.get("username") or u) for u in users if u][:20]
        findings.append({
            "title": f"Usernames WordPress enumerados: {', '.join(usernames[:5])}{'…' if len(usernames) > 5 else ''}",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "vuln",
            "details": {
                "node": "vuln", "step": "wpscan", "asset": target_url, "tool": "wpscan",
                "evidence": f"Usuários descobertos via wpscan: {', '.join(usernames)}",
                "discovered_users": usernames,
                "owasp_category": "A07:2021 Identification and Authentication Failures",
                "impact": "Usernames expostos permitem ataques direcionados de brute-force contra /wp-login.php.",
            },
        })

    # Interesting findings (backup files, XML-RPC, readme, etc.)
    interesting = list(data.get("interesting_findings") or [])
    for item in interesting[:20]:
        if not isinstance(item, dict):
            continue
        itype = str(item.get("type") or "")
        iurl = str(item.get("url") or target_url)
        entries = list(item.get("interesting_entries") or [])
        sev = "medium" if itype in ("xmlrpc", "backup", "readme") else "low"
        findings.append({
            "title": f"WordPress: {itype} exposto em {iurl}",
            "severity": sev,
            "risk_score": 5 if sev == "medium" else 2,
            "source_worker": "vuln",
            "details": {
                "node": "vuln", "step": "wpscan", "asset": iurl, "tool": "wpscan",
                "evidence": "\n".join(str(e) for e in entries[:5]),
                "finding_type": itype,
                "url": iurl,
                "owasp_category": "A05:2021 Security Misconfiguration",
            },
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# TLS/SSL testers (testssl / sslscan)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_testssl_findings(
    stdout: str, target: str, tool_name: str = "testssl"
) -> list[dict[str, Any]]:
    """Parse testssl.sh or sslscan text output.

    testssl uses severity labels: CRITICAL, HIGH, MEDIUM, LOW, INFO, OK, WARN
    sslscan uses: SSLv2, SSLv3, BEAST, POODLE, Heartbleed, etc.
    """
    findings: list[dict[str, Any]] = []
    if not stdout:
        return findings

    # Try JSON first (testssl --jsonfile or --json flag)
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict):
            for _id, result in (data.get("scanResult") or [{}])[0].items() if isinstance((data.get("scanResult") or [{}])[0], dict) else []:
                sev_raw = str(result.get("severity") or "").upper()
                finding_str = str(result.get("finding") or "")
                if sev_raw in ("CRITICAL", "HIGH") and finding_str and "not vulnerable" not in finding_str.lower():
                    sev = "critical" if sev_raw == "CRITICAL" else "high"
                    findings.append({
                        "title": f"TLS: {_id} — {finding_str[:120]}",
                        "severity": sev, "risk_score": 9 if sev == "critical" else 7,
                        "source_worker": "vuln",
                        "details": {
                            "node": "vuln", "step": tool_name, "asset": target, "tool": tool_name,
                            "evidence": finding_str[:500], "testssl_id": _id,
                            "owasp_category": "A02:2021 Cryptographic Failures",
                        },
                    })
        if findings:
            return findings
    except (json.JSONDecodeError, ValueError, IndexError, TypeError):
        pass

    # Text output parsing
    # testssl: "VULNERABLE_ID      CRITICAL  finding text"
    # sslscan headers like "SSLv3 enabled", "BEAST:", "Heartbleed:"

    _SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "warn": "low"}
    _VULN_PATTERNS = [
        (re.compile(r"HEARTBLEED", re.I), "critical", "Heartbleed (CVE-2014-0160) — informação de memória exposta"),
        (re.compile(r"POODLE", re.I), "high", "POODLE attack — SSLv3 downgrade"),
        (re.compile(r"BEAST", re.I), "medium", "BEAST attack — CBC cipher vulnerability"),
        (re.compile(r"CRIME", re.I), "high", "CRIME attack — TLS compression"),
        (re.compile(r"BREACH", re.I), "medium", "BREACH attack — HTTP compression"),
        (re.compile(r"FREAK", re.I), "high", "FREAK attack — export cipher downgrade"),
        (re.compile(r"LOGJAM", re.I), "high", "LOGJAM attack — DH parameter weakness"),
        (re.compile(r"ROBOT", re.I), "high", "ROBOT attack — RSA PKCS#1 v1.5 oracle"),
        (re.compile(r"SSLv2.*enabled|enabled.*SSLv2", re.I), "critical", "SSLv2 habilitado — protocolo obsoleto"),
        (re.compile(r"SSLv3.*enabled|enabled.*SSLv3", re.I), "high", "SSLv3 habilitado — POODLE attack possível"),
        (re.compile(r"TLSv1\.0.*enabled|TLS 1\.0.*enabled", re.I), "medium", "TLS 1.0 habilitado — protocolo deprecated"),
        (re.compile(r"RC4|DES\b|3DES|EXPORT|NULL cipher|ANON", re.I), "high", "Cipher fraco ou inseguro habilitado"),
        (re.compile(r"self.signed|self signed", re.I), "medium", "Certificado autoassinado"),
        (re.compile(r"certificate.*expired|expired.*certificate", re.I), "high", "Certificado TLS expirado"),
        (re.compile(r"OCSP stapling.*not supported", re.I), "low", "OCSP Stapling não suportado"),
    ]

    seen: set[str] = set()
    for pattern, sev, title in _VULN_PATTERNS:
        if pattern.search(stdout):
            key = title[:50]
            if key not in seen:
                seen.add(key)
                findings.append({
                    "title": f"TLS/{tool_name}: {title}",
                    "severity": sev,
                    "risk_score": {"critical": 9, "high": 7, "medium": 5, "low": 3}.get(sev, 3),
                    "source_worker": "vuln",
                    "details": {
                        "node": "vuln", "step": tool_name, "asset": target, "tool": tool_name,
                        "evidence": pattern.pattern,
                        "owasp_category": "A02:2021 Cryptographic Failures",
                        "remediation": "Desabilitar protocolos e ciphers inseguros. Configurar TLS 1.2+ com ciphers modernos (AES-GCM, ChaCha20-Poly1305).",
                    },
                })

    # testssl structured lines: "ID  SEVERITY  finding"
    line_pattern = re.compile(r"^\s*(\w[\w_-]*)\s+(CRITICAL|HIGH|MEDIUM|WARN|LOW)\s+(.+)$", re.MULTILINE)
    for m in line_pattern.finditer(stdout):
        tid, sev_raw, finding = m.group(1), m.group(2).lower(), m.group(3).strip()
        if "not vulnerable" in finding.lower() or "OK" in finding or finding.startswith("--"):
            continue
        sev = _SEVERITY_MAP.get(sev_raw, "low")
        key = f"{tid}:{finding[:40]}"
        if key not in seen:
            seen.add(key)
            findings.append({
                "title": f"TLS/{tool_name} [{tid}]: {finding[:150]}",
                "severity": sev,
                "risk_score": {"critical": 9, "high": 7, "medium": 5, "low": 3}.get(sev, 3),
                "source_worker": "vuln",
                "details": {
                    "node": "vuln", "step": tool_name, "asset": target, "tool": tool_name,
                    "evidence": finding[:500], "testssl_id": tid,
                    "owasp_category": "A02:2021 Cryptographic Failures",
                },
            })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# JWT Tool parser
# ─────────────────────────────────────────────────────────────────────────────

def _extract_jwt_tool_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse jwt_tool output — alg:none, key confusion, weak secrets."""
    findings: list[dict[str, Any]] = []
    if not stdout:
        return findings

    _ATTACK_PATTERNS = [
        (re.compile(r"alg.*none.*success|none.*attack.*success|\[FOUND\].*none", re.I),
         "critical", "JWT Algorithm None — autenticação completamente bypassada",
         "Servidor aceita JWT com alg=none — qualquer token não assinado é válido. "
         "Atacante pode forjar qualquer identidade sem conhecer a chave secreta.",
         "CVE-2015-9235"),
        (re.compile(r"key.*confusion.*success|RS256.*HS256.*success|\[FOUND\].*confusion", re.I),
         "critical", "JWT Key Confusion (RS256→HS256) — bypass de verificação de assinatura",
         "Servidor trata chave pública RSA como segredo HMAC. Atacante usa chave pública "
         "para assinar tokens HS256 válidos.",
         None),
        (re.compile(r"weak.*secret.*found|cracked.*secret|\[FOUND\].*secret|jwt.*secret.*found", re.I),
         "critical", "JWT Secret Fraco — chave descoberta por brute-force",
         "Segredo HMAC do JWT é fraco e foi descoberto. Atacante pode forjar tokens válidos.",
         None),
        (re.compile(r"jwks.*inject|\[FOUND\].*jwks|jku.*inject", re.I),
         "high", "JWT JKU/JWKS Injection — chave de verificação controlada pelo atacante",
         "Servidor carrega chave pública do URL no header JWT (jku/x5u). "
         "Atacante fornece URL próprio com chave controlada.",
         None),
        (re.compile(r"kid.*inject|\[FOUND\].*kid|sql.*kid|path.*traversal.*kid", re.I),
         "high", "JWT Kid Injection — parâmetro kid explorável (SQLi/LFI)",
         "Campo kid do JWT header não sanitizado — pode ser usado para injeção SQL ou LFI.",
         None),
        (re.compile(r"expired.*accepted|exp.*not.*verified|expiry.*bypass", re.I),
         "high", "JWT Expiry Não Verificado — tokens expirados aceitos",
         "Servidor não verifica campo exp do JWT. Tokens expirados permanecem válidos indefinidamente.",
         None),
    ]

    for pattern, sev, title, impact, cve in _ATTACK_PATTERNS:
        if pattern.search(stdout):
            findings.append({
                "title": title,
                "severity": sev,
                "risk_score": 10 if sev == "critical" else 8,
                "source_worker": "vuln",
                "details": {
                    "node": "vuln", "step": "jwt_tool", "asset": target, "tool": "jwt_tool",
                    "evidence": stdout[:800],
                    "impact": impact,
                    "cve_id": cve,
                    "owasp_category": "A07:2021 Identification and Authentication Failures",
                    "remediation": "Verificar e forçar algoritmo esperado. Nunca aceitar alg=none. Usar segredos longos e aleatórios (256+ bits). Validar exp, iat, iss em todas as requisições.",
                },
            })

    if not findings and stdout.strip():
        # Generic: jwt_tool ran but no specific attack found — still log as candidate
        if "vulnerable" in stdout.lower() or "[+]" in stdout or "success" in stdout.lower():
            findings.append({
                "title": f"JWT — possível vulnerabilidade detectada pelo jwt_tool",
                "severity": "high",
                "risk_score": 7,
                "source_worker": "vuln",
                "details": {
                    "node": "vuln", "step": "jwt_tool", "asset": target, "tool": "jwt_tool",
                    "evidence": stdout[:600],
                    "owasp_category": "A07:2021 Identification and Authentication Failures",
                },
            })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# SAST tools (semgrep / bandit / trivy)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_semgrep_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse semgrep JSON output."""
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return findings

    results = list(data.get("results") or [])
    sev_map = {"error": "high", "warning": "medium", "info": "low"}

    for item in results[:100]:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("check_id") or "")
        msg = str(item.get("extra", {}).get("message") or item.get("message") or check_id)
        sev_raw = str(item.get("extra", {}).get("severity") or item.get("severity") or "warning").lower()
        sev = sev_map.get(sev_raw, "medium")
        path = str(item.get("path") or "")
        line = item.get("start", {}).get("line") or ""
        findings.append({
            "title": f"[semgrep] {msg[:200]}",
            "severity": sev,
            "risk_score": {"high": 7, "medium": 5, "low": 2}.get(sev, 2),
            "source_worker": "vuln",
            "details": {
                "node": "vuln", "step": "semgrep", "asset": target, "tool": "semgrep",
                "evidence": f"{path}:{line} — {msg[:300]}",
                "check_id": check_id, "file_path": path, "line": line,
                "owasp_category": "A03:2021 Injection",
            },
        })
    return findings


def _extract_bandit_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse bandit JSON output (Python SAST)."""
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return findings

    results = list(data.get("results") or [])
    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    for item in results[:100]:
        if not isinstance(item, dict):
            continue
        issue_text = str(item.get("issue_text") or "")
        sev_raw = str(item.get("issue_severity") or "LOW").upper()
        sev = sev_map.get(sev_raw, "low")
        test_id = str(item.get("test_id") or "")
        filename = str(item.get("filename") or "")
        line_no = item.get("line_number") or ""
        findings.append({
            "title": f"[bandit] {test_id}: {issue_text[:180]}",
            "severity": sev,
            "risk_score": {"high": 7, "medium": 4, "low": 2}.get(sev, 2),
            "source_worker": "vuln",
            "details": {
                "node": "vuln", "step": "bandit", "asset": target, "tool": "bandit",
                "evidence": f"{filename}:{line_no} — {issue_text[:400]}",
                "test_id": test_id, "file_path": filename, "line": line_no,
                "cwe": str(item.get("issue_cwe", {}).get("id") or ""),
                "owasp_category": "A03:2021 Injection",
            },
        })
    return findings


def _extract_trivy_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse trivy JSON output (container/IaC/package vulnerabilities)."""
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads((stdout or "").strip())
    except (json.JSONDecodeError, ValueError):
        return findings

    # trivy JSON: {"Results": [{"Target": "...", "Vulnerabilities": [...]}]}
    results = list(data.get("Results") or data.get("results") or [])
    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    for result in results:
        if not isinstance(result, dict):
            continue
        scan_target = str(result.get("Target") or target)
        vulns = list(result.get("Vulnerabilities") or [])
        for v in vulns[:50]:
            if not isinstance(v, dict):
                continue
            vuln_id = str(v.get("VulnerabilityID") or "")
            pkg = str(v.get("PkgName") or "")
            inst_ver = str(v.get("InstalledVersion") or "")
            fixed_ver = str(v.get("FixedVersion") or "")
            title = str(v.get("Title") or vuln_id)
            sev_raw = str(v.get("Severity") or "LOW").upper()
            sev = sev_map.get(sev_raw, "low")
            cvss = None
            try:
                cvss = float((v.get("CVSS") or {}).get("nvd", {}).get("V3Score") or 0) or None
            except (TypeError, ValueError):
                pass

            findings.append({
                "title": f"[trivy] {title[:200]}",
                "severity": sev,
                "risk_score": {"critical": 10, "high": 8, "medium": 5, "low": 2}.get(sev, 2),
                "source_worker": "vuln",
                "details": {
                    "node": "vuln", "step": "trivy", "asset": scan_target, "tool": "trivy",
                    "evidence": f"{pkg} {inst_ver} → {vuln_id}" + (f" (fix: {fixed_ver})" if fixed_ver else ""),
                    "cve_id": vuln_id if vuln_id.startswith("CVE-") else None,
                    "package": pkg, "installed_version": inst_ver, "fixed_version": fixed_ver,
                    "cvss": cvss,
                    "owasp_category": "A06:2021 Vulnerable and Outdated Components",
                },
            })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Port scanners (naabu / masscan)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_naabu_masscan_findings(
    stdout: str, target: str, tool_name: str
) -> list[dict[str, Any]]:
    """Parse naabu (host:port per line) and masscan (text/JSON) output."""
    findings: list[dict[str, Any]] = []
    open_ports: list[dict] = []

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # naabu: "host:port" or "ip:port"
        m = re.match(r"^([\w.\-:]+):(\d+)$", line)
        if m:
            host, port = m.group(1), int(m.group(2))
            open_ports.append({"host": host, "port": port, "proto": "tcp"})
            continue

        # masscan: "Discovered open port PORT/PROTO on HOST"
        m2 = re.search(r"open port (\d+)/(tcp|udp) on ([\d.]+)", line, re.I)
        if m2:
            open_ports.append({"host": m2.group(3), "port": int(m2.group(1)), "proto": m2.group(2)})
            continue

        # masscan JSON lines: {"ip": "...", "ports": [{"port": ..., "proto": ...}]}
        if line.startswith("{"):
            try:
                obj = json.loads(line.rstrip(","))
                if isinstance(obj, dict):
                    ip = str(obj.get("ip") or "")
                    for p in obj.get("ports") or []:
                        if isinstance(p, dict):
                            open_ports.append({"host": ip, "port": int(p.get("port") or 0), "proto": str(p.get("proto") or "tcp")})
            except (json.JSONDecodeError, ValueError):
                pass

    if not open_ports:
        return findings

    interesting = [p for p in open_ports if p["port"] not in (80, 443, 8080, 8443)]
    all_ports_str = ", ".join(f"{p['host']}:{p['port']}" for p in open_ports[:20])

    findings.append({
        "title": f"Portas abertas ({tool_name}): {len(open_ports)} porta(s) em {target}",
        "severity": "medium" if interesting else "info",
        "risk_score": 4 if interesting else 1,
        "source_worker": "recon",
        "details": {
            "node": "recon", "step": tool_name, "asset": target, "tool": tool_name,
            "evidence": all_ports_str,
            "open_ports": open_ports[:200],
            "interesting_ports": interesting[:50],
            "count": len(open_ports),
            "owasp_category": "A05:2021 Security Misconfiguration" if interesting else "",
        },
    })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Interactsh-client — OOB callback receiver
# ─────────────────────────────────────────────────────────────────────────────

def _extract_interactsh_findings(
    stdout: str, target: str
) -> list[dict[str, Any]]:
    """Parse interactsh-client output — OOB DNS/HTTP/SMTP callbacks.

    interactsh-client JSON line format:
    {"unique-id": "...", "full-id": "...", "q-type": "A", "raw-request": "...",
     "remote-address": "1.2.3.4", "timestamp": "...", "protocol": "dns"}
    """
    findings: list[dict[str, Any]] = []
    callbacks: list[dict] = []

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and obj.get("protocol"):
                callbacks.append(obj)
        except (json.JSONDecodeError, ValueError):
            # Plain text: "Got interaction from X.X.X.X"
            m = re.search(r"interaction.*?(\d+\.\d+\.\d+\.\d+)", line, re.I)
            if m:
                callbacks.append({"protocol": "dns", "remote-address": m.group(1), "raw": line})

    if not callbacks:
        return findings

    for cb in callbacks[:20]:
        proto = str(cb.get("protocol") or "dns").upper()
        remote = str(cb.get("remote-address") or "")
        raw_req = str(cb.get("raw-request") or cb.get("raw") or "")[:300]
        unique_id = str(cb.get("unique-id") or cb.get("full-id") or "")

        vuln_type = {
            "DNS": "SSRF/Blind SSRF confirmado via callback DNS OOB",
            "HTTP": "SSRF/RCE confirmado via callback HTTP OOB",
            "SMTP": "SSRF confirmado via callback SMTP OOB",
        }.get(proto, f"OOB callback {proto} recebido")

        findings.append({
            "title": f"{vuln_type} — IP {remote}",
            "severity": "critical",
            "risk_score": 10,
            "source_worker": "vuln",
            "details": {
                "node": "vuln", "step": "interactsh-client", "asset": target, "tool": "interactsh-client",
                "evidence": f"Callback {proto} recebido de {remote}: {raw_req}",
                "oob_callback": {"protocol": proto.lower(), "remote_address": remote, "interaction_id": unique_id},
                "owasp_category": "A10:2021 Server-Side Request Forgery",
                "impact": f"Callback OOB confirma que o servidor está realizando requisições externas. {proto} callback de {remote} prova execução do payload.",
                "verification_status": "confirmed",
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
    # Prefer full stdout (stored since findings_extractor v2); fall back to preview
    stdout = str(result.get("stdout_full") or result.get("stdout_preview") or "").strip()
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

        elif tool == "linkfinder":
            findings = _extract_linkfinder_findings(stdout, target)

        elif tool in ("nuclei-js-secrets", "nuclei-js-analysis"):
            # Route through nuclei parser — these are nuclei templates targeting JS files
            findings = _extract_nuclei_findings(None, stdout, target, tool_name=tool)

        elif tool in ("gitleaks", "trufflehog"):
            findings = _extract_gitleaks_trufflehog_findings(stdout, target, tool)

        elif tool in ("waybackurls", "gau"):
            findings = _extract_waybackurls_gau_findings(stdout, target, tool)

        elif tool in ("zap-baseline", "zap_baseline", "zap-ajax", "zap_ajax_spider",
                      "zap-active", "zap_active_scan", "zap-api", "zap_api_scan"):
            findings = _extract_zap_findings(parsed, stdout, target, tool)

        # ── Subdomain discovery tools ──────────────────────────────────────
        elif tool in ("subfinder", "findomain", "assetfinder", "alterx",
                      "shuffledns", "dnsx", "sublist3r"):
            findings = _extract_subdomain_discovery_findings(stdout, target, tool)

        # ── Parameter discovery ────────────────────────────────────────────
        elif tool in ("arjun", "paramspider"):
            findings = _extract_param_discovery_findings(stdout, target, tool)

        # ── WordPress scanner ──────────────────────────────────────────────
        elif tool == "wpscan":
            findings = _extract_wpscan_findings(stdout, target)

        # ── TLS/SSL testers ────────────────────────────────────────────────
        elif tool in ("testssl", "sslscan", "testssl.sh"):
            findings = _extract_testssl_findings(stdout, target, tool)

        # ── JWT tool ───────────────────────────────────────────────────────
        elif tool == "jwt_tool":
            findings = _extract_jwt_tool_findings(stdout, target)

        # ── SAST tools ─────────────────────────────────────────────────────
        elif tool == "semgrep":
            findings = _extract_semgrep_findings(stdout, target)
        elif tool == "bandit":
            findings = _extract_bandit_findings(stdout, target)
        elif tool == "trivy":
            findings = _extract_trivy_findings(stdout, target)

        # ── Port scanners (modern) ─────────────────────────────────────────
        elif tool in ("naabu", "masscan"):
            findings = _extract_naabu_masscan_findings(stdout, target, tool)

        # ── OOB callback receiver ──────────────────────────────────────────
        elif tool == "interactsh-client":
            findings = _extract_interactsh_findings(stdout, target)

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
        # ── Evidence gate + business impact scoring ────────────────────────
        # Ponto #4: marca verification_status (confirmed/candidate/hypothesis)
        # Ponto #5: ajusta risk_score com contexto de endpoint
        try:
            from app.services.evidence_gate import enrich_finding_with_gate
            f = enrich_finding_with_gate(f, tool_name=tool)
        except Exception:
            pass

        title = str(f.get("title") or "").strip()[:500]
        severity = str(f.get("severity") or "info").lower()
        risk_score = int(f.get("risk_score") or 1)
        details = dict(f.get("details") or {})
        tool_col = str(details.get("tool") or tool)[:100]
        domain_col = str(details.get("asset") or target)[:255]

        if not title:
            continue

        # Extract CVE id first (needed for dedup below)
        cve_id: str | None = None
        cve_raw = str(details.get("cve_id") or "").strip().upper()
        if cve_raw.startswith("CVE-"):
            cve_id = cve_raw

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

        try:
            cvss_val: float | None = float(details["cvss"])
        except (KeyError, TypeError, ValueError):
            cvss_val = None

        # Pull verification_status / url from enriched details
        v_status = str(details.get("verification_status") or "candidate")
        finding_url = str(
            f.get("url")
            or details.get("url")
            or details.get("matched-at")
            or ""
        )[:2000] or None

        # ── Confidence score: derived from tool reliability + verification status ──
        # TOOL_CONFIDENCE: base confidence per tool (0-100)
        # Replaces hardcoded 50 — now each tool contributes its known FP rate
        _TOOL_CONFIDENCE: dict[str, int] = {
            # Exploitation tools — direct proof
            "sqlmap": 90,           # SQL injection confirmed with payload
            "dalfox": 88,           # XSS confirmed with callback
            "wapiti": 75,           # Active exploitation attempt
            "wpscan": 80,           # Plugin version + CVE confirmed
            "gitleaks": 82,         # Pattern match in secret
            "trufflehog": 80,       # Entropy + pattern match
            "hydra": 85,            # Credential confirmed
            # Nuclei — depends on template type
            "nuclei": 70,           # Generic nuclei (matcher varies)
            # Discovery / recon tools
            "httpx": 85,            # HTTP probe — fact, not opinion
            "nmap": 75,             # Port scan — open port is fact
            "nmap-ssl": 78,         # SSL probe — cipher fact
            "nmap-http": 70,        # HTTP scripts — moderate reliability
            "nmap-vuln": 35,        # nmap vuln scripts — moderate FP rate
            "nmap-vulscan": 5,      # CVE version-match only, no exploit
            "nikto": 35,            # High FP rate historically
            "shodan-cli": 60,       # Passive intel — no direct test
            "curl-headers": 72,     # Header presence is fact; risk is opinion
            "wafw00f": 80,          # WAF detection — fairly reliable
            "whatweb": 75,          # Tech fingerprint — reliable
            "ffuf": 65,             # Directory brute — path found ≠ vuln
            "gobuster": 65,         # Same as ffuf
            "feroxbuster": 68,      # Slightly better status filtering
            "nuclei-sqli": 78,      # Nuclei SQLi template
            "nuclei-xss": 75,       # Nuclei XSS template
            "nuclei-ssrf": 72,      # Nuclei SSRF template
            "nuclei-rce": 80,       # Nuclei RCE template — high confidence
            "nuclei-auth": 75,      # Nuclei auth template
            "nuclei-lfi": 75,       # Nuclei LFI template
            "nuclei-exposure": 70,  # Nuclei exposure template
            "nuclei-jwt": 78,       # JWT template
            "nuclei-cors": 70,      # CORS template
            "nuclei-graphql": 76,   # GraphQL template
            "nuclei-default-credentials": 82,  # Default cred confirmed
            "nuclei-auth-bypass": 78,           # Auth bypass template
            "jwt_tool": 85,         # JWT tool — confirms JWT flaw
            "interactsh-client": 95, # OOB callback = confirmed interaction = highest confidence
            "theharvester": 55,     # OSINT — unverified
            "h8mail": 50,           # Email breach — no direct verification
            "amass": 70,            # DNS/OSINT enumeration
            "subfinder": 72,        # Subdomain discovery
            "findomain": 72,        # Subdomain discovery
            "assetfinder": 70,      # Subdomain discovery
            "alterx": 65,           # Permutation-based — may not exist
            "shuffledns": 73,       # Bruteforce + resolution confirmed
            "dnsx": 80,             # DNS resolution — host exists = fact
            "sublist3r": 68,        # Mixed sources — moderate reliability
            "arjun": 75,            # Parameter discovery — params confirmed present
            "paramspider": 68,      # URL parameter crawl — moderate
            "wpscan": 85,           # WP scanner — CVE+version confirmed
            "testssl": 82,          # TLS probe — cipher facts
            "testssl.sh": 82,
            "sslscan": 80,          # TLS probe
            "naabu": 80,            # Port scanner — open port confirmed
            "masscan": 75,          # Fast port scanner — some FPs possible
            "semgrep": 72,          # SAST — static analysis
            "trivy": 78,            # Container/supply chain scanning
            "bandit": 65,           # Python SAST
            "katana": 65,           # Web crawler
            "linkfinder": 68,       # JS endpoint extractor
            "exploit_chain_engine": 88,  # Chain correlation
            "js_pollution_analyzer": 80, # Prototype pollution — active test
            "wfuzz": 65,            # Fuzzer — path found ≠ vuln
            "crackmapexec": 78,     # SMB/AD — credential confirmed
        }

        # Prefix match for nuclei-* variants not listed
        _base_confidence = _TOOL_CONFIDENCE.get(tool_col, 0)
        if _base_confidence == 0 and tool_col.startswith("nuclei-"):
            _base_confidence = 70  # default nuclei variant
        if _base_confidence == 0:
            _base_confidence = 50  # fallback

        # Adjust by verification status
        _v_multiplier = {
            "confirmed": 1.15,
            "candidate": 1.0,
            "hypothesis": 0.6,
        }.get(v_status, 1.0)

        confidence_score = min(99, max(1, int(_base_confidence * _v_multiplier)))

        finding = Finding(
            scan_job_id=job.id,
            title=title,
            severity=severity,
            cve=cve_id,
            cvss=cvss_val,
            domain=domain_col,
            tool=tool_col,
            risk_score=risk_score,
            confidence_score=confidence_score,
            details=details,
            verification_status=v_status,
            url=finding_url,
            created_at=datetime.utcnow(),
        )
        db.add(finding)
        try:
            db.flush()
            created += 1
        except Exception:
            db.rollback()
            continue

        # ── PoC Sandbox Execution (DeepAudit pattern) ─────────────────────────
        # HIGH/CRITICAL candidates → schedule P21 validation item.
        # P21 item completes → T1 block (tasks.py) promotes to 'confirmed'.
        # P21 item fails    → T1 block marks as 'refuted' (FP suppressed).
        # Only HIGH/CRITICAL get P21; MEDIUM/LOW/INFO get T1 stage-2 below.
        _poc_scheduled = False
        if severity in ("critical", "high") and v_status != "confirmed":
            try:
                from app.services.poc_validator import schedule_poc_validation as _schedule_poc
                _poc_scheduled = _schedule_poc(db, finding, job)
            except Exception:
                pass

        # ── T1: Evidence gate stage 2 ─────────────────────────────────────────
        # MEDIUM/LOW/INFO candidates → seed a lightweight verification item.
        # HIGH/CRITICAL that already have a P21 item skip this to avoid
        # creating two competing verification items for the same finding.
        if v_status in ("candidate", "hypothesis") and not _poc_scheduled:
            try:
                _seed_verification_work_item(db, job, item, finding, tool, finding_url)
            except Exception:
                pass

    if created:
        db.commit()

    return created


# ── T1: Evidence gate stage 2 helpers ─────────────────────────────────────────

# Map tool → verification tool (more precise follow-up)
_VERIFICATION_TOOL_MAP: dict[str, str] = {
    # Generic → targeted nuclei checks
    "nmap":           "nuclei",
    "nmap-vuln":      "nuclei",
    "nmap-vulscan":   "nuclei",
    "masscan":        "nuclei",
    "shodan-cli":     "nuclei",
    "theharvester":   "nuclei",
    "tech_correlator": "nuclei",
    "curl-headers":   "shcheck",
    "wafw00f":        "nuclei-headers",
    # WAF / header findings → safety check
    "shcheck":        "nuclei-headers",
    # httpx findings → dalfox/arjun
    "httpx":          "dalfox",
    "katana-js":      "dalfox",
    # arjun parameter discovery → targeted injection
    "arjun":          "sqlmap",
}

# Findings that should NOT generate verification items (already definitive)
_NO_VERIFY_TOOLS = {"sqlmap", "dalfox", "wpscan", "hydra", "nuclei-default-credentials"}

# Keywords in title that map to a specific verification tool
_TITLE_VERIFICATION: list[tuple[str, str]] = [
    ("xss",              "dalfox"),
    ("cross-site",       "dalfox"),
    ("sql injection",    "sqlmap"),
    ("sqli",             "sqlmap"),
    ("open redirect",    "nuclei-redirect"),
    ("ssrf",             "nuclei-ssrf"),
    ("lfi",              "nuclei-lfi"),
    ("rce",              "nuclei-rce"),
    ("default credentials", "nuclei-default-credentials"),
    ("exposed",          "nuclei-exposure"),
    ("header",           "shcheck"),
    ("cors",             "nuclei-cors"),
    ("cve-",             "nuclei"),
]


def _seed_verification_work_item(
    db,
    job,
    source_item,
    finding,
    tool: str,
    finding_url: str | None,
) -> None:
    """Create a targeted verification ScanWorkItem for a candidate/hypothesis finding.

    The verification item runs a more precise tool against the same target,
    scoped to the finding's URL when available. On completion, the poll task
    will update the finding's verification_status to "confirmed" or "refuted".
    """
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import resource_class_for_tool

    if str(tool or "").lower() in _NO_VERIFY_TOOLS:
        return

    target = str(source_item.target or finding.domain or "").strip()
    if not target:
        return

    # Choose the best verification tool
    title_lower = str(finding.title or "").lower()
    verify_tool = _VERIFICATION_TOOL_MAP.get(tool.lower(), "nuclei")

    # Title-based override
    for kw, vt in _TITLE_VERIFICATION:
        if kw in title_lower:
            verify_tool = vt
            break

    # CVE specific → nuclei with CVE template
    if finding.cve and finding.cve.startswith("CVE-"):
        cve_slug = finding.cve.lower().replace("-", "-")
        verify_tool = f"nuclei-{cve_slug}"

    # Build metadata linking back to the finding
    meta: dict = {
        "source": "evidence_gate_stage2",
        "verifies_finding_id": finding.id,
        "verifies_title": str(finding.title or "")[:120],
        "verifies_tool": tool,
        "verification_url": finding_url or "",
    }

    # Determine phase: reuse P09 (web app scanning) as default verification phase
    phase_id = str(source_item.phase_id or "P09")

    rc = resource_class_for_tool(verify_tool)

    # Use a higher priority (lower number = more urgent)
    base_priority = int(source_item.priority or 100)
    verify_priority = max(1, base_priority - 5)

    # Check dedup
    already = db.query(ScanWorkItem.id).filter(
        ScanWorkItem.scan_job_id == job.id,
        ScanWorkItem.phase_id == phase_id,
        ScanWorkItem.tool_name == verify_tool[:120],
        ScanWorkItem.target == target[:500],
        ScanWorkItem.status.notin_(["completed", "done", "failed", "skipped"]),
    ).first()
    if already:
        return

    verify_item = ScanWorkItem(
        scan_job_id=job.id,
        phase_id=phase_id,
        target=target[:500],
        tool_name=verify_tool[:120],
        profile="",
        resource_class=rc,
        priority=verify_priority,
        status="queued",
        max_attempts=1,  # verification runs once; no retry
        item_metadata=meta,
        created_at=__import__("datetime").datetime.utcnow(),
        updated_at=__import__("datetime").datetime.utcnow(),
    )
    db.add(verify_item)
