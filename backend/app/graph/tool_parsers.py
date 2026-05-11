from __future__ import annotations

import json
import re
from typing import Any

# ─────────────────────────────────────────────────────────────
# ANSI / CLI text utilities
# ─────────────────────────────────────────────────────────────
ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*m|\[[0-9]{1,3}m')


def _strip_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text (e.g., [92m, [0m, etc)."""
    if not text:
        return text
    return ANSI_ESCAPE_PATTERN.sub('', text)


KNOWN_WAF_MODELS: list[str] = [
    "cloudflare",
    "akamai",
    "imperva",
    "modsecurity",
    "mod_security",
    "f5",
    "aws waf",
    "barracuda",
    "fortiweb",
    "google cloud armor",
    "google cloud app armor",
]

WAF_VENDOR_ALIASES: list[tuple[str, tuple[str, ...]]] = [
    ("Cloudflare", ("cloudflare",)),
    ("Akamai", ("akamai",)),
    ("Imperva", ("imperva", "incapsula")),
    ("ModSecurity", ("modsecurity", "mod_security")),
    ("F5", ("f5", "big-ip asm", "bigip asm")),
    ("AWS WAF", ("aws waf", "amazon waf", "amazon web application firewall")),
    ("Barracuda", ("barracuda",)),
    ("FortiWeb", ("fortiweb",)),
    ("Google Cloud Armor", ("google cloud armor", "google cloud app armor", "app armor (google cloud)", "gcp armor")),
]


def _sanitize_cli_text(value: str | None) -> str:
    if not value:
        return ""
    sanitized = str(value)
    sanitized = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", sanitized)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def _normalize_waf_vendor(value: str | None) -> str:
    blob = _sanitize_cli_text(value).lower()
    if not blob:
        return ""
    for canonical, aliases in WAF_VENDOR_ALIASES:
        if any(alias in blob for alias in aliases):
            return canonical
    for model in KNOWN_WAF_MODELS:
        if model in blob:
            return model.title()
    return ""


def _truncate_log(value: Any, limit: int = 400) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}..."


def _severity_to_risk_score(severity: str) -> int:
    sev = str(severity or "").strip().lower()
    if sev == "critical":
        return 9
    if sev == "high":
        return 7
    if sev == "medium":
        return 5
    if sev == "low":
        return 3
    return 2


# ─────────────────────────────────────────────────────────────
# Tool output parsers (_extract_* functions)
# ─────────────────────────────────────────────────────────────

def _extract_asm_findings(result: dict[str, Any], step_name: str, default_target: str) -> list[dict[str, Any]]:
    raw = result.get("asm_findings")
    if not isinstance(raw, list) or not raw:
        return []

    findings: list[dict[str, Any]] = []
    tool = str(result.get("tool") or "unknown").strip().lower()
    for item in raw:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "info").strip().lower()
        rule_id = str(item.get("rule_id") or "asm-rule").strip()
        title = str(item.get("title") or f"ASM Rule Match: {rule_id}").strip()
        details: dict[str, Any] = {
            "node": "scan",
            "asset": default_target,
            "step": step_name,
            "tool": tool,
            "rule_id": rule_id,
            "tags": item.get("tags", []),
            "matches": item.get("matches", []),
            "match_count": int(item.get("match_count") or 0),
            "remediation": item.get("remediation"),
            "references": item.get("references", []),
            "description": item.get("description"),
        }
        findings.append(
            {
                "title": f"ASM Rule: {title}",
                "severity": severity,
                "risk_score": _severity_to_risk_score(severity),
                "source_worker": "scan",
                "details": details,
            }
        )

    return findings


def _extract_tool_output_findings(result: dict[str, Any], step_name: str, default_target: str) -> list[dict[str, Any]]:
    tool = str(result.get("tool") or "").strip().lower()
    stdout = str(result.get("stdout") or result.get("output") or "")
    if not tool or not stdout.strip():
        return []

    if tool == "wafw00f":
        return _extract_wafw00f_findings(stdout, step_name, default_target)
    if tool == "shcheck":
        return _extract_shcheck_findings(stdout, step_name, default_target)
    if tool == "curl-headers":
        return _extract_curl_headers_findings(stdout, step_name, default_target)
    if tool == "nikto":
        return _extract_nikto_findings(stdout, step_name, default_target)
    if tool in {"nmap-vulscan", "vulscan"}:
        return _extract_nmap_vulscan_findings(stdout, step_name, default_target)
    if tool == "sslscan":
        return _extract_sslscan_findings(stdout, step_name, default_target)
    if tool == "testssl":
        return _extract_testssl_findings(stdout, step_name, default_target)
    if tool == "sqlmap":
        return _extract_sqlmap_findings(stdout, step_name, default_target)
    if tool == "dalfox":
        return _extract_dalfox_findings(stdout, step_name, default_target)
    if tool == "wapiti":
        return _extract_wapiti_findings(stdout, step_name, default_target)
    if tool == "shodan-cli":
        return _extract_shodan_findings(stdout, step_name, default_target)
    if tool == "amass":
        return _extract_amass_findings(stdout, step_name, default_target)
    if tool == "sublist3r":
        return _extract_sublist3r_findings(stdout, step_name, default_target)
    if tool == "dnsenum":
        return _extract_dnsenum_findings(stdout, step_name, default_target)
    if tool == "massdns":
        return _extract_massdns_findings(stdout, step_name, default_target)
    if tool == "subjack":
        return _extract_subjack_findings(stdout, step_name, default_target)
    if tool == "ffuf":
        return _extract_ffuf_findings(stdout, step_name, default_target)
    if tool == "gobuster":
        return _extract_gobuster_findings(stdout, step_name, default_target)
    if tool == "cloudenum":
        return _extract_cloudenum_findings(stdout, step_name, default_target)
    if tool == "whatweb":
        return _extract_whatweb_findings(stdout, step_name, default_target)
    if tool == "katana":
        return _extract_katana_findings(stdout, step_name, default_target)
    return []


def _extract_shodan_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai CVEs e portas abertas da resposta JSON da API Shodan."""
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    matches = data.get("matches", [])
    if not matches or not isinstance(matches, list):
        return []

    findings: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    open_ports_per_ip: dict[str, list[str]] = {}

    for match in matches:
        if not isinstance(match, dict):
            continue
        ip_str = str(match.get("ip_str") or default_target)
        port = match.get("port")
        transport = str(match.get("transport") or "tcp")
        product = _sanitize_cli_text(str(match.get("product") or ""))
        version = _sanitize_cli_text(str(match.get("version") or ""))

        # Agrupa portas por IP para finding informativo consolidado
        if port:
            service_label = f"{port}/{transport}"
            if product:
                service_label += f" ({product}"
                if version:
                    service_label += f" {version}"
                service_label += ")"
            open_ports_per_ip.setdefault(ip_str, []).append(service_label)

        # CVEs reportados pelo Shodan para este host/servico
        vulns = match.get("vulns") or {}
        if not isinstance(vulns, dict):
            continue
        for cve_id, vuln_info in vulns.items():
            cve_id = str(cve_id or "").upper().strip()
            if not cve_id.startswith("CVE-"):
                continue
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            cvss = 0.0
            summary = ""
            if isinstance(vuln_info, dict):
                try:
                    cvss = float(vuln_info.get("cvss") or 0)
                except (TypeError, ValueError):
                    cvss = 0.0
                summary = _sanitize_cli_text(str(vuln_info.get("summary") or ""))

            if cvss >= 9.0:
                severity = "critical"
            elif cvss >= 7.0:
                severity = "high"
            elif cvss >= 4.0:
                severity = "medium"
            else:
                severity = "low"

            risk_score = min(10, max(1, int(round(cvss))))
            evidence = summary[:500] if summary else f"{cve_id} identificado pelo Shodan para {ip_str}"

            findings.append({
                "title": cve_id,
                "severity": severity,
                "risk_score": risk_score,
                "source_worker": "osint",
                "details": {
                    "node": "osint",
                    "step": step_name,
                    "asset": ip_str,
                    "tool": "shodan-cli",
                    "evidence": evidence,
                    "cvss": cvss,
                    "cve_id": cve_id,
                },
            })

    # Um finding informativo por IP com as portas expostas
    for ip_str, ports in open_ports_per_ip.items():
        ports_str = ", ".join(ports[:20])
        findings.append({
            "title": f"Portas expostas publicamente (Shodan): {ip_str}",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": step_name,
                "asset": ip_str,
                "tool": "shodan-cli",
                "evidence": f"Portas detectadas pelo Shodan: {ports_str}",
                "open_ports": ports,
            },
        })

    return findings


def _extract_wafw00f_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        line = _sanitize_cli_text(raw_line)
        if not line:
            continue
        match = re.search(r"is behind\s+(.+?)\s+WAF", line, re.IGNORECASE)
        if match:
            vendor = _sanitize_cli_text(match.group(1) or "")
            normalized_vendor = _normalize_waf_vendor(vendor or line) or vendor
            findings.append(
                {
                    "title": f"WAF detectado: {normalized_vendor}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "wafw00f",
                        "evidence": line,
                        "waf_vendor": normalized_vendor,
                        "waf_model_match": bool(_normalize_waf_vendor(normalized_vendor)),
                        "waf_detected": True,
                    },
                }
            )
            break
    return findings


def _extract_shcheck_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_missing: set[str] = set()
    seen_present: set[str] = set()
    header_pattern = re.compile(
        r"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection)",
        re.IGNORECASE,
    )
    missing_tokens = ["missing", "not set", "absent", "not configured", "misconfigured"]
    present_tokens = ["present", "set", "configured", "ok", "enabled", "good"]

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        header_match = header_pattern.search(line)
        if not header_match:
            continue
        header = str(header_match.group(1) or "").strip().lower()
        lowered = line.lower()
        is_missing = any(token in lowered for token in missing_tokens)
        is_present = any(token in lowered for token in present_tokens) or (":" in line and not is_missing)

        if is_missing:
            if header in seen_missing:
                continue
            seen_missing.add(header)
            sev = "medium" if header in {"strict-transport-security", "content-security-policy", "x-frame-options"} else "low"
            findings.append(
                {
                    "title": f"Header de seguranca ausente: {header}",
                    "severity": sev,
                    "risk_score": 5 if sev == "medium" else 3,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "shcheck",
                        "header_name": header,
                        "header_issue": "missing",
                        "evidence": line,
                    },
                }
            )
            continue

        if is_present:
            if header in seen_present:
                continue
            seen_present.add(header)
            findings.append(
                {
                    "title": f"Header de seguranca configurado: {header}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "shcheck",
                        "header_name": header,
                        "header_issue": "present",
                        "evidence": line,
                    },
                }
            )
    return findings


def _extract_curl_headers_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    expected_headers = {
        "strict-transport-security": {
            "owasp": "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
            "reason": "reduz downgrade HTTPS e risco de cookie/token em canal inseguro",
            "remediation": "habilitar HSTS com max-age adequado, includeSubDomains e preload quando aplicavel",
            "severity": "medium",
        },
        "content-security-policy": {
            "owasp": "A03:2021 Injection / A05:2021 Security Misconfiguration",
            "reason": "limita execucao de scripts, carregamento de recursos e abuso de XSS",
            "remediation": "definir CSP restritiva com default-src, script-src, object-src 'none' e frame-ancestors",
            "severity": "medium",
        },
        "x-frame-options": {
            "owasp": "A01:2021 Broken Access Control / A05:2021 Security Misconfiguration",
            "reason": "reduz risco de clickjacking quando frame-ancestors ainda nao cobre o caso",
            "remediation": "usar DENY/SAMEORIGIN ou preferir CSP frame-ancestors com politica equivalente",
            "severity": "medium",
        },
        "x-content-type-options": {
            "owasp": "A05:2021 Security Misconfiguration",
            "reason": "reduz MIME sniffing e interpretacao incorreta de conteudo",
            "remediation": "configurar X-Content-Type-Options: nosniff",
            "severity": "low",
        },
        "referrer-policy": {
            "owasp": "A01:2021 Broken Access Control / A05:2021 Security Misconfiguration",
            "reason": "reduz vazamento de caminhos, parametros e tokens por Referer",
            "remediation": "configurar strict-origin-when-cross-origin ou politica mais restritiva",
            "severity": "low",
        },
        "permissions-policy": {
            "owasp": "A05:2021 Security Misconfiguration",
            "reason": "reduz exposicao de APIs sensiveis do navegador",
            "remediation": "desabilitar recursos nao usados, como camera, microphone, geolocation e payment",
            "severity": "low",
        },
        "cross-origin-opener-policy": {
            "owasp": "A05:2021 Security Misconfiguration",
            "reason": "isola contexto de navegacao e reduz abuso cross-origin",
            "remediation": "avaliar same-origin para aplicacoes que suportam isolamento",
            "severity": "low",
        },
        "cross-origin-resource-policy": {
            "owasp": "A05:2021 Security Misconfiguration",
            "reason": "reduz carregamento indevido de recursos por origens externas",
            "remediation": "avaliar same-origin ou same-site conforme necessidade funcional",
            "severity": "low",
        },
    }

    blocks: list[tuple[str, str]] = []
    current_url = default_target
    current_lines: list[str] = []

    for raw_line in stdout.splitlines():
        line = str(raw_line or "")
        if line.startswith("# URL:"):
            if current_lines:
                blocks.append((current_url, "\n".join(current_lines).strip()))
                current_lines = []
            current_url = line.replace("# URL:", "", 1).strip() or default_target
            continue
        if line.strip():
            current_lines.append(line)

    if current_lines:
        blocks.append((current_url, "\n".join(current_lines).strip()))

    if not blocks and stdout.strip():
        blocks.append((default_target, stdout.strip()))

    seen: set[tuple[str, str, str]] = set()
    for block_url, block_text in blocks:
        block_lower = block_text.lower()

        for header, metadata in expected_headers.items():
            present = re.search(rf"(?im)^\s*{re.escape(header)}\s*:\s*.+$", block_text) is not None
            issue = "present" if present else "missing"
            dedupe_key = (str(block_url or default_target).strip().lower(), header, issue)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            if present:
                match = re.search(rf"(?im)^\s*{re.escape(header)}\s*:\s*(.+)$", block_text)
                evidence = f"{header}: {str(match.group(1) if match else '').strip()}".strip()
                findings.append(
                    {
                        "title": f"Header de seguranca configurado: {header}",
                        "severity": "info",
                        "risk_score": 1,
                        "source_worker": "analise_vulnerabilidade",
                        "details": {
                            "node": "vuln",
                            "step": step_name,
                            "asset": block_url or default_target,
                            "tool": "curl-headers",
                            "header_name": header,
                            "header_issue": "present",
                            "owasp_category": metadata["owasp"],
                            "owasp_top_10": metadata["owasp"],
                            "header_expected_reason": metadata["reason"],
                            "remediation": metadata["remediation"],
                            "evidence": evidence,
                            "http_headers_raw": block_text[:1400],
                        },
                    }
                )
            else:
                sev = str(metadata.get("severity") or "low")
                findings.append(
                    {
                        "title": f"Header de seguranca ausente: {header}",
                        "severity": sev,
                        "risk_score": 5 if sev == "medium" else 3,
                        "source_worker": "analise_vulnerabilidade",
                        "details": {
                            "node": "vuln",
                            "step": step_name,
                            "asset": block_url or default_target,
                            "tool": "curl-headers",
                            "header_name": header,
                            "header_issue": "missing",
                            "owasp_category": metadata["owasp"],
                            "owasp_top_10": metadata["owasp"],
                            "header_expected_reason": metadata["reason"],
                            "remediation": metadata["remediation"],
                            "evidence": f"{header}: missing",
                            "http_headers_raw": block_text[:1400],
                        },
                    }
                )

        status_match = re.search(r"(?im)^\s*HTTP/\S+\s+(\d{3})\b", block_text)
        if status_match:
            status_code = str(status_match.group(1) or "").strip()
            findings.append(
                {
                    "title": f"HTTP status observado: {status_code}",
                    "severity": "info",
                    "risk_score": 1,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": block_url or default_target,
                        "tool": "curl-headers",
                        "http_status": status_code,
                        "owasp_category": "A05:2021 Security Misconfiguration",
                        "evidence": re.search(r"(?im)^\s*HTTP/\S+\s+\d{3}.*$", block_text).group(0),
                        "http_headers_raw": block_text[:1400],
                    },
                }
            )

    return findings


def _extract_nikto_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_headers: set[str] = set()

    ignore_tokens = [
        "target host",
        "target ip",
        "target port",
        "start time",
        "end time",
        "no web server found",
        "nikto installation",
        "multiple ips",
        "cloudflare detected",
        "uncommon header",
        "cgi directories",
    ]

    header_pattern = re.compile(
        r"Suggested security header missing:\s*(\S+)",
        re.IGNORECASE,
    )

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line.startswith("+"):
            continue
        lowered = line.lower()

        # Extrai headers ausentes especialmente
        header_match = header_pattern.search(line)
        if header_match:
            header = str(header_match.group(1) or "").strip().lower()
            if header not in seen_headers:
                seen_headers.add(header)
                sev = "medium" if header in {"strict-transport-security", "content-security-policy", "permissions-policy"} else "low"
                findings.append(
                    {
                        "title": f"Header de seguranca ausente: {header}",
                        "severity": sev,
                        "risk_score": 5 if sev == "medium" else 3,
                        "source_worker": "analise_vulnerabilidade",
                        "details": {
                            "node": "vuln",
                            "step": step_name,
                            "asset": default_target,
                            "tool": "nikto",
                            "header_name": header,
                            "header_issue": "missing",
                            "evidence": line,
                        },
                    }
                )
            continue

        # Ignora linhas com tokens conhecidos
        if any(token in lowered for token in ignore_tokens):
            continue

        if lowered in seen:
            continue
        seen.add(lowered)

        # CVEs e vulnerabilidades
        sev = "high" if ("cve-" in lowered or "osvdb" in lowered) else "medium"
        findings.append(
            {
                "title": f"Nikto: {line.lstrip('+ ').strip()[:180]}",
                "severity": sev,
                "risk_score": 7 if sev == "high" else 5,
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": step_name,
                    "asset": default_target,
                    "tool": "nikto",
                    "evidence": line,
                },
            }
        )
        if len(findings) >= 30:
            break
    return findings


def _extract_nmap_vulscan_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    db_refs: list[str] = []
    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", line, re.IGNORECASE)
        if cve_match:
            cve_id = str(cve_match.group(0) or "").upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            findings.append(
                {
                    "title": cve_id,
                    "severity": "high",
                    "risk_score": 7,
                    "source_worker": "analise_vulnerabilidade",
                    "details": {
                        "node": "vuln",
                        "step": step_name,
                        "asset": default_target,
                        "tool": "nmap-vulscan",
                        "vuln_db": "vulscan",
                        "cve": cve_id,
                        "evidence": line,
                    },
                }
            )
            continue

        lowered = line.lower()
        if any(token in lowered for token in ["exploitdb", "osvdb", "securityfocus", "packetstorm"]):
            db_refs.append(line)

    if not findings and db_refs:
        findings.append(
            {
                "title": "Referencias de vulnerabilidade identificadas (sem CVE explicito)",
                "severity": "medium",
                "risk_score": 5,
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": step_name,
                    "asset": default_target,
                    "tool": "nmap-vulscan",
                    "vuln_db": "vulscan",
                    "evidence": " | ".join(db_refs[:5]),
                },
            }
        )
    return findings


def _extract_sslscan_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _add(title: str, severity: str, evidence: str, category: str, remediation: str) -> None:
        key = (title, evidence[:160])
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {
                "title": title,
                "severity": severity,
                "risk_score": _severity_to_risk_score(severity),
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": step_name,
                    "asset": default_target,
                    "tool": "sslscan",
                    "owasp_category": category,
                    "owasp_top_10": category,
                    "remediation": remediation,
                    "evidence": evidence,
                },
            }
        )

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        lowered = line.lower()
        if "sslv2" in lowered or "sslv3" in lowered:
            _add(
                "SSL legado habilitado no endpoint",
                "high",
                line,
                "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
                "desabilitar SSLv2/SSLv3 e permitir apenas TLS moderno",
            )
        if "tlsv1.0" in lowered or "tlsv1.1" in lowered:
            _add(
                "TLS legado habilitado no endpoint",
                "medium",
                line,
                "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
                "desabilitar TLS 1.0/1.1 e exigir TLS 1.2+ ou TLS 1.3",
            )
        if any(token in lowered for token in ["self signed", "certificate expired", "expired", "not trusted", "unable to get local issuer"]):
            _add(
                "Problema de certificado TLS detectado",
                "high",
                line,
                "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
                "emitir certificado valido, corrigir cadeia intermediaria e monitorar renovacao antes do vencimento",
            )
        if any(token in lowered for token in [" rc4", " 3des", " des ", " null", " anonymous", " export", " md5"]):
            _add(
                "Cipher suite fraco detectado",
                "medium",
                line,
                "A02:2021 Cryptographic Failures",
                "remover cipher suites fracos e priorizar AEAD como TLS_AES_* ou ECDHE com AES-GCM/CHACHA20",
            )
    return findings


def _extract_testssl_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _add(title: str, severity: str, evidence: str, category: str, remediation: str) -> None:
        key = (title, evidence[:160])
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {
                "title": title,
                "severity": severity,
                "risk_score": _severity_to_risk_score(severity),
                "source_worker": "analise_vulnerabilidade",
                "details": {
                    "node": "vuln",
                    "step": step_name,
                    "asset": default_target,
                    "tool": "testssl",
                    "owasp_category": category,
                    "owasp_top_10": category,
                    "remediation": remediation,
                    "evidence": evidence,
                },
            }
        )

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        lowered = line.lower()
        if ("ssl" in lowered and "offered" in lowered) or "sslv2" in lowered or "sslv3" in lowered:
            _add(
                "SSL legado habilitado no endpoint",
                "high",
                line,
                "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
                "desabilitar SSLv2/SSLv3 e permitir apenas TLS moderno",
            )
        if any(token in lowered for token in ["tls 1.0", "tlsv1.0", "tls 1.1", "tlsv1.1"]):
            _add(
                "TLS legado habilitado no endpoint",
                "medium",
                line,
                "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
                "desabilitar TLS 1.0/1.1 e exigir TLS 1.2+ ou TLS 1.3",
            )
        if any(token in lowered for token in ["expired", "self-signed", "self signed", "not trusted", "chain of trust", "hostname mismatch"]):
            _add(
                "Problema de certificado TLS detectado",
                "high",
                line,
                "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
                "corrigir validade, hostname, cadeia intermediaria e autoridade emissora confiavel",
            )
        if any(token in lowered for token in ["rc4", "3des", "sweet32", "null cipher", "anonymous", "export cipher", "md5"]):
            _add(
                "Cipher suite fraco detectado",
                "medium",
                line,
                "A02:2021 Cryptographic Failures",
                "remover suites legadas/fracas e priorizar TLS 1.3 ou TLS 1.2 com AEAD",
            )
        if "hsts" in lowered and any(token in lowered for token in ["not offered", "missing", "not set"]):
            _add(
                "HSTS ausente no endpoint HTTPS",
                "medium",
                line,
                "A02:2021 Cryptographic Failures / A05:2021 Security Misconfiguration",
                "habilitar Strict-Transport-Security com max-age adequado",
            )
    return findings


def _extract_wapiti_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Parse wapiti inline warning lines (emitidos durante o scan com -v 1)."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    # (regex, severity, risk_score, title, header_name)
    _PATTERNS = [
        (
            re.compile(r"CSP is not set for URL:\s*(\S+)", re.IGNORECASE),
            "medium", 5,
            "Content Security Policy (CSP) ausente",
            "content-security-policy",
        ),
        (
            re.compile(r"X-Content-Type-Options is not set on\s*(\S+)", re.IGNORECASE),
            "low", 3,
            "X-Content-Type-Options ausente",
            "x-content-type-options",
        ),
        (
            re.compile(r"Host\s+(\S+)\s+serves HTTP content without redirecting to HTTPS", re.IGNORECASE),
            "medium", 6,
            "Canal nao cifrado: sem redirecionamento HTTPS",
            None,
        ),
        (
            re.compile(r"Strict-Transport-Security.*?not set.*?(\S+)", re.IGNORECASE),
            "medium", 5,
            "HSTS ausente",
            "strict-transport-security",
        ),
        (
            re.compile(r"X-Frame-Options.*?not set.*?(\S+)", re.IGNORECASE),
            "low", 3,
            "X-Frame-Options ausente (clickjacking)",
            "x-frame-options",
        ),
        (
            re.compile(r"\[!\].*?SQL\s+injection.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "SQL Injection detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?XSS.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "Cross-Site Scripting (XSS) detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?Path\s+Traversal.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "Path Traversal detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?SSRF.*?(\S+)", re.IGNORECASE),
            "high", 8,
            "Server-Side Request Forgery (SSRF) detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?CRLF\s+Injection.*?(\S+)", re.IGNORECASE),
            "medium", 5,
            "CRLF Injection detectado",
            None,
        ),
        (
            re.compile(r"\[!\].*?Open\s+Redirect.*?(\S+)", re.IGNORECASE),
            "medium", 5,
            "Open Redirect detectado",
            None,
        ),
    ]

    for raw_line in stdout.splitlines():
        line = str(raw_line or "").strip()
        if not line or line.startswith("[*]") or line.startswith("[+]"):
            continue

        for pattern, severity, risk_score, title, header_name in _PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            key = f"{title}:{default_target}"
            if key in seen:
                break
            seen.add(key)
            details: dict[str, Any] = {
                "node": "vuln",
                "step": step_name,
                "asset": default_target,
                "tool": "wapiti",
                "evidence": line[:500],
            }
            # Extrai payload se disponível na linha
            payload_match = re.search(r"payload=([^\s]+)", line)
            if payload_match:
                details["payload"] = payload_match.group(1)
            if header_name:
                details["header_name"] = header_name
                details["header_issue"] = "missing"
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "risk_score": risk_score,
                    "source_worker": "analise_vulnerabilidade",
                    "details": details,
                }
            )
            break

    return findings


def _extract_sqlmap_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    text = str(stdout or "")
    if not text.strip():
        return []

    vulnerable = bool(
        re.search(r"(?i)\b(is|appears to be)\s+vulnerable\b", text)
        or re.search(r"(?i)\bParameter:\s+.+?\((GET|POST|URI|Cookie|Header)\)", text)
        or re.search(r"(?i)\bPayload:\s+", text)
    )
    if not vulnerable:
        return []

    parameter_match = re.search(r"(?im)^\s*Parameter:\s*(.+?)\s*\((GET|POST|URI|Cookie|Header)\)", text)
    payloads = re.findall(r"(?im)^\s*Payload:\s*(.+)$", text)
    dbms_match = re.search(r"(?i)back-end DBMS:\s*(.+)", text)
    techniques = re.findall(r"(?im)^\s*Type:\s*(.+)$", text)
    evidence_lines = []
    for raw in text.splitlines():
        line = str(raw or "").strip()
        if not line:
            continue
        if re.search(r"(?i)(Parameter:|Type:|Title:|Payload:|back-end DBMS|is vulnerable|appears to be vulnerable)", line):
            evidence_lines.append(line)
        if len(evidence_lines) >= 16:
            break

    details = {
        "node": "vuln",
        "step": step_name,
        "asset": default_target,
        "tool": "sqlmap",
        "evidence": "\n".join(evidence_lines) or text[:1200],
        "validation_status": "verified",
        "owasp_category": "A03:2021 Injection",
        "impact": "Injeção SQL pode permitir leitura indevida, bypass de autenticação e acesso a dados sensíveis conforme privilégios do backend.",
        "remediation": "Usar queries parametrizadas/prepared statements, validação server-side, ORM seguro, least privilege no banco e testes automatizados de payloads.",
    }
    if parameter_match:
        details["parameter"] = parameter_match.group(1).strip()
        details["injection_location"] = parameter_match.group(2).strip()
    if payloads:
        details["payload"] = payloads[0][:500]
        details["payloads"] = payloads[:8]
    if dbms_match:
        details["dbms"] = dbms_match.group(1).strip()[:160]
    if techniques:
        details["sqlmap_techniques"] = [item.strip() for item in techniques[:8]]

    findings.append(
        {
            "title": "SQL Injection validado por sqlmap",
            "severity": "high",
            "risk_score": 8,
            "source_worker": "analise_vulnerabilidade",
            "details": details,
        }
    )
    return findings


def _extract_dalfox_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = [str(line or "").strip() for line in (stdout or "").splitlines() if str(line or "").strip()]
    if not lines:
        return []

    positive_lines = [
        line for line in lines
        if re.search(r"(?i)(\[V\]|verified|vulnerable|poc|payload|reflected|stored xss|dom xss|alert\()", line)
    ]
    if not positive_lines:
        return []

    payloads: list[str] = []
    for line in positive_lines:
        payload_match = re.search(r"(?i)payload[:=]\s*(.+)$", line)
        if payload_match:
            payloads.append(payload_match.group(1).strip())
            continue
        if "<script" in line.lower() or "alert(" in line.lower():
            payloads.append(line)

    verified = any(re.search(r"(?i)(\[V\]|verified|vulnerable|poc)", line) for line in positive_lines)
    severity = "high" if verified else "medium"
    findings.append(
        {
            "title": "Cross-Site Scripting (XSS) validado por dalfox" if verified else "Possível XSS/reflection detectado por dalfox",
            "severity": severity,
            "risk_score": 8 if severity == "high" else 5,
            "source_worker": "analise_vulnerabilidade",
            "details": {
                "node": "vuln",
                "step": step_name,
                "asset": default_target,
                "tool": "dalfox",
                "evidence": "\n".join(positive_lines[:16]),
                "payload": payloads[0][:500] if payloads else "",
                "payloads": payloads[:8],
                "validation_status": "verified" if verified else "hypothesis",
                "owasp_category": "A03:2021 Injection",
                "impact": "XSS pode permitir execução de JavaScript no contexto do usuário, roubo de sessão, ações indevidas e pivô para abuso de conta.",
                "remediation": "Aplicar encoding contextual, sanitização server-side, validação de entrada e CSP restritiva; evitar confiar somente em validação no frontend.",
            },
        }
    )
    return findings


# ── Parsers de ferramentas parcialmente implementadas ────────────────────────


def _extract_amass_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdomínios descobertos pelo amass enum."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        subdomain = raw_line.strip().lower()
        if not subdomain or subdomain in seen:
            continue
        if not re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", subdomain):
            continue
        seen.add(subdomain)
    if not seen:
        return []
    subdomains_list = sorted(seen)
    findings.append({
        "title": f"Subdominios descobertos (amass): {len(subdomains_list)} encontrados",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "amass",
            "evidence": ", ".join(subdomains_list[:50]),
            "subdomains": subdomains_list[:200],
            "count": len(subdomains_list),
        },
    })
    return findings


def _extract_sublist3r_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdomínios descobertos pelo sublist3r."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        # Remove ANSI color codes (e.g., [92m, [0m, etc)
        line = _strip_ansi_codes(raw_line).strip().lower()
        if not line or "sublist3r" in line or line.startswith("[") or line.startswith("-"):
            continue
        if not re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", line):
            continue
        seen.add(line)
    if not seen:
        return []
    subdomains_list = sorted(seen)
    findings.append({
        "title": f"Subdominios descobertos (sublist3r): {len(subdomains_list)} encontrados",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "sublist3r",
            "evidence": ", ".join(subdomains_list[:50]),
            "subdomains": subdomains_list[:200],
            "count": len(subdomains_list),
        },
    })
    return findings


def _extract_dnsenum_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai registros DNS do dnsenum."""
    findings: list[dict[str, Any]] = []
    records: list[str] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("dnsenum") or line.startswith("--"):
            continue
        if re.search(r"\d+\.\d+\.\d+\.\d+", line) or re.search(r"(NS|MX|A|AAAA|TXT|SOA|CNAME)\s", line, re.IGNORECASE):
            records.append(line[:200])
    if not records:
        return []
    findings.append({
        "title": f"Registros DNS enumerados (dnsenum): {len(records)} registros",
        "severity": "info",
        "risk_score": 1,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "dnsenum",
            "evidence": "\n".join(records[:30]),
            "dns_records": records[:100],
            "count": len(records),
        },
    })
    # Zone Transfer detection
    if re.search(r"zone\s+transfer|AXFR", stdout, re.IGNORECASE):
        findings.append({
            "title": "Transferencia de zona DNS permitida (AXFR)",
            "severity": "high",
            "risk_score": 8,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "dnsenum",
                "evidence": "Zone transfer (AXFR) habilitado — expoe toda a estrutura DNS do dominio.",
            },
        })
    return findings


def _extract_massdns_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdomínios validados pelo massdns (formato: subdomain. A ip)."""
    findings: list[dict[str, Any]] = []
    resolved: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # formato massdns -o S: sub.domain.com. A 1.2.3.4
        parts = line.split()
        if len(parts) >= 3:
            subdomain = parts[0].rstrip(".").lower()
            record_type = parts[1].upper()
            value = parts[2]
            if subdomain not in seen and re.match(r"^[a-z0-9\-\.]+\.[a-z]{2,}$", subdomain):
                seen.add(subdomain)
                resolved.append({"subdomain": subdomain, "type": record_type, "value": value})
    if not resolved:
        return []
    findings.append({
        "title": f"Subdominios validados (massdns): {len(resolved)} resolvidos",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "massdns",
            "evidence": ", ".join(r["subdomain"] for r in resolved[:50]),
            "resolved_records": resolved[:200],
            "count": len(resolved),
        },
    })
    return findings


def _extract_subjack_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai subdominios vulneraveis a takeover do subjack."""
    findings: list[dict[str, Any]] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # formato subjack: [Vulnerable] sub.domain.com  [service]
        m = re.search(r"\[Vulnerable\]\s+(\S+)", line, re.IGNORECASE)
        if m:
            subdomain = m.group(1).strip().lower()
            service_m = re.search(r"\[(\w+)\]\s*$", line)
            service = service_m.group(1) if service_m else "unknown"
            findings.append({
                "title": f"Subdomain Takeover: {subdomain}",
                "severity": "high",
                "risk_score": 9,
                "source_worker": "osint",
                "details": {
                    "node": "osint",
                    "step": step_name,
                    "asset": subdomain,
                    "tool": "subjack",
                    "evidence": line[:500],
                    "takeover_service": service,
                },
            })
    return findings


def _extract_ffuf_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai paths/vhosts descobertos pelo ffuf."""
    findings: list[dict[str, Any]] = []
    paths: list[dict[str, str]] = []
    # Tenta JSON primeiro (ffuf -of json)
    try:
        data = json.loads(stdout)
        for result in (data.get("results") or []):
            url = result.get("url", "")
            status_code = result.get("status", 0)
            length = result.get("length", 0)
            paths.append({"url": url, "status": str(status_code), "length": str(length)})
    except (json.JSONDecodeError, ValueError):
        # Parse formato texto: /path [Status: 200, Size: 1234, Words: 56]
        for raw_line in (stdout or "").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("::") or line.startswith("_"):
                continue
            m = re.match(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line)
            if m:
                paths.append({"url": m.group(1), "status": m.group(2), "length": m.group(3)})
    if not paths:
        return []
    findings.append({
        "title": f"Paths descobertos (ffuf): {len(paths)} endpoints",
        "severity": "info",
        "risk_score": 3,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "ffuf",
            "evidence": "\n".join(f"{p['url']} [{p['status']}]" for p in paths[:30]),
            "discovered_paths": paths[:200],
            "count": len(paths),
        },
    })
    return findings


def _extract_gobuster_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai paths descobertos pelo gobuster dir."""
    findings: list[dict[str, Any]] = []
    paths: list[dict[str, str]] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("=") or line.startswith("Gobuster"):
            continue
        # formato: /path (Status: 200) [Size: 1234]
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d+)\)", line)
        if m:
            paths.append({"path": m.group(1), "status": m.group(2)})
            continue
        # formato quiet (-q): /path
        m2 = re.match(r"^(/[^\s]+)$", line)
        if m2:
            paths.append({"path": m2.group(1), "status": "200"})
    if not paths:
        return []
    sensitive_patterns = re.compile(r"(admin|backup|config|\.env|\.git|\.htaccess|wp-admin|phpmyadmin|api|debug|test|staging)", re.IGNORECASE)
    sensitive_paths = [p for p in paths if sensitive_patterns.search(p["path"])]
    if sensitive_paths:
        findings.append({
            "title": f"Paths sensiveis expostos (gobuster): {len(sensitive_paths)} encontrados",
            "severity": "medium",
            "risk_score": 6,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "gobuster",
                "evidence": "\n".join(f"{p['path']} [{p['status']}]" for p in sensitive_paths[:20]),
                "sensitive_paths": sensitive_paths[:100],
                "count": len(sensitive_paths),
            },
        })
    findings.append({
        "title": f"Content Discovery (gobuster): {len(paths)} paths",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "recon",
        "details": {
            "node": "recon",
            "step": step_name,
            "asset": default_target,
            "tool": "gobuster",
            "evidence": "\n".join(f"{p['path']} [{p['status']}]" for p in paths[:30]),
            "discovered_paths": paths[:200],
            "count": len(paths),
        },
    })
    return findings


def _extract_cloudenum_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai buckets/blobs/containers do cloud_enum."""
    findings: list[dict[str, Any]] = []
    buckets: list[str] = []
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # cloud_enum imprime: [+] Open S3 bucket: https://bucket.s3.amazonaws.com
        # ou: OPEN S3 BUCKET: name
        if re.search(r"(OPEN|found|bucket|blob|container)", line, re.IGNORECASE):
            url_m = re.search(r"(https?://\S+)", line)
            if url_m:
                buckets.append(url_m.group(1))
            elif ":" in line:
                buckets.append(line.split(":", 1)[1].strip())
    if not buckets:
        return []
    findings.append({
        "title": f"Cloud Storage Expostos: {len(buckets)} recursos",
        "severity": "high",
        "risk_score": 8,
        "source_worker": "osint",
        "details": {
            "node": "osint",
            "step": step_name,
            "asset": default_target,
            "tool": "cloudenum",
            "evidence": "\n".join(buckets[:20]),
            "cloud_resources": buckets[:100],
            "count": len(buckets),
        },
    })
    return findings


def _extract_whatweb_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai tecnologias fingerprinted pelo whatweb."""
    findings: list[dict[str, Any]] = []
    technologies: list[str] = []
    server_header = ""
    powered_by = ""
    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # whatweb: http://target [200 OK] Apache[2.4], PHP[7.4], ...
        for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9\-_.]+)\[([^\]]+)\]", line):
            tech_name = m.group(1).strip()
            tech_version = m.group(2).strip()
            technologies.append(f"{tech_name}/{tech_version}")
            if tech_name.lower() in {"apache", "nginx", "iis", "lighttpd", "server"}:
                server_header = f"{tech_name}/{tech_version}"
            if tech_name.lower() in {"php", "asp.net", "x-powered-by"}:
                powered_by = f"{tech_name}/{tech_version}"
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                for tech in data.get("technologies", []):
                    if isinstance(tech, dict):
                        name = tech.get("name", "")
                        version = tech.get("version", "")
                        technologies.append(f"{name}/{version}" if version else name)
        except (json.JSONDecodeError, ValueError):
            pass
    if not technologies:
        return []
    tech_unique = sorted(set(technologies))
    findings.append({
        "title": f"Tecnologias detectadas: {len(tech_unique)} componentes",
        "severity": "info",
        "risk_score": 2,
        "source_worker": "osint",
        "details": {
            "node": "osint",
            "step": step_name,
            "asset": default_target,
            "tool": "whatweb",
            "evidence": ", ".join(tech_unique[:30]),
            "technologies": tech_unique[:100],
            "count": len(tech_unique),
        },
    })
    if server_header:
        findings.append({
            "title": f"Header Server Exposto: {server_header}",
            "severity": "low",
            "risk_score": 3,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": step_name,
                "asset": default_target,
                "tool": "whatweb",
                "evidence": f"Server header expoe versao: {server_header}",
                "header_name": "server",
                "header_value": server_header,
            },
        })
    if powered_by:
        findings.append({
            "title": f"Header X-Powered-By Exposto: {powered_by}",
            "severity": "low",
            "risk_score": 3,
            "source_worker": "osint",
            "details": {
                "node": "osint",
                "step": step_name,
                "asset": default_target,
                "tool": "whatweb",
                "evidence": f"X-Powered-By expoe tecnologia: {powered_by}",
                "header_name": "x-powered-by",
                "header_value": powered_by,
            },
        })
    return findings


def _extract_katana_findings(stdout: str, step_name: str, default_target: str) -> list[dict[str, Any]]:
    """Extrai URLs descobertas pelo katana, incluindo robots.txt e sitemap.xml."""
    findings: list[dict[str, Any]] = []
    urls: list[str] = []
    robots_entries: list[str] = []
    sitemap_entries: list[str] = []
    forms: list[str] = []
    sensitive_params: list[str] = []
    param_pattern = re.compile(r"[?&](search|user|username|password|passwd|id|token|key|api_key|secret|session|auth)=", re.IGNORECASE)
    exposed_artifact_pattern = re.compile(
        r"(\.bak$|\.old$|\.backup$|\.zip$|\.tar$|\.gz$|\.sql$|\.env$|\.kdbx$|\.pyc$|"
        r"/ftp/|package(?:-lock)?\.json$|suspicious_errors\.ya?ml$)",
        re.IGNORECASE,
    )
    source_exposure_pattern = re.compile(
        r"(/node_modules/|/build/routes/|/src/|/server/|/juice-shop/)",
        re.IGNORECASE,
    )
    admin_api_pattern = re.compile(
        r"(/rest/admin|/rest/user|/api/users|/api/basket|/api/cards|/api/address|/rest/order|/rest/wallet|/rest/deluxe)",
        re.IGNORECASE,
    )
    redirect_param_pattern = re.compile(r"[?&](to|url|redirect|next|return|continue)=", re.IGNORECASE)
    exposed_artifacts: list[str] = []
    source_paths: list[str] = []
    admin_api_paths: list[str] = []
    redirect_candidates: list[str] = []

    for raw_line in (stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(r"^https?://", line):
            urls.append(line)
            path_lower = line.lower()
            if "/robots.txt" in path_lower:
                robots_entries.append(line)
            if "/sitemap" in path_lower and ".xml" in path_lower:
                sitemap_entries.append(line)
            if param_pattern.search(line):
                sensitive_params.append(line)
            if exposed_artifact_pattern.search(line):
                exposed_artifacts.append(line)
            if source_exposure_pattern.search(line):
                source_paths.append(line)
            if admin_api_pattern.search(line):
                admin_api_paths.append(line)
            if redirect_param_pattern.search(line):
                redirect_candidates.append(line)

    if robots_entries:
        findings.append({
            "title": "Robots.txt acessivel",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(robots_entries[:10]),
                "robots_urls": robots_entries[:20],
            },
        })
    if sitemap_entries:
        findings.append({
            "title": "Sitemap.xml acessivel",
            "severity": "info",
            "risk_score": 2,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(sitemap_entries[:10]),
                "sitemap_urls": sitemap_entries[:20],
            },
        })
    if sensitive_params:
        findings.append({
            "title": f"Parametros sensiveis identificados: {len(sensitive_params)} URLs",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(sensitive_params[:20]),
                "sensitive_urls": sensitive_params[:100],
                "count": len(sensitive_params),
            },
        })
    if exposed_artifacts:
        high_signal = [
            url for url in exposed_artifacts
            if re.search(r"(\.kdbx$|\.env$|\.sql$|suspicious_errors\.ya?ml$|package-lock\.json(?:\.bak)?$)", url, re.IGNORECASE)
        ]
        severity = "high" if high_signal else "medium"
        findings.append({
            "title": f"Artefatos sensiveis ou backups expostos: {len(exposed_artifacts)} itens",
            "severity": severity,
            "risk_score": 7 if severity == "high" else 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(exposed_artifacts[:25]),
                "exposed_artifacts": exposed_artifacts[:120],
                "validation_status": "verified",
                "owasp_category": "A05:2021 Security Misconfiguration / A01:2021 Broken Access Control",
                "impact": "Arquivos de backup, metadados de dependencias ou artefatos internos podem revelar versoes, rotas, segredos operacionais ou material reutilizavel em ataques.",
                "remediation": "Remover diretorios/arquivos de apoio do deploy publico, bloquear listagem/acesso direto e validar pipeline para impedir publicacao de backups e artefatos internos.",
                "count": len(exposed_artifacts),
            },
        })
    if source_paths:
        findings.append({
            "title": f"Codigo/rotas internas expostas via frontend: {len(source_paths)} caminhos",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(source_paths[:25]),
                "exposed_source_paths": source_paths[:120],
                "validation_status": "verified",
                "owasp_category": "A05:2021 Security Misconfiguration",
                "impact": "Rotas internas e dependencias expostas aceleram engenharia reversa, enumeração de APIs e priorização de exploração.",
                "remediation": "Revisar build/public assets, source maps, bundles e regras de static hosting para publicar somente artefatos necessarios.",
                "count": len(source_paths),
            },
        })
    if admin_api_paths:
        findings.append({
            "title": f"Endpoints administrativos/API sensiveis descobertos: {len(admin_api_paths)} caminhos",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(admin_api_paths[:25]),
                "sensitive_api_urls": admin_api_paths[:120],
                "validation_status": "hypothesis",
                "owasp_category": "A01:2021 Broken Access Control / API1 Broken Object Level Authorization",
                "impact": "Endpoints administrativos ou de identidade exigem validação de autenticação/autorização para descartar IDOR, enumeração e acesso indevido.",
                "remediation": "Aplicar autorização server-side por rota/objeto, respostas consistentes para não autorizados e testes automatizados de controle de acesso.",
                "count": len(admin_api_paths),
            },
        })
    if redirect_candidates:
        findings.append({
            "title": f"Possiveis parametros de redirecionamento abertos: {len(redirect_candidates)} URLs",
            "severity": "medium",
            "risk_score": 5,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(redirect_candidates[:25]),
                "redirect_candidate_urls": redirect_candidates[:80],
                "validation_status": "hypothesis",
                "owasp_category": "A01:2021 Broken Access Control / A05:2021 Security Misconfiguration",
                "impact": "Redirecionamentos não validados podem facilitar phishing, token leakage e bypass de fluxos de confiança.",
                "remediation": "Usar allowlist estrita de destinos, normalização de URL e rejeição de esquemas/dominios externos.",
                "count": len(redirect_candidates),
            },
        })
    if urls:
        findings.append({
            "title": f"URLs crawled (katana): {len(urls)} endpoints",
            "severity": "info",
            "risk_score": 1,
            "source_worker": "recon",
            "details": {
                "node": "recon",
                "step": step_name,
                "asset": default_target,
                "tool": "katana",
                "evidence": "\n".join(urls[:30]),
                "discovered_urls": urls[:200],
                "count": len(urls),
            },
        })
    return findings
