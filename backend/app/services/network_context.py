"""Contexto de rede CANÔNICO — fonte única usada na CRIAÇÃO e na exibição.

Toda vulnerabilidade carrega o MESMO formato: host real, IP resolvido (+dono),
portas, url/path, cadeia de origem (correlações) e reports HackerOne. Resolver o
IP é feito por DNS real (cacheado) — honesto: para alvos atrás de CDN, retorna o
IP de borda; só observações reais entram (não inventamos atribuição).
"""

from __future__ import annotations

import re
import socket
import threading

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_dns_cache: dict[str, str | None] = {}
_dns_lock = threading.Lock()


def resolve_ip(host: str) -> str | None:
    """Resolve o host para IP via DNS (cacheado). None se falhar."""
    h = str(host or "").strip().lower().split("/")[0].split(":")[0]
    if not h or _IP_RE.match(h):
        return h if _IP_RE.match(h) else None
    with _dns_lock:
        if h in _dns_cache:
            return _dns_cache[h]
    ip = None
    try:
        socket.setdefaulttimeout(4.0)
        ip = socket.gethostbyname(h)
    except Exception:
        ip = None
    with _dns_lock:
        _dns_cache[h] = ip
    return ip


def build_network_context(details: dict, host: str | None, url: str | None = None,
                          path: str | None = None, resolve_dns: bool = True) -> dict:
    """Bloco de rede canônico. Usa IP/portas observados; senão resolve por DNS."""
    d = details if isinstance(details, dict) else {}
    nested = d.get("details") if isinstance(d.get("details"), dict) else {}

    def pick(*keys):
        for src in (d, nested):
            for k in keys:
                v = src.get(k)
                if v not in (None, "", [], {}):
                    return v
        return None

    host = (host or pick("host", "hostname", "subdomain", "asset") or "")
    host = str(host).strip().replace("http://", "").replace("https://", "").split("/")[0] or None

    # IP observado (chaves variadas) ou extraído da evidência.
    ip = pick("resolved_ip", "bypass_ip", "ip", "host_ip", "ip_address", "origin_ip")
    ip_observed = bool(ip)
    if not ip:
        ev = str(pick("evidence", "description") or "")
        m = _IP_RE.search(ev)
        ip = m.group(1) if m else None
        ip_observed = bool(ip)
    if not ip and host and resolve_dns:
        ip = resolve_ip(host)   # DNS real (borda/CDN) — honesto

    ip_owner = pick("ip_owner", "asn_org", "org", "isp")
    if not ip_owner:
        ev = str(pick("evidence") or "")
        mo = re.search(r"\d{1,3}(?:\.\d{1,3}){3}\s*\(([^)]+)\)", ev)
        if mo:
            ip_owner = mo.group(1).split("/")[0].strip()

    ports = pick("all_open_ports", "open_ports", "sensitive_ports", "ports")
    if isinstance(ports, (int, str)):
        ports = [ports]
    ports = [str(p) for p in ports][:20] if isinstance(ports, list) else []

    source = []
    for k in ("shodan_finding_id", "waf_bypass_finding_id", "verifies_finding_id",
              "source_finding_id", "chain_finding_id"):
        if d.get(k):
            source.append({"field": k, "finding_id": d.get(k)})
    reports = d.get("matched_reports") or (d.get("learning_source") or {}).get("matched_reports") or []

    if not url:
        url = pick("matched_at", "url", "request_url", "target_url", "endpoint")
        if not url and host:
            url = f"https://{host}{path or ''}"

    return {
        "host": host,
        "resolved_ip": str(ip) if ip else None,
        "ip_source": "observed" if ip_observed else ("dns" if ip else None),
        "ip_owner": str(ip_owner) if ip_owner else None,
        "ports": ports,
        "url": str(url) if url else None,
        "path": str(path) if path else None,
        "source_findings": source or None,
        "hackerone_reports": [str(r) for r in reports][:6] or None,
    }


# família → categoria OWASP (backfill na criação quando faltar)
_FAMILY_OWASP = {
    "xss": "A03:2021 Injection", "sqli": "A03:2021 Injection", "rce": "A03:2021 Injection",
    "command_injection": "A03:2021 Injection", "ssti": "A03:2021 Injection",
    "xxe": "A05:2021 Security Misconfiguration", "nosql_injection": "A03:2021 Injection",
    "ssrf": "A10:2021 SSRF", "idor": "A01:2021 Broken Access Control",
    "broken_access_control": "A01:2021 Broken Access Control", "bola_bfla": "A01:2021 Broken Access Control",
    "auth_bypass": "A07:2021 Identification and Authentication Failures",
    "jwt_oauth": "A07:2021 Identification and Authentication Failures",
    "csrf": "A01:2021 Broken Access Control", "open_redirect": "A01:2021 Broken Access Control",
    "lfri": "A05:2021 Security Misconfiguration", "path_traversal": "A01:2021 Broken Access Control",
    "deserialization": "A08:2021 Software and Data Integrity Failures",
    "prototype_pollution": "A08:2021 Software and Data Integrity Failures",
    "cors": "A05:2021 Security Misconfiguration", "security_headers": "A05:2021 Security Misconfiguration",
    "misconfiguration": "A05:2021 Security Misconfiguration", "tls_ssl": "A02:2021 Cryptographic Failures",
    "secrets": "A05:2021 Security Misconfiguration", "info_exposure": "A01:2021 Broken Access Control",
    "vulnerable_dependency": "A06:2021 Vulnerable and Outdated Components",
    "subdomain_takeover": "A05:2021 Security Misconfiguration",
    "excessive_data_exposure": "A01:2021 Broken Access Control",
    "mass_assignment": "A08:2021 Software and Data Integrity Failures",
    "type_juggling": "A07:2021 Identification and Authentication Failures",
    "graphql_api": "A03:2021 Injection", "header_injection": "A03:2021 Injection",
    "race_condition": "A04:2021 Insecure Design", "business_logic": "A04:2021 Insecure Design",
    "file_upload": "A04:2021 Insecure Design", "websocket": "A03:2021 Injection",
    "dos": "A05:2021 Security Misconfiguration",
}


def owasp_for_family(family_id: str | None) -> str | None:
    return _FAMILY_OWASP.get(str(family_id or ""))
