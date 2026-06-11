"""Heatmap · superfície × severidade — "onde os achados se acumulam".

Agrega os Findings REAIS de um scan numa matriz [categoria de superfície] ×
[severidade]. A categoria de superfície é derivada de sinais reais do finding
(domínio, url, ferramenta, título) — nenhum dado é inventado; findings sem
sinal suficiente caem em "Aplicações web" (o default honesto para um achado HTTP).
"""
from __future__ import annotations

import re
from typing import Any

# Ordem das linhas do heatmap (igual ao design).
SURFACE_CATEGORIES = [
    "Aplicações web",
    "APIs",
    "Infraestrutura / IPs",
    "Painéis & consoles",
    "DNS / certificados",
]

# Colunas (severidades consideradas no heatmap; info fica fora, como no design).
HEATMAP_SEVERITIES = ["critical", "high", "medium", "low"]

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ferramentas → categoria forte
_DNS_TOOLS = {"sslscan", "testssl", "testssl.sh", "dnsx", "subfinder", "amass",
              "dnsrecon", "dnsenum", "sublist3r", "assetfinder", "shuffledns", "findomain"}
_INFRA_TOOLS = {"nmap", "naabu", "masscan", "nmap-vulscan"}
_PANEL_KW = ("grafana", "portainer", "jenkins", "kibana", "zabbix", "prometheus",
             "rancher", "kubernetes", "k8s", "console", "painel", "admin", "dashboard",
             "metabase", "portal")
_DNS_TITLE_KW = ("tls", "ssl", "certificate", "certificad", "cipher", "dns", "subdomain",
                 "subdomín", "cname", "spf", "dmarc", "dkim", "takeover", "zone transfer")
_INFRA_TITLE_KW = ("port ", "porta ", "open port", "serviço", "service ", "smb", "rdp",
                   "ssh", "ftp", "snmp", "exposed service")
_API_TITLE_KW = ("api ", "endpoint", "graphql", "swagger", "openapi", "rest ", "jwt", "token")


def classify_surface(*, domain: str = "", url: str = "", tool: str = "", title: str = "") -> str:
    """Classifica um finding numa das SURFACE_CATEGORIES a partir de sinais reais."""
    d = (domain or "").lower().strip()
    u = (url or "").lower().strip()
    tl = (tool or "").lower().strip()
    ti = (title or "").lower().strip()
    host = d or _host_from_url(u)

    # 1. DNS / certificados (sinal de ferramenta ou título)
    if tl in _DNS_TOOLS or any(k in ti for k in _DNS_TITLE_KW):
        return "DNS / certificados"

    # 2. Painéis & consoles (host ou título batem com console conhecido)
    if any(k in host for k in _PANEL_KW) or any(k in ti for k in ("painel", "console", "admin panel")):
        return "Painéis & consoles"

    # 3. APIs
    if (
        host.startswith("api") or ".api." in host or "api-" in host or "-api" in host
        or "/api/" in u or any(k in ti for k in _API_TITLE_KW)
    ):
        return "APIs"

    # 4. Infraestrutura / IPs
    if _IP_RE.match(host) or tl in _INFRA_TOOLS or any(k in ti for k in _INFRA_TITLE_KW):
        return "Infraestrutura / IPs"

    # 5. default honesto: aplicação web
    return "Aplicações web"


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    m = re.sub(r"^[a-z]+://", "", url)
    return m.split("/", 1)[0].split(":", 1)[0]


def build_heatmap(findings: list[Any]) -> dict[str, Any]:
    """Constrói a matriz superfície × severidade a partir de Findings reais.

    Retorna estrutura pronta para o frontend:
      { categories, severities, matrix: {cat: {sev: n}}, totals: {cat: n}, max }
    """
    matrix: dict[str, dict[str, int]] = {
        cat: {sev: 0 for sev in HEATMAP_SEVERITIES} for cat in SURFACE_CATEGORIES
    }

    for f in findings:
        sev = str(getattr(f, "severity", "") or "").lower()
        if sev not in HEATMAP_SEVERITIES:
            continue  # info e desconhecidos ficam fora do heatmap
        details = getattr(f, "details", None) or {}
        cat = classify_surface(
            domain=str(getattr(f, "domain", "") or ""),
            url=str(getattr(f, "url", "") or ""),
            tool=str(getattr(f, "tool", "") or ""),
            title=str(getattr(f, "title", "") or "")
            + " "
            + str(details.get("description") or "" if isinstance(details, dict) else ""),
        )
        matrix[cat][sev] += 1

    totals = {cat: sum(row.values()) for cat, row in matrix.items()}
    max_cell = max((v for row in matrix.values() for v in row.values()), default=0)

    return {
        "categories": SURFACE_CATEGORIES,
        "severities": HEATMAP_SEVERITIES,
        "matrix": matrix,
        "totals": totals,
        "max": max_cell,
        "total_findings": sum(totals.values()),
    }
