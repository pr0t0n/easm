"""
tech_vuln_correlator.py — Technology stack → CVE/vulnerability correlation.

When a tool run (httpx, whatweb, nmap, wapiti) detects a technology and version,
this service:

  1. Extracts (product, version) tuples from the finding/result
  2. Looks up known CVEs via NIST NVD API (free, no key needed for basic queries)
  3. Creates high-priority CVE findings for the scan
  4. Seeds targeted nuclei work-items (nuclei -t cves/<product>/) for each
     detected technology so active exploitation testing is scheduled

Flow triggered by poll_scan_work_item after httpx/whatweb/nmap completes.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any

import requests
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Local high-signal CVE lookup table
# Maps (product_keyword) → list of known critical/high CVEs for quick wins.
# Supplemented by live NVD queries.
# ─────────────────────────────────────────────────────────────────────────────
LOCAL_TECH_CVES: dict[str, list[dict]] = {
    "wordpress": [
        {"cve": "CVE-2022-21661", "cvss": 9.8, "severity": "critical",
         "title": "WordPress < 5.8.3 SQL Injection (WP_Query)",
         "remediation": "Atualizar para WordPress >= 5.8.3"},
        {"cve": "CVE-2019-8942", "cvss": 8.8, "severity": "high",
         "title": "WordPress < 5.0.1 Remote Code Execution via Cropped Image",
         "remediation": "Atualizar para WordPress >= 5.0.1"},
    ],
    "php": [
        {"cve": "CVE-2019-11043", "cvss": 9.8, "severity": "critical",
         "title": "PHP-FPM RCE (nginx + php-fpm configuration)",
         "remediation": "Atualizar PHP, revisar configuração nginx + php-fpm"},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "cvss": 9.8, "severity": "critical",
         "title": "Apache HTTP Server 2.4.49 Path Traversal / RCE",
         "remediation": "Atualizar Apache para versão > 2.4.49"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "severity": "critical",
         "title": "Apache HTTP Server 2.4.49/2.4.50 Path Traversal / RCE",
         "remediation": "Atualizar Apache para versão > 2.4.50"},
        {"cve": "CVE-2017-7679", "cvss": 9.8, "severity": "critical",
         "title": "Apache HTTP Server mod_mime Buffer Overread",
         "remediation": "Atualizar Apache para versão >= 2.2.33 / 2.4.26"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "cvss": 9.4, "severity": "critical",
         "title": "nginx resolver Off-By-One Heap Write (< 1.20.1)",
         "remediation": "Atualizar nginx para >= 1.20.1"},
        {"cve": "CVE-2019-20372", "cvss": 5.3, "severity": "medium",
         "title": "nginx HTTP Request Smuggling (0.6.18 - 1.17.7)",
         "remediation": "Atualizar nginx para >= 1.17.7"},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "cvss": 9.8, "severity": "critical",
         "title": "Spring4Shell — Spring MVC RCE (Spring Framework < 5.3.18)",
         "remediation": "Atualizar Spring Framework para >= 5.3.18 / 5.2.20"},
        {"cve": "CVE-2022-22963", "cvss": 9.8, "severity": "critical",
         "title": "Spring Cloud Function SpEL RCE (< 3.1.7 / < 3.2.3)",
         "remediation": "Atualizar Spring Cloud Function para >= 3.1.7"},
    ],
    "log4j": [
        {"cve": "CVE-2021-44228", "cvss": 10.0, "severity": "critical",
         "title": "Log4Shell — Apache Log4j2 RCE via JNDI",
         "remediation": "Atualizar Log4j2 para >= 2.17.1; mitigação: -Dlog4j2.formatMsgNoLookups=true"},
    ],
    "struts": [
        {"cve": "CVE-2017-5638", "cvss": 10.0, "severity": "critical",
         "title": "Apache Struts 2 Content-Type RCE (Equifax breach)",
         "remediation": "Atualizar Struts para >= 2.3.32 / 2.5.10.1"},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600", "cvss": 9.8, "severity": "critical",
         "title": "Drupalgeddon 2 — Drupal < 7.58 / 8.x < 8.3.9 RCE",
         "remediation": "Atualizar Drupal para >= 7.58 / 8.3.9 / 8.4.6 / 8.5.1"},
    ],
    "jboss": [
        {"cve": "CVE-2017-12149", "cvss": 9.8, "severity": "critical",
         "title": "JBoss AS RCE via Deserialization",
         "remediation": "Atualizar JBoss / aplicar patch CVE-2017-12149"},
    ],
    "jenkins": [
        {"cve": "CVE-2019-1003000", "cvss": 8.8, "severity": "high",
         "title": "Jenkins Script Security Sandbox Bypass",
         "remediation": "Atualizar Jenkins e plugins Script Security / Pipeline"},
    ],
    "tomcat": [
        {"cve": "CVE-2020-1938", "cvss": 9.8, "severity": "critical",
         "title": "Apache Tomcat Ghostcat AJP File Read/Include (< 9.0.31)",
         "remediation": "Desabilitar AJP connector ou atualizar Tomcat para >= 9.0.31"},
        {"cve": "CVE-2017-12617", "cvss": 9.8, "severity": "critical",
         "title": "Apache Tomcat 8.5.x/9.0.x RCE via HTTP PUT (JSP upload)",
         "remediation": "Atualizar Tomcat >= 9.0.1/8.5.23; desabilitar DefaultServlet readonly=false"},
        {"cve": "CVE-2019-0232", "cvss": 8.1, "severity": "high",
         "title": "Apache Tomcat CGI Servlet RCE (Windows, CGI enabled)",
         "remediation": "Atualizar Tomcat >= 9.0.18/8.5.40; desabilitar CGI Servlet"},
    ],
    "iis": [
        {"cve": "CVE-2017-7269", "cvss": 10.0, "severity": "critical",
         "title": "IIS 6.0 WebDAV Buffer Overflow RCE",
         "remediation": "Desabilitar WebDAV ou atualizar; IIS 6.0 EOL"},
        {"cve": "CVE-2010-2730", "cvss": 9.3, "severity": "critical",
         "title": "IIS 7.5 FastCGI Remote Code Execution",
         "remediation": "Atualizar IIS e aplicar MS10-065"},
    ],
    "exchange": [
        {"cve": "CVE-2021-26855", "cvss": 9.8, "severity": "critical",
         "title": "Microsoft Exchange ProxyLogon SSRF → RCE",
         "remediation": "Aplicar patches KB5001779; isolar Exchange da internet"},
        {"cve": "CVE-2021-34473", "cvss": 9.8, "severity": "critical",
         "title": "Microsoft Exchange ProxyShell RCE (< Nov 2021 CU)",
         "remediation": "Aplicar patches Exchange CU Nov 2021 ou posterior"},
    ],
    "django": [
        {"cve": "CVE-2019-14234", "cvss": 9.8, "severity": "critical",
         "title": "Django < 2.1.11 SQL Injection via JSON field key lookup",
         "remediation": "Atualizar Django >= 2.1.11 / 2.2.4"},
        {"cve": "CVE-2022-28347", "cvss": 9.8, "severity": "critical",
         "title": "Django < 4.0.4 SQL Injection via QuerySet.explain()",
         "remediation": "Atualizar Django >= 3.2.13 / 4.0.4"},
    ],
    "rails": [
        {"cve": "CVE-2019-5420", "cvss": 9.8, "severity": "critical",
         "title": "Rails < 5.2.2.1 Development Mode RCE via file_fixture_path",
         "remediation": "Atualizar Rails >= 5.2.2.1; nunca expor development mode"},
        {"cve": "CVE-2020-8164", "cvss": 9.8, "severity": "critical",
         "title": "Rails Unsafe Deserialization of `rendered_format` leading to RCE",
         "remediation": "Atualizar Rails >= 6.0.3.1 / 5.2.4.3"},
    ],
    "laravel": [
        {"cve": "CVE-2021-3129", "cvss": 9.8, "severity": "critical",
         "title": "Laravel <= 8.4.2 RCE via debug mode + Ignition",
         "remediation": "Desabilitar APP_DEBUG=false em produção; atualizar Ignition >= 2.5.2"},
    ],
    "confluence": [
        {"cve": "CVE-2022-26134", "cvss": 10.0, "severity": "critical",
         "title": "Atlassian Confluence OGNL RCE (unauthenticated)",
         "remediation": "Atualizar Confluence >= 7.4.17 / 7.13.7 / 7.14.3 / 7.15.2 / 7.16.4 / 7.17.4 / 7.18.1"},
        {"cve": "CVE-2023-22527", "cvss": 10.0, "severity": "critical",
         "title": "Atlassian Confluence SSTI RCE (< 8.5.4)",
         "remediation": "Atualizar Confluence >= 8.5.4 ou aplicar workaround de mitigação"},
    ],
    "jira": [
        {"cve": "CVE-2022-0540", "cvss": 9.8, "severity": "critical",
         "title": "Atlassian Jira Authentication Bypass in WebWork",
         "remediation": "Atualizar Jira >= 8.13.18 / 8.20.6 / 8.22.0"},
    ],
    "grafana": [
        {"cve": "CVE-2021-43798", "cvss": 7.5, "severity": "high",
         "title": "Grafana < 8.3.1 Path Traversal — leitura de arquivos locais",
         "remediation": "Atualizar Grafana para >= 8.3.1"},
        {"cve": "CVE-2022-31107", "cvss": 9.8, "severity": "critical",
         "title": "Grafana OAuth account takeover (< 9.0.3 / 8.5.9)",
         "remediation": "Atualizar Grafana para >= 9.0.3 ou 8.5.9"},
    ],
    "jquery": [
        {"cve": "CVE-2019-11358", "cvss": 6.1, "severity": "medium",
         "title": "jQuery < 3.4.0 Prototype Pollution",
         "remediation": "Atualizar jQuery para >= 3.4.0"},
        {"cve": "CVE-2015-9251", "cvss": 6.1, "severity": "medium",
         "title": "jQuery < 3.0.0 XSS via cross-domain AJAX requests",
         "remediation": "Atualizar jQuery para >= 3.0.0"},
    ],
    "litespeed": [
        {"cve": "CVE-2022-0073", "cvss": 9.8, "severity": "critical",
         "title": "LiteSpeed Web Server < 6.0.12 RCE via crafted HTTP request",
         "remediation": "Atualizar LiteSpeed para >= 6.0.12"},
        {"cve": "CVE-2021-43798", "cvss": 7.5, "severity": "high",
         "title": "LiteSpeed Path Traversal — leitura de arquivos fora do webroot",
         "remediation": "Atualizar LiteSpeed para versão corrigida"},
    ],
    "portainer": [
        {"cve": "CVE-2022-26336", "cvss": 9.8, "severity": "critical",
         "title": "Portainer < 2.11.1 — acesso não autenticado à API de containers Docker",
         "remediation": "Atualizar Portainer para >= 2.11.1 e restringir acesso por IP/VPN"},
    ],
    "rabbitmq": [
        {"cve": "CVE-2021-22116", "cvss": 7.5, "severity": "high",
         "title": "RabbitMQ < 3.8.16 — DoS via malformed AMQP connection",
         "remediation": "Atualizar RabbitMQ para >= 3.8.16"},
    ],
    "grafana": [
        {"cve": "CVE-2021-43798", "cvss": 7.5, "severity": "high",
         "title": "Grafana < 8.3.1 Path Traversal — leitura de arquivos locais",
         "remediation": "Atualizar Grafana para >= 8.3.1"},
        {"cve": "CVE-2022-31107", "cvss": 9.8, "severity": "critical",
         "title": "Grafana OAuth account takeover (< 9.0.3 / 8.5.9)",
         "remediation": "Atualizar Grafana para >= 9.0.3 ou 8.5.9"},
    ],
    "zabbix": [
        {"cve": "CVE-2022-23131", "cvss": 9.8, "severity": "critical",
         "title": "Zabbix < 5.4.9 SAML SSO Authentication Bypass",
         "remediation": "Atualizar Zabbix para >= 5.4.9 / 6.0.0alpha6"},
        {"cve": "CVE-2022-23134", "cvss": 5.3, "severity": "medium",
         "title": "Zabbix < 5.4.9 Setup page accessible without auth",
         "remediation": "Atualizar Zabbix e bloquear acesso ao /setup.php externamente"},
    ],
    "kibana": [
        {"cve": "CVE-2019-7609", "cvss": 10.0, "severity": "critical",
         "title": "Kibana < 5.6.15 / 6.6.1 RCE via Timelion prototype pollution",
         "remediation": "Atualizar Kibana para >= 5.6.15 / 6.6.1"},
    ],
    "react": [],   # React itself rarely has critical CVEs; deps are the issue
    "angular": [],
    "vue": [],
    "ssl 3.0": [
        {"cve": "CVE-2014-3566", "cvss": 3.4, "severity": "low",
         "title": "POODLE — SSLv3 CBC-mode padding oracle",
         "remediation": "Desabilitar SSLv3 no servidor TLS"},
    ],
    "tls 1.0": [
        {"cve": "CVE-2011-3389", "cvss": 4.3, "severity": "medium",
         "title": "BEAST — TLS 1.0 CBC encryption vulnerability",
         "remediation": "Desabilitar TLS 1.0; usar TLS 1.2+"},
    ],
    "openssl": [
        {"cve": "CVE-2022-0778", "cvss": 7.5, "severity": "high",
         "title": "OpenSSL Infinite Loop in BN_mod_sqrt() — DoS",
         "remediation": "Atualizar OpenSSL para >= 1.0.2zd / 1.1.1n / 3.0.2"},
        {"cve": "CVE-2016-0800", "cvss": 5.9, "severity": "medium",
         "title": "DROWN — SSLv2 cross-protocol attack on TLS",
         "remediation": "Desabilitar SSLv2 no servidor"},
    ],
}

# Product keywords to nuclei template tags
TECH_TO_NUCLEI_TAGS: dict[str, list[str]] = {
    "wordpress":  ["wordpress", "wp"],
    "joomla":     ["joomla"],
    "drupal":     ["drupal"],
    "apache":     ["apache"],
    "nginx":      ["nginx"],
    "tomcat":     ["tomcat"],
    "jenkins":    ["jenkins"],
    "spring":     ["spring"],
    "php":        ["php"],
    "jquery":     ["jquery"],
    "iis":        ["iis"],
    "sharepoint": ["sharepoint"],
    "exchange":   ["exchange"],
    "confluence": ["confluence"],
    "jira":       ["jira"],
    "gitlab":     ["gitlab"],
    "grafana":    ["grafana"],
    "elasticsearch": ["elasticsearch"],
    "kibana":     ["kibana"],
    "portainer":  ["portainer"],
    "rabbitmq":   ["rabbitmq"],
    "zabbix":     ["zabbix"],
    "litespeed":  ["litespeed"],
    "flower":     ["flower"],
    "redis":      ["redis"],
    "mongo":      ["mongodb"],
    "docker":     ["docker"],
    "kubernetes": ["kubernetes"],
    "django":     ["django"],
    "rails":      ["rails"],
    "laravel":    ["laravel"],
    "struts":     ["struts"],
    "websphere":  ["websphere"],
    "weblogic":   ["weblogic"],
    "jboss":      ["jboss"],
    "solr":       ["solr"],
}

# ── Perfis de ataque específicos por tech stack ───────────────────────────────
# Mapeia keyword de tech → lista de (tool_name, phase_id) a enfileirar.
# Isso implementa o ponto #2 do usuário: cada tech detectada ativa
# um perfil de ataque específico em vez de rodar tudo para todos.
#
# Exemplos de lógica:
#   WordPress → wpscan (P09) + nuclei-wp-plugins (P09)
#   Django    → nuclei-django-debug (P09) + arjun IDOR scan (P12)
#   GraphQL   → nuclei-graphql (P09)
#   JWT       → nuclei-jwt (P09)
#   S3/Cloud  → nuclei-s3-misconfig (P07)

TECH_ATTACK_PROFILES: dict[str, list[dict]] = {
    "wordpress": [
        {"tool": "wpscan",             "phase": "P09", "priority_boost": -10},
        {"tool": "nuclei-wordpress",   "phase": "P09", "priority_boost": -8},
        {"tool": "nuclei-wp-plugins",  "phase": "P09", "priority_boost": -6},
    ],
    "joomla": [
        {"tool": "nuclei-joomla",      "phase": "P09", "priority_boost": -8},
    ],
    "drupal": [
        {"tool": "nuclei-drupal",      "phase": "P09", "priority_boost": -10},
    ],
    "django": [
        {"tool": "nuclei-django",      "phase": "P09", "priority_boost": -8},
        # Django debug mode expõe /admin, tracebacks, SQL queries
        {"tool": "nuclei-django-debug-mode", "phase": "P09", "priority_boost": -10},
        # DRF: IDs sequenciais → IDOR em /api/users/{id}/
        {"tool": "arjun",              "phase": "P12", "priority_boost": -5},
    ],
    "laravel": [
        {"tool": "nuclei-laravel",     "phase": "P09", "priority_boost": -10},
        # Laravel debug (APP_DEBUG=true) → full stack trace + env vars
        {"tool": "nuclei-laravel-debug", "phase": "P09", "priority_boost": -10},
    ],
    "rails": [
        {"tool": "nuclei-rails",       "phase": "P09", "priority_boost": -8},
    ],
    "graphql": [
        # Introspection, BOLA, nested query DoS
        {"tool": "nuclei-graphql",     "phase": "P09", "priority_boost": -10},
        {"tool": "nuclei-graphql-introspection", "phase": "P09", "priority_boost": -12},
    ],
    "spring": [
        {"tool": "nuclei-spring",      "phase": "P09", "priority_boost": -10},
        # Spring Actuator: /actuator/env expõe TODAS as env vars
        {"tool": "nuclei-spring-actuator", "phase": "P09", "priority_boost": -12},
    ],
    "jenkins": [
        {"tool": "nuclei-jenkins",     "phase": "P09", "priority_boost": -10},
    ],
    "confluence": [
        {"tool": "nuclei-confluence",  "phase": "P09", "priority_boost": -12},
    ],
    "jira": [
        {"tool": "nuclei-jira",        "phase": "P09", "priority_boost": -8},
    ],
    "gitlab": [
        {"tool": "nuclei-gitlab",      "phase": "P09", "priority_boost": -8},
    ],
    "grafana": [
        {"tool": "nuclei-grafana",     "phase": "P09", "priority_boost": -8},
    ],
    "kibana": [
        {"tool": "nuclei-kibana",      "phase": "P09", "priority_boost": -8},
    ],
    "elasticsearch": [
        {"tool": "nuclei-elasticsearch", "phase": "P09", "priority_boost": -8},
    ],
    "tomcat": [
        {"tool": "nuclei-tomcat",      "phase": "P09", "priority_boost": -10},
        # Ghostcat + HTTP PUT RCE — templates específicos de CVE
        {"tool": "nuclei-cve-2020-1938", "phase": "P09", "priority_boost": -12},
        {"tool": "nuclei-cve-2017-12617", "phase": "P09", "priority_boost": -12},
    ],
    "iis": [
        {"tool": "nuclei-iis",         "phase": "P09", "priority_boost": -8},
    ],
    "exchange": [
        {"tool": "nuclei-exchange",    "phase": "P09", "priority_boost": -12},
        {"tool": "nuclei-cve-2021-26855", "phase": "P09", "priority_boost": -15},
    ],
    "sharepoint": [
        {"tool": "nuclei-sharepoint",  "phase": "P09", "priority_boost": -8},
    ],
    "portainer": [
        {"tool": "nuclei-portainer",   "phase": "P09", "priority_boost": -12},
    ],
    "zabbix": [
        {"tool": "nuclei-zabbix",      "phase": "P09", "priority_boost": -10},
    ],
    "struts": [
        {"tool": "nuclei-struts",      "phase": "P09", "priority_boost": -12},
        {"tool": "nuclei-cve-2017-5638", "phase": "P09", "priority_boost": -15},
    ],
    "weblogic": [
        {"tool": "nuclei-weblogic",    "phase": "P09", "priority_boost": -12},
    ],
    "docker": [
        {"tool": "nuclei-docker",      "phase": "P09", "priority_boost": -10},
    ],
    # JWT em header → testa alg:none, weak secret, kid injection
    "jwt": [
        {"tool": "nuclei-jwt",         "phase": "P09", "priority_boost": -10},
    ],
    # S3 / CloudFront → bucket misconfiguration, origin bypass
    "s3": [
        {"tool": "nuclei-s3",          "phase": "P07", "priority_boost": -10},
        {"tool": "nuclei-aws-bucket",  "phase": "P07", "priority_boost": -10},
    ],
    "cloudfront": [
        {"tool": "nuclei-cloudfront",  "phase": "P07", "priority_boost": -8},
    ],
    "php": [
        {"tool": "nuclei-php",         "phase": "P09", "priority_boost": -5},
    ],
    "nginx": [
        {"tool": "nuclei-nginx",       "phase": "P09", "priority_boost": -5},
    ],
    "apache": [
        {"tool": "nuclei-apache",      "phase": "P09", "priority_boost": -8},
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Technology extraction from tool results
# ─────────────────────────────────────────────────────────────────────────────

def _extract_technologies(tool_name: str, result: dict[str, Any], target: str) -> list[dict]:
    """
    Return list of {product, version, source} from a completed work item result.
    """
    techs: list[dict] = []
    stdout = str(result.get("stdout_full") or result.get("stdout_preview") or "")
    parsed = result.get("parsed_result")
    tool = tool_name.lower()

    if tool in ("httpx",):
        rows = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])
        for row in rows:
            if not isinstance(row, dict):
                continue
            for tech in (row.get("tech") or row.get("technologies") or []):
                tech_str = str(tech or "").strip()
                if tech_str:
                    product, version = _split_product_version(tech_str)
                    techs.append({"product": product, "version": version, "source": "httpx"})
            # TLS cipher version leaks
            tls = dict(row.get("tls") or {})
            if tls:
                cipher = str(tls.get("cipher") or "")
                if "TLS_1_0" in cipher or "TLSv1.0" in cipher or "tls1.0" in cipher.lower():
                    techs.append({"product": "TLS 1.0", "version": "", "source": "httpx-tls"})
                elif "SSL" in cipher:
                    techs.append({"product": "SSL 3.0", "version": "", "source": "httpx-tls"})

    elif tool in ("whatweb", "whatweb-basic"):
        # whatweb line: http://host [200 OK] Apache[2.4.41], PHP[7.4.3], jQuery[3.3.1], ...
        # Strip the leading URL + HTTP status before parsing
        for line in stdout.splitlines():
            line = line.strip()
            # Remove "http://host.tld [200 OK] " prefix
            line = re.sub(r"^https?://\S+\s+\[.*?\]\s*", "", line)
            bracket_pattern = re.compile(r"([A-Za-z][\w\s\.-]{1,30}?)\[([^\]]+)\]")
            skip = {"Country", "IP", "HTML5", "Title", "HTTPServer", "Allow",
                    "UncommonHeaders", "Cookies", "Meta-Author", "Email",
                    "PoweredBy", "Script", "Bootstrap", "Google-Analytics",
                    "Microsoft-IIS", "X-Powered-By"}
            for m in bracket_pattern.finditer(line):
                product_raw = m.group(1).strip().rstrip(",")
                version_raw = m.group(2).strip()
                if not product_raw or product_raw in skip:
                    continue
                # Skip HTTP status codes like "200 OK"
                if re.match(r"^\d{3}\s", version_raw):
                    continue
                if product_raw == "HTTPServer":
                    product_raw, version_raw = _split_product_version(version_raw)
                techs.append({"product": product_raw, "version": version_raw, "source": "whatweb"})

    elif tool in ("nmap", "nmap-http", "nmap-ssl", "nmap-vuln"):
        # nmap service version: PORT/proto  open  SERVICE  PRODUCT VERSION
        # Stop at | to exclude NSE script output (|_ prefix)
        service_pattern = re.compile(
            r"^\d+/\w+\s+open\s+\S+\s+([^|\n]+)", re.MULTILINE
        )
        skip_nmap = {"tcpwrapped", "unknown", "filtered", "closed", ""}
        for m in service_pattern.finditer(stdout):
            version_line = m.group(1).strip()
            if not version_line:
                continue
            product, version = _split_product_version(version_line)
            product_lower = product.lower()
            if product_lower in skip_nmap or product_lower.startswith("|"):
                continue
            techs.append({"product": product, "version": version, "source": "nmap"})

        # HTTP server header extracted by nmap NSE: "|_http-server-header: nginx/1.18.0"
        server_pattern = re.compile(r"\|_http-server-header:\s*([^\n|]+)", re.MULTILINE)
        for m in server_pattern.finditer(stdout):
            val = m.group(1).strip()
            if not val or val.lower() in ("cloudflare", ""):
                continue  # generic CDN, no version info
            product, version = _split_product_version(val)
            if product and product.lower() not in skip_nmap:
                techs.append({"product": product, "version": version, "source": "nmap-header"})

    elif tool == "shodan-cli":
        data = parsed if isinstance(parsed, dict) else {}
        for banner in (data.get("banners") or []):
            if not isinstance(banner, dict):
                continue
            banner_text = str(banner.get("banner") or "")
            server_m = re.search(r"(?i)^Server:\s*(.+)$", banner_text, re.MULTILINE)
            if server_m:
                product, version = _split_product_version(server_m.group(1).strip())
                if product:
                    techs.append({"product": product, "version": version, "source": "shodan"})

    elif tool == "wapiti":
        # wapiti reports detected tech in its output
        for line in stdout.splitlines():
            if "detected" in line.lower() or "found" in line.lower():
                m = re.search(r"([\w\.\-]+)[\s/]+([\d\.]+)", line)
                if m:
                    techs.append({"product": m.group(1), "version": m.group(2), "source": "wapiti"})

    # Deduplicate by product (case-insensitive)
    seen: set[str] = set()
    unique: list[dict] = []
    for t in techs:
        key = t["product"].lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


def _split_product_version(raw: str) -> tuple[str, str]:
    """
    Split various product+version formats:
      "nginx/1.18.0"           → ("nginx", "1.18.0")
      "Apache httpd 2.4.41"    → ("Apache", "2.4.41")
      "OpenSSL 1.1.1n 15 Mar"  → ("OpenSSL", "1.1.1")
      "jQuery[3.3.1]"          → ("jQuery", "3.3.1")
      "PHP:8.1.34"             → ("PHP", "8.1.34")   ← httpx format
      "Bootstrap:7"            → ("Bootstrap", "7")
      "cloudflare"             → ("cloudflare", "")
    """
    raw = raw.strip().rstrip(",")
    if not raw:
        return "", ""

    # colon separator: "PHP:8.1.34" or "Bootstrap:7"  (httpx tech format)
    if ":" in raw and not raw.startswith("http") and ":/" not in raw:
        parts = raw.split(":", 1)
        product = parts[0].strip()
        version = parts[1].strip().split()[0]  # stop at first space/extra info
        if product:
            return product, version

    # slash separator: "nginx/1.18.0" or "Apache/2.4.41"
    if "/" in raw and not raw.startswith("http"):
        parts = raw.split("/", 1)
        product = parts[0].strip()
        version = parts[1].strip().split()[0]  # stop at first space/extra info
        return product, version

    # Find first occurrence of a version-like string (d.d.d or d.d or d-suffix)
    ver_m = re.search(r"([\d]+(?:[\.\-][\w]+){1,4})", raw)
    if ver_m:
        # Product is everything before the version number
        product = raw[:ver_m.start()].strip().split()[-1] if raw[:ver_m.start()].strip() else raw.split()[0]
        # Use the first word as product if before the version is multi-word
        words_before = raw[:ver_m.start()].strip().split()
        if words_before:
            product = words_before[0]  # e.g. "Apache" from "Apache httpd 2.4.41"
        return product, ver_m.group(1)

    # No version found — return first word as product
    return raw.split()[0] if raw.split() else raw, ""


# ─────────────────────────────────────────────────────────────────────────────
# NVD API lookup
# ─────────────────────────────────────────────────────────────────────────────

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CACHE: dict[str, list[dict]] = {}     # in-process cache per worker lifetime


def _nvd_lookup(product: str, version: str, *, max_results: int = 5) -> list[dict]:
    """
    Query NIST NVD for CVEs matching product+version.
    Returns list of {cve, cvss, severity, description, remediation}.
    """
    cache_key = f"{product.lower()}:{version.lower()}"
    if cache_key in _NVD_CACHE:
        return _NVD_CACHE[cache_key]

    keyword = product if not version else f"{product} {version}"
    try:
        resp = requests.get(
            _NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=15,
            headers={"User-Agent": "EASM-Security-Scanner/1.0"},
        )
        if resp.status_code == 429:
            # NVD rate limit — skip
            _NVD_CACHE[cache_key] = []
            return []
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.debug("NVD API error for %s: %s", keyword, exc)
        _NVD_CACHE[cache_key] = []
        return []

    findings: list[dict] = []
    for item in (data.get("vulnerabilities") or []):
        cve_item = dict(item.get("cve") or {})
        cve_id = str(cve_item.get("id") or "")
        if not cve_id.startswith("CVE-"):
            continue

        # Get CVSS score (prefer v3)
        cvss = 0.0
        severity = "medium"
        metrics = dict(cve_item.get("metrics") or {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(key) or []
            if metric_list:
                m = dict(metric_list[0])
                cvss_data = dict(m.get("cvssData") or {})
                try:
                    cvss = float(cvss_data.get("baseScore") or 0)
                    severity = str(cvss_data.get("baseSeverity") or "MEDIUM").lower()
                except (TypeError, ValueError):
                    pass
                break

        # Only report high/critical
        if cvss < 7.0:
            continue

        # Description
        desc = ""
        for d in (cve_item.get("descriptions") or []):
            if dict(d).get("lang") == "en":
                desc = str(dict(d).get("value") or "")[:300]
                break

        findings.append({
            "cve": cve_id,
            "cvss": cvss,
            "severity": severity,
            "description": desc,
            "remediation": f"Verificar versão de {product} e aplicar patches CVE {cve_id}",
        })
        time.sleep(0.05)  # be nice to NVD rate limits

    _NVD_CACHE[cache_key] = findings
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Nuclei targeted work-item seeding
# ─────────────────────────────────────────────────────────────────────────────

def _seed_attack_profile_for_tech(
    db: Session,
    scan_id: int,
    target: str,
    product: str,
) -> int:
    """Implementa tech stack → attack profile (ponto #2 do usuário).

    Para cada tech detectada, enfileira ferramentas de ataque específicas
    com alta prioridade, em vez de rodar tudo para todos os targets.

    Retorna número de work items criados.
    """
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import resource_class_for_tool, PHASE_PRIORITY

    product_lower = str(product or "").strip().lower()
    seeded = 0

    # Match por keywords (ex: "spring boot" → "spring")
    for tech_kw, profile_list in TECH_ATTACK_PROFILES.items():
        if tech_kw not in product_lower:
            continue
        for entry in profile_list:
            tool_name = str(entry.get("tool") or "")[:120]
            phase_id = str(entry.get("phase") or "P09")
            priority_boost = int(entry.get("priority_boost") or 0)
            if not tool_name:
                continue

            already = (
                db.query(ScanWorkItem.id)
                .filter(
                    ScanWorkItem.scan_job_id == scan_id,
                    ScanWorkItem.phase_id == phase_id,
                    ScanWorkItem.tool_name == tool_name,
                    ScanWorkItem.target == target[:500],
                )
                .first()
            )
            if already:
                continue

            rc = resource_class_for_tool(tool_name)
            base_pri = PHASE_PRIORITY.get(phase_id, 100) + {"light": 0, "medium": 5, "heavy": 15, "oob": 20}.get(rc, 0)
            item = ScanWorkItem(
                scan_job_id=scan_id,
                phase_id=phase_id,
                target=target[:500],
                tool_name=tool_name,
                profile=tool_name,
                resource_class=rc,
                priority=max(1, base_pri + priority_boost),
                status="queued",
                max_attempts=2,
                item_metadata={
                    "source": "tech_attack_profile",
                    "detected_tech": product,
                    "tech_keyword": tech_kw,
                    "engine": "tech_vuln_correlator",
                },
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(item)
            try:
                db.flush()
                seeded += 1
                logger.info(
                    "tech_profile_seed scan=%s target=%s tech=%s → tool=%s phase=%s",
                    scan_id, target, product, tool_name, phase_id,
                )
            except Exception:
                db.rollback()

    return seeded


def _seed_targeted_nuclei(
    db: Session,
    scan_id: int,
    target: str,
    product: str,
    phase_id: str = "P09",
) -> int:
    """
    Add a nuclei work item targeted at the detected product/technology.
    Returns 1 if created, 0 if already exists.
    """
    from app.models.models import ScanWorkItem
    from app.services.scan_work_queue import resource_class_for_tool, PHASE_PRIORITY

    tech_lower = product.lower()
    # Find matching nuclei tag
    tag: str | None = None
    for kw, tags in TECH_TO_NUCLEI_TAGS.items():
        if kw in tech_lower:
            tag = tags[0]
            break
    if not tag:
        return 0

    tool_name = f"nuclei-{tag}"[:120]
    already = (
        db.query(ScanWorkItem.id)
        .filter(
            ScanWorkItem.scan_job_id == scan_id,
            ScanWorkItem.phase_id == phase_id,
            ScanWorkItem.tool_name == tool_name,
            ScanWorkItem.target == target[:500],
        )
        .first()
    )
    if already:
        return 0

    rc = resource_class_for_tool(tool_name)
    pri = PHASE_PRIORITY.get(phase_id, 100) + {"light": 0, "medium": 5, "heavy": 15}.get(rc, 0)
    item = ScanWorkItem(
        scan_job_id=scan_id,
        phase_id=phase_id,
        target=target[:500],
        tool_name=tool_name,
        profile=tool_name,
        resource_class=rc,
        priority=pri - 5,   # slightly higher priority than normal
        status="queued",
        max_attempts=2,
        item_metadata={
            "source": "tech_correlator",
            "detected_tech": product,
            "engine": "tech_vuln_correlator",
        },
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(item)
    try:
        db.flush()
        return 1
    except Exception:
        db.rollback()
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def correlate_tech_vulns(
    db: Session,
    scan_id: int,
    target: str,
    tool_name: str,
    work_item_id: int,
) -> dict[str, Any]:
    """
    Called after a tech-detection tool completes.
    1. Extract detected technologies from the work item result
    2. Look up CVEs (local table first, NVD API for unknown products)
    3. Create Finding records for each CVE
    4. Seed targeted nuclei work-items for each detected tech

    Returns summary dict for logging.
    """
    from app.models.models import ScanWorkItem, ScanJob, Finding

    item = db.query(ScanWorkItem).filter(ScanWorkItem.id == work_item_id).first()
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not item or not job:
        return {"error": "item or job not found"}

    result = dict(item.result or {})
    techs = _extract_technologies(tool_name, result, target)
    if not techs:
        return {"techs": 0, "findings": 0, "nuclei_queued": 0}

    findings_created = 0
    nuclei_queued = 0

    for tech in techs:
        product = str(tech.get("product") or "").strip()
        version = str(tech.get("version") or "").strip()
        source = str(tech.get("source") or tool_name)

        if not product:
            continue

        # ── 1. Local CVE table ────────────────────────────────────────────────
        product_lower = product.lower()
        local_cves: list[dict] = []
        for kw, cves in LOCAL_TECH_CVES.items():
            if kw in product_lower:
                local_cves.extend(cves)

        # ── 2. NVD live lookup (only for products with a version) ─────────────
        nvd_cves: list[dict] = []
        if version and product_lower not in ("cloudflare", "cdn", "waf"):
            try:
                nvd_cves = _nvd_lookup(product, version, max_results=5)
            except Exception as exc:
                logger.debug("NVD lookup failed: %s", exc)

        all_cves = local_cves + nvd_cves

        # ── 3. Persist technology finding if not already present ──────────────
        tech_title = f"Tecnologia detectada: {product}" + (f" {version}" if version else "")
        tech_exists = (
            db.query(Finding.id)
            .filter(
                Finding.scan_job_id == scan_id,
                Finding.title == tech_title,
                Finding.domain == target[:255],
            )
            .first()
        )
        if not tech_exists:
            db.add(Finding(
                scan_job_id=scan_id,
                title=tech_title,
                severity="info",
                risk_score=1,
                domain=target[:255],
                tool=source[:100],
                confidence_score=70,
                details={
                    "node": "recon",
                    "step": "tech_correlator",
                    "asset": target,
                    "tool": source,
                    "product": product,
                    "version": version,
                    "phase_id": str(item.phase_id),
                    "evidence": f"{source} detected {product}" + (f" {version}" if version else ""),
                    "owasp_category": "A06:2021 Vulnerable and Outdated Components" if version else "",
                },
                created_at=datetime.utcnow(),
            ))
            try:
                db.flush()
                findings_created += 1
            except Exception:
                db.rollback()

        # ── 4. Persist CVE findings ───────────────────────────────────────────
        for cve_info in all_cves:
            cve_id = str(cve_info.get("cve") or "").upper()
            if not cve_id.startswith("CVE-"):
                continue

            # Dedup: one CVE per target domain
            cve_exists = (
                db.query(Finding.id)
                .filter(
                    Finding.scan_job_id == scan_id,
                    Finding.cve == cve_id,
                    Finding.domain == target[:255],
                )
                .first()
            )
            if cve_exists:
                continue

            sev_raw = str(cve_info.get("severity") or "high").lower()
            severity = sev_raw if sev_raw in ("critical", "high", "medium", "low") else "high"
            cvss = cve_info.get("cvss")
            try:
                cvss = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss = None

            title = str(cve_info.get("title") or cve_id)
            remediation = str(cve_info.get("remediation") or "").strip() or None

            db.add(Finding(
                scan_job_id=scan_id,
                title=title[:500],
                severity=severity,
                cve=cve_id,
                cvss=cvss,
                risk_score=int(round(float(cvss or 7.0))),
                domain=target[:255],
                tool=source[:100],
                recommendation=remediation,
                confidence_score=60,
                details={
                    "node": "vuln",
                    "step": "tech_correlator",
                    "asset": target,
                    "tool": source,
                    "product": product,
                    "version": version,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "description": str(cve_info.get("description") or ""),
                    "evidence": f"{source} detected {product}" + (f" {version}" if version else "")
                                + f" → known CVE {cve_id}",
                    "owasp_category": "A06:2021 Vulnerable and Outdated Components",
                    "impact": "Componente com CVE conhecido permite exploração remota se versão vulnerável confirmada.",
                    "remediation": remediation or f"Verificar versão de {product} e aplicar patches relevantes",
                    "validation_status": "hypothesis",  # needs manual confirmation
                },
                created_at=datetime.utcnow(),
            ))
            try:
                db.flush()
                findings_created += 1
            except Exception:
                db.rollback()

        # ── 5. Queue targeted nuclei scan (genérico) ──────────────────────────
        nuclei_queued += _seed_targeted_nuclei(db, scan_id, target, product, phase_id="P09")

        # ── 6. Tech attack profile: ferramenta específica para o tech stack ──
        # Implementa o ponto #2: WordPress → wpscan; Django → nuclei-django-debug;
        # GraphQL → nuclei-graphql-introspection; Tomcat → CVE específico; etc.
        nuclei_queued += _seed_attack_profile_for_tech(db, scan_id, target, product)

    try:
        db.commit()
    except Exception:
        db.rollback()

    logger.info(
        "tech_correlator scan=%s target=%s tool=%s techs=%d findings=%d nuclei=%d",
        scan_id, target, tool_name, len(techs), findings_created, nuclei_queued,
    )
    return {
        "techs": len(techs),
        "tech_list": [f"{t['product']} {t['version']}".strip() for t in techs],
        "findings": findings_created,
        "nuclei_queued": nuclei_queued,
    }
