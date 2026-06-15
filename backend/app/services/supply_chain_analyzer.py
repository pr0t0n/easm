"""
supply_chain_analyzer.py — Análise de supply chain e dependências de terceiros.

Detecta:
  1. Scripts JS de terceiros sem SRI (CDN, GTM, analytics) via httpx tech detection + HTML
  2. Dependências com CVE em package.json / requirements.txt expostos
  3. Versões de bibliotecas JS vulneráveis em bundles (httpx tech + katana URLs)
  4. node_modules expostos via katana crawl (source code traversal)
  5. Pixels de tracking com potencial de exfiltração de dados
  6. Fontes de terceiros e iframes externos (data leak vectors)

Estratégia de dados:
  - Primário: DB cache (httpx parsed_result.tech + katana parsed_result URLs)
  - Secundário: Kali runner HTTP proxy (curl via runner API para HTML full)
  - Terciário: Direct HTTP (fallback, bloqueado por WAF/Cloudflare em produção)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

import requests

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 15
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}

# ─────────────────────────────────────────────────────────────────────────────
# Known third-party CDNs and services
# ─────────────────────────────────────────────────────────────────────────────

TRACKING_DOMAINS = {
    "googletagmanager.com": {
        "risk": "medium", "type": "analytics_gtm",
        "httpx_tech_patterns": ["Google Tag Manager"],
        "description": "Google Tag Manager — pode injetar scripts arbitrários se conta comprometida",
    },
    "google-analytics.com": {
        "risk": "low", "type": "analytics",
        "httpx_tech_patterns": ["Google Analytics"],
        "description": "Google Analytics — coleta dados de navegação de usuários",
    },
    "facebook.net": {
        "risk": "medium", "type": "social_pixel",
        "httpx_tech_patterns": ["Facebook Pixel", "Facebook"],
        "description": "Facebook Pixel — exfiltra eventos de usuário para Meta",
    },
    "connect.facebook.net": {
        "risk": "medium", "type": "social_pixel",
        "httpx_tech_patterns": [],
        "description": "Facebook SDK — acesso a comportamento do usuário",
    },
    "hotjar.com": {
        "risk": "high", "type": "session_recording",
        "httpx_tech_patterns": ["Hotjar"],
        "description": "Hotjar — grava sessões completas de usuários incluindo campos de formulário",
    },
    "fullstory.com": {
        "risk": "high", "type": "session_recording",
        "httpx_tech_patterns": ["FullStory"],
        "description": "FullStory — grava sessões de usuários, pode capturar dados sensíveis",
    },
    "mouseflow.com": {
        "risk": "high", "type": "session_recording",
        "httpx_tech_patterns": ["Mouseflow"],
        "description": "Mouseflow — session recording com potencial de captura de PII",
    },
    "clarity.ms": {
        "risk": "medium", "type": "session_recording",
        "httpx_tech_patterns": ["Microsoft Clarity", "Clarity"],
        "description": "Microsoft Clarity — heatmaps e session recordings",
    },
    "intercom.io": {
        "risk": "medium", "type": "customer_support",
        "httpx_tech_patterns": ["Intercom"],
        "description": "Intercom — acesso a dados de suporte e conversas",
    },
    "zendesk.com": {
        "risk": "low", "type": "customer_support",
        "httpx_tech_patterns": ["Zendesk"],
        "description": "Zendesk — widget de suporte",
    },
    "jsdelivr.net": {
        "risk": "medium", "type": "cdn",
        "httpx_tech_patterns": [],
        "description": "jsDelivr CDN — se comprometido, pode servir JS malicioso",
    },
    "unpkg.com": {
        "risk": "medium", "type": "cdn",
        "httpx_tech_patterns": [],
        "description": "unpkg CDN — mirrors npm, risco de pacote malicioso",
    },
    "cdnjs.cloudflare.com": {
        "risk": "low", "type": "cdn",
        "httpx_tech_patterns": [],
        "description": "Cloudflare CDNJS — CDN relativamente confiável",
    },
    "cdn.jsdelivr.net": {
        "risk": "medium", "type": "cdn",
        "httpx_tech_patterns": [],
        "description": "jsDelivr CDN — sem SRI é vetor de supply chain",
    },
    "ajax.googleapis.com": {
        "risk": "low", "type": "cdn",
        "httpx_tech_patterns": [],
        "description": "Google Libraries CDN",
    },
    "code.jquery.com": {
        "risk": "medium", "type": "cdn",
        "httpx_tech_patterns": [],
        "description": "jQuery CDN — verificar versão para CVEs",
    },
    "sentry.io": {
        "risk": "low", "type": "monitoring",
        "httpx_tech_patterns": ["Sentry"],
        "description": "Sentry error tracking — pode exfiltrar stack traces com dados",
    },
    "newrelic.com": {
        "risk": "low", "type": "monitoring",
        "httpx_tech_patterns": ["New Relic"],
        "description": "New Relic APM — telemetria de performance",
    },
    "segment.io": {
        "risk": "medium", "type": "analytics",
        "httpx_tech_patterns": ["Segment"],
        "description": "Segment.io — analytics hub, consolida dados de múltiplas fontes",
    },
    "mixpanel.com": {
        "risk": "medium", "type": "analytics",
        "httpx_tech_patterns": ["Mixpanel"],
        "description": "Mixpanel — analytics com dados de comportamento",
    },
}

# Vulnerable library patterns (name → known CVE info)
VULNERABLE_JS_LIBS: list[dict] = [
    {
        "pattern": r"jquery[.\-/](\d+\.\d+\.?\d*)(\.min)?\.js",
        "httpx_pattern": r"jQuery:(\d+\.\d+\.?\d*)",
        "name": "jQuery",
        "vulnerable_below": "3.5.0",
        "cve": "CVE-2019-11358",
        "description": "Prototype Pollution via $.extend()",
        "severity": "medium",
    },
    {
        "pattern": r"bootstrap[.\-/](\d+\.\d+\.?\d*)(\.min)?\.js",
        "httpx_pattern": r"Bootstrap:(\d+\.\d+\.?\d*)",
        "name": "Bootstrap JS",
        "vulnerable_below": "4.3.1",
        "cve": "CVE-2019-8331",
        "description": "XSS via data-template attribute",
        "severity": "medium",
    },
    {
        "pattern": r"angular[.\-/](\d+\.\d+\.?\d*)(\.min)?\.js",
        "httpx_pattern": r"AngularJS:(\d+\.\d+\.?\d*)",
        "name": "AngularJS",
        "vulnerable_below": "1.8.0",
        "cve": "CVE-2019-14863",
        "description": "Prototype Pollution",
        "severity": "high",
    },
    {
        "pattern": r"lodash[.\-/](\d+\.\d+\.?\d*)(\.min)?\.js",
        "httpx_pattern": r"Lodash:(\d+\.\d+\.?\d*)",
        "name": "Lodash",
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2021-23337",
        "description": "Command injection via template",
        "severity": "high",
    },
    {
        "pattern": r"moment[.\-/](\d+\.\d+\.?\d*)(\.min)?\.js",
        "httpx_pattern": r"Moment\.?js:(\d+\.\d+\.?\d*)",
        "name": "Moment.js",
        "vulnerable_below": "2.29.4",
        "cve": "CVE-2022-24785",
        "description": "Path Traversal via locale input",
        "severity": "high",
    },
    {
        "pattern": r"handlebars[.\-/](\d+\.\d+\.?\d*)(\.min)?\.js",
        "httpx_pattern": r"Handlebars\.?js:(\d+\.\d+\.?\d*)",
        "name": "Handlebars",
        "vulnerable_below": "4.7.7",
        "cve": "CVE-2021-23369",
        "description": "Prototype Pollution → RCE em server-side",
        "severity": "critical",
    },
    {
        "pattern": r"chart\.js[.\-/](\d+\.\d+\.?\d*)(\.min)?\.js",
        "httpx_pattern": r"Chart\.?js:(\d+\.\d+\.?\d*)",
        "name": "Chart.js",
        "vulnerable_below": "2.9.4",
        "cve": "CVE-2019-11360",
        "description": "XSS via labels",
        "severity": "medium",
    },
]

# Exposed sensitive files to check
SENSITIVE_FILES = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "requirements.txt",
    "Pipfile",
    "composer.json",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    ".env",
    ".env.local",
    ".env.production",
    "config.json",
    "settings.json",
    "app.config.js",
    ".npmrc",
    ".pypirc",
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _parse_version(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", v)[:3])
    except Exception:
        return (0, 0, 0)


def _version_below(version: str, threshold: str) -> bool:
    return _parse_version(version) < _parse_version(threshold)


def _safe_get(url: str, timeout: int = _DEFAULT_TIMEOUT) -> requests.Response | None:
    try:
        return requests.get(url, timeout=timeout, headers=_HEADERS,
                            verify=False, allow_redirects=True)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# DB-cached analysis (primary — works even when direct HTTP is blocked by WAF)
# ─────────────────────────────────────────────────────────────────────────────


def _analyze_from_httpx_tech(target: str, tech_list: list[str]) -> list[dict]:
    """
    Mine httpx technology-detection results for supply chain risks.
    httpx already ran in Kali runner with WAF bypass, results are in DB.
    """
    findings = []

    # ── Check tracking domains ────────────────────────────────────────────────
    for domain, info in TRACKING_DOMAINS.items():
        for pattern in info.get("httpx_tech_patterns", []):
            if any(pattern.lower() in t.lower() for t in tech_list):
                if info["type"] == "session_recording":
                    severity = "high"
                    title = f"[SUPPLY-CHAIN] Session Recording de Terceiro: {domain}"
                    description = (
                        f"{info['description']}. "
                        f"Ferramentas de session recording capturam TUDO que o usuário digita, "
                        f"incluindo campos de senha, dados de cartão e PII. "
                        f"Violação potencial de LGPD Art. 46."
                    )
                elif info["type"] == "analytics_gtm":
                    severity = "medium"
                    title = "[SUPPLY-CHAIN] Google Tag Manager — Risco de Injeção de Script"
                    description = (
                        "Google Tag Manager detectado. GTM carrega scripts de terceiros DINAMICAMENTE, "
                        "tornando SRI impossível de aplicar nos scripts carregados via tags. "
                        "Se a conta GTM for comprometida (phishing, credential stuffing), "
                        "um atacante pode injetar JS malicioso em PRODUÇÃO sem acesso ao servidor. "
                        "Vetor real: phishing do dev/mktg → conta GTM comprometida → "
                        "JS keylogger em produção capturando credenciais de todos os usuários."
                    )
                else:
                    severity = info["risk"]
                    title = f"[SUPPLY-CHAIN] Third-party Script Detectado: {domain}"
                    description = info["description"]

                findings.append({
                    "title": title,
                    "severity": severity,
                    "domain": target,
                    "source_tool": "supply_chain_analyzer",
                    "evidence": f"Tecnologia detectada por httpx: {pattern} ({domain})",
                    "description": description,
                    "details": {
                        "source": "supply_chain_httpx_tech",
                        "third_party_domain": domain,
                        "type": info["type"],
                        "detected_via": "httpx technology fingerprint",
                        "attack_scenario": (
                            f"1. Phishing/credential stuffing na conta {domain}\n"
                            f"2. Atacante injeta JS malicioso via painel do serviço\n"
                            f"3. JS malicioso executa em todos os browsers dos usuários\n"
                            f"4. Keylogger captura credenciais, dados de cartão, PII"
                        ) if info["type"] in ("session_recording", "analytics_gtm") else None,
                        "business_impact": (
                            "Dados pessoais e comportamento de usuários sendo enviados "
                            "para servidor de terceiro. LGPD Art. 7 e Art. 46."
                        ),
                    },
                })
                break  # One finding per domain

    # ── Check vulnerable library versions ────────────────────────────────────
    for lib_info in VULNERABLE_JS_LIBS:
        httpx_pat = lib_info.get("httpx_pattern", "")
        if not httpx_pat:
            continue
        for t in tech_list:
            m = re.search(httpx_pat, t, re.IGNORECASE)
            if m:
                version = m.group(1)
                if _version_below(version, lib_info["vulnerable_below"]):
                    findings.append({
                        "title": f"[SUPPLY-CHAIN] {lib_info['name']} {version} vulnerável ({lib_info['cve']})",
                        "severity": lib_info["severity"],
                        "domain": target,
                        "cve": lib_info["cve"],
                        "source_tool": "supply_chain_analyzer",
                        "evidence": (
                            f"{lib_info['name']} {version} detectado por httpx tech-detect. "
                            f"Versão segura: >= {lib_info['vulnerable_below']}"
                        ),
                        "description": (
                            f"{lib_info['name']} versão {version} contém {lib_info['cve']}: "
                            f"{lib_info['description']}. "
                            f"Atualizar para >= {lib_info['vulnerable_below']}."
                        ),
                        "details": {
                            "source": "supply_chain_httpx_tech",
                            "lib_name": lib_info["name"],
                            "lib_version": version,
                            "fix_version": lib_info["vulnerable_below"],
                            "cve": lib_info["cve"],
                            "reproduction_steps": [
                                f"# Verificar versão em produção:",
                                f"curl -s https://{target}/ | grep -i '{lib_info['name'].lower()}'",
                                f"# Confirmar CVE:",
                                f"# Buscar: https://nvd.nist.gov/vuln/detail/{lib_info['cve']}",
                            ],
                        },
                    })
                break  # found a match for this lib

    return findings


def _analyze_katana_urls(target: str, urls: list[str]) -> list[dict]:
    """
    Mine katana crawl results for supply chain risks.
    Looks for: node_modules exposed, external JS files, CDN links.
    """
    findings = []

    # ── node_modules exposure (CRITICAL — source code traversal) ─────────────
    node_mod_urls = [u for u in urls if "node_modules" in str(u)]
    if node_mod_urls:
        # Extract unique package names and versions
        packages: dict[str, str] = {}
        pkg_pattern = re.compile(r"node_modules/(?:\.pnpm/)?([^/@]+)@?([0-9][^/]*)?")
        for url in node_mod_urls[:50]:
            m = pkg_pattern.search(str(url))
            if m:
                pkg_name = m.group(1)
                pkg_ver = m.group(2) or "unknown"
                # Clean up pnpm lockfile hash from version
                pkg_ver = re.sub(r"_[a-f0-9]{16,}.*", "", pkg_ver).strip("/")
                if pkg_name not in packages:
                    packages[pkg_name] = pkg_ver

        pkg_list = [f"{k}@{v}" for k, v in list(packages.items())[:10]]
        example_url = str(node_mod_urls[0])[:200]

        findings.append({
            "title": "[SUPPLY-CHAIN] node_modules Expostos via HTTP (Source Code Traversal)",
            "severity": "critical",
            "domain": target,
            "source_tool": "supply_chain_analyzer",
            "evidence": (
                f"{len(node_mod_urls)} URLs de node_modules acessíveis. "
                f"Pacotes expostos: {', '.join(pkg_list[:5])}. "
                f"Exemplo: {example_url}"
            ),
            "description": (
                "O diretório node_modules está sendo servido via HTTP, expondo o código-fonte "
                "de todas as dependências de produção. Isso revela:\n"
                "• Versões exatas de todas as dependências (attack surface mapping)\n"
                "• Código-fonte do servidor (lógica de negócio em Node.js)\n"
                "• Possível travessia de diretório para arquivos sensíveis\n"
                "• Roadmap para exploração de CVEs em pacotes específicos\n"
                f"Pacotes identificados: {', '.join(pkg_list)}"
            ),
            "details": {
                "source": "supply_chain_katana",
                "total_node_module_urls": len(node_mod_urls),
                "packages_exposed": packages,
                "example_urls": [str(u)[:200] for u in node_mod_urls[:5]],
                "attack_impact": (
                    "Atacante pode mapear exatamente quais pacotes e versões estão em produção, "
                    "identificar CVEs específicos e construir exploits direcionados. "
                    "Combinado com RCE, pode exfiltrar o código-fonte completo da aplicação."
                ),
                "reproduction_steps": [
                    f"curl -s 'https://{target}/app/node_modules/' | grep -i package",
                    f"# Acessar: https://{target}/app/node_modules/.pnpm/",
                ],
                "fix": (
                    "Nunca servir diretório node_modules via HTTP. "
                    "Configurar regra no servidor web (nginx/apache) para bloquear acesso "
                    "a node_modules, .git, .env e outros diretórios sensíveis."
                ),
            },
        })

        # Check specific vulnerable packages in node_modules
        vuln_npm = {
            "express": ("4.21.2", "CVE-2024-43796", "XSS via response.redirect()"),
            "lodash": ("4.17.20", "CVE-2021-23337", "Command injection via template"),
            "axios": ("0.21.0", "CVE-2021-3749", "ReDoS"),
            "minimist": ("1.2.5", "CVE-2021-44906", "Prototype Pollution"),
            "node-fetch": ("2.6.0", "CVE-2022-0235", "Information Exposure"),
            "jsonwebtoken": ("8.5.1", "CVE-2022-23529", "Insecure default algorithm"),
            "qs": ("6.5.2", "CVE-2022-24999", "Prototype Pollution"),
            "path-parse": ("1.0.6", "CVE-2021-23343", "ReDoS"),
        }
        for pkg_name, (vuln_ver, cve, vuln_desc) in vuln_npm.items():
            if pkg_name in packages:
                actual_ver = packages[pkg_name]
                if actual_ver != "unknown" and _version_below(actual_ver, vuln_ver):
                    findings.append({
                        "title": f"[SUPPLY-CHAIN] {pkg_name}@{actual_ver} vulnerável — {cve}",
                        "severity": "high",
                        "domain": target,
                        "cve": cve,
                        "source_tool": "supply_chain_analyzer",
                        "evidence": (
                            f"{pkg_name}@{actual_ver} exposto em node_modules. "
                            f"Versão vulnerável: < {vuln_ver}"
                        ),
                        "description": (
                            f"Pacote npm {pkg_name} versão {actual_ver} contém {cve}: {vuln_desc}. "
                            f"Versão segura: >= {vuln_ver}. "
                            f"Pacote está exposto via HTTP em node_modules."
                        ),
                        "details": {
                            "source": "supply_chain_katana",
                            "package": pkg_name,
                            "version": actual_ver,
                            "cve": cve,
                            "fix_version": vuln_ver,
                        },
                    })

    # ── External JS files from crawl ──────────────────────────────────────────
    external_js = []
    for url in urls:
        url_str = str(url)
        if url_str.endswith(".js") or ".js?" in url_str:
            # Check if it's from a third-party domain
            for td_domain in TRACKING_DOMAINS:
                if td_domain in url_str and target not in url_str:
                    external_js.append((td_domain, url_str))
                    break

    for td_domain, script_url in external_js[:5]:
        td_info = TRACKING_DOMAINS[td_domain]
        findings.append({
            "title": f"[SUPPLY-CHAIN] Script Externo sem SRI: {td_domain}",
            "severity": "medium",
            "domain": target,
            "source_tool": "supply_chain_analyzer",
            "evidence": f"Script de terceiro encontrado no crawl: {script_url[:150]}",
            "description": (
                f"Script carregado de {td_domain} sem verificação SRI. "
                f"{td_info['description']}. "
                f"Se o CDN for comprometido, JS malicioso afetará todos os usuários."
            ),
            "details": {
                "source": "supply_chain_katana",
                "third_party_domain": td_domain,
                "type": td_info["type"],
                "script_url": script_url[:500],
                "fix": "Adicionar integrity='sha384-...' crossorigin='anonymous' ao script tag",
            },
        })

    return findings


def analyze_page_supply_chain(domain: str, base_url: str, html: str | None = None) -> list[dict]:
    """
    Analisa HTML de uma página em busca de supply chain risks.
    Aceita HTML pré-carregado (para evitar bloqueios WAF).
    """
    findings = []

    if html is None:
        r = _safe_get(base_url)
        if not r or r.status_code not in [200, 206]:
            return findings
        html = r.text

    # ── Scripts externos ──────────────────────────────────────────────────────
    script_pattern = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE
    )
    for m in script_pattern.finditer(html):
        script_url = m.group(1)
        tag = m.group(0)
        has_sri = "integrity=" in tag.lower()

        third_party_domain = None
        for td in TRACKING_DOMAINS:
            if td in script_url:
                third_party_domain = td
                break

        if third_party_domain:
            td_info = TRACKING_DOMAINS[third_party_domain]

            if td_info["type"] == "session_recording":
                findings.append({
                    "title": f"[SUPPLY-CHAIN] Session Recording de Terceiro: {third_party_domain}",
                    "severity": "high",
                    "domain": domain,
                    "source_tool": "supply_chain_analyzer",
                    "evidence": f"Script carregado de {third_party_domain}: {script_url[:100]}",
                    "description": (
                        f"{td_info['description']}. "
                        f"Ferramentas de session recording capturam TUDO que o usuário digita, "
                        f"incluindo campos de senha, dados de cartão e PII. "
                        f"Violação potencial de LGPD Art. 46."
                    ),
                    "details": {
                        "source": "supply_chain_html",
                        "third_party_domain": third_party_domain,
                        "type": td_info["type"],
                        "has_sri": has_sri,
                        "script_url": script_url[:500],
                    },
                })
            elif not has_sri and td_info["type"] == "cdn":
                findings.append({
                    "title": f"[SUPPLY-CHAIN] CDN sem Sub-Resource Integrity: {third_party_domain}",
                    "severity": "medium",
                    "domain": domain,
                    "source_tool": "supply_chain_analyzer",
                    "evidence": f"Script sem SRI: {script_url[:100]}",
                    "description": (
                        f"Script carregado de {third_party_domain} sem hash SRI. "
                        f"Se o CDN for comprometido, JavaScript malicioso pode ser injetado. "
                        f"{td_info['description']}"
                    ),
                    "details": {
                        "source": "supply_chain_html",
                        "third_party_domain": third_party_domain,
                        "has_sri": False,
                        "script_url": script_url[:500],
                        "fix": "Adicionar integrity='sha384-...' crossorigin='anonymous' ao script tag",
                    },
                })
            elif "googletagmanager.com" in third_party_domain and not has_sri:
                findings.append({
                    "title": "[SUPPLY-CHAIN] Google Tag Manager Carregado sem SRI",
                    "severity": "medium",
                    "domain": domain,
                    "source_tool": "supply_chain_analyzer",
                    "evidence": f"GTM script: {script_url[:100]}",
                    "description": (
                        "Google Tag Manager carrega scripts de terceiros DINAMICAMENTE, "
                        "tornando SRI impossível de aplicar nos scripts carregados via tags. "
                        "Vetor real: phishing do dev/mktg → conta GTM comprometida → "
                        "JS keylogger em produção."
                    ),
                    "details": {
                        "source": "supply_chain_html",
                        "type": "analytics_gtm",
                        "script_url": script_url[:500],
                    },
                })

        # Check for vulnerable library versions in script URL
        for lib_info in VULNERABLE_JS_LIBS:
            m2 = re.search(lib_info["pattern"], script_url, re.IGNORECASE)
            if m2:
                version = m2.group(1)
                if _version_below(version, lib_info["vulnerable_below"]):
                    findings.append({
                        "title": f"[SUPPLY-CHAIN] {lib_info['name']} {version} com {lib_info['cve']}",
                        "severity": lib_info["severity"],
                        "domain": domain,
                        "cve": lib_info["cve"],
                        "source_tool": "supply_chain_analyzer",
                        "evidence": f"Versão {version} de {lib_info['name']} encontrada em {script_url[:100]}",
                        "description": (
                            f"{lib_info['name']} versão {version} é vulnerável a {lib_info['cve']}: "
                            f"{lib_info['description']}. "
                            f"Versão segura: >= {lib_info['vulnerable_below']}"
                        ),
                        "details": {
                            "source": "supply_chain_html",
                            "lib_name": lib_info["name"],
                            "lib_version": version,
                            "fix_version": lib_info["vulnerable_below"],
                            "cve": lib_info["cve"],
                        },
                    })

    # ── Iframes externos ──────────────────────────────────────────────────────
    iframe_pattern = re.compile(r'<iframe[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    for m in iframe_pattern.finditer(html):
        iframe_url = m.group(1)
        if iframe_url.startswith("http") and domain not in iframe_url:
            findings.append({
                "title": "[SUPPLY-CHAIN] iframe Externo Carregado",
                "severity": "low",
                "domain": domain,
                "source_tool": "supply_chain_analyzer",
                "evidence": f"iframe externo: {iframe_url[:100]}",
                "description": (
                    "Iframe externo carregado de domínio de terceiro. "
                    "Se o site de origem for comprometido, pode executar código no contexto da página."
                ),
                "details": {"source": "supply_chain_html", "iframe_url": iframe_url[:300]},
            })

    return findings


def check_exposed_dependencies(domain: str, base_url: str) -> list[dict]:
    """Verifica se arquivos de dependências estão expostos publicamente."""
    findings = []

    for filename in SENSITIVE_FILES:
        url = base_url.rstrip("/") + "/" + filename
        r = _safe_get(url, timeout=10)
        if not r or r.status_code != 200:
            continue

        text = r.text
        is_sensitive = False
        sensitive_info = []

        if ".env" in filename:
            env_patterns = [
                (r"(?:DB|DATABASE)_(?:PASSWORD|PASS|PWD)\s*=\s*\S+", "DB password"),
                (r"(?:API_KEY|SECRET_KEY|APP_SECRET)\s*=\s*\S+", "API/Secret key"),
                (r"AWS_(?:SECRET|ACCESS_KEY)\s*=\s*\S+", "AWS credentials"),
                (r"(?:PRIVATE_KEY|RSA_KEY)\s*=\s*\S+", "Private key"),
            ]
            for pat, desc in env_patterns:
                if re.search(pat, text, re.IGNORECASE):
                    is_sensitive = True
                    sensitive_info.append(desc)

        elif filename in ("package.json", "requirements.txt", "composer.json"):
            is_sensitive = True
            sensitive_info.append("dependency manifest exposed")

            vulnerable_npm = {
                "lodash": "4.17.20",
                "axios": "0.21.0",
                "minimist": "1.2.5",
                "node-fetch": "2.6.0",
                "jsonwebtoken": "8.5.1",
            }
            for pkg, vuln_below in vulnerable_npm.items():
                pattern = rf'"{pkg}"\s*:\s*"[~^]?(\d+\.\d+\.?\d*)"'
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    ver = m.group(1)
                    if _version_below(ver, vuln_below):
                        sensitive_info.append(f"{pkg} {ver} < {vuln_below} (vulnerable)")

        if is_sensitive:
            findings.append({
                "title": f"[SUPPLY-CHAIN] Arquivo de Dependência Exposto: {filename}",
                "severity": "high" if ".env" in filename else "medium",
                "domain": domain,
                "source_tool": "supply_chain_analyzer",
                "evidence": f"HTTP 200 em /{filename}. Info: {', '.join(sensitive_info[:3])}",
                "description": (
                    f"O arquivo {filename} está acessível publicamente. "
                    f"Expõe: {', '.join(sensitive_info)}."
                ),
                "details": {
                    "source": "supply_chain_http",
                    "file": filename,
                    "sensitive_info": sensitive_info,
                    "url": url,
                },
            })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────


def run_supply_chain_scan(
    db: Any,
    scan_id: int,
    target_domains: list[str] | None = None,
    max_domains: int = 50,
) -> dict[str, Any]:
    """
    Entry point: executa supply chain analysis usando dados DB-cached + HTTP fallback.

    Estratégia:
    1. Para cada target: busca httpx tech results e katana URL results do DB
    2. Analisa tech list para tracking tools e lib versions vulneráveis
    3. Analisa katana URLs para node_modules exposure e CDN scripts
    4. Tenta HTTP direto como fallback (funciona se não há WAF/Cloudflare bloqueando)
    5. Persiste findings no DB
    """
    from app.models.models import Finding, ScanJob, ScanWorkItem

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return {"error": "Scan not found"}

    if not target_domains:
        existing = (
            db.query(Finding.domain)
            .filter(Finding.scan_job_id == scan_id)
            .distinct()
            .limit(max_domains)
            .all()
        )
        target_domains = [r[0] for r in existing if r[0]]

    total_findings = 0
    domains_analyzed = 0
    method_counts = {"httpx_tech": 0, "katana_urls": 0, "html_parse": 0, "http_files": 0}
    # In-session dedup: track (domain, title) pairs added this run to avoid
    # duplicates when multiple sources (httpx_tech + html_parse) find the same issue
    _session_seen: set[tuple[str, str]] = set()

    for domain in target_domains:
        domain_findings: list[dict] = []

        # ── 1. Mine httpx cached results from DB ──────────────────────────────
        # Order by id DESC to get the most recent completed result
        httpx_items = (
            db.query(ScanWorkItem)
            .filter(
                ScanWorkItem.scan_job_id == scan_id,
                ScanWorkItem.tool_name == "httpx",
                ScanWorkItem.target == domain,
                ScanWorkItem.status == "completed",
            )
            .order_by(ScanWorkItem.id.desc())
            .first()
        )
        if httpx_items and httpx_items.result:
            pr = httpx_items.result.get("parsed_result", [])
            for entry in (pr if isinstance(pr, list) else []):
                if not isinstance(entry, dict):
                    continue
                tech_list = entry.get("tech", [])
                if tech_list:
                    tech_findings = _analyze_from_httpx_tech(domain, tech_list)
                    if tech_findings:
                        domain_findings.extend(tech_findings)
                        method_counts["httpx_tech"] += len(tech_findings)
                    break  # one httpx result per target is enough

        # ── 2. Mine katana crawl results from DB ──────────────────────────────
        katana_items = (
            db.query(ScanWorkItem)
            .filter(
                ScanWorkItem.scan_job_id == scan_id,
                ScanWorkItem.tool_name == "katana",
                ScanWorkItem.target == domain,
                ScanWorkItem.status == "completed",
            )
            .order_by(ScanWorkItem.id.desc())
            .first()
        )
        if katana_items and katana_items.result:
            urls = katana_items.result.get("parsed_result", [])
            if urls:
                katana_findings = _analyze_katana_urls(domain, urls)
                if katana_findings:
                    domain_findings.extend(katana_findings)
                    method_counts["katana_urls"] += len(katana_findings)

        # ── 3. Also check gospider results (similar to katana) ────────────────
        gospider_items = (
            db.query(ScanWorkItem)
            .filter(
                ScanWorkItem.scan_job_id == scan_id,
                ScanWorkItem.tool_name == "gospider",
                ScanWorkItem.target == domain,
                ScanWorkItem.status == "completed",
            )
            .order_by(ScanWorkItem.id.desc())
            .first()
        )
        if gospider_items and gospider_items.result:
            urls = gospider_items.result.get("parsed_result", [])
            if urls:
                gospider_findings = _analyze_katana_urls(domain, urls)
                if gospider_findings:
                    domain_findings.extend(gospider_findings)
                    method_counts["katana_urls"] += len(gospider_findings)

        # ── 4. HTTP fallback (for non-WAF-protected targets) ──────────────────
        base_url = f"https://{domain}" if not domain.startswith("http") else domain
        r = _safe_get(base_url, timeout=8)
        if r and r.status_code in [200, 206] and len(r.text) > 200:
            html_findings = analyze_page_supply_chain(domain, base_url, html=r.text)
            if html_findings:
                domain_findings.extend(html_findings)
                method_counts["html_parse"] += len(html_findings)

            # Check exposed dependency files
            file_findings = check_exposed_dependencies(domain, base_url)
            if file_findings:
                domain_findings.extend(file_findings)
                method_counts["http_files"] += len(file_findings)

        if domain_findings:
            domains_analyzed += 1

        # ── Persist findings ──────────────────────────────────────────────────
        for bf in domain_findings:
            title = bf["title"][:500]
            dedup_key = (domain, title)

            # In-session dedup (prevents duplicates within a single run before commit)
            if dedup_key in _session_seen:
                continue
            _session_seen.add(dedup_key)

            # DB dedup (prevents re-adding on subsequent runs)
            exists = (
                db.query(Finding.id)
                .filter(
                    Finding.scan_job_id == scan_id,
                    Finding.domain == domain,
                    Finding.title == title,
                )
                .first()
            )
            if exists:
                continue

            details_payload = bf.get("details", {}) or {}
            # Enrich details so report engine can extract target, description, and CVE info
            finding_domain = bf.get("domain", domain)
            details_payload["evidence"] = bf.get("evidence", "")[:2000]
            details_payload["target"] = finding_domain  # ← ensures per-subdomain target resolution
            details_payload["url"] = f"https://{finding_domain}"
            if bf.get("description"):
                details_payload["description"] = bf.get("description", "")[:2000]
            if bf.get("cve") and not details_payload.get("cve"):
                details_payload["cve"] = bf["cve"]

            f = Finding(
                scan_job_id=scan_id,
                domain=finding_domain,
                title=title,
                severity=bf["severity"],
                cve=bf.get("cve"),
                tool=bf.get("source_tool", "supply_chain_analyzer"),
                recommendation=bf.get("evidence", "")[:2000],
                details=details_payload,
                retest_status="confirmed",
                risk_score={"critical": 9, "high": 7, "medium": 5, "low": 2}.get(bf["severity"], 5),
                created_at=datetime.now(),
            )
            db.add(f)
            total_findings += 1

    if total_findings:
        try:
            db.commit()
        except Exception:
            db.rollback()

    logger.info(
        "supply_chain_scan: %d domains analyzed, %d findings (methods: %s)",
        domains_analyzed, total_findings, method_counts,
    )
    return {
        "domains_analyzed": domains_analyzed,
        "findings_created": total_findings,
        "method_counts": method_counts,
    }
