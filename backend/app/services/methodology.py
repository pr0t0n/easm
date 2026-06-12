"""Scorecard de cobertura de metodologia (torna o scan um entregável de pentest
auditável, não 'saída de scanner').

Mede, por scan, quais CLASSES de vulnerabilidade do nosso catálogo foram de fato
EXERCITADAS (houve work item testando) e quais ficaram sem cobertura — com %.
Inspirado na ideia de checklist de metodologia (OWASP WSTG / API Top 10) que os
skills de pentest mapeiam.
"""

from __future__ import annotations

from sqlalchemy import func, text
from sqlalchemy.orm import Session

# Catálogo-alvo: classes que um pentest web/API deveria cobrir.
# (exclui dos/outros/misconfiguration genérico — não são "técnicas testáveis")
METHODOLOGY_FAMILIES: list[str] = [
    "xss", "sqli", "rce", "ssrf", "idor", "broken_access_control", "auth_bypass",
    "jwt_oauth", "csrf", "open_redirect", "lfri", "path_traversal", "xxe",
    "file_upload", "deserialization", "subdomain_takeover", "cors",
    "header_injection", "race_condition", "graphql_api", "business_logic",
    "info_exposure", "secrets", "security_headers", "tls_ssl", "vulnerable_dependency",
    "nosql_injection", "websocket", "mass_assignment", "bola_bfla",
    "excessive_data_exposure", "prototype_pollution", "type_juggling",
]


def compute_methodology_coverage(db: Session, scan_id: int) -> dict:
    """Retorna cobertura por classe: tested/total, %, e classes não testadas."""
    from app.models.models import ScanWorkItem, Finding, ExecutedToolRun
    from app.services.vuln_family import classify_family, family_label

    tested: set[str] = set()

    # Famílias exercitadas via EXECUÇÕES REAIS de ferramentas. O motor ofensivo
    # (offensive_operator) NÃO cria ScanWorkItem — ele registra cada execução em
    # executed_tool_runs. Sem contar essa tabela, o scorecard via apenas os
    # ACHADOS e marcava como "não testado" classes cujas ferramentas de fato
    # rodaram (ex.: dalfox=XSS, sqlmap=SQLi, nuclei-auth-bypass=Auth Bypass,
    # nuclei-lfi=LFI) mas não produziram achado — o oposto de transparência.
    etr_rows = (
        db.query(ExecutedToolRun.tool_name)
        .filter(ExecutedToolRun.scan_job_id == scan_id)
        .group_by(ExecutedToolRun.tool_name)
        .all()
    )
    for (tool_name,) in etr_rows:
        fam = classify_family(title="", tool=str(tool_name or ""))
        if fam in METHODOLOGY_FAMILIES:
            tested.add(fam)

    # Famílias exercitadas via work items (modos que usam a fila de work items).
    wi_rows = (
        db.query(ScanWorkItem.tool_name, func.count(ScanWorkItem.id))
        .filter(ScanWorkItem.scan_job_id == scan_id)
        .group_by(ScanWorkItem.tool_name)
        .all()
    )
    for tool_name, _cnt in wi_rows:
        fam = classify_family(title="", tool=str(tool_name or ""))
        if fam in METHODOLOGY_FAMILIES:
            tested.add(fam)

    # Famílias com achado (cobertura "produtiva").
    f_rows = db.query(Finding.tool, Finding.title, Finding.cve).filter(Finding.scan_job_id == scan_id).all()
    produced: set[str] = set()
    for tool, title, cve in f_rows:
        fam = classify_family(title=title, tool=tool, cve=cve)
        if fam in METHODOLOGY_FAMILIES:
            produced.add(fam)
            tested.add(fam)

    untested = [f for f in METHODOLOGY_FAMILIES if f not in tested]
    total = len(METHODOLOGY_FAMILIES)
    coverage_pct = int(len(tested) / total * 100) if total else 0
    return {
        "total_families": total,
        "tested_count": len(tested),
        "produced_count": len(produced),
        "coverage_pct": coverage_pct,
        "tested": sorted(tested),
        "produced": sorted(produced),
        "untested": [{"family": f, "label": family_label(f)} for f in untested],
    }
