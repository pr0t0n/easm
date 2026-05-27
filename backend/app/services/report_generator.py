"""
report_generator.py — Gerador de relatório executivo EASM.

Gera HTML rico com:
  - Sumário executivo por domínio raiz
  - Breakdown de severidades com gráficos CSS
  - Superfície de ataque de alto risco (infra ops, dev envs, APIs sensíveis)
  - Achados por categoria OWASP
  - Recomendações priorizadas
  - Delta vs scan anterior (quando disponível)
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session


# ─── Classificação de subdomínios ────────────────────────────────────────────
INFRA_KEYWORDS = {"portainer", "rancher", "jenkins", "gitlab", "grafana", "kibana",
                  "elastic", "prometheus", "rabbitmq", "flower", "zabbix", "nagios",
                  "redis", "mongo", "consul", "vault", "k8s", "kubernetes"}
DEV_KEYWORDS = {"dev-", "staging", "homolog", "hml-", "qa-", "test-", "sandbox", "sandbox."}
SENSITIVE_API_KEYWORDS = {"auth", "sso", "token", "api-", "api.", "internal", "intranet",
                          "crm", "erp", "bi-", "card", "bank", "invoice", "customer"}


def _classify_domain(domain: str) -> str:
    d = domain.lower()
    sub = d.split(".")[0] if "." in d else d
    if any(k in sub for k in INFRA_KEYWORDS):
        return "infra_ops"
    if any(k in sub or k in d for k in DEV_KEYWORDS):
        return "dev_environment"
    if any(k in sub for k in SENSITIVE_API_KEYWORDS):
        return "sensitive_api"
    return "standard"


def _severity_color(sev: str) -> str:
    return {"critical": "#c0392b", "high": "#e67e22",
            "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6"}.get(sev, "#95a5a6")


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def generate_executive_report(
    db: Session,
    scan_id: int,
    previous_scan_id: int | None = None,
) -> str:
    """
    Gera e retorna HTML do relatório executivo para o scan indicado.
    """
    from app.models.models import Finding, ScanJob

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return "<h1>Scan não encontrado</h1>"

    findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == scan_id)
        .order_by(Finding.id)
        .all()
    )

    # Delta: findings do scan anterior para comparação
    prev_titles: set[str] = set()
    if previous_scan_id:
        prev_findings = db.query(Finding.title).filter(Finding.scan_job_id == previous_scan_id).all()
        prev_titles = {r.title for r in prev_findings}

    # ── Agregações ───────────────────────────────────────────────────────────
    total = len(findings)
    by_sev: dict[str, int] = defaultdict(int)
    by_domain: dict[str, list] = defaultdict(list)
    by_owasp: dict[str, list] = defaultdict(list)
    new_findings: list = []
    high_risk_targets: dict[str, list] = defaultdict(list)

    for f in findings:
        sev = str(f.severity or "info")
        by_sev[sev] += 1
        dom = str(f.domain or "")
        by_domain[dom].append(f)
        det = dict(f.details or {})
        owasp = str(det.get("owasp_category") or "Não categorizado")
        if owasp:
            by_owasp[owasp].append(f)
        if f.title not in prev_titles:
            new_findings.append(f)
        cls = _classify_domain(dom)
        if cls in ("infra_ops", "dev_environment", "sensitive_api"):
            high_risk_targets[cls].append(f)

    targets_scanned = sorted(by_domain.keys())
    root_domains = sorted({_root_domain(d) for d in targets_scanned})

    # ── Score de risco ────────────────────────────────────────────────────────
    risk_score = (
        by_sev.get("critical", 0) * 40
        + by_sev.get("high", 0) * 15
        + by_sev.get("medium", 0) * 5
        + by_sev.get("low", 0) * 1
    )
    risk_level = "CRÍTICO" if risk_score >= 80 else ("ALTO" if risk_score >= 40 else ("MÉDIO" if risk_score >= 15 else "BAIXO"))
    risk_color = "#c0392b" if risk_score >= 80 else ("#e67e22" if risk_score >= 40 else ("#f39c12" if risk_score >= 15 else "#27ae60"))

    # ── Top findings por severidade ───────────────────────────────────────────
    top_findings = sorted(findings, key=lambda f: (_severity_order(f.severity or "info"), -(f.risk_score or 0)))[:20]

    now = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")
    domains_str = ", ".join(root_domains)

    # ── CSS Severity bars ─────────────────────────────────────────────────────
    def sev_bar(label: str, count: int, color: str) -> str:
        if count == 0:
            return ""
        pct = min(100, count * 8)
        return f"""
        <div class="sev-row">
          <span class="sev-label" style="color:{color}">{label}</span>
          <div class="sev-bar-bg">
            <div class="sev-bar" style="width:{pct}%;background:{color}"></div>
          </div>
          <span class="sev-count" style="color:{color}">{count}</span>
        </div>"""

    def finding_row(f: Any, is_new: bool = False) -> str:
        sev = str(f.severity or "info")
        color = _severity_color(sev)
        det = dict(f.details or {})
        evidence = str(det.get("evidence") or "")[:200]
        owasp = str(det.get("owasp_category") or "")
        new_badge = '<span class="badge-new">NOVO</span>' if is_new else ""
        cve = f'<code style="font-size:11px;color:#e74c3c">{f.cve}</code>' if f.cve else ""
        return f"""
        <tr>
          <td><span class="sev-badge" style="background:{color}">{sev.upper()}</span></td>
          <td>{f.title or ""} {new_badge} {cve}</td>
          <td>{f.domain or ""}</td>
          <td style="font-size:11px;color:#666">{evidence}</td>
          <td style="font-size:11px">{owasp}</td>
        </tr>"""

    # ── High-risk section ─────────────────────────────────────────────────────
    def high_risk_section() -> str:
        if not high_risk_targets:
            return ""
        rows = []
        class_labels = {
            "infra_ops": ("🔴 Infraestrutura Operacional", "#c0392b"),
            "dev_environment": ("🟠 Ambientes de Desenvolvimento", "#e67e22"),
            "sensitive_api": ("🟡 APIs / Serviços Sensíveis", "#f39c12"),
        }
        for cls in ["infra_ops", "dev_environment", "sensitive_api"]:
            items = high_risk_targets.get(cls, [])
            if not items:
                continue
            label, color = class_labels[cls]
            domains_in_class = sorted({str(f.domain or "") for f in items})
            rows.append(f"""
            <div class="risk-class">
              <h4 style="color:{color}">{label} — {len(domains_in_class)} subdomínios</h4>
              <p style="font-size:12px;color:#666">
                {', '.join(domains_in_class[:15])}{'...' if len(domains_in_class) > 15 else ''}
              </p>
            </div>""")
        if not rows:
            return ""
        return f"""
        <div class="section">
          <h2>⚠️ Superfície de Alto Risco</h2>
          <p>Subdomínios com infraestrutura operacional, ambientes de desenvolvimento
             ou APIs críticas acessíveis externamente:</p>
          {"".join(rows)}
        </div>"""

    # ── OWASP breakdown ───────────────────────────────────────────────────────
    def owasp_section() -> str:
        if not by_owasp:
            return ""
        rows = sorted(by_owasp.items(), key=lambda x: -len(x[1]))
        items = "".join(
            f'<tr><td>{cat}</td><td>{len(flist)}</td>'
            f'<td>{"".join(f"<span class=\"sev-badge\" style=\"background:{_severity_color(f.severity or \"info\")}\">{(f.severity or \"info\").upper()}</span>" for f in sorted(flist, key=lambda f: _severity_order(f.severity or "info"))[:3])}</td></tr>'
            for cat, flist in rows[:10]
        )
        return f"""
        <div class="section">
          <h2>📊 Distribuição OWASP Top 10</h2>
          <table class="findings-table">
            <thead><tr><th>Categoria</th><th>Ocorrências</th><th>Severidades</th></tr></thead>
            <tbody>{items}</tbody>
          </table>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Relatório EASM — {domains_str}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f8f9fa; color: #2c3e50; line-height: 1.5; }}
    .page {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
    .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
               color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }}
    .header h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 4px; }}
    .header .meta {{ font-size: 13px; color: #a0aec0; margin-top: 8px; }}
    .score-badge {{ display: inline-block; background: {risk_color};
                   color: white; padding: 6px 18px; border-radius: 20px;
                   font-size: 14px; font-weight: 700; margin-top: 12px; }}
    .grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }}
    .stat-card {{ background: white; border-radius: 8px; padding: 16px;
                 text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    .stat-card .num {{ font-size: 32px; font-weight: 800; }}
    .stat-card .lbl {{ font-size: 12px; color: #666; margin-top: 4px; }}
    .section {{ background: white; border-radius: 8px; padding: 24px;
               box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 20px; }}
    .section h2 {{ font-size: 17px; font-weight: 700; margin-bottom: 16px;
                  padding-bottom: 8px; border-bottom: 2px solid #eee; }}
    .sev-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
    .sev-label {{ width: 80px; font-size: 13px; font-weight: 600; }}
    .sev-bar-bg {{ flex: 1; background: #f0f0f0; border-radius: 4px; height: 18px; }}
    .sev-bar {{ height: 18px; border-radius: 4px; transition: width .3s; }}
    .sev-count {{ width: 36px; text-align: right; font-weight: 700; font-size: 15px; }}
    .findings-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    .findings-table th {{ background: #f8f9fa; padding: 8px 10px; text-align: left;
                         font-weight: 600; border-bottom: 2px solid #dee2e6; }}
    .findings-table td {{ padding: 8px 10px; border-bottom: 1px solid #f0f0f0;
                         vertical-align: top; }}
    .findings-table tr:hover {{ background: #f8f9ff; }}
    .sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
                 color: white; font-size: 10px; font-weight: 700; margin-right: 2px; }}
    .badge-new {{ display: inline-block; background: #27ae60; color: white;
                 font-size: 9px; padding: 1px 6px; border-radius: 3px;
                 font-weight: 700; margin-left: 4px; }}
    .risk-class {{ border-left: 4px solid #ccc; padding-left: 12px; margin-bottom: 12px; }}
    .reco-item {{ padding: 12px; background: #fffbf0; border-left: 4px solid #f39c12;
                 border-radius: 0 6px 6px 0; margin-bottom: 10px; font-size: 13px; }}
    .reco-item.critical {{ background: #fff5f5; border-color: #c0392b; }}
    .reco-item.high {{ background: #fff8f0; border-color: #e67e22; }}
    .footer {{ text-align: center; font-size: 11px; color: #aaa; margin-top: 32px; padding-bottom: 24px; }}
    @media (max-width: 700px) {{ .grid {{ grid-template-columns: repeat(2, 1fr); }} }}
  </style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <h1>🛡️ Relatório EASM — Superfície de Ataque Externa</h1>
    <div class="meta">
      Domínios: <strong>{domains_str}</strong> &nbsp;|&nbsp;
      Gerado: {now} &nbsp;|&nbsp;
      Scan ID: #{scan_id}
      {f'&nbsp;|&nbsp; Scan anterior: #{previous_scan_id}' if previous_scan_id else ''}
    </div>
    <div class="score-badge">Risco: {risk_level} ({risk_score} pts)</div>
  </div>

  <!-- STATS GRID -->
  <div class="grid">
    <div class="stat-card">
      <div class="num" style="color:#c0392b">{by_sev.get('critical',0)}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat-card">
      <div class="num" style="color:#e67e22">{by_sev.get('high',0)}</div>
      <div class="lbl">High</div>
    </div>
    <div class="stat-card">
      <div class="num" style="color:#f39c12">{by_sev.get('medium',0)}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="stat-card">
      <div class="num" style="color:#3498db">{by_sev.get('low',0)}</div>
      <div class="lbl">Low</div>
    </div>
    <div class="stat-card">
      <div class="num" style="color:#95a5a6">{by_sev.get('info',0)}</div>
      <div class="lbl">Info</div>
    </div>
  </div>

  <!-- SEVERITY BARS -->
  <div class="section">
    <h2>📈 Distribuição por Severidade ({total} findings totais)</h2>
    {sev_bar('Critical', by_sev.get('critical',0), '#c0392b')}
    {sev_bar('High', by_sev.get('high',0), '#e67e22')}
    {sev_bar('Medium', by_sev.get('medium',0), '#f39c12')}
    {sev_bar('Low', by_sev.get('low',0), '#3498db')}
    {sev_bar('Info', by_sev.get('info',0), '#95a5a6')}
    <p style="margin-top:12px;font-size:12px;color:#666">
      {len(targets_scanned)} alvos escaneados em {len(root_domains)} domínio(s) raiz
      {f' &nbsp;|&nbsp; <strong style="color:#27ae60">{len(new_findings)} novos</strong> vs scan anterior' if previous_scan_id else ''}
    </p>
  </div>

  <!-- HIGH RISK SURFACE -->
  {high_risk_section()}

  <!-- TOP FINDINGS -->
  <div class="section">
    <h2>🎯 Principais Achados</h2>
    <table class="findings-table">
      <thead>
        <tr>
          <th style="width:80px">Sev.</th>
          <th>Título</th>
          <th style="width:200px">Domínio</th>
          <th>Evidência</th>
          <th style="width:160px">OWASP</th>
        </tr>
      </thead>
      <tbody>
        {"".join(finding_row(f, f.title not in prev_titles) for f in top_findings)}
      </tbody>
    </table>
  </div>

  <!-- OWASP BREAKDOWN -->
  {owasp_section()}

  <!-- RECOMMENDATIONS -->
  <div class="section">
    <h2>✅ Recomendações Prioritárias</h2>
    {"".join(
        f'<div class="reco-item {f.severity or \"\"}">'
        f'<strong>[{(f.severity or "info").upper()}]</strong> '
        f'{f.recommendation or dict(f.details or {}).get("remediation") or f.title}'
        f'</div>'
        for f in sorted(
            [x for x in findings if x.recommendation or (dict(x.details or {}).get("remediation"))],
            key=lambda x: _severity_order(x.severity or "info")
        )[:15]
    )}
    <div class="reco-item" style="background:#f0f7ff;border-color:#3498db">
      <strong>Geral:</strong> Implementar WAF + proteção de origem (restringir acesso direto ao IP do servidor).
      Configurar HSTS, CSP e X-Frame-Options no nível do load balancer/CDN para herança automática.
      Revisar todos os subdomínios de desenvolvimento ({len(high_risk_targets.get("dev_environment", []))} encontrados) — remover ou colocar atrás de VPN/IP allowlist.
    </div>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    Relatório gerado pela plataforma EASM &nbsp;|&nbsp; {now} &nbsp;|&nbsp;
    Este relatório é confidencial e destinado exclusivamente ao uso interno.
  </div>

</div>
</body>
</html>"""

    return html


def _root_domain(domain: str) -> str:
    """Extrai domínio raiz."""
    parts = domain.lower().rstrip(".").split(".")
    two_part_tlds = {"com.br", "org.br", "net.br", "gov.br", "edu.br",
                     "co.uk", "org.uk", "me.uk", "co.nz", "com.au"}
    if len(parts) >= 3:
        candidate = ".".join(parts[-2:])
        if candidate in two_part_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain
