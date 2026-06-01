"""
report_generator.py — Gerador de relatório de Pentest Automatizado.

Gera HTML rico com:
  SEÇÃO PENTEST (prioridade — o que o cliente pagou para saber):
  - Sumário executivo: vulnerabilidades confirmadas com PoC
  - Chains de ataque: sequências de exploração provadas
  - Vulnerabilidades críticas com passos de reprodução
  - Matriz de risco confirmado por alvo
  - Ações obrigatórias para o Blue Team (com criticidade e prazo)

  SEÇÃO EASM (contexto — o que está exposto):
  - Superfície de ataque: subdomínios, portas, tecnologias
  - Achados de descoberta por severidade (com status de verificação)
  - Distribuição OWASP Top 10
  - Inventário de ativos de alto risco (infra, dev, APIs sensíveis)
  - Delta vs scan anterior (novos findings)
  - Recomendações priorizadas
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


def _md_to_html(md: str) -> str:
    """Conversor Markdown→HTML mínimo (headers, bold, code, listas, parágrafos).

    Suficiente para a narrativa de ataque (gerada em Markdown). Faz escape de
    HTML antes de aplicar a formatação, evitando injeção.
    """
    import re as _re

    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    out: list[str] = []
    in_list = False
    for raw in str(md or "").split("\n"):
        line = raw.rstrip()
        if not line.strip():
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        e = esc(line.strip())
        # inline: **bold** e `code`
        e = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", e)
        e = _re.sub(r"`(.+?)`", r'<code style="background:#f1f1f4;padding:1px 5px;border-radius:3px;font-size:12px">\1</code>', e)
        if line.startswith("### "):
            out.append(f'<h4 style="font-size:13px;margin:10px 0 4px;color:#34495e">{e[4:]}</h4>')
        elif line.startswith("## "):
            out.append(f'<h3 style="font-size:15px;margin:14px 0 6px;color:#c0392b">{e[3:]}</h3>')
        elif line.startswith("# "):
            out.append(f'<h2 style="font-size:17px;margin:16px 0 8px">{e[2:]}</h2>')
        elif line.lstrip().startswith(("- ", "* ")):
            if not in_list:
                out.append('<ul style="margin:4px 0 8px 20px">')
                in_list = True
            out.append(f"<li style='margin-bottom:3px'>{e[2:]}</li>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f'<p style="margin-bottom:8px">{e}</p>')
    if in_list:
        out.append("</ul>")
    return "".join(out)


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

    # ── Recommendation builder helper (avoids inline f-string with escapes) ──
    def _build_reco_html(flist: list) -> str:
        items_with_reco = [
            x for x in flist
            if getattr(x, "recommendation", None) or dict(getattr(x, "details", None) or {}).get("remediation")
        ]
        items_sorted = sorted(items_with_reco, key=lambda x: _severity_order(x.severity or "info"))[:15]
        parts = []
        for item in items_sorted:
            sev = item.severity or "info"
            det = dict(item.details or {}) if item.details else {}
            text = item.recommendation or det.get("remediation") or item.title or ""
            parts.append(
                f'<div class="reco-item {sev}">'
                f'<strong>[{sev.upper()}]</strong> {text}'
                f"</div>"
            )
        parts.append(
            '<div class="reco-item" style="background:#f0f7ff;border-color:#3498db">'
            "<strong>Geral:</strong> Implementar WAF + proteção de origem. "
            "Configurar HSTS, CSP e X-Frame-Options no nível do load balancer/CDN. "
            f"Revisar subdomínios de desenvolvimento ({len(high_risk_targets.get('dev_environment', []))} encontrados)."
            "</div>"
        )
        return "".join(parts)

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

        def _owasp_sev_badges(flist: list) -> str:
            badges = []
            for f in sorted(flist, key=lambda f: _severity_order(f.severity or "info"))[:3]:
                sev = f.severity or "info"
                c = _severity_color(sev)
                badges.append(f'<span class="sev-badge" style="background:{c}">{sev.upper()}</span>')
            return "".join(badges)

        items = "".join(
            f'<tr><td>{cat}</td><td>{len(flist)}</td><td>{_owasp_sev_badges(flist)}</td></tr>'
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
    {_build_reco_html(findings)}
    <div class="reco-item" style="background:#f0f7ff;border-color:#3498db">
      <strong>Geral:</strong> Implementar WAF + proteção de origem (restringir acesso direto ao IP do servidor).
      Configurar HSTS, CSP e X-Frame-Options no nível do load balancer/CDN para herança automática.
      Revisar todos os subdomínios de desenvolvimento ({len(high_risk_targets.get("dev_environment", []))} encontrados) — remover ou colocar atrás de VPN/IP allowlist.
    </div>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    Relatório de Pentest Automatizado &nbsp;|&nbsp; {now} &nbsp;|&nbsp;
    Este relatório é confidencial e destinado exclusivamente ao uso interno.
    &nbsp;|&nbsp; Conteúdo: superfície de ataque + vulnerabilidades confirmadas com PoC.
  </div>

</div>
</body>
</html>"""

    return html


def generate_pentest_report(
    db: "Session",
    scan_id: int,
    previous_scan_id: int | None = None,
) -> str:
    """Gera relatório completo de Pentest: seção pentest (confirmados + chains)
    seguida da seção EASM (superfície + exposições).

    Este é o relatório primário da plataforma — combina prova de exploração
    com inventário completo de superfície de ataque.
    """
    from app.models.models import Finding, ScanJob

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return "<h1>Scan não encontrado</h1>"

    all_findings = (
        db.query(Finding)
        .filter(Finding.scan_job_id == scan_id, Finding.is_false_positive.is_(False))
        .order_by(Finding.id)
        .all()
    )

    # ── Categorize by verification status ────────────────────────────────────
    try:
        from app.services.exploitation_gate import filter_report_ready_findings
        categorized = filter_report_ready_findings(all_findings)
    except Exception:
        confirmed_findings = [f for f in all_findings if getattr(f, "verification_status", "") == "confirmed"]
        categorized = {
            "confirmed": confirmed_findings,
            "candidates": [f for f in all_findings if getattr(f, "verification_status", "") == "candidate"],
            "hypotheses": [f for f in all_findings if getattr(f, "verification_status", "") == "hypothesis"],
            "total_confirmed_critical": sum(1 for f in confirmed_findings if f.severity == "critical"),
            "total_confirmed_high": sum(1 for f in confirmed_findings if f.severity == "high"),
        }

    confirmed_list = categorized.get("confirmed") or []
    candidate_list = categorized.get("candidates") or []
    hypothesis_list = categorized.get("hypotheses") or []

    # ── Exploit chains from state_data ───────────────────────────────────────
    state_data = dict(job.state_data or {})
    chain_findings = [
        f for f in all_findings
        if dict(f.details or {}).get("chain_finding")
    ]

    # ── Aggregate counts ──────────────────────────────────────────────────────
    total_all = len(all_findings)
    total_confirmed = len(confirmed_list)
    conf_critical = categorized.get("total_confirmed_critical", 0)
    conf_high = categorized.get("total_confirmed_high", 0)
    conf_medium = sum(1 for f in confirmed_list if f.severity == "medium")

    # ── PROCESSO ÚNICO DE VISIBILIDADE (FIX B) ────────────────────────────────
    # Contagem canônica de "vulnerabilidades" = findings actionable (severity>=low,
    # não-FP) — EXATAMENTE o que vai p/ a tabela vulnerabilities e a UI. Garante
    # que report, dashboard e VulnerabilitiesPage mostrem o MESMO número.
    _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    vuln_findings = [f for f in all_findings if _SEV_RANK.get(str(f.severity or "").lower(), 0) >= 1]
    vuln_count = len(vuln_findings)
    vuln_by_sev = {s: sum(1 for f in vuln_findings if str(f.severity or "").lower() == s)
                   for s in ("critical", "high", "medium", "low")}
    info_count = total_all - vuln_count  # coverage/headers info-level

    # ── Crown Jewels (FIX C) — ativos de alto valor identificados ─────────────
    crown_jewels = list(state_data.get("crown_jewels") or [])

    # ── P21 PoC sandbox validation stats ─────────────────────────────────────
    p21_total = p21_confirmed = p21_refuted = p21_pending = 0
    try:
        from app.models.models import ScanWorkItem as _SWI_rpt
        _p21_items = (
            db.query(_SWI_rpt)
            .filter(_SWI_rpt.scan_job_id == scan_id, _SWI_rpt.phase_id == "P21")
            .all()
        )
        p21_total = len(_p21_items)
        p21_confirmed = sum(1 for _i in _p21_items if _i.status in ("completed", "done"))
        p21_refuted = sum(1 for _i in _p21_items if _i.status == "failed")
        p21_pending = sum(1 for _i in _p21_items if _i.status not in ("completed", "done", "failed"))
    except Exception:
        pass

    # ── Kill chain phase coverage ─────────────────────────────────────────────
    # Query phase completion rates for the scan progress strip
    phase_coverage: dict[str, dict[str, int]] = {}
    try:
        from app.models.models import ScanWorkItem as _SWI_ph
        import sqlalchemy as _sa
        _ph_rows = (
            db.query(_SWI_ph.phase_id, _SWI_ph.status, _sa.func.count(_SWI_ph.id))
            .filter(_SWI_ph.scan_job_id == scan_id)
            .group_by(_SWI_ph.phase_id, _SWI_ph.status)
            .all()
        )
        for _ph_id, _ph_status, _ph_cnt in _ph_rows:
            if _ph_id not in phase_coverage:
                phase_coverage[_ph_id] = {"total": 0, "completed": 0, "failed": 0, "queued": 0}
            phase_coverage[_ph_id]["total"] += _ph_cnt
            if _ph_status in ("completed", "done"):
                phase_coverage[_ph_id]["completed"] += _ph_cnt
            elif _ph_status == "failed":
                phase_coverage[_ph_id]["failed"] += _ph_cnt
            else:
                phase_coverage[_ph_id]["queued"] += _ph_cnt
    except Exception:
        pass

    # ── Helpers ───────────────────────────────────────────────────────────────
    now = datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")
    domains_str = job.target_query or str(scan_id)

    def _sev_color(s: str) -> str:
        return {"critical": "#c0392b", "high": "#e67e22",
                "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6"}.get(s.lower(), "#95a5a6")

    def _sev_badge(s: str) -> str:
        c = _sev_color(s)
        return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700">{s.upper()}</span>'

    def _status_badge(vs: str) -> str:
        cfg = {
            "confirmed":  ("#27ae60", "✓ CONFIRMADO"),
            "candidate":  ("#f39c12", "⚠ CANDIDATO"),
            "hypothesis": ("#95a5a6", "? HIPÓTESE"),
        }
        color, label = cfg.get(vs, ("#95a5a6", vs.upper()))
        return f'<span style="background:{color};color:#fff;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700">{label}</span>'

    def _family_of(f: Any, det: dict) -> str:
        from app.services.vuln_family import classify_family
        return classify_family(
            title=getattr(f, "title", ""), tool=getattr(f, "tool", ""),
            owasp=str(det.get("owasp_category") or ""), cve=getattr(f, "cve", None),
            learning_family=(det.get("learning_source") or {}).get("vuln_family"),
        )

    def _family_badge(f: Any, det: dict) -> str:
        """Selo da CLASSE + técnica MITRE ATT&CK — lidera toda vulnerabilidade."""
        try:
            from app.services.vuln_family import family_label
            from app.services.framework_mapping import attack_for_family
            fam = _family_of(f, det)
            badge = (f'<span style="font-size:10px;font-weight:800;text-transform:uppercase;'
                     f'letter-spacing:.04em;color:#2c3e50;background:#eef2ff;border:1px solid #c7d2fe;'
                     f'border-radius:4px;padding:2px 7px">{family_label(fam)}</span>')
            atk = attack_for_family(fam)
            if atk:
                badge += (f' <span style="font-size:10px;font-weight:700;color:#7c3aed;'
                          f'background:#f5f3ff;border:1px solid #ddd6fe;border-radius:4px;padding:2px 7px" '
                          f'title="{atk["technique_name"]}">🎯 {atk["technique"]} · {atk["tactic_name"]}</span>')
            return badge
        except Exception:
            return ""

    def _confirmed_finding_block(f: Any, idx: int) -> str:
        det = dict(f.details or {})
        evidence = str(det.get("evidence") or "")[:500]
        remediation = str(f.recommendation or det.get("remediation") or det.get("blue_team_action") or "Corrigir conforme OWASP Top 10.")[:600]
        tool_name = str(f.tool or "")
        owasp = str(det.get("owasp_category") or "")
        matched_at = str(det.get("matched_at") or det.get("matched-at") or f.url or f.domain or "")
        cvss_str = f"CVSS {f.cvss:.1f}" if f.cvss else ""
        sev = str(f.severity or "info")
        cve_str = f'<code style="color:#e74c3c;font-size:11px">{f.cve}</code>' if f.cve else ""
        conf_str = f'<span style="color:#666;font-size:11px">Confiança: {f.confidence_score}%</span>' if f.confidence_score else ""
        curl_cmd = str(det.get("curl_command") or "").strip()

        # ── Pull real P21 sandbox validation output ───────────────────────────
        # Query the P21 ScanWorkItem that verified this exact finding.
        # If found and complete, display actual tool output as evidence — not a template.
        poc_evidence_html = ""
        try:
            from app.models.models import ScanWorkItem as _SWI_block
            _poc = (
                db.query(_SWI_block)
                .filter(
                    _SWI_block.scan_job_id == job.id,
                    _SWI_block.phase_id == "P21",
                    _SWI_block.item_metadata["verifies_finding_id"].astext == str(f.id),
                )
                .first()
            )
            if _poc:
                _pr = dict(_poc.result or {})
                _poc_out = str(
                    _pr.get("stdout_full") or _pr.get("stdout_preview") or ""
                )[:1200].strip()
                _poc_status = str(_poc.status or "")
                _poc_tool = str(_poc.tool_name or tool_name)
                _is_done = _poc_status in ("completed", "done")
                _is_fail = _poc_status == "failed"
                _poc_icon = "✅" if _is_done else ("❌" if _is_fail else "⏳")
                _poc_label = "PoC Confirmado" if _is_done else ("PoC Refutado — revisão manual" if _is_fail else "PoC em andamento")
                _border_color = "#27ae60" if _is_done else ("#c0392b" if _is_fail else "#f39c12")
                if _poc_out:
                    _safe = _poc_out.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    poc_evidence_html = f'''<div style="margin-top:10px;border-left:3px solid {_border_color};padding-left:10px">
              <strong style="font-size:12px">{_poc_icon} Evidência Sandbox — {_poc_tool} ({_poc_label}):</strong>
              <pre style="background:#0d0d1a;color:#00e676;padding:10px;border-radius:6px;font-size:10px;overflow:auto;max-height:200px;margin-top:6px;font-family:monospace">{_safe}</pre>
            </div>'''
                elif _poc_status in ("completed", "done"):
                    poc_evidence_html = f'<p style="font-size:11px;color:#27ae60;margin-top:6px">{_poc_icon} {_poc_tool} executou e confirmou a vulnerabilidade (sem saída de texto capturada).</p>'
        except Exception:
            pass

        # ── Reproduction command template (HOW to reproduce manually) ─────────
        repro = ""
        target_url = matched_at or str(f.domain or job.target_query or "TARGET")
        # Prefer nuclei curl-command when available (exact proof request)
        if curl_cmd:
            repro = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto">{curl_cmd[:600]}</pre>'
        elif tool_name == "sqlmap":
            repro = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto">sqlmap -u "{target_url}" --forms --level=3 --risk=2 --batch --dump</pre>'
        elif tool_name == "dalfox":
            repro = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto">dalfox url "{target_url}" --skip-bav --silence</pre>'
        elif tool_name in ("gitleaks", "trufflehog"):
            repro = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto">curl -s "{target_url}/.git/config" | grep -i "url|remote"</pre>'
        elif tool_name == "jwt_tool":
            repro = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto"># Capture JWT token from {target_url}\njwt_tool TOKEN -X a  # alg:none attack\njwt_tool TOKEN -X s  # key confusion attack</pre>'
        elif tool_name.startswith("nuclei"):
            template_id = str(det.get("template_id") or tool_name)
            repro = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto">nuclei -u "{target_url}" -t {template_id} -v</pre>'
        elif tool_name == "exploit_chain_engine":
            chain_narrative = str(det.get("chain_narrative") or "Ver passos da chain acima")
            repro = f'<div style="background:#fff8f0;padding:10px;border-radius:6px;font-size:12px;border-left:3px solid #e67e22">{chain_narrative}</div>'
        elif evidence:
            repro = f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto">{evidence[:300]}</pre>'

        return f"""
        <div style="background:#fff;border-left:4px solid {_sev_color(sev)};padding:16px;margin-bottom:16px;border-radius:0 8px 8px 0;box-shadow:0 1px 4px rgba(0,0,0,.08)">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
            <span style="font-size:13px;font-weight:700;color:#555">#{idx}</span>
            {_family_badge(f, det)}
            {_sev_badge(sev)}
            {_status_badge("confirmed")}
            {cve_str}
            {conf_str}
            <span style="font-size:11px;color:#999;margin-left:auto">{cvss_str} &nbsp; {tool_name}</span>
          </div>
          <h4 style="font-size:14px;font-weight:700;color:#2c3e50;margin-bottom:6px">{f.title}</h4>
          {'<p style="font-size:12px;color:#666;margin-bottom:8px">🎯 Alvo: <code style="background:#f8f9fa;padding:2px 6px;border-radius:3px">' + matched_at + '</code></p>' if matched_at else ''}
          {'<p style="font-size:11px;color:#666;margin-bottom:4px">📋 ' + owasp + '</p>' if owasp else ''}
          {'<div style="margin:10px 0"><strong style="font-size:12px">▶ Reprodução:</strong>' + repro + '</div>' if repro else ''}
          {poc_evidence_html}
          <div style="background:#fff5f5;padding:10px;border-radius:6px;margin-top:8px">
            <strong style="font-size:12px;color:#c0392b">🛡 Blue Team — Ação Obrigatória:</strong>
            <p style="font-size:12px;margin-top:4px">{remediation}</p>
          </div>
        </div>"""

    def _chain_block(f: Any, idx: int) -> str:
        det = dict(f.details or {})
        matched = ", ".join(det.get("matched_tags") or [])
        narrative = str(det.get("chain_narrative") or det.get("chain_description") or "")
        recommendation = str(det.get("recommendation") or det.get("blue_team_action") or "")
        cvss_str = f"CVSS {f.cvss:.1f}" if f.cvss else ""
        sev = str(f.severity or "high")
        return f"""
        <div style="background:#fff8f0;border:2px solid {_sev_color(sev)};padding:16px;margin-bottom:16px;border-radius:8px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="font-size:18px">⛓</span>
            {_sev_badge(sev)}
            <strong style="font-size:14px">Chain #{idx}: {f.title.replace("[EXPLOIT CHAIN] ","")}</strong>
            <span style="font-size:11px;color:#999;margin-left:auto">{cvss_str}</span>
          </div>
          {'<p style="font-size:12px;margin-bottom:8px;line-height:1.6"><strong>Sequência de Ataque:</strong> ' + narrative + '</p>' if narrative else ''}
          {'<p style="font-size:11px;color:#666;margin-bottom:8px">🏷 Tags de evidência: <code>' + matched + '</code></p>' if matched else ''}
          {'<div style="background:#fff5f5;padding:10px;border-radius:6px"><strong style="font-size:12px;color:#c0392b">🛡 Blue Team:</strong><p style="font-size:12px;margin-top:4px">' + recommendation + '</p></div>' if recommendation else ''}
        </div>"""

    # ── Candidatos HIGH/CRITICAL aguardando validação P21 ────────────────────
    # These were detected but not yet confirmed by sandbox — may be FPs or real.
    # Shown as "Pending Validation" so the Blue Team knows what's in the queue.
    _hc_candidates = [
        f for f in candidate_list
        if str(f.severity or "").lower() in ("critical", "high")
        and not dict(f.details or {}).get("chain_finding")
    ]
    candidates_section = ""
    if _hc_candidates:
        _cand_rows = "".join(
            f'<tr>'
            f'<td style="font-size:10px;font-weight:700;color:#3730a3">{_family_badge(_f, dict(_f.details or {}))}</td>'
            f'<td style="font-size:12px;max-width:280px">{_f.title[:100] if _f.title else ""}</td>'
            f'<td><span style="background:{(_sev_color(_f.severity or "info"))};color:white;'
            f'padding:1px 6px;border-radius:3px;font-size:10px">{(_f.severity or "").upper()}</span></td>'
            f'<td style="font-size:11px;color:#666">{str(_f.tool or "")[:30]}</td>'
            f'<td style="font-size:11px;color:#666;max-width:200px;overflow:hidden;text-overflow:ellipsis">'
            f'{str(_f.url or _f.domain or "")[:80]}</td>'
            f'<td style="font-size:11px;color:#f39c12;font-weight:600">⏳ Aguardando P21</td>'
            f'</tr>'
            for _f in _hc_candidates[:25]
        )
        candidates_section = (
            '<div class="section" style="border-top:4px solid #f39c12">'
            f'<h2 style="color:#f39c12">⏳ HIGH/CRITICAL Aguardando Validação P21 ({len(_hc_candidates)} findings)</h2>'
            '<p style="font-size:12px;color:#666;margin-bottom:12px">'
            'Estas vulnerabilidades foram detectadas mas ainda <strong>não tiveram PoC de sandbox executado</strong>. '
            'Podem ser falsos positivos — aguardam execução do P21 para promoção a Confirmado ou descarte como Refutado. '
            'Não inclua estas no relatório executivo até confirmação.</p>'
            '<table class="findings-table">'
            '<thead><tr><th>Classe</th><th>Vulnerabilidade</th><th>Severidade</th><th>Ferramenta</th><th>Alvo</th><th>Status</th></tr></thead>'
            f'<tbody>{_cand_rows}</tbody>'
            '</table>'
            + (f'<p style="font-size:11px;color:#999;margin-top:8px">… e mais {len(_hc_candidates) - 25} findings não exibidos.</p>' if len(_hc_candidates) > 25 else '')
            + '</div>'
        )

    # ── Pentest sections ──────────────────────────────────────────────────────
    pentest_confirmed_section = ""
    if confirmed_list:
        blocks = "".join(_confirmed_finding_block(f, i + 1) for i, f in enumerate(confirmed_list[:20]))
        pentest_confirmed_section = f"""
  <div class="section" style="border-top:4px solid #c0392b">
    <h2 style="color:#c0392b">🔴 Vulnerabilidades Confirmadas com PoC ({len(confirmed_list)} total)</h2>
    <p style="font-size:12px;color:#666;margin-bottom:16px">
      Estas vulnerabilidades foram <strong>comprovadas por exploração ativa</strong>.
      Cada uma inclui passos de reprodução e ação obrigatória para o Blue Team.
    </p>
    {blocks}
  </div>"""

    pentest_chains_section = ""
    if chain_findings:
        blocks = "".join(_chain_block(f, i + 1) for i, f in enumerate(chain_findings[:10]))
        pentest_chains_section = f"""
  <div class="section" style="border-top:4px solid #e67e22">
    <h2 style="color:#e67e22">⛓ Chains de Ataque Detectadas ({len(chain_findings)} chains)</h2>
    <p style="font-size:12px;color:#666;margin-bottom:16px">
      Sequências de vulnerabilidades encadeadas que permitem escalação de impacto.
      Cada chain representa um caminho de ataque completo — cada passo deve ser
      corrigido individualmente para quebrar a chain.
    </p>
    {blocks}
  </div>"""

    # ── BlueTeam matrix ───────────────────────────────────────────────────────
    blueteam_items: list[tuple[str, str, str, str]] = []  # (priority, title, target, action)
    for f in confirmed_list[:15]:
        det = dict(f.details or {})
        action = str(f.recommendation or det.get("remediation") or "Corrigir imediatamente")[:200]
        priority = {"critical": "P1 - IMEDIATO (24h)", "high": "P2 - URGENTE (72h)",
                    "medium": "P3 - IMPORTANTE (7d)", "low": "P4 - PLANEJADO (30d)"}.get(
            str(f.severity or "medium").lower(), "P3"
        )
        target = str(f.url or f.domain or "")[:80]
        blueteam_items.append((priority, str(f.title or "")[:100], target, action))

    blueteam_section = ""
    if blueteam_items:
        rows = "".join(f"""
          <tr>
            <td><span style="background:#c0392b;color:#fff;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700">{p}</span></td>
            <td style="font-size:12px">{t}</td>
            <td style="font-size:11px;color:#666;max-width:150px;overflow:hidden;text-overflow:ellipsis">{tgt}</td>
            <td style="font-size:11px">{a[:120]}</td>
          </tr>""" for p, t, tgt, a in blueteam_items)
        blueteam_section = f"""
  <div class="section" style="border-top:4px solid #3498db">
    <h2 style="color:#3498db">🛡 Matriz de Ação — Blue Team</h2>
    <p style="font-size:12px;color:#666;margin-bottom:12px">
      Ações ordenadas por criticidade. Baseadas exclusivamente em vulnerabilidades confirmadas.
    </p>
    <table class="findings-table">
      <thead><tr><th>Prioridade</th><th>Vulnerabilidade</th><th>Alvo</th><th>Ação Requerida</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""

    # ── Per-target risk matrix ────────────────────────────────────────────────
    # Shows which targets have the most confirmed HIGH/CRITICAL findings —
    # helps Blue Team triage: patch the riskiest targets first.
    target_risk_section = ""
    try:
        from collections import Counter as _Counter
        _target_scores: dict[str, dict[str, int]] = {}
        for _f in all_findings:
            _dom = str(_f.domain or "").strip()
            _sev = str(_f.severity or "").lower()
            _vs = str(getattr(_f, "verification_status", "") or "")
            if not _dom:
                continue
            if _dom not in _target_scores:
                _target_scores[_dom] = {"critical": 0, "high": 0, "medium": 0, "total": 0}
            _target_scores[_dom]["total"] += 1
            if _sev in ("critical", "high") and _vs == "confirmed":
                _target_scores[_dom][_sev] += 1

        # Only include targets with at least one confirmed HIGH or CRITICAL
        _risky = {k: v for k, v in _target_scores.items() if v["critical"] + v["high"] > 0}
        if _risky:
            # Sort by critical desc, then high desc
            _sorted_targets = sorted(_risky.items(), key=lambda x: (-x[1]["critical"], -x[1]["high"]))[:20]
            _target_rows = []
            for _dn, _sc in _sorted_targets:
                _risk_num = _sc["critical"] * 10 + _sc["high"] * 5
                _risk_color = "#c0392b" if _sc["critical"] > 0 else "#e67e22"
                _target_rows.append(
                    f'<tr>'
                    f'<td style="font-size:12px;font-weight:600">{_dn}</td>'
                    f'<td style="text-align:center"><span style="background:#c0392b;color:white;padding:2px 8px;border-radius:3px;font-size:11px">{_sc["critical"]}</span></td>'
                    f'<td style="text-align:center"><span style="background:#e67e22;color:white;padding:2px 8px;border-radius:3px;font-size:11px">{_sc["high"]}</span></td>'
                    f'<td style="text-align:center;font-size:11px;color:#666">{_sc["total"]}</td>'
                    f'<td><div style="background:{_risk_color};height:8px;border-radius:4px;width:{min(100, _risk_num * 5)}%"></div></td>'
                    f'</tr>'
                )
            target_risk_section = (
                '<div class="section" style="border-top:4px solid #9b59b6">'
                '<h2 style="color:#9b59b6">🎯 Matriz de Risco por Alvo</h2>'
                '<p style="font-size:12px;color:#666;margin-bottom:12px">'
                'Alvos com vulnerabilidades confirmadas ordenados por criticidade. '
                'Patch priority: começar pelo topo.</p>'
                '<table class="findings-table">'
                '<thead><tr>'
                '<th>Alvo / Domínio</th>'
                '<th style="text-align:center">Critical</th>'
                '<th style="text-align:center">High</th>'
                '<th style="text-align:center">Total</th>'
                '<th>Risk Score</th>'
                '</tr></thead>'
                f'<tbody>{"".join(_target_rows)}</tbody>'
                '</table></div>'
            )
    except Exception:
        pass

    # ── Cross-scan delta (new findings vs previous scan) ─────────────────────
    delta_section = ""
    if previous_scan_id:
        try:
            from app.models.models import Finding as _FindingDelta
            _prev_titles = set(
                str(t) for (t,) in
                db.query(_FindingDelta.title)
                .filter(_FindingDelta.scan_job_id == previous_scan_id)
                .all()
            )
            _new_findings = [
                _f for _f in confirmed_list
                if str(_f.title or "") not in _prev_titles
            ]
            _fixed_count = len(_prev_titles) - (len(all_findings) - len(_new_findings))
            if _new_findings:
                _delta_rows = "".join(
                    f'<tr>'
                    f'<td style="font-size:12px">{_f.title[:80]}</td>'
                    f'<td><span style="background:{_sev_color(_f.severity or "info")};color:white;padding:1px 6px;border-radius:3px;font-size:10px">{(_f.severity or "").upper()}</span></td>'
                    f'<td style="font-size:11px;color:#666">{str(_f.domain or "")[:60]}</td>'
                    f'</tr>'
                    for _f in _new_findings[:15]
                )
                delta_section = (
                    '<div class="section" style="border-top:4px solid #e74c3c">'
                    f'<h2 style="color:#e74c3c">🆕 Novos Findings vs Scan #{previous_scan_id} ({len(_new_findings)} novos confirmados)</h2>'
                    '<p style="font-size:12px;color:#666;margin-bottom:12px">'
                    f'Vulnerabilidades confirmadas que não existiam no scan anterior. '
                    f'{"Atenção: superfície de ataque cresceu." if len(_new_findings) > 5 else "Superfície relativamente estável."}'
                    '</p>'
                    '<table class="findings-table">'
                    '<thead><tr><th>Vulnerabilidade</th><th>Severidade</th><th>Domínio</th></tr></thead>'
                    f'<tbody>{_delta_rows}</tbody>'
                    '</table></div>'
                )
        except Exception:
            pass

    # ── EASM sections (full existing report) ─────────────────────────────────
    easm_html = generate_executive_report(db, scan_id, previous_scan_id)
    # Extract body content from EASM report (strip <html><head><body> wrapper)
    _body_start = easm_html.find('<div class="page">')
    _body_end = easm_html.rfind("</div>") + 6
    easm_body = easm_html[_body_start:_body_end] if _body_start > 0 else ""

    # ── Executive summary for the full pentest report ─────────────────────────
    exec_risk_label = ("CRÍTICO" if conf_critical > 0 else
                       ("ALTO" if conf_high > 0 else
                        ("MÉDIO" if conf_medium > 0 else "BAIXO")))
    exec_risk_color = ("#c0392b" if conf_critical > 0 else
                       ("#e67e22" if conf_high > 0 else
                        ("#f39c12" if conf_medium > 0 else "#27ae60")))

    # ── P21 sandbox stats strip HTML ─────────────────────────────────────────
    poc_strip_html = ""
    if p21_total > 0:
        poc_strip_html = (
            '<div style="background:#0d1117;color:#e6edf3;border-radius:8px;'
            'padding:14px 20px;margin-bottom:20px;display:flex;align-items:center;'
            'gap:20px;flex-wrap:wrap">'
            '<span style="font-size:13px;font-weight:700;color:#58a6ff">🔬 P21 Sandbox PoC</span>'
            f'<span style="font-size:12px"><span style="color:#3fb950;font-weight:700">{p21_confirmed}</span> confirmados</span>'
            f'<span style="font-size:12px"><span style="color:#f85149;font-weight:700">{p21_refuted}</span> refutados (FP suprimidos)</span>'
            f'<span style="font-size:12px"><span style="color:#d29922;font-weight:700">{p21_pending}</span> em andamento</span>'
            f'<span style="font-size:11px;color:#8b949e;margin-left:auto">{p21_total} validações agendadas'
            ' — somente confirmados aparecem como HIGH/CRITICAL</span>'
            '</div>'
        )

    # ── Kill chain phase coverage HTML ───────────────────────────────────────
    phase_coverage_html = ""
    if phase_coverage:
        _PHASE_ORDER = [
            "P01", "P02", "P03", "P04", "P05", "P06", "P07", "P08",
            "P09", "P10", "P11", "P12", "P13", "P14", "P15", "P16",
            "P17", "P18", "P19", "P20", "P21", "P22",
        ]
        pills: list[str] = []
        for _pid in _PHASE_ORDER:
            _ph = phase_coverage.get(_pid, {})
            _comp = _ph.get("completed", 0)
            _fail = _ph.get("failed", 0)
            _queued = _ph.get("queued", 0)
            _in_scan = bool(_ph)
            if _comp > 0:
                _bg, _fg = "#27ae60", "white"
            elif _fail > 0 and _comp == 0:
                _bg, _fg = "#e74c3c", "white"
            elif _queued > 0:
                _bg, _fg = "#f39c12", "white"
            else:
                _bg, _fg = "#eee", "#999"
            _title = f"{_pid}: {_comp} ok {_fail} fail {_queued} queue"
            pills.append(
                f'<div style="background:{_bg};color:{_fg};padding:4px 8px;border-radius:4px;'
                f'font-size:10px;font-weight:700;min-width:36px;text-align:center" title="{_title}">{_pid}</div>'
            )
        phase_coverage_html = (
            '<div style="background:white;border-radius:8px;padding:16px;'
            'margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.08)">'
            '<div style="font-size:13px;font-weight:700;color:#555;margin-bottom:10px">'
            '⛓ Kill Chain — Cobertura de Fases</div>'
            f'<div style="display:flex;flex-wrap:wrap;gap:6px">{"".join(pills)}</div>'
            '<div style="display:flex;gap:16px;margin-top:8px;font-size:10px;color:#666">'
            '<span><span style="background:#27ae60;color:white;padding:1px 6px;border-radius:3px">■</span> Completo</span>'
            '<span><span style="background:#f39c12;color:white;padding:1px 6px;border-radius:3px">■</span> Em andamento</span>'
            '<span><span style="background:#e74c3c;color:white;padding:1px 6px;border-radius:3px">■</span> Com falhas</span>'
            '<span><span style="background:#eee;padding:1px 6px;border-radius:3px">■</span> Não iniciado</span>'
            '</div></div>'
        )

    # ── Crown Jewels HTML (FIX C) ─────────────────────────────────────────────
    crown_jewels_html = ""
    if crown_jewels:
        _cj_rows = []
        for cj in crown_jewels[:12]:
            _t = str(cj.get("target") or cj.get("subdomain") or "")
            _lbl = str(cj.get("label") or "ativo crítico").replace("_", " ")
            _on_asset = [f for f in vuln_findings
                         if _t and (_t in str(f.domain or "") or _t in str(f.url or ""))]
            _hc = sum(1 for f in _on_asset if str(f.severity or "").lower() in ("critical", "high"))
            # ── Frente D: impacto de NEGÓCIO por joia — capacidade comprovada
            # (actions-on-objectives da validação ativa) no ativo crítico.
            _exploited = [f for f in _on_asset
                          if (dict(f.details or {}).get("exploitation") or {}).get("actively_validated")]
            _impact_cell = "—"
            if _exploited:
                _caps = []
                for _ef in _exploited[:2]:
                    _aoo = dict(_ef.details or {}).get("actions_on_objectives") or {}
                    _cap = str(_aoo.get("capability_narrative") or "")
                    if _cap:
                        _caps.append(_cap)
                _impact_cell = (
                    '<span style="background:#c0392b;color:#fff;padding:1px 6px;border-radius:4px;'
                    f'font-size:9px;font-weight:700">⚔️ EXPLORADO</span> '
                    + (f'<span style="font-size:10px;color:#666">{_caps[0][:90]}</span>' if _caps else "")
                )
            _badge = (f'<span style="background:#c0392b;color:#fff;padding:1px 7px;border-radius:10px;'
                      f'font-size:10px;font-weight:700">{_hc} H/C</span>') if _hc else \
                     ('<span style="background:#7f8c8d;color:#fff;padding:1px 7px;border-radius:10px;'
                      'font-size:10px">sem crítico</span>')
            _cj_rows.append(
                f'<tr><td style="font-size:12px;font-weight:600">⭐ {_t}</td>'
                f'<td style="font-size:11px;color:#8e44ad">{_lbl}</td>'
                f'<td style="text-align:center">{_badge}</td>'
                f'<td style="font-size:11px">{_impact_cell}</td></tr>'
            )
        crown_jewels_html = (
            '<div class="section" style="border-top:4px solid #8e44ad">'
            f'<h2 style="color:#8e44ad">⭐ Joias da Coroa ({len(crown_jewels)})</h2>'
            '<p style="font-size:12px;color:#666;margin-bottom:12px">'
            'Ativos de maior valor — autenticação, pagamento, dados, administração e infraestrutura. '
            'Concentram a prioridade de teste e de defesa: uma falha aqui compromete todo o ambiente. '
            'A coluna <strong>Impacto</strong> mostra a capacidade que um atacante teria '
            '(comprovada por validação ativa), sempre como possibilidade — sem execução destrutiva.</p>'
            '<table class="findings-table">'
            '<thead><tr><th>Ativo</th><th>Classificação</th><th style="text-align:center">Achados</th><th>Impacto comprovado</th></tr></thead>'
            f'<tbody>{"".join(_cj_rows)}</tbody></table></div>'
        )

    # ── #3: Progressão de táticas MITRE ATT&CK (linguagem padrão de pentest) ──
    attack_progression_html = ""
    try:
        from app.services.vuln_family import classify_family as _cf_atk
        from app.services.framework_mapping import tactic_progression
        _fams_seen = []
        for _f in vuln_findings:
            _d = dict(_f.details or {})
            _fams_seen.append(_cf_atk(
                title=_f.title, tool=_f.tool, owasp=str(_d.get("owasp_category") or ""),
                cve=_f.cve, learning_family=(_d.get("learning_source") or {}).get("vuln_family"),
            ))
        _prog = tactic_progression(_fams_seen)
        if _prog:
            _steps = " <span style='color:#c7d2fe'>→</span> ".join(
                f'<span style="display:inline-block;background:#f5f3ff;border:1px solid #ddd6fe;'
                f'border-radius:6px;padding:4px 10px;margin:2px;font-size:11px">'
                f'<b style="color:#7c3aed">{p["tactic_name"]}</b> '
                f'<span style="color:#999;font-size:10px">{", ".join(p["techniques"][:4])}</span></span>'
                for p in _prog
            )
            attack_progression_html = (
                '<div class="section" style="border-top:4px solid #7c3aed">'
                f'<h2 style="color:#7c3aed">🎯 Progressão MITRE ATT&CK ({len(_prog)} táticas observadas)</h2>'
                '<p style="font-size:12px;color:#666;margin-bottom:12px">A cadeia de ataque mapeada às '
                'táticas ATT&CK Enterprise — da esquerda (entrada) à direita (impacto). Cada classe de '
                'vulnerabilidade confirmada corresponde a uma técnica validada.</p>'
                f'<div style="line-height:2.2">{_steps}</div></div>'
            )
    except Exception as _atk_err:
        import logging as _atklog
        _atklog.getLogger(__name__).debug("attack_progression failed: %s", _atk_err)

    # ── Frente D: Narrativa do Ataque embutida ───────────────────────────────
    # A história recon→exploração→objetivos. Gerada no scan (state_data) ou
    # sob demanda aqui. Convertida de Markdown para HTML.
    attack_narrative_html = ""
    try:
        _narr = str(state_data.get("attack_narrative") or "")
        if not _narr.strip():
            from app.services.attack_narrative import run_attack_narrative as _run_narr
            _res = _run_narr(db, job)
            _narr = str((_res or {}).get("narrative") or "")
        if _narr.strip():
            attack_narrative_html = (
                '<div class="section" style="border-top:4px solid #c0392b">'
                '<h2 style="color:#c0392b">🎯 Narrativa do Ataque</h2>'
                '<div style="font-size:13px;line-height:1.7;color:#2c3e50">'
                + _md_to_html(_narr) +
                '</div></div>'
            )
    except Exception as _narr_err:
        import logging as _nlog
        _nlog.getLogger(__name__).debug("attack_narrative embed failed: %s", _narr_err)

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Relatório de Pentest — {domains_str}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f8f9fa; color: #2c3e50; line-height: 1.5; }}
    .page {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
    .pentest-header {{ background: linear-gradient(135deg, #1a1a2e 0%, #c0392b 100%);
               color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }}
    .pentest-header h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 4px; }}
    .pentest-header .meta {{ font-size: 13px; color: #ffd0d0; margin-top: 8px; }}
    .score-badge {{ display: inline-block; background: {exec_risk_color};
                   color: white; padding: 6px 18px; border-radius: 20px;
                   font-size: 14px; font-weight: 700; margin-top: 12px; border: 2px solid rgba(255,255,255,0.3); }}
    .pentest-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
    .stat-card {{ background: white; border-radius: 8px; padding: 16px;
                 text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    .stat-card .num {{ font-size: 32px; font-weight: 800; }}
    .stat-card .lbl {{ font-size: 11px; color: #666; margin-top: 4px; }}
    .section {{ background: white; border-radius: 8px; padding: 24px;
               box-shadow: 0 1px 4px rgba(0,0,0,.08); margin-bottom: 20px; }}
    .section h2 {{ font-size: 17px; font-weight: 700; margin-bottom: 16px;
                  padding-bottom: 8px; border-bottom: 2px solid #eee; }}
    .findings-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    .findings-table th {{ background: #f8f9fa; padding: 8px 10px; text-align: left;
                         font-weight: 600; border-bottom: 2px solid #dee2e6; }}
    .findings-table td {{ padding: 8px 10px; border-bottom: 1px solid #f0f0f0;
                         vertical-align: top; }}
    .easm-section-divider {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                             color: white; padding: 16px 24px; border-radius: 8px;
                             margin: 32px 0 16px 0; font-size: 14px; font-weight: 600; }}
    .footer {{ text-align: center; font-size: 11px; color: #aaa; margin-top: 32px; padding-bottom: 24px; }}
    @media (max-width: 700px) {{ .pentest-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
  </style>
</head>
<body>
<div class="page">

  <!-- PENTEST HEADER -->
  <div class="pentest-header">
    <h1>🔴 Relatório de Pentest Automatizado</h1>
    <div class="meta">
      Alvos: <strong>{domains_str}</strong> &nbsp;|&nbsp;
      Gerado: {now} &nbsp;|&nbsp;
      Scan ID: #{scan_id}
      {f'&nbsp;|&nbsp; Scan anterior: #{previous_scan_id}' if previous_scan_id else ''}
    </div>
    <div class="score-badge">Risco Confirmado: {exec_risk_label}</div>
  </div>

  <!-- PENTEST STATS -->
  <div class="pentest-grid">
    <div class="stat-card" style="border-top:3px solid #c0392b">
      <div class="num" style="color:#c0392b">{conf_critical}</div>
      <div class="lbl">Critical Confirmados</div>
    </div>
    <div class="stat-card" style="border-top:3px solid #e67e22">
      <div class="num" style="color:#e67e22">{conf_high}</div>
      <div class="lbl">High Confirmados</div>
    </div>
    <div class="stat-card" style="border-top:3px solid #f39c12">
      <div class="num" style="color:#f39c12">{len(chain_findings)}</div>
      <div class="lbl">Chains de Ataque</div>
    </div>
    <div class="stat-card" style="border-top:3px solid #8e44ad">
      <div class="num" style="color:#8e44ad">{len(crown_jewels)}</div>
      <div class="lbl">Joias da Coroa</div>
    </div>
  </div>

  <!-- VULN COUNT — fonte única (igual UI/dashboard): severity>=low -->
  <div style="display:flex;gap:10px;align-items:center;background:#fff;border-radius:8px;padding:12px 16px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.08);flex-wrap:wrap">
    <span style="font-size:22px;font-weight:800;color:#2c3e50">{vuln_count}</span>
    <span style="font-size:12px;color:#666;font-weight:600">vulnerabilidades</span>
    <span style="font-size:11px;color:#999">(🔴 {vuln_by_sev['critical']} · 🟠 {vuln_by_sev['high']} · 🟡 {vuln_by_sev['medium']} · 🔵 {vuln_by_sev['low']})</span>
    <span style="font-size:10px;color:#bbb;margin-left:auto">+ {info_count} itens informativos (headers/cobertura) · contagem idêntica ao inventário e dashboard</span>
  </div>

  <!-- P21 POC SANDBOX STRIP -->
  {poc_strip_html}

  <!-- ATTACK NARRATIVE (Frente D) -->
  {attack_narrative_html}

  <!-- MITRE ATT&CK TACTIC PROGRESSION (#3) -->
  {attack_progression_html}

  <!-- KILL CHAIN PHASE COVERAGE -->
  {phase_coverage_html}

  <!-- CROWN JEWELS -->
  {crown_jewels_html}

  <!-- NO CONFIRMED FINDINGS NOTICE -->
  {'<div class="section" style="border-left:4px solid #27ae60"><h2 style="color:#27ae60">✅ Nenhuma Vulnerabilidade Confirmada com PoC</h2><p style="font-size:13px;color:#666">Nenhuma ferramenta de exploração ativa (sqlmap, dalfox, nuclei-confirmed) confirmou vulnerabilidades exploráveis. Existem ' + str(len(candidate_list)) + ' findings candidatos que requerem verificação manual na fase P17.</p></div>' if not confirmed_list and not chain_findings else ''}

  <!-- PENTEST: CONFIRMED VULNERABILITIES -->
  {pentest_confirmed_section}

  <!-- PENTEST: EXPLOIT CHAINS -->
  {pentest_chains_section}

  <!-- BLUETEAM: ACTION MATRIX -->
  {blueteam_section}

  <!-- CANDIDATES AWAITING P21 VALIDATION -->
  {candidates_section}

  <!-- PER-TARGET RISK MATRIX -->
  {target_risk_section}

  <!-- CROSS-SCAN DELTA (new confirmed findings vs previous scan) -->
  {delta_section}

  <!-- DIVIDER: EASM SECTION -->
  <div class="easm-section-divider">
    📊 SEÇÃO 2 — SUPERFÍCIE DE ATAQUE E EXPOSIÇÕES (EASM)
    &nbsp;|&nbsp; {vuln_count} vulnerabilidades &nbsp;|&nbsp;
    {len(confirmed_list)} confirmadas &nbsp;|&nbsp;
    {len(candidate_list)} candidatas &nbsp;|&nbsp;
    {len(hypothesis_list)} hipóteses &nbsp;|&nbsp;
    {info_count} informativos
  </div>

  <!-- EASM BODY (full existing report content) -->
  {easm_body}

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
