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
import html as _html
import re
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


# Padrão único de exibição de alvo nos relatórios: NUNCA limita o teste, só o que
# aparece na célula/linha. Um alvo único longo é truncado; uma string multi-alvo
# (";"/"," — ex.: target_query com 28 hosts) vira "primeiro +N". Evita que um nome
# gigante estoure a largura da tabela e force quebra de página.
TARGET_DISPLAY_MAX = 42


def _short_target(value: Any, max_chars: int = TARGET_DISPLAY_MAX) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = [p.strip() for p in re.split(r"[;,]", raw) if p.strip()]
    if len(parts) > 1:
        first = parts[0]
        if len(first) > max_chars:
            first = first[: max_chars - 1] + "…"
        return f"{first} +{len(parts) - 1}"
    return raw if len(raw) <= max_chars else raw[: max_chars - 1] + "…"


def generate_executive_report(
    db: Session,
    scan_id: int,
    previous_scan_id: int | None = None,
) -> str:
    """
    Gera e retorna HTML do relatório executivo para o scan indicado.
    """
    from app.models.models import Finding, ScanJob
    from app.services.bas_exclusion import exclude_simulated

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return "<h1>Scan não encontrado</h1>"

    findings = (
        exclude_simulated(db.query(Finding))
        .filter(Finding.scan_job_id == scan_id)
        .order_by(Finding.id)
        .all()
    )

    try:
        from app.services.evidence_contract_service import apply_finding_validation, link_artifacts_to_findings
        link_artifacts_to_findings(db, job)
        for _finding in findings:
            apply_finding_validation(db, _finding)
        db.commit()
    except Exception:
        db.rollback()

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

    now = datetime.now().strftime("%d/%m/%Y %H:%M UTC")
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
          <td style="font-size:11px;word-break:break-word">{_html.escape(_short_target(f.domain))}</td>
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
            domains_in_class = sorted({_short_target(f.domain) for f in items if f.domain})
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
            # Distribuição real de severidade por categoria (contagem), não apenas
            # os 3 primeiros badges — antes repetia o mesmo rótulo e não somava.
            counts: dict[str, int] = {}
            for f in flist:
                s = str(f.severity or "info").lower()
                counts[s] = counts.get(s, 0) + 1
            order = [("critical", "#c0392b"), ("high", "#e67e22"), ("medium", "#f39c12"), ("low", "#3498db"), ("info", "#95a5a6")]
            badges = [
                f'<span class="sev-badge" style="background:{c}">{counts[s]} {s[:1].upper()}</span>'
                for s, c in order if counts.get(s)
            ]
            return "".join(badges) or "—"

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

  <!-- RECOMMENDATIONS: removidas aqui — duplicavam a "🛡 Matriz de Ação — Blue Team"
       do relatório técnico, que embute esta seção EASM. -->

  <!-- FOOTER -->
  <div class="footer">
    Relatório ScriptKidd.o &nbsp;|&nbsp; {now} &nbsp;|&nbsp;
    Este relatório é confidencial e destinado exclusivamente ao uso interno.
    &nbsp;|&nbsp; Conteúdo: superfície de ataque + vulnerabilidades confirmadas com PoC.
  </div>

</div>
</body>
</html>"""

    return html


def _render_quality_gate_html(quality: dict[str, Any]) -> str:
    """"Quality Gate do Pentest" section of the report. build_scan_quality()
    already computes precise, plain-language explanations of why coverage is
    incomplete (depth_requirements.blocking_requirement_ids,
    preflight_summary.non_success_reason_counts, and the operator_message
    fields on auth_precondition_summary/business_logic_precondition_summary)
    -- previously none of that reached the report, only the generic top-6
    `gaps` titles did, so an operator reading the PDF/HTML had no way to see
    the specific reason (e.g. "needs a second identity") behind a gap."""
    _score = float(quality.get("score") or 0)
    _grade = _html.escape(str(quality.get("grade") or "—"))
    _label = _html.escape(str(quality.get("label") or ""))
    _gate = dict(quality.get("quality_gate") or {})
    _loop = dict((quality.get("loop_agent") or {}).get("quality_gate_loop") or {})
    _gate_status = _html.escape(str(_gate.get("status") or "not_run").replace("_", " "))
    _gate_bg = "#fff3cd" if _gate.get("status") in {"remediation_scheduled", "exhausted"} or _score < 70 else "#eafaf1"
    _gate_border = "#f39c12" if _gate.get("status") in {"remediation_scheduled", "exhausted"} or _score < 70 else "#27ae60"
    _gaps = list(quality.get("gaps") or [])[:6]
    _gap_rows = "".join(
        "<li>"
        f"<strong>{_html.escape(str(gap.get('title') or 'Gap de qualidade'))}</strong>: "
        f"{_html.escape(str(gap.get('action') or gap.get('detail') or 'Revisar evidência/cobertura.'))}"
        "</li>"
        for gap in _gaps
    )
    _components = dict(quality.get("components") or {})
    _component_bits = " · ".join(
        f"{_html.escape(name.replace('_', ' '))}: {float(item.get('score') or 0):.0f}%"
        for name, item in _components.items()
    )
    _loop_bits = []
    if _loop:
        _loop_bits.append(f"rodadas={int(_loop.get('rounds') or 0)}")
        if _loop.get("first_score") is not None and _loop.get("last_score") is not None:
            _loop_bits.append(f"score {_loop.get('first_score')} -> {_loop.get('last_score')}")
        if _loop.get("score_delta") is not None:
            _loop_bits.append(f"delta={_loop.get('score_delta')}")
        _loop_bits.append(f"ações={int(_loop.get('actions_scheduled') or 0)}")
    _loop_html = (
        '<p style="font-size:11px;color:#555;margin-bottom:8px">'
        f'<strong>Loop Agent:</strong> {_html.escape(" · ".join(_loop_bits))}</p>'
    ) if _loop_bits else ""

    _blocking_ids = list((dict(quality.get("depth_requirements") or {})).get("blocking_requirement_ids") or [])
    _preflight_summary = dict(quality.get("preflight_summary") or {})
    _reason_buckets = dict(_preflight_summary.get("non_success_reason_buckets") or {})
    _legacy_reasons = list(_preflight_summary.get("non_success_reason_counts") or [])
    _actionable_reasons = list(_reason_buckets.get("actionable_pending") or [])
    _precondition_reasons = list(_reason_buckets.get("precondition_absent") or [])
    _tool_failure_reasons = list(_reason_buckets.get("tool_failures") or [])
    _other_reasons = list(_reason_buckets.get("other") or [])
    if not _reason_buckets:
        _actionable_reasons = _legacy_reasons
    _operator_messages = [
        text for text in (
            (dict(quality.get("auth_precondition_summary") or {})).get("operator_message")
            if (dict(quality.get("auth_precondition_summary") or {})).get("blocked") else None,
            (dict(quality.get("business_logic_precondition_summary") or {})).get("operator_message")
            if (dict(quality.get("business_logic_precondition_summary") or {})).get("blockers") else None,
        )
        if text
    ]

    def _reason_rows(items: list[dict[str, Any]]) -> str:
        return "".join(
            f'<li><strong>{_html.escape(str(item.get("reason") or ""))}</strong>: {int(item.get("count") or 0)} ocorrência(s)</li>'
            for item in items[:6]
        )

    _actionable_rows = _reason_rows(_actionable_reasons)
    _precondition_rows = _reason_rows(_precondition_reasons)
    _tool_failure_rows = _reason_rows(_tool_failure_reasons)
    _other_rows = _reason_rows(_other_reasons)
    _explain_parts: list[str] = []
    if _blocking_ids:
        _explain_parts.append(
            '<p style="font-size:11px;color:#555;margin-bottom:4px">'
            f'<strong>Requisitos bloqueando de fato:</strong> {_html.escape(", ".join(_blocking_ids))}</p>'
        )
    for msg in _operator_messages:
        _explain_parts.append(f'<p style="font-size:11px;color:#555;margin-bottom:4px">{_html.escape(msg)}</p>')
    if _actionable_rows:
        _explain_parts.append(
            '<p style="font-size:11px;color:#555;margin-bottom:2px">Alvos não totalmente escaneados por motivo:</p>'
            f'<ul style="font-size:11px;color:#555;margin-left:18px">{_actionable_rows}</ul>'
        )
    if _precondition_rows:
        _explain_parts.append(
            '<p style="font-size:11px;color:#555;margin-bottom:2px">Testes não aplicáveis por falta de superfície/precondição:</p>'
            f'<ul style="font-size:11px;color:#555;margin-left:18px">{_precondition_rows}</ul>'
        )
    if _tool_failure_rows:
        _explain_parts.append(
            '<p style="font-size:11px;color:#555;margin-bottom:2px">Falhas de ferramenta ou perfil:</p>'
            f'<ul style="font-size:11px;color:#555;margin-left:18px">{_tool_failure_rows}</ul>'
        )
    if _other_rows:
        _explain_parts.append(
            '<p style="font-size:11px;color:#555;margin-bottom:2px">Outros motivos preservados para auditoria:</p>'
            f'<ul style="font-size:11px;color:#555;margin-left:18px">{_other_rows}</ul>'
        )
    _explain_html = (
        '<div style="margin-top:10px;padding-top:8px;border-top:1px solid rgba(0,0,0,0.08)">'
        + "".join(_explain_parts) + "</div>"
    ) if _explain_parts else ""

    return (
        f'<div class="section" style="border-left:4px solid {_gate_border};background:{_gate_bg}">'
        '<h2>Quality Gate do Pentest</h2>'
        f'<p style="font-size:13px;color:#555;margin-bottom:8px">'
        f'Score de qualidade: <strong>{_score:.1f}% ({_grade} — {_label})</strong> · '
        f'Gate: <strong>{_gate_status}</strong>'
        f'{(" · rodada " + str(_gate.get("rounds"))) if _gate.get("rounds") else ""}'
        '</p>'
        f'<p style="font-size:11px;color:#777;margin-bottom:8px">{_html.escape(_component_bits)}</p>'
        + _loop_html
        + (f'<ul style="font-size:12px;color:#555;margin-left:18px">{_gap_rows}</ul>' if _gap_rows else
           '<p style="font-size:12px;color:#555">Sem gaps automáticos pendentes.</p>')
        + _explain_html
        + (
            '<p style="font-size:11px;color:#8a6d3b;margin-top:8px">'
            'Relatório qualificado: findings não confirmados permanecem como candidatos/hipóteses até EvidenceArtifact + ValidationRun suficientes.'
            '</p>'
        )
        + '</div>'
    )


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
    from app.services.bas_exclusion import exclude_simulated

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return "<h1>Scan não encontrado</h1>"

    all_findings = (
        exclude_simulated(db.query(Finding))
        .filter(Finding.scan_job_id == scan_id, Finding.is_false_positive.is_(False))
        .order_by(Finding.id)
        .all()
    )

    # ── Evidence contract reconciliation ──────────────────────────────────────
    # evidence_gate.py assigns verification_status at creation time from tool-name
    # heuristics alone (e.g. sqlmap/dalfox auto-"confirmed"). Before the report is
    # built, re-derive it from actual EvidenceArtifact proof (baseline vs exploit,
    # authenticated identity) so the deliverable never inflates unproven findings.
    try:
        from app.services.evidence_contract_service import apply_finding_validation, link_artifacts_to_findings
        from app.models.models import FindingAdjudication
        from app.services.finding_adjudication import project_adjudication_to_finding
        link_artifacts_to_findings(db, job)
        for _finding in all_findings:
            apply_finding_validation(db, _finding)
            _latest_adj = (
                db.query(FindingAdjudication)
                .filter(FindingAdjudication.finding_id == _finding.id)
                .order_by(FindingAdjudication.cycle.desc())
                .first()
            )
            if _latest_adj is not None:
                project_adjudication_to_finding(db, _finding, _latest_adj)
        db.commit()
    except Exception:
        db.rollback()

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
    now = datetime.now().strftime("%d/%m/%Y %H:%M UTC")
    # target_query may hold dozens of targets joined by ; or , — rendering the
    # raw string as "Alvos:" produced a huge unwrapped blob at the top of the
    # report. Show a compact summary + a collapsible full list instead.
    domains_list = [t.strip() for t in re.split(r"[;,\n]+", str(job.target_query or "")) if t.strip()]
    domains_count = len(domains_list)
    if domains_count > 6:
        domains_compact = ", ".join(domains_list[:6]) + f" … (+{domains_count - 6})"
    elif domains_list:
        domains_compact = ", ".join(domains_list)
    else:
        domains_compact = str(scan_id)
    domains_str = domains_compact
    domains_title = (f"{domains_list[0]} +{domains_count - 1} alvos" if domains_count > 1 else (domains_list[0] if domains_list else str(scan_id)))
    domains_full_html = ", ".join(_html.escape(d) for d in domains_list)

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

    def _d3fend_html(f: Any, det: dict) -> str:
        """Contramedida D3FEND correlacionada à técnica ATT&CK (ofensa→defesa)."""
        try:
            from app.services.framework_mapping import attack_for_family
            atk = attack_for_family(_family_of(f, det))
            if atk and atk.get("d3fend"):
                csf = f' · NIST CSF {atk["nist_csf"]}' if atk.get("nist_csf") else ""
                return (f'<p style="font-size:11px;margin-top:6px;color:#2980b9">'
                        f'🛡 Contramedida D3FEND: <b>{atk["d3fend"]}</b>{csf}</p>')
        except Exception:
            pass
        return ""

    def _network_line(det: dict) -> str:
        """Linha de contexto de rede (host↔IP↔porta) no relatório."""
        n = det.get("network") if isinstance(det.get("network"), dict) else None
        if not n:
            return ""
        bits = []
        if n.get("resolved_ip"):
            bits.append(f"IP <b>{n['resolved_ip']}</b>" + (f" ({n['ip_owner']})" if n.get("ip_owner") else ""))
        if n.get("ports"):
            bits.append("portas " + ", ".join(str(p) for p in n["ports"]))
        if n.get("source_findings"):
            bits.append("origem: " + ", ".join(f"#{s['finding_id']}" for s in n["source_findings"]))
        if not bits:
            return ""
        return ('<p style="font-size:11px;color:#666;margin-bottom:6px">🌐 ' + " · ".join(bits) + '</p>')

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
            repro = (
                '<p style="font-size:11px;color:#9a6700"><strong>Orientação manual:</strong> '
                'o relatório pode explicar a exploração, mas este comando não é reenviado pelo scanner. '
                'A execução automática para em enumeração estrutural e nunca faz dump.</p>'
                f'<pre style="background:#1a1a2e;color:#00ff88;padding:10px;border-radius:6px;font-size:11px;overflow-x:auto">'
                f'sqlmap -u "{target_url}" --forms --level=3 --risk=2 --batch --dbs --tables --columns</pre>'
            )
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
          {_network_line(det)}
          {'<p style="font-size:11px;color:#666;margin-bottom:4px">📋 ' + owasp + '</p>' if owasp else ''}
          {'<div style="margin:10px 0"><strong style="font-size:12px">▶ Reprodução:</strong>' + repro + '</div>' if repro else ''}
          {poc_evidence_html}
          <div style="background:#fff5f5;padding:10px;border-radius:6px;margin-top:8px">
            <strong style="font-size:12px;color:#c0392b">🛡 Blue Team — Ação Obrigatória:</strong>
            <p style="font-size:12px;margin-top:4px">{remediation}</p>
            {_d3fend_html(f, det)}
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
    # Risk reflects the full exposure (all severities), not only P21-confirmed
    # findings — otherwise 14 CVSS-9.x criticals awaiting validation read as
    # "BAIXO". Confirmed counts are still surfaced separately in the stat cards.
    exec_risk_label = ("CRÍTICO" if vuln_by_sev.get("critical", 0) > 0 else
                       ("ALTO" if vuln_by_sev.get("high", 0) > 0 else
                        ("MÉDIO" if vuln_by_sev.get("medium", 0) > 0 else "BAIXO")))
    exec_risk_color = ("#c0392b" if vuln_by_sev.get("critical", 0) > 0 else
                       ("#e67e22" if vuln_by_sev.get("high", 0) > 0 else
                        ("#f39c12" if vuln_by_sev.get("medium", 0) > 0 else "#27ae60")))

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

    # ── Quality gate / report readiness ─────────────────────────────────────
    quality_html = ""
    try:
        from app.services.scan_quality import build_scan_quality

        quality_html = _render_quality_gate_html(build_scan_quality(db, job))
    except Exception:
        quality_html = ""

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

    # ── ATLAS / NIST AI RMF: ameaças de IA/LLM (se houve teste de LLM) ────────
    ai_threats_html = ""
    try:
        from app.services.framework_mapping import atlas_for_llm
        _llm = dict(state_data.get("llm_risk_report") or {})
        _llm_findings = _llm.get("findings") or []
        if _llm.get("enabled") and _llm_findings:
            _by_strat: dict[str, dict] = {}
            for r in _llm_findings:
                strat = str(r.get("strategy") or "")
                atk = atlas_for_llm(strat)
                if not atk:
                    continue
                slot = _by_strat.setdefault(atk["atlas"], {**atk, "count": 0, "hits": 0})
                slot["count"] += 1
                if str(r.get("severity") or "").lower() in ("critical", "high", "medium") or r.get("vulnerable"):
                    slot["hits"] += 1
            if _by_strat:
                _rows = "".join(
                    f'<tr><td style="font-size:11px;font-weight:700;color:#b8860b">{a["atlas"]}</td>'
                    f'<td style="font-size:12px">{a["atlas_name"]}</td>'
                    f'<td style="font-size:11px;color:#666">{a["genai_risk"]}</td>'
                    f'<td style="font-size:11px;color:#666">{a["nist_ai_rmf"]}</td>'
                    f'<td style="text-align:center;font-size:11px">{a["hits"]}/{a["count"]}</td></tr>'
                    for a in _by_strat.values()
                )
                ai_threats_html = (
                    '<div class="section" style="border-top:4px solid #b8860b">'
                    f'<h2 style="color:#b8860b">🤖 Ameaças de IA — MITRE ATLAS ({len(_by_strat)} técnicas testadas)</h2>'
                    '<p style="font-size:12px;color:#666;margin-bottom:10px">Avaliação do endpoint de IA/LLM mapeada '
                    'ao MITRE ATLAS (adversarial AI) e ao NIST AI RMF. hits/total = probes com resposta vulnerável.</p>'
                    '<table class="findings-table"><thead><tr><th>ATLAS</th><th>Técnica</th>'
                    '<th>GenAI Risk</th><th>NIST AI RMF</th><th style="text-align:center">Hits</th></tr></thead>'
                    f'<tbody>{_rows}</tbody></table></div>'
                )
    except Exception as _ai_err:
        import logging as _ailog
        _ailog.getLogger(__name__).debug("ai_threats failed: %s", _ai_err)

    # ── #2/#6: Caminhos de ataque rumo às Joias da Coroa (objetivo) ───────────
    attack_paths_html = ""
    try:
        from app.services.attack_path import build_attack_paths
        _ap = build_attack_paths(db, scan_id, job=job)
        if _ap["paths"]:
            _cards = []
            for p in _ap["paths"][:8]:
                _chain = " <span style='color:#c7d2fe'>→</span> ".join(
                    f'<span style="display:inline-block;background:#fff;border:1px solid {_sev_color(s["severity"])};'
                    f'border-radius:6px;padding:3px 8px;margin:2px;font-size:10.5px">'
                    f'<b style="color:#7c3aed">{s["tactic_name"]}</b>: {s["family_label"]}'
                    f'{" ✅" if s["confirmed"] else ""}</span>'
                    for s in p["steps"][:8]
                ) or '<span style="color:#999;font-size:11px">sem passos mapeados</span>'
                _flag = ('<span style="background:#c0392b;color:#fff;padding:1px 8px;border-radius:10px;'
                         'font-size:10px;font-weight:700">OBJETIVO ALCANÇÁVEL</span>'
                         if p["objective_reachable"] else
                         '<span style="background:#7f8c8d;color:#fff;padding:1px 8px;border-radius:10px;'
                         'font-size:10px">parcial</span>')
                _cards.append(
                    f'<div style="background:#faf9ff;border:1px solid #ddd6fe;border-radius:8px;padding:12px;margin-bottom:10px">'
                    f'<div style="margin-bottom:6px"><b style="font-size:13px;color:#2c3e50">⭐ {p["objective"]}</b> '
                    f'<span style="font-size:11px;color:#8e44ad">{p["label"]}</span> &nbsp; {_flag}</div>'
                    f'<div style="line-height:2">{_chain}</div></div>'
                )
            attack_paths_html = (
                '<div class="section" style="border-top:4px solid #7c3aed">'
                f'<h2 style="color:#7c3aed">🗺 Caminhos de Ataque rumo ao Objetivo '
                f'({_ap["objectives_reachable"]}/{_ap["paths_with_findings"]} joias alcançáveis)</h2>'
                '<p style="font-size:12px;color:#666;margin-bottom:12px">Sequência de passos por joia da coroa, '
                'ordenada pelas táticas MITRE ATT&CK (entrada → escalada → impacto). ✅ = passo confirmado por '
                'validação ativa. Isto é um pentest: caminho rumo a um objetivo, não uma lista solta.</p>'
                f'{"".join(_cards)}</div>'
            )
    except Exception as _ap_err:
        import logging as _aplog
        _aplog.getLogger(__name__).debug("attack_paths failed: %s", _ap_err)

    # ── #5: Scorecard de cobertura de metodologia ────────────────────────────
    methodology_html = ""
    try:
        from app.services.methodology import compute_methodology_coverage
        _cov = compute_methodology_coverage(db, scan_id)
        _cov_color = "#27ae60" if _cov["coverage_pct"] >= 70 else ("#f39c12" if _cov["coverage_pct"] >= 40 else "#c0392b")
        _untested = ", ".join(u["label"] for u in _cov["untested"][:14]) or "—"
        methodology_html = (
            '<div class="section" style="border-top:4px solid #16a085">'
            f'<h2 style="color:#16a085">📋 Cobertura de Metodologia — {_cov["coverage_pct"]}%</h2>'
            '<p style="font-size:12px;color:#666;margin-bottom:10px">'
            f'Classes de vulnerabilidade exercitadas: <b style="color:{_cov_color}">{_cov["tested_count"]}/{_cov["total_families"]}</b> '
            f'({_cov["produced_count"]} com achados). Transparência de pentest: o que foi testado e o que não foi.</p>'
            '<div style="background:#eee;border-radius:6px;height:14px;overflow:hidden;margin-bottom:10px">'
            f'<div style="width:{_cov["coverage_pct"]}%;height:100%;background:{_cov_color}"></div></div>'
            f'<p style="font-size:11px;color:#888"><b>Não testado neste scan:</b> {_untested}</p>'
            '</div>'
        )
    except Exception as _cov_err:
        import logging as _covlog
        _covlog.getLogger(__name__).debug("methodology_coverage failed: %s", _cov_err)

    # ── Inteligência HackerOne: POR QUE cada classe foi testada ───────────────
    learning_intel_html = ""
    try:
        from app.models.models import ScanWorkItem as _SWI_li2
        _items = db.query(_SWI_li2).filter(
            _SWI_li2.scan_job_id == scan_id,
            _SWI_li2.item_metadata["source"].astext == "hackerone_learnings",
        ).all()
        _byfam: dict[str, dict] = {}
        for _it in _items:
            _m = dict(_it.item_metadata or {})
            _fam = str(_m.get("vuln_family") or "outros")
            _slot = _byfam.setdefault(_fam, {"engine": _m.get("engine"), "sim": 0, "reports": [], "count": 0})
            _slot["count"] += 1
            _slot["sim"] = max(_slot["sim"], int(_m.get("similarity_pct") or 0))
            for _r in (_m.get("matched_reports") or []):
                if _r and _r not in _slot["reports"] and len(_slot["reports"]) < 6:
                    _slot["reports"].append(_r)
        _sem = {k: v for k, v in _byfam.items() if v["engine"] == "semantic_match"}
        if _sem:
            _rows_li = "".join(
                f'<tr><td style="font-size:12px;font-weight:700;text-transform:uppercase">{k.replace("_"," ")}</td>'
                f'<td style="text-align:center;font-size:12px;color:#16a085;font-weight:700">{v["sim"]}%</td>'
                f'<td style="text-align:center;font-size:11px">{v["count"]}</td>'
                f'<td style="font-size:10px;color:#666;font-family:monospace">'
                + (", ".join("#" + str(r) for r in v["reports"]) or "—") + '</td></tr>'
                for k, v in sorted(_sem.items(), key=lambda x: -x[1]["sim"])
            )
            learning_intel_html = (
                '<div class="section" style="border-top:4px solid #16a085">'
                f'<h2 style="color:#16a085">🧠 Inteligência HackerOne — por que cada classe foi testada</h2>'
                '<p style="font-size:12px;color:#666;margin-bottom:10px">A plataforma cruzou o perfil do alvo '
                'contra os ~10.000 reports HackerOne (busca semântica) e priorizou as classes mais '
                'SEMELHANTES a este alvo. Cada teste foi escolhido porque reports reais comprovam a falha em '
                'alvos parecidos — não por varredura cega.</p>'
                '<table class="findings-table"><thead><tr><th>Classe testada</th>'
                '<th style="text-align:center">Similaridade</th><th style="text-align:center">Testes</th>'
                '<th>Reports HackerOne que motivaram</th></tr></thead>'
                f'<tbody>{_rows_li}</tbody></table></div>'
            )
    except Exception as _li_err:
        import logging as _lilog
        _lilog.getLogger(__name__).debug("learning_intel failed: %s", _li_err)

    # ── NIST CSF 2.0 rollup (compliance) ──────────────────────────────────────
    nist_csf_html = ""
    try:
        from app.services.vuln_family import classify_family as _cf_csf
        from app.services.framework_mapping import csf_for_family
        _csf_count: dict[str, dict] = {}
        for _f in vuln_findings:
            _d = dict(_f.details or {})
            _fam = _cf_csf(title=_f.title, tool=_f.tool, owasp=str(_d.get("owasp_category") or ""),
                           cve=_f.cve, learning_family=(_d.get("learning_source") or {}).get("vuln_family"))
            _csf = csf_for_family(_fam)
            if _csf:
                slot = _csf_count.setdefault(_csf["subcategory"], {"name": _csf["name"], "count": 0})
                slot["count"] += 1
        if _csf_count:
            _csf_rows = "".join(
                f'<tr><td style="font-size:11px;font-weight:700;color:#2980b9">{sub}</td>'
                f'<td style="font-size:12px">{v["name"]}</td>'
                f'<td style="text-align:center;font-size:12px;font-weight:700">{v["count"]}</td></tr>'
                for sub, v in sorted(_csf_count.items(), key=lambda x: -x[1]["count"])
            )
            nist_csf_html = (
                '<div class="section" style="border-top:4px solid #2980b9">'
                f'<h2 style="color:#2980b9">📑 Alinhamento NIST CSF 2.0 ({len(_csf_count)} subcategorias)</h2>'
                '<p style="font-size:12px;color:#666;margin-bottom:10px">Achados mapeados às subcategorias do '
                'NIST Cybersecurity Framework 2.0 — para avaliação de maturidade e compliance regulatório.</p>'
                '<table class="findings-table"><thead><tr><th>Subcategoria</th><th>Função · Categoria</th>'
                '<th style="text-align:center">Achados</th></tr></thead>'
                f'<tbody>{_csf_rows}</tbody></table></div>'
            )
    except Exception as _csf_err:
        import logging as _csflog
        _csflog.getLogger(__name__).debug("nist_csf failed: %s", _csf_err)

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

    # ── P21 adjudication dossiers and return wires ──────────────────────────
    adjudication_html = ""
    try:
        from app.models.models import FindingAdjudication, FindingIntelligenceSnapshot, ValidationWire
        from app.services.finding_adjudication import build_finding_assessment

        _adj_rows = []
        _adjudication_findings = (
            db.query(Finding)
            .filter(Finding.scan_job_id == scan_id)
            .order_by(Finding.id.asc())
            .limit(100)
            .all()
        )
        for _finding in _adjudication_findings:
            _adj = (
                db.query(FindingAdjudication)
                .filter(FindingAdjudication.finding_id == _finding.id)
                .order_by(FindingAdjudication.cycle.desc())
                .first()
            )
            if _adj is None:
                continue
            _wires = (
                db.query(ValidationWire)
                .filter(ValidationWire.finding_id == _finding.id)
                .order_by(ValidationWire.id.asc())
                .all()
            )
            _intel = (
                db.query(FindingIntelligenceSnapshot)
                .filter(FindingIntelligenceSnapshot.finding_id == _finding.id)
                .order_by(FindingIntelligenceSnapshot.fetched_at.desc())
                .first()
            )
            _missing = ", ".join(str(item) for item in list(_adj.missing_evidence or [])) or "—"
            _wire_text = " · ".join(
                f"#{wire.id} {wire.action_id} [{wire.status}] → {wire.tool_name or 'ação interna'}"
                for wire in _wires
            ) or "nenhum wire necessário/criado"
            _cve_text = "—"
            if _intel:
                _cve_text = (
                    f"{_intel.cve_id or 'sem CVE'} · aplicabilidade={_intel.applicability} · "
                    f"CVSS={_intel.cvss_score if _intel.cvss_score is not None else '—'} "
                    f"({_intel.cvss_source or 'sem fonte'}) · KEV={_intel.kev if _intel.kev is not None else '—'} · "
                    f"exploit={_intel.public_exploit_status}"
                )
            _assessment = build_finding_assessment(db, job, _finding).get("answers") or {}
            _fp = dict(_assessment.get("false_positive") or {})
            _rec = dict(_assessment.get("recommendation") or {})
            _poc = dict(_assessment.get("poc") or {})
            _exploit = dict(_assessment.get("public_exploit") or {})
            _attack_path = dict(_assessment.get("attack_path") or {})
            _poc_steps = " | ".join(str(step) for step in list(_poc.get("steps") or [])[:4]) or "—"
            _exploit_urls = " | ".join(str(url) for url in list(_exploit.get("urls") or [])[:4]) or "—"
            _answer_text = (
                f"FP={_fp.get('answer')} · causa={_fp.get('cause') or '—'} · "
                f"recomendação={_rec.get('text') or '—'} · PoC={_poc.get('status')} · passos={_poc_steps}"
            )
            _closure_text = (
                f"{_cve_text} · exploit URLs={_exploit_urls} · "
                f"attack path={'montado' if _attack_path.get('mounted') else 'não demonstrado'}"
            )
            _adj_rows.append(
                '<tr>'
                f'<td><strong>F-{_finding.id}</strong><br>{_html.escape(str(_finding.title or ""))}</td>'
                f'<td><strong>{_html.escape(str(_adj.final_verdict))}</strong><br>'
                f'<span style="font-size:10px;color:#777">proposta LLM: {_html.escape(str(_adj.proposed_verdict or "—"))}</span></td>'
                f'<td>{_html.escape(str(_adj.reason_code))}<br><span style="font-size:10px;color:#777">confiança {_adj.confidence:.2f}</span></td>'
                f'<td>{_html.escape(_missing)}</td>'
                f'<td>{_html.escape(_answer_text)}</td>'
                '</tr>'
            )
        if _adj_rows:
            adjudication_html = (
                '<div class="section" style="border-top:4px solid #2563eb">'
                '<h2 style="color:#1d4ed8">P21 — Adjudicação, Lacunas e Wires de Revalidação</h2>'
                '<p style="font-size:12px;color:#666;margin-bottom:12px">A coluna "O que falta" lista a evidência '
                'que originou a lacuna. A proposta da LLM é consultiva; o veredito final é produzido pelo '
                'evidence gate após execução real.</p>'
                '<table class="findings-table paginate" data-page-size="15"><thead><tr>'
                '<th>Finding</th><th>Veredito</th><th>Causa</th><th>O que falta</th><th>Resposta/PoC</th>'
                f'</tr></thead><tbody>{"".join(_adj_rows)}</tbody></table></div>'
            )
    except Exception as _adj_err:
        import logging as _adj_log
        _adj_log.getLogger(__name__).debug("adjudication report section failed: %s", _adj_err)

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Relatório de Pentest — {domains_title}</title>
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
    /* Paginated tables (P21 adjudication) carry long free text: force a fixed
       layout with wrapping so wide cells (Resposta/PoC, CVE/exploit) stay inside
       the page instead of overflowing off the right edge. */
    .findings-table.paginate {{ table-layout: fixed; }}
    .findings-table.paginate th, .findings-table.paginate td {{
        word-break: break-word; overflow-wrap: anywhere; white-space: normal; }}
    .findings-table.paginate td {{ font-size: 12px; }}
    .easm-section-divider {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                             color: white; padding: 16px 24px; border-radius: 8px;
                             margin: 32px 0 16px 0; font-size: 14px; font-weight: 600; }}
    .footer {{ text-align: center; font-size: 11px; color: #aaa; margin-top: 32px; padding-bottom: 24px; }}
    @media (max-width: 700px) {{ .pentest-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
    /* Controle de quebra de página na impressão/PDF: seções e linhas não partem
       no meio; o cabeçalho da tabela repete a cada página. */
    .findings-table {{ table-layout: fixed; }}
    .findings-table th, .findings-table td {{ word-break: break-word; overflow-wrap: anywhere; }}
    @media print {{
      .section {{ break-inside: avoid; }}
      .findings-table tr {{ break-inside: avoid; }}
      .findings-table thead {{ display: table-header-group; }}
      h2, h3 {{ break-after: avoid; }}
      .stat-card, .risk-class, .reco-item {{ break-inside: avoid; }}
      pre {{ white-space: pre-wrap !important; word-break: break-all; overflow-x: visible !important; }}
    }}
  </style>
</head>
<body>
<div class="page">

  <!-- PENTEST HEADER -->
  <div class="pentest-header">
    <h1>🔴 Relatório ScriptKidd.o</h1>
    <div class="meta">
      Alvos: <strong>{domains_compact}</strong>
      {f'<details style="display:inline-block;margin-left:8px;vertical-align:top"><summary style="cursor:pointer;display:inline;color:#ffd0d0">ver todos ({domains_count})</summary><div style="margin-top:6px;font-weight:400;max-width:900px">{domains_full_html}</div></details>' if domains_count > 6 else ''}
      &nbsp;|&nbsp;
      Gerado: {now} &nbsp;|&nbsp;
      Scan ID: #{scan_id}
      {f'&nbsp;|&nbsp; Scan anterior: #{previous_scan_id}' if previous_scan_id else ''}
    </div>
    <div class="score-badge">Risco de Exposição: {exec_risk_label}</div>
  </div>

  <!-- PENTEST STATS -->
  <div class="pentest-grid">
    <div class="stat-card" style="border-top:3px solid #c0392b">
      <div class="num" style="color:#c0392b">{vuln_by_sev['critical']}</div>
      <div class="lbl">Críticos <span style="color:#999">· {conf_critical} confirmados</span></div>
    </div>
    <div class="stat-card" style="border-top:3px solid #e67e22">
      <div class="num" style="color:#e67e22">{vuln_by_sev['high']}</div>
      <div class="lbl">Altos <span style="color:#999">· {conf_high} confirmados</span></div>
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

  <!-- QUALITY GATE -->
  {quality_html}

  <!-- P21 POC SANDBOX STRIP -->
  {poc_strip_html}

  <!-- P21 FINDING ADJUDICATION AND RETURN WIRES -->
  {adjudication_html}

  <!-- ATTACK NARRATIVE (Frente D) -->
  {attack_narrative_html}

  <!-- MITRE ATT&CK TACTIC PROGRESSION (#3) -->
  {attack_progression_html}

  <!-- AI/LLM THREATS — MITRE ATLAS / NIST AI RMF -->
  {ai_threats_html}

  <!-- ATTACK PATHS TO OBJECTIVE (#2/#6) -->
  {attack_paths_html}

  <!-- METHODOLOGY COVERAGE SCORECARD (#5) -->
  {methodology_html}

  <!-- HACKERONE LEARNING INTELLIGENCE — why each class was tested -->
  {learning_intel_html}

  <!-- NIST CSF 2.0 COMPLIANCE ROLLUP -->
  {nist_csf_html}

  <!-- KILL CHAIN PHASE COVERAGE -->
  {phase_coverage_html}

  <!-- CROWN JEWELS -->
  {crown_jewels_html}

  <!-- NO CONFIRMED FINDINGS NOTICE -->
  {'<div class="section" style="border-left:4px solid #27ae60"><h2 style="color:#27ae60">✅ Nenhuma Vulnerabilidade Confirmada com PoC</h2><p style="font-size:13px;color:#666">Nenhuma ferramenta de exploração ativa (sqlmap, dalfox, nuclei-confirmed) confirmou vulnerabilidades exploráveis. Existem ' + str(len(candidate_list)) + ' findings candidatos que requerem verificação P21 ou revisão manual.</p></div>' if not confirmed_list and not chain_findings else ''}

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
<script>
(function() {{
  var PS_DEFAULT = 15;
  function paginate(table) {{
    var size = parseInt(table.getAttribute('data-page-size') || PS_DEFAULT, 10);
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.rows);
    if (rows.length <= size) return;
    var page = 0, pages = Math.ceil(rows.length / size);
    var nav = document.createElement('div');
    nav.className = 'no-print';
    nav.style.cssText = 'display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:10px;font-size:12px;color:#666';
    var info = document.createElement('span');
    var prev = document.createElement('button');
    var next = document.createElement('button');
    prev.textContent = '‹ anterior'; next.textContent = 'próxima ›';
    [prev, next].forEach(function(b) {{ b.style.cssText = 'padding:4px 10px;border:1px solid #ccc;border-radius:6px;background:#fff;cursor:pointer'; }});
    function render() {{
      rows.forEach(function(r, i) {{ r.style.display = (i >= page*size && i < (page+1)*size) ? '' : 'none'; }});
      info.textContent = rows.length + ' itens · página ' + (page+1) + '/' + pages;
      prev.disabled = page <= 0; next.disabled = page >= pages-1;
      prev.style.opacity = prev.disabled ? 0.4 : 1; next.style.opacity = next.disabled ? 0.4 : 1;
    }}
    prev.onclick = function() {{ if (page>0) {{ page--; render(); }} }};
    next.onclick = function() {{ if (page<pages-1) {{ page++; render(); }} }};
    nav.appendChild(info); nav.appendChild(prev); nav.appendChild(next);
    table.parentNode.insertBefore(nav, table.nextSibling);
    render();
    window.addEventListener('beforeprint', function() {{ rows.forEach(function(r) {{ r.style.display = ''; }}); }});
    window.addEventListener('afterprint', function() {{ render(); }});
  }}
  document.querySelectorAll('table.paginate').forEach(paginate);
}})();
</script>
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



# ══════════════════════════════════════════════════════════════════════════════
# Relatórios VALID v2 — HTML PURO, dado 100% real da plataforma
# ------------------------------------------------------------------------------
# Reproduzem o design VALID (capa escura #27272C, acento #1767E5, Archivo, papel
# #f3f2f2, rampa de severidade log). Nada de mock: severidade, rating por
# densidade/alvo, risco por framework, superfície, heatmap por classe, caminhos
# de ataque, MITRE ATT&CK, NIST/CIS/ISO, CVEs e inventário completo vêm do banco.
# O nome da EMPRESA dona do relatório é variável (capa + cabeçalho).
# ══════════════════════════════════════════════════════════════════════════════
import math as _math

_V_BLUE = "#1767E5"
_V_INK = "#201e1d"
_V_MUTED = "#605d5d"
_SEV_CELL = {"critical": "#7c1405", "high": "#dd2b0f", "medium": "#ff9783", "low": "#d7d3d3", "info": "#eae7e7"}
_SEV_FG = {"critical": "#fff", "high": "#fff", "medium": "#201e1d", "low": "#201e1d", "info": "#605d5d"}
_SEV_PT = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Info"}
_SEV_ABBR = {"critical": "Crít", "high": "Alto", "medium": "Méd", "low": "Baixo", "info": "Info"}
_SEV_KEYS = ("critical", "high", "medium", "low", "info")
_SEV_W = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 1.0, "info": 0.5}
_HEAT_RAMP = ["#ffe0d9", "#ffc4b8", "#ff9783", "#ff563c", "#dd2b0f", "#ae1800", "#7c1405"]
_VERIF_PT = {"confirmed": "Confirmado", "hypothesis": "Hipótese", "candidate": "Candidato",
             "refuted": "Refutado", "pending_retest": "Reteste"}

# SLA de referência por prioridade (proposta — não é compromisso contratual).
_PRIO = {
    "critical": ("P0", "#7c1405", "#fff", "7 dias"),
    "high": ("P1", "#dd2b0f", "#fff", "30 dias"),
    "medium": ("P2", "#ff9783", "#201e1d", "90 dias"),
    "low": ("P3", "#d7d3d3", "#201e1d", "180 dias"),
    "info": ("Obs", "transparent", "#201e1d", "—"),
}

# família → (ISO/IEC 27001:2022 Anexo A, CIS Controls v8) — mapeamento de
# referência curado (metadado de compliance, como o mapa MITRE/CSF). "—" quando
# não há correspondência de alta confiança.
_FAMILY_ISO_CIS: dict[str, tuple[str, str]] = {
    "rce": ("8.28 · 8.25", "16.1 · 16.12"), "command_injection": ("8.28", "16.1"),
    "sqli": ("8.28", "16.1"), "nosql_injection": ("8.28", "16.1"),
    "xss": ("8.28 · 8.29", "16.1 · 16.11"), "xxe": ("8.28", "16.1"),
    "path_traversal": ("8.28", "16.1"), "lfri": ("8.28", "16.1"),
    "file_upload": ("8.28 · 8.26", "16.1"), "header_injection": ("8.28", "16.1"),
    "prototype_pollution": ("8.28", "16.11"), "deserialization": ("8.28", "16.1"),
    "ssti": ("8.28", "16.1"), "ssrf": ("8.28 · 8.20", "16.1 · 13.3"),
    "vulnerable_dependency": ("8.8", "7.4 · 2.2"), "misconfiguration": ("8.9", "4.1"),
    "security_headers": ("8.9 · 8.26", "16.7"), "cors": ("8.9 · 8.26", "16.7"),
    "idor": ("5.15 · 8.3", "6.8 · 16.10"), "broken_access_control": ("5.15 · 8.3", "6.8 · 16.10"),
    "bola_bfla": ("5.15 · 8.3", "6.8 · 16.10"), "mass_assignment": ("5.15 · 8.28", "6.8 · 16.1"),
    "auth_bypass": ("5.17 · 8.5", "6.3 · 6.8"), "jwt_oauth": ("5.17 · 8.5", "6.3"),
    "type_juggling": ("5.17 · 8.28", "6.3 · 16.1"),
    "business_logic": ("8.28 · 5.15", "16.1 · 16.10"),
    "secrets": ("5.17 · 8.24", "3.11 · 16.9"), "info_exposure": ("8.12 · 5.12", "3.11 · 4.8"),
    "excessive_data_exposure": ("8.12 · 5.12", "3.11"), "tls_ssl": ("8.24", "3.10"),
    "subdomain_takeover": ("8.9 · 5.9", "4.8 · 1.1"), "graphql_api": ("8.28 · 8.26", "16.1"),
    "websocket": ("8.28 · 8.26", "16.1"), "csrf": ("8.28", "16.1"),
    "open_redirect": ("8.28", "16.1"), "race_condition": ("8.28", "16.1"),
    "dos": ("8.6 · 8.20", "12.2"), "outros": ("8.8", "12.2 · 4.4"),
}

_FW_LABEL = {"iso27001": "ISO 27001", "nist": "NIST CSF", "cis_v8": "CIS v8", "pci": "PCI DSS"}


def _v_grade_color(grade: str) -> str:
    return {"A": "#4cc13e", "B": "#4cc13e", "C": "#f4c10b", "D": "#f4c10b", "F": "#ec3013"}.get(str(grade), "#ec3013")


def _num(n) -> str:
    """Milhar em pt-BR (1.234). NUNCA usar '.replace(",", ".")' direto num bloco de
    f-strings concatenadas — o replace vaza e corrompe vírgulas de CSS (repeat(2,1fr))."""
    try:
        return f"{int(n):,}".replace(",", ".")
    except (TypeError, ValueError):
        return str(n)


def _clip(text: str, n: int) -> str:
    """Trunca em limite de palavra com reticências (evita corte no meio da palavra)."""
    t = str(text or "").strip()
    if len(t) <= n:
        return t
    cut = t[:n].rsplit(" ", 1)[0]
    return (cut or t[:n]).rstrip(",;:.") + "…"


# CVSS coerente com a severidade — IDÊNTICO à regra do CSV (export.csv). Usa o
# valor medido quando cai na faixa da severidade; senão traduz a severidade para
# o piso da faixa CVSS v3, de modo que reclassifique de volta à MESMA severidade.
_CVSS_FLOOR = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "info": 0.0}


def _cvss_band(score: float) -> str:
    return ("critical" if score >= 9.0 else "high" if score >= 7.0
            else "medium" if score >= 4.0 else "low" if score >= 0.1 else "info")


def _finding_cvss_num(f) -> float | None:
    sev = str(getattr(f, "severity", "") or "").strip().lower()
    measured = None
    d = f.details if isinstance(getattr(f, "details", None), dict) else {}
    adj = d.get("adjudicated_cvss")
    for v in (getattr(f, "cvss", None), d.get("cvss"),
              adj.get("score") if isinstance(adj, dict) else None):
        if v is None or str(v).strip() == "":
            continue
        try:
            measured = float(v)
            break
        except (TypeError, ValueError):
            continue
    if measured is not None and (sev not in _CVSS_FLOOR or _cvss_band(measured) == sev):
        return measured
    if sev in _CVSS_FLOOR:
        return _CVSS_FLOOR[sev]
    return measured


def _finding_cvss(f, dash: str = "—") -> str:
    v = _finding_cvss_num(f)
    return f"{v:.1f}" if v is not None else dash


def _v_heat(count: int, weight: float, max_weighted: float, height: str = "30px") -> str:
    """Célula de heatmap com escala logarítmica (igual ao design VALID)."""
    if not count:
        return (f'<span class="hc" style="height:{height};background:#eae7e7;color:#9b9797">—</span>')
    val = count * weight
    t = (_math.log(val + 1) / _math.log(max_weighted + 1)) if max_weighted > 0 else 0.0
    k = min(6, int(t * 7))
    bg = _HEAT_RAMP[k]
    fg = "#fff" if k >= 4 else "#201e1d"
    return f'<span class="hc" style="height:{height};background:{bg};color:{fg}">{_num(count)}</span>'


def _v_sev(sev: str, abbr: bool = False) -> str:
    s = str(sev or "info").lower()
    label = (_SEV_ABBR if abbr else _SEV_PT).get(s, "Info")
    bg = _SEV_CELL.get(s, "#eae7e7")
    fg = _SEV_FG.get(s, "#605d5d")
    extra = "box-shadow:inset 0 0 0 1px #9b9797;" if s == "info" else ""
    return f'<span class="sev" style="background:{bg};color:{fg};{extra}">{label}</span>'


_V_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0;-webkit-print-color-adjust:exact;print-color-adjust:exact}
html,body{background:#3a3a40}
body{font-family:'Archivo',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#201e1d;line-height:1.5;font-size:14px}
@page{size:A4;margin:0}
.sheet{width:210mm;min-height:296mm;background:#f3f2f2;padding:13mm 14mm 11mm;margin:0 auto 12px;display:flex;flex-direction:column;overflow:hidden}
.cover{background:#27272C;color:#fff;padding:14mm 14mm 12mm}
.content{flex:1;min-width:0;padding-top:2px}
.hd{display:flex;justify-content:space-between;align-items:baseline;border-bottom:2px solid #201e1d;padding-bottom:8px;font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.hd span:first-child{font-weight:600}
.brand{color:#1767E5;font-weight:800}
.cover-hd{display:flex;justify-content:space-between;align-items:baseline;border-bottom:2px solid #fff;padding-bottom:8px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;font-weight:600}
.ft{display:flex;justify-content:space-between;margin-top:12px;padding-top:10px;font-size:10px;color:#605d5d;letter-spacing:.06em;text-transform:uppercase}
.cover-ft{color:#fff;border-top:2px solid #fff;margin-top:16px;padding-top:16px}
a{color:#1767E5;text-decoration:none}
.eyebrow{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#1767E5;font-weight:600}
.h1{font-size:40px;line-height:1.03;font-weight:800;letter-spacing:-.02em}
.h2{font-size:26px;line-height:1.1;font-weight:800;letter-spacing:-.015em;margin-top:4px}
.h2sm{font-size:22px;line-height:1.1;font-weight:800;letter-spacing:-.015em;margin-top:4px}
.lead{font-size:13px;color:#444141;line-height:1.5}
.muted{color:#605d5d}
.up{font-size:11px;letter-spacing:.08em;text-transform:uppercase;font-weight:600}
.r2{border-top:2px solid #201e1d}
.r2b{border-bottom:2px solid #201e1d}
.th{display:grid;align-items:baseline;padding:6px 0;font-size:9.5px;letter-spacing:.05em;text-transform:uppercase;color:#605d5d;font-weight:600;border-bottom:1px solid #bab6b6}
.tr{display:grid;align-items:start;padding:6px 0;border-bottom:1px solid #d7d3d3;font-size:12px;line-height:1.3}
.tr:last-child{border-bottom:none}
.num{text-align:right;font-variant-numeric:tabular-nums}
.b{font-weight:800}.b6{font-weight:600}
.sev{display:inline-block;font-weight:800;padding:2px 6px;font-size:10px;white-space:nowrap;align-self:start}
.hc{display:flex;align-items:center;padding:0 8px;font-weight:800;font-size:12.5px}
.wrap{overflow-wrap:anywhere;min-width:0}
.kpis{display:grid;border-top:2px solid #201e1d;border-bottom:2px solid #201e1d}
.stat-l{font-size:11px;color:#605d5d;text-transform:uppercase;letter-spacing:.06em}
.cover-brand{padding-top:16mm;display:flex;flex-direction:column;gap:14px}
.cover-name{font-size:40px;font-weight:800;letter-spacing:-.02em;line-height:1.05}
.cover-accent{width:96px;height:8px;background:#1767E5}
.cover-tag{font-size:14px;letter-spacing:.04em;color:#E7E7E8}
.cover-foot-block{margin-top:auto}
.cover-type{border-top:8px solid #1767E5;padding:14px 0 18px;display:flex;flex-direction:column;gap:6px}
.cover-type-l{font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:600}
.cover-type-t{font-size:34px;line-height:1.05;font-weight:800;letter-spacing:-.02em}
.cover-type-s{font-size:14px;color:#E7E7E8}
.cover-meta2{display:grid;grid-template-columns:2fr 1fr;border-top:2px solid #fff}
.cover-meta2>div{padding:14px 14px 4px 0}
.cover-meta-r{border-left:2px solid #fff;padding:14px 0 4px 14px}
.cover-meta-v{font-size:20px;font-weight:800;line-height:1.15;margin-top:4px}
@media print{html,body{background:#fff}.sheet{margin:0;height:296mm;min-height:296mm;max-height:296mm;overflow:hidden;page-break-after:always;break-after:page}.sheet:last-child{page-break-after:auto;break-after:auto}.content{overflow:hidden}.tr,.th{break-inside:avoid}}
@media screen and (max-width:760px){.sheet{width:100%;min-height:0;padding:22px 16px}.h1,.cover-name{font-size:30px}.h2{font-size:22px}}
"""


def _v_hd(company: str, section: str) -> str:
    return (f'<div class="hd"><span><b class="brand">{_html.escape(company)}</b> · Gestão de Vulnerabilidades</span>'
            f'<span>{_html.escape(section)}</span></div>')


def _v_sheet(company: str, section: str, body: str, ref: str, n: int, total: int) -> str:
    return (f'<section class="sheet">{_v_hd(company, section)}<div class="content">{body}</div>'
            f'<div class="ft"><span>{_html.escape(ref)}</span><span>{n:02d} / {total:02d}</span></div></section>')


def _v_cover(company: str, kind_top: str, big_title: str, subtitle: str, escopo: str,
             referencia: str, foot_left: str, total: int) -> str:
    e = _html.escape
    return (
        f'<section class="sheet cover">'
        f'<div class="cover-hd"><span>{e(kind_top)}</span><span>Confidencial · uso interno</span></div>'
        f'<div class="cover-brand"><div class="cover-name">{e(company)}</div>'
        f'<div class="cover-accent"></div>'
        f'<div class="cover-tag">Gestão contínua de exposição e vulnerabilidades</div></div>'
        f'<div class="cover-foot-block">'
        f'<div class="cover-type"><div class="cover-type-l">Tipo de relatório</div>'
        f'<div class="cover-type-t">{e(big_title)}</div><div class="cover-type-s">{e(subtitle)}</div></div>'
        f'<div class="cover-meta2"><div><div class="cover-type-l">Escopo</div>'
        f'<div class="cover-meta-v">{e(escopo)}</div></div>'
        f'<div class="cover-meta-r"><div class="cover-type-l">Referência</div>'
        f'<div class="cover-meta-v">{e(referencia)}</div></div></div></div>'
        f'<div class="ft cover-ft"><span>{e(foot_left)}</span><span>01 / {total:02d}</span></div>'
        f'</section>'
    )


def _v_shell(doc_title: str, sheets: str) -> str:
    return (f'<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{_html.escape(doc_title)}</title><style>{_V_CSS}</style></head>'
            f'<body>{sheets}</body></html>')


def _host_short(h: str) -> str:
    h = str(h or "").strip()
    if not h or h in ("—", "raiz"):
        return h or "—"
    first = h.split(".")[0]
    return first or h


def _v_max_weighted(rows: list[dict], keys=("critical", "high", "medium", "low")) -> float:
    m = 0.0
    for r in rows:
        for k in keys:
            m = max(m, float(r.get(k, 0)) * _SEV_W[k])
    return m


def _v_common(db: "Session", scan_id: int, company_name: str | None):
    """Agregações reais compartilhadas pelos dois relatórios VALID."""
    from app.models.models import Finding, ScanJob
    from app.services.bas_exclusion import exclude_simulated
    from app.services.risk_service import _grade_from_score, _log_exposure_penalty, compute_framework_scores
    from app.services.strategy_runtime import parse_scope_targets
    from app.services.vuln_family import classify_family, family_label

    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        return None

    company = (str(company_name or "").strip()
               or str(getattr(getattr(job, "access_group", None), "name", "") or "").strip()
               or "Empresa")
    findings = (
        exclude_simulated(db.query(Finding))
        .filter(Finding.scan_job_id == scan_id, Finding.is_false_positive.isnot(True))
        .order_by(Finding.id)
        .all()
    )

    sev = {s: 0 for s in _SEV_KEYS}
    fam_of: dict[int, str] = {}
    for f in findings:
        s = str(f.severity or "info").lower()
        if s in sev:
            sev[s] += 1
        det = f.details if isinstance(f.details, dict) else {}
        fam_of[f.id] = classify_family(
            title=f.title, tool=f.tool, owasp=str(det.get("owasp_category") or ""),
            cve=f.cve, learning_family=(det.get("learning_source") or {}).get("vuln_family"),
        )

    scope_hosts = parse_scope_targets(str(job.target_query or ""))
    host_set = {str(f.domain or "").strip().lower() for f in findings if f.domain}
    n_targets = max(1, len(scope_hosts), len(host_set))
    density = {k: sev[k] / n_targets for k in ("critical", "high", "medium", "low")}
    score = max(0.0, round(100.0 - _log_exposure_penalty(
        density["critical"], density["high"], density["medium"], density["low"]), 1))
    grade = _grade_from_score(score)
    triaged = sum(1 for f in findings if str(f.verification_status or "").lower() in ("confirmed", "refuted"))
    try:
        frameworks = compute_framework_scores(
            severity_count=sev, findings_total=float(len(findings)),
            findings_triaged=float(triaged), n_targets=float(n_targets))
    except Exception:
        frameworks = {}

    # superfície (host × severidade) e classe (família × severidade)
    by_host: dict[str, dict] = {}
    by_class: dict[str, dict] = {}
    for f in findings:
        s = str(f.severity or "info").lower()
        host = str(f.domain or "").strip() or "—"
        hr = by_host.setdefault(host, {"host": host, **{k: 0 for k in _SEV_KEYS}, "total": 0})
        if s in hr:
            hr[s] += 1
        hr["total"] += 1
        fam = fam_of[f.id]
        cr = by_class.setdefault(fam, {"family": fam, "label": family_label(fam),
                                       **{k: 0 for k in _SEV_KEYS}, "total": 0})
        if s in cr:
            cr[s] += 1
        cr["total"] += 1

    def _sk(r):
        return (r["critical"], r["high"], r["medium"], r["low"], r["total"])
    surface = sorted(by_host.values(), key=_sk, reverse=True)
    vuln_class = sorted(by_class.values(), key=_sk, reverse=True)

    # matriz severidade × verificação
    verif = {s: {"confirmed": 0, "hypothesis": 0, "candidate": 0} for s in _SEV_KEYS}
    for f in findings:
        s = str(f.severity or "info").lower()
        v = str(f.verification_status or "candidate").lower()
        if v not in ("confirmed", "hypothesis", "candidate"):
            v = "candidate"
        if s in verif:
            verif[s][v] += 1

    # catálogo de recomendações (real, deduplicado por texto, ordenado por volume)
    rec_count: dict[str, int] = {}
    for f in findings:
        rec = str(f.recommendation or "").strip()
        if rec:
            rec_count[rec] = rec_count.get(rec, 0) + 1
    rec_sorted = sorted(rec_count.items(), key=lambda kv: (-kv[1], kv[0]))
    rec_code: dict[str, str] = {txt: f"R{i + 1:02d}" for i, (txt, _c) in enumerate(rec_sorted)}
    rec_catalog = [(rec_code[txt], txt, c) for txt, c in rec_sorted]

    # CVEs reais
    cve_map: dict[str, dict] = {}
    for f in findings:
        cid = str(f.cve or "").strip().upper()
        if not cid.startswith("CVE-"):
            continue
        cur = cve_map.get(cid)
        cvss = _finding_cvss_num(f) or 0.0
        if (cur is None) or (cvss > cur["cvss"]):
            cve_map[cid] = {"cve": cid, "cvss": cvss, "title": str(f.title or ""),
                            "host": str(f.domain or "—"), "severity": str(f.severity or "info").lower()}
    cve_list = sorted(cve_map.values(), key=lambda r: -r["cvss"])

    # caminhos de ataque + joias
    try:
        from app.services.attack_path import build_attack_paths
        paths = build_attack_paths(db, scan_id, job=job, max_paths=12)
    except Exception:
        paths = {"paths": [], "objectives_total": 0, "paths_with_findings": 0, "objectives_reachable": 0}
    jewels = [j for j in (dict(job.state_data or {}).get("crown_jewels") or []) if isinstance(j, dict)]

    total = len(findings)
    classified = sev["critical"] + sev["high"] + sev["medium"] + sev["low"]
    return {
        "job": job, "company": company, "findings": findings, "fam_of": fam_of,
        "sev": sev, "n_targets": n_targets, "score": score, "grade": grade,
        "frameworks": frameworks, "surface": surface, "vuln_class": vuln_class,
        "verif": verif, "rec_catalog": rec_catalog, "rec_code": rec_code,
        "cve_list": cve_list, "paths": paths, "jewels": jewels, "triaged": triaged,
        "total": total, "classified": classified, "scope_n": len(scope_hosts),
        "hosts_n": len(host_set),
    }


def _v_ref(scan_id: int) -> str:
    _MES = ["", "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho",
            "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
    now = datetime.now()
    return f"{_MES[now.month]} {now.year} · ciclo #{scan_id}"


def _v_distribution_bar(sev: dict) -> str:
    total = max(1, sum(sev.values()))
    seg = "".join(
        f'<div style="width:{100 * sev[k] / total:.2f}%;background:{_SEV_CELL[k]}"></div>'
        for k in _SEV_KEYS if sev[k]
    )
    legend = "".join(
        f'<div style="display:flex;gap:6px;align-items:center"><span style="width:11px;height:11px;'
        f'background:{_SEV_CELL[k]};flex:none;{"box-shadow:inset 0 0 0 1px #bab6b6" if k=="info" else ""}"></span>'
        f'<span><b>{sev[k]}</b> {_SEV_PT[k]} · {100 * sev[k] / total:.1f}%</span></div>'
        for k in _SEV_KEYS
    )
    return (
        f'<div style="display:flex;height:28px;border:2px solid #201e1d">{seg}</div>'
        f'<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;padding:8px 0 4px;font-size:11.5px">{legend}</div>'
    )


def _v_heat_table(rows: list[dict], name_key: str, name_label: str, *, name_col="minmax(0,2fr)",
                  keys=("critical", "high", "medium", "low"), show_total=True, name_short=False,
                  height="30px", cap=None) -> str:
    """Tabela-heatmap família/host × severidade (rampa log)."""
    rows = rows[:cap] if cap else rows
    maxw = _v_max_weighted(rows, keys)
    ncols = len(keys)
    tot_col = " 56px" if show_total else ""
    gt = f"{name_col} repeat({ncols},minmax(0,1fr)){tot_col}"
    heads = "".join(f"<span>{_SEV_PT[k]}</span>" for k in keys)
    thead = (f'<div class="th" style="grid-template-columns:{gt};gap:3px">'
             f'<span>{_html.escape(name_label)}</span>{heads}'
             f'{"<span class=num>Total</span>" if show_total else ""}</div>')
    body = ""
    for r in rows:
        nm = _host_short(r[name_key]) if name_short else r[name_key]
        cells = "".join(_v_heat(r.get(k, 0), _SEV_W[k], maxw, height) for k in keys)
        tot = (f'<span class="num b" style="align-self:center">{_num(r["total"])}</span>'
               if show_total else "")
        fw = "600" if (r.get("critical") or r.get("high")) else "400"
        body += (f'<div class="tr" style="grid-template-columns:{gt};gap:3px;padding-bottom:3px;border-bottom:none">'
                 f'<span class="wrap" style="align-self:center;font-size:12.5px;font-weight:{fw}">{_html.escape(str(nm))}</span>'
                 f'{cells}{tot}</div>')
    return f'<div class="r2 r2b">{thead}{body}</div>'


# ──────────────────────────────────────────────────────────────────────────────
# RELATÓRIO EXECUTIVO VALID (v2)
# ──────────────────────────────────────────────────────────────────────────────
def generate_valid_executive_report(
    db: "Session",
    scan_id: int,
    company_name: str | None = None,
    previous_scan_id: int | None = None,
) -> str:
    from app.services.framework_mapping import attack_for_family, csf_for_family
    from app.services.vuln_family import family_label

    ctx = _v_common(db, scan_id, company_name)
    if not ctx:
        return "<html><body><h1>Scan não encontrado</h1></body></html>"
    e = _html.escape
    company, sev, grade, score = ctx["company"], ctx["sev"], ctx["grade"], ctx["score"]
    n_targets, frameworks, surface = ctx["n_targets"], ctx["frameworks"], ctx["surface"]
    vuln_class, paths, jewels = ctx["vuln_class"], ctx["paths"], ctx["jewels"]
    findings, fam_of, total = ctx["findings"], ctx["fam_of"], ctx["total"]
    gcolor = _v_grade_color(grade)
    ref = _v_ref(scan_id)
    crit_high = sev["critical"] + sev["high"]
    escopo = str(ctx["job"].target_query or "")
    escopo_c = ", ".join([t.strip() for t in re.split(r"[;,\n]+", escopo) if t.strip()][:2]) or f"scan #{scan_id}"
    if len(escopo_c) > 46:
        escopo_c = escopo_c[:45] + "…"

    pages: list[tuple[str, str]] = []

    # ── P2 · Metodologia & rating ────────────────────────────────────────────
    grade_scale = "".join(
        f'<div style="padding:8px 10px;background:{"#ec3013" if g==grade else "#eae7e7"};'
        f'color:{"#fff" if g==grade else "#201e1d"};font-size:22px;font-weight:800;display:flex;'
        f'justify-content:space-between;align-items:baseline">{g}'
        f'{"<span style=\'font-size:11px;font-weight:600;text-transform:uppercase\'>atual</span>" if g==grade else ""}</div>'
        for g in ("A", "B", "C", "D", "F")
    )
    calc_rows = [
        ("Rating consolidado", f"Nota do alvo a partir do volume e severidade dos achados, exposição dos ativos e joias da coroa, normalizada por <b>densidade por alvo</b> (não pelo somatório bruto) e convertida na grade A–F. Valor atual: <b>{score:.0f} · {grade}</b>.", "Plataforma"),
        ("Nota por framework", "Maturidade estimada para cada framework a partir das evidências reais do scan (penalidade log-amortecida por severidade/configuração/exposição, crédito por WAF e remediação).", "Plataforma"),
        ("Severidade", "Classificação de cada achado em Crítico/Alto/Médio/Baixo/Info por impacto e explorabilidade (CVSS v3).", "Plataforma"),
        ("Prioridade P0·P1·P2", "Ordenação por severidade, depois valor do alvo (joia), CVSS e verificação — nunca por critério isolado.", "Plataforma"),
        ("Risco ponderado (heatmap)", "Quantidade × peso da severidade (<b>C 10 · A 5 · M 2 · B 1</b>) em escala logarítmica, para que poucos críticos não sumam diante de muitos médios.", "Este relatório"),
        ("Status NIST · ISO", "Cada classe de achado é associada a uma categoria/controle; o status é a maior severidade entre os achados associados.", "Este relatório"),
        ("Mapeamento MITRE", "Cada classe de vulnerabilidade é associada à técnica ATT&CK que ela habilita; soma de achados e de críticos/altos por técnica.", "Este relatório"),
    ]
    calc_html = "".join(
        f'<div class="tr" style="grid-template-columns:170px minmax(0,1fr) 96px;gap:14px;padding:9px 0">'
        f'<span class="b">{k}</span><span class="wrap">{v}</span><span class="small">{src}</span></div>'
        for k, v, src in calc_rows
    )
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">01 · Metodologia &amp; rating</div>'
        f'<div class="h2">Como cada número deste relatório é obtido</div></div>'
        f'<div class="up" style="padding-bottom:6px">Escala de grade</div>'
        f'<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:3px">{grade_scale}</div>'
        f'<div style="display:flex;justify-content:space-between;padding:4px 0 16px;font-size:11px" class="muted">'
        f'<span>Melhor postura</span><span>Pior postura</span></div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:170px minmax(0,1fr) 96px;gap:14px">'
        f'<span>Indicador</span><span>Como é calculado</span><span>Origem</span></div>{calc_html}</div>'
        f'<div class="lead" style="padding-top:8px">Fonte: findings reais do scan #{scan_id} '
        f'({total} achados, {n_targets} alvo(s)). Os pesos internos do rating e das notas por framework são '
        f'definidos pela plataforma de origem.</div>'
    )
    pages.append(("Metodologia", body))

    # ── P3 · Sumário executivo ───────────────────────────────────────────────
    # leitura executiva (derivada de dado real)
    reads: list[tuple[str, str]] = []
    if sev["critical"] and surface:
        top_crit = max(surface, key=lambda r: r["critical"])
        if top_crit["critical"]:
            reads.append(("Risco crítico concentrado",
                          f'{e(_host_short(top_crit["host"]))} detém {top_crit["critical"]} de {sev["critical"]} '
                          f'crítico(s) do ciclo — priorize a contenção deste ativo.'))
    plist = paths.get("paths") or []
    rce_paths = sum(1 for p in plist if any(str(s.get("family")) == "rce" for s in (p.get("steps") or [])))
    reach = paths.get("objectives_reachable", 0)
    if plist:
        reads.append(("Caminhos de ataque mapeados",
                      f'{len(plist)} caminho(s) correlacionado(s); {rce_paths} termina(m) em execução remota '
                      f'e {reach} objetivo(s) marcado(s) como alcançável(is).'))
    if not jewels:
        reads.append(("Governança bloqueia priorização",
                      "Nenhuma joia da coroa (ativo crítico de negócio) definida — o risco ainda não é "
                      "ponderado por valor de negócio."))
    else:
        reads.append(("Joias da coroa", f"{len(jewels)} ativo(s) crítico(s) de negócio definido(s) para ponderar prioridade."))
    worst = None
    if frameworks:
        worst = min(frameworks.values(), key=lambda fw: float(fw.get("score") or 0))
        reads.append(("Maturidade de frameworks",
                      f'Pior nota: {e(str(worst.get("label") or ""))} em {e(str(worst.get("grade") or "—"))} '
                      f'({float(worst.get("score") or 0):.0f}/100). Detalhe na conformidade.'))
    reads_html = "".join(
        f'<div class="tr" style="grid-template-columns:36px minmax(0,1fr);gap:0 12px;padding:7px 0">'
        f'<span class="b" style="font-size:19px;color:#1767E5">{i + 1:02d}</span>'
        f'<div><b>{e(t)}.</b> {e(d)}</div></div>'
        for i, (t, d) in enumerate(reads[:4])
    )
    body = (
        f'<div style="padding:18px 0 12px"><div class="eyebrow">02 · Sumário executivo · {e(escopo_c)}</div>'
        f'<div class="h1" style="margin-top:4px">Exposição a vulnerabilidades — visão executiva</div>'
        f'<div class="muted" style="font-size:13px;margin-top:5px">{ref} · {n_targets} ativo(s) analisado(s) · '
        f'{total} achados · fonte: plataforma de análise de exposição</div></div>'
        f'<div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,2fr);border-top:2px solid #201e1d;border-bottom:2px solid #201e1d">'
        f'<div style="background:{gcolor};color:#fff;padding:14px;display:flex;flex-direction:column;justify-content:space-between;gap:10px">'
        f'<div class="up">Rating consolidado</div>'
        f'<div style="display:flex;align-items:baseline;gap:12px"><span style="font-size:62px;line-height:.85;font-weight:800">{grade}</span>'
        f'<span style="font-size:20px;font-weight:600">{score:.0f}</span></div>'
        f'<div style="font-size:11.5px;line-height:1.35">Densidade de risco por alvo, escala A–F.</div></div>'
        f'<div style="display:grid;grid-template-columns:repeat(2,1fr)">'
        f'<div style="padding:11px 16px;border-left:2px solid #201e1d;border-bottom:2px solid #201e1d"><div class="stat-l">Críticos + altos</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.05;color:#ae1800">{crit_high}</div>'
        f'<div class="stat-l" style="text-transform:none">{sev["critical"]} críticos · {sev["high"]} altos</div></div>'
        f'<div style="padding:11px 16px;border-left:2px solid #201e1d;border-bottom:2px solid #201e1d"><div class="stat-l">Achados abertos</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.05">{_num(total)}</div>'
        f'<div class="stat-l" style="text-transform:none">{crit_high} priorizados no plano</div></div>'
        f'<div style="padding:11px 16px;border-left:2px solid #201e1d"><div class="stat-l">Ativos analisados</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.05">{n_targets}</div>'
        f'<div class="stat-l" style="text-transform:none">{len([r for r in surface if r["critical"]])} com críticos</div></div>'
        f'<div style="padding:11px 16px;border-left:2px solid #201e1d"><div class="stat-l">Joias da coroa</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.05">{len(jewels)}</div>'
        f'<div class="stat-l" style="text-transform:none">{"definidas" if jewels else "nenhuma definida"}</div></div>'
        f'</div></div>'
        f'<div style="padding-top:12px"><div class="up" style="padding-bottom:5px">Leitura executiva</div>'
        f'<div class="r2">{reads_html}</div></div>'
        f'<div style="margin-top:auto;border:2px solid #201e1d;padding:11px 14px;display:grid;grid-template-columns:120px minmax(0,1fr);gap:14px;align-items:start">'
        f'<div class="up" style="color:#ae1800">Decisão requerida</div>'
        f'<div>Aprovar janela emergencial para os <b>{sev["critical"]} item(ns) P0</b> (crítico), '
        f'designar donos por ativo{"" if jewels else " e definir as joias da coroa"} antes do próximo ciclo.</div></div>'
    )
    pages.append(("Sumário executivo", body))

    # ── P4 · Risco por superfície ────────────────────────────────────────────
    top_assets = surface[:10]
    maxtot = max([r["total"] for r in top_assets], default=1)
    asset_rows = "".join(
        f'<div class="tr" style="grid-template-columns:minmax(0,1.5fr) minmax(0,2fr) 56px 64px;gap:12px;align-items:center">'
        f'<span class="wrap b6">{e(_host_short(r["host"]))}</span>'
        f'<div style="height:10px;background:#eae7e7"><div style="height:10px;width:{100 * r["total"] / maxtot:.1f}%;'
        f'background:{"#201e1d" if r["critical"] else "#7d7979"}"></div></div>'
        f'<span class="num">{r["total"]}</span>'
        f'<span class="num b" style="color:{"#ae1800" if r["critical"] else "#7d7979"}">{r["critical"] or "—"}</span></div>'
        for r in top_assets
    ) or '<div class="tr">Sem superfície classificável.</div>'
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">03 · Risco associado</div>'
        f'<div class="h2">Onde a exposição se concentra por superfície</div></div>'
        f'<div class="up" style="padding-bottom:6px">Distribuição por severidade · {total} achados</div>'
        f'{_v_distribution_bar(sev)}'
        f'<div class="up" style="padding:14px 0 6px">Heatmap · superfície × severidade '
        f'<span class="muted" style="text-transform:none;font-weight:400">(cor = risco ponderado, escala log)</span></div>'
        f'{_v_heat_table(surface, "host", "Superfície", name_short=True, cap=6, height="40px")}'
        f'<div class="up" style="padding:16px 0 6px">Top 10 ativos por volume '
        f'<span class="muted" style="text-transform:none;font-weight:400">— críticos em destaque</span></div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:minmax(0,1.5fr) minmax(0,2fr) 56px 64px;gap:12px">'
        f'<span>Ativo</span><span>Volume</span><span class="num">Vulns</span><span class="num">Críticas</span></div>{asset_rows}</div>'
    )
    pages.append(("Risco por superfície", body))

    # ── P5 · Heatmap por classe ──────────────────────────────────────────────
    crit_fams = [c for c in vuln_class if c["critical"]]
    lead = (f'{len(crit_fams)} classe(s) concentram os {sev["critical"]} crítico(s); '
            f'{e(vuln_class[0]["label"]) if vuln_class else "—"} lidera em volume.') if vuln_class else "Sem achados classificados."
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">04 · Onde está o risco</div>'
        f'<div class="h2">Risco por classe de vulnerabilidade</div>'
        f'<div class="lead" style="padding-top:8px">{lead}</div></div>'
        f'{_v_heat_table(vuln_class, "label", "Classe de vulnerabilidade", cap=18)}'
        f'<div class="lead" style="padding-top:8px">Cor = risco ponderado (C 10 · A 5 · M 2 · B 1), escala logarítmica. '
        f'Total inclui achados informativos não exibidos nas colunas de severidade.</div>'
    )
    pages.append(("Heatmap por classe", body))

    # ── P6 · Visão de operação (P0/P1) ───────────────────────────────────────
    p2 = sev["medium"]
    backlog = sev["low"] + sev["info"]
    plan_group: dict[str, dict] = {}
    for f in findings:
        s = str(f.severity or "info").lower()
        if s not in ("critical", "high"):
            continue
        fam = fam_of[f.id]
        g = plan_group.setdefault((s, fam), {"sev": s, "fam": fam, "label": family_label(fam),
                                             "qtd": 0, "hosts": {}, "rec": ""})
        g["qtd"] += 1
        h = _host_short(str(f.domain or "—"))
        g["hosts"][h] = g["hosts"].get(h, 0) + 1
        if not g["rec"] and f.recommendation:
            g["rec"] = str(f.recommendation)
    plan = sorted(plan_group.values(), key=lambda x: (0 if x["sev"] == "critical" else 1, -x["qtd"]))[:8]
    plan_rows = "".join(
        f'<div class="tr" style="grid-template-columns:40px minmax(0,1.6fr) minmax(0,1fr) 34px minmax(0,1.7fr);gap:10px;padding:5px 0">'
        f'<span class="b" style="color:{_PRIO[g["sev"]][1] if _PRIO[g["sev"]][1]!="transparent" else "#201e1d"}">{_PRIO[g["sev"]][0]}</span>'
        f'<span class="b6 wrap">{e(g["label"])}</span>'
        f'<span class="wrap muted">{e(", ".join(f"{h} ({n})" for h, n in sorted(g["hosts"].items(), key=lambda kv:-kv[1])[:2]))}</span>'
        f'<span class="num b">{g["qtd"]}</span>'
        f'<span class="wrap">{e(_clip(g["rec"] or "Validar e corrigir conforme boas práticas.", 96))}</span></div>'
        for g in plan
    ) or '<div class="tr">Não há itens P0/P1 neste ciclo.</div>'
    body = (
        f'<div style="padding:14px 0 10px"><div class="eyebrow">05 · Visão de operação</div>'
        f'<div class="h2">{crit_high} itens P0/P1 resolvem 100% do risco crítico e alto</div></div>'
        f'<div class="kpis" style="grid-template-columns:repeat(4,1fr)">'
        f'<div style="padding:10px 14px;background:#7c1405;color:#fff"><div class="up">P0 · emergencial</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.1">{sev["critical"]}</div><div style="font-size:11.5px">SLA proposto ≤ 7 dias</div></div>'
        f'<div style="padding:10px 14px;background:#dd2b0f;color:#fff"><div class="up">P1 · alta</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.1">{sev["high"]}</div><div style="font-size:11.5px">SLA proposto ≤ 30 dias</div></div>'
        f'<div style="padding:10px 14px;border-left:2px solid #201e1d"><div class="up muted">P2 · planejada</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.1">{p2}</div><div class="stat-l" style="text-transform:none">SLA proposto ≤ 90 dias</div></div>'
        f'<div style="padding:10px 14px;border-left:2px solid #201e1d"><div class="up muted">Backlog restante</div>'
        f'<div style="font-size:34px;font-weight:800;line-height:1.1">{_num(backlog)}</div>'
        f'<div class="stat-l" style="text-transform:none">baixo + informativo</div></div></div>'
        f'<div class="up" style="padding:12px 0 5px">Frentes de correção · P0 e P1 agrupados por causa</div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:40px minmax(0,1.6fr) minmax(0,1fr) 34px minmax(0,1.7fr);gap:10px">'
        f'<span>Prio</span><span>Frente</span><span>Ativos</span><span class="num">Qtd</span><span>Ação</span></div>{plan_rows}</div>'
        f'<div class="lead" style="padding-top:8px">SLAs são proposta de referência, ordenados por severidade e volume real de achados.</div>'
    )
    pages.append(("Operação", body))

    # ── P7 · MITRE ATT&CK ────────────────────────────────────────────────────
    tech: dict[str, dict] = {}
    for f in findings:
        m = attack_for_family(fam_of[f.id])
        if not m:
            continue
        s = str(f.severity or "info").lower()
        slot = tech.setdefault(m["technique"], {"name": m["technique_name"], "tactic": m["tactic_name"],
                                                "f": 0, "c": 0, "h": 0, "fams": {}})
        slot["f"] += 1
        if s == "critical":
            slot["c"] += 1
        elif s == "high":
            slot["h"] += 1
        slot["fams"][family_label(fam_of[f.id])] = True
    tech_sorted = sorted(tech.items(), key=lambda kv: (-kv[1]["c"], -kv[1]["f"]))[:8]
    tech_rows = "".join(
        f'<div class="tr" style="grid-template-columns:minmax(0,1.2fr) minmax(0,1.5fr) minmax(0,1.6fr) 48px 66px;gap:10px;padding:7px 0'
        f'{";background:#ffe0d9" if d["c"] else ""}">'
        f'<span class="b6 wrap">{e(d["tactic"])}</span>'
        f'<span class="wrap"><b>{e(tid)}</b> {e(d["name"])}</span>'
        f'<span class="wrap muted">{e(", ".join(list(d["fams"])[:3]))}</span>'
        f'<span class="num">{d["f"]}</span>'
        f'<span class="num b" style="color:{"#7c1405" if d["c"] else "#201e1d"}">{d["c"]} · {d["h"]}</span></div>'
        for tid, d in tech_sorted
    ) or '<div class="tr">Sem técnicas mapeáveis.</div>'
    # caminhos alcançáveis (chips)
    path_rows = ""
    for p in plist[:6]:
        steps = p.get("steps") or []
        chips = ""
        for i, st in enumerate(steps[:5]):
            fam = str(st.get("family") or "")
            lbl = st.get("family_label") or family_label(fam)
            hot = fam in ("rce", "sqli", "nosql_injection")
            chips += (f'{"<span>→</span>" if i else ""}<span style="padding:1px 6px;'
                      f'background:{"#7c1405" if hot else "#eae7e7"};color:{"#fff" if hot else "#201e1d"};'
                      f'{"font-weight:600" if hot else ""}">{e(str(lbl)[:22])}</span>')
        extra = f'<span class="muted">+{len(steps) - 5}</span>' if len(steps) > 5 else ""
        reachable = p.get("objective_reachable")
        path_rows += (
            f'<div class="tr" style="grid-template-columns:minmax(0,1.3fr) 84px minmax(0,2.6fr);gap:10px;align-items:center">'
            f'<span class="b6 wrap">{e(_host_short(str(p.get("target") or "—")))}</span>'
            f'<span class="up" style="font-size:10px;color:{"#ae1800" if reachable else "#605d5d"}">{"alcançável" if reachable else "mapeado"}</span>'
            f'<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;font-size:11px">{chips}{extra}</div></div>')
    paths_block = (
        f'<div class="up" style="padding:16px 0 6px">Caminhos de ataque mapeados '
        f'<span class="muted" style="text-transform:none;font-weight:400">— {reach} de {len(plist)} alcançável(is)</span></div>'
        f'<div class="r2 r2b">{path_rows}</div>') if plist else ""
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">06 · Ameaça · MITRE ATT&amp;CK</div>'
        f'<div class="h2">Técnicas habilitadas pela superfície exposta</div></div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:minmax(0,1.2fr) minmax(0,1.5fr) minmax(0,1.6fr) 48px 66px;gap:10px">'
        f'<span>Tática</span><span>Técnica</span><span>Classes de origem</span><span class="num">Achados</span><span class="num">Crít·Alto</span></div>{tech_rows}</div>'
        f'<div class="lead" style="padding-top:6px">Mapeamento derivado das classes de vulnerabilidade — indica técnicas '
        f'habilitadas, não telemetria de ataque.</div>{paths_block}'
    )
    pages.append(("MITRE ATT&CK", body))

    # ── P8 · Conformidade NIST/ISO/CIS/PCI ───────────────────────────────────
    fw_cards = "".join(
        f'<div style="padding:10px 12px{";border-left:2px solid #201e1d" if i else ""}">'
        f'<div class="up">{_FW_LABEL.get(k, k)}</div>'
        f'<div style="display:flex;align-items:baseline;gap:8px">'
        f'<span style="font-size:30px;font-weight:800;color:{_v_grade_color(str(fw.get("grade")))}">{e(str(fw.get("grade") or "—"))}</span>'
        f'<span style="font-size:15px;font-weight:600">{float(fw.get("score") or 0):.0f}</span></div></div>'
        for i, (k, fw) in enumerate((frameworks or {}).items())
    ) or '<div class="muted" style="padding:10px 0">Notas por framework indisponíveis.</div>'
    # por família → CSF + regs + crit/high
    fam_csf: dict[str, dict] = {}
    for f in findings:
        fam = fam_of[f.id]
        c = csf_for_family(fam)
        key = (c["subcategory"], c["name"]) if c else ("—", family_label(fam))
        slot = fam_csf.setdefault(key, {"sub": key[0], "name": key[1], "fams": {}, "regs": 0, "c": 0, "h": 0})
        slot["regs"] += 1
        slot["fams"][family_label(fam)] = True
        s = str(f.severity or "info").lower()
        if s == "critical":
            slot["c"] += 1
        elif s == "high":
            slot["h"] += 1
    csf_sorted = sorted(fam_csf.values(), key=lambda x: (-x["c"], -x["h"], -x["regs"]))[:9]
    csf_rows = "".join(
        f'<div class="tr" style="grid-template-columns:96px minmax(0,2fr) 44px 56px;gap:10px;padding:6px 0'
        f'{";background:#ffe0d9" if d["c"] else ""}">'
        f'<span class="b">{e(d["sub"])}</span>'
        f'<span class="wrap">{e(d["name"])} <span class="muted">· {e(", ".join(list(d["fams"])[:2]))}</span></span>'
        f'<span class="num">{d["regs"]}</span>'
        f'<span class="num b" style="color:{"#7c1405" if d["c"] else "#201e1d"}">{d["c"]} · {d["h"]}</span></div>'
        for d in csf_sorted
    ) or '<div class="tr">Sem mapeamento de controles.</div>'
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">07 · Conformidade · NIST · ISO · CIS · PCI</div>'
        f'<div class="h2">Cada classe de achado mapeada ao controle a corrigir</div></div>'
        f'<div class="kpis" style="grid-template-columns:repeat({max(1,len(frameworks or {}))},1fr)">{fw_cards}</div>'
        f'<div class="up" style="padding:16px 0 6px">NIST CSF 2.0 · categorias impactadas '
        f'<span class="muted" style="text-transform:none;font-weight:400">(status = maior severidade associada)</span></div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:96px minmax(0,2fr) 44px 56px;gap:10px">'
        f'<span>Categoria</span><span>Descrição · classes</span><span class="num">Regs</span><span class="num">Crít·Alto</span></div>{csf_rows}</div>'
        f'<div class="lead" style="padding-top:8px">Notas por framework conforme a plataforma. Mapeamento de categorias '
        f'derivado das classes de achado; mapa completo ISO/CIS no relatório técnico.</div>'
    )
    pages.append(("Conformidade", body))

    # ── P9 · Roadmap + decisões ──────────────────────────────────────────────
    sys_fams = [c for c in vuln_class if c["family"] in ("misconfiguration", "security_headers", "tls_ssl", "cors") and c["total"]]
    sys_txt = ", ".join(f'{e(c["label"])} ({c["total"]})' for c in sys_fams[:3]) or "cabeçalhos, TLS e configuração"
    body = (
        f'<div style="padding:20px 0 16px"><div class="eyebrow">08 · Plano 90 dias</div>'
        f'<div class="h2">Conter, corrigir, sustentar</div></div>'
        f'<div style="display:grid;grid-template-columns:repeat(3,1fr);border-top:2px solid #201e1d;border-bottom:2px solid #201e1d;font-size:13px;line-height:1.45">'
        f'<div style="padding:14px 14px 16px 0;display:flex;flex-direction:column;gap:8px">'
        f'<div class="up" style="color:#7c1405">0–7 dias · Conter</div>'
        f'<div style="font-size:18px;font-weight:800">Eliminar os {sev["critical"]} P0</div>'
        f'<div style="border-top:1px solid #bab6b6;padding-top:6px">Mitigar/corrigir os achados críticos nos ativos de maior exposição.</div>'
        f'<div style="border-top:1px solid #bab6b6;padding-top:6px">Revogar segredos expostos e fechar serviços indevidos.</div></div>'
        f'<div style="padding:14px 14px 16px;border-left:2px solid #201e1d;display:flex;flex-direction:column;gap:8px">'
        f'<div class="up" style="color:#dd2b0f">8–30 dias · Corrigir</div>'
        f'<div style="font-size:18px;font-weight:800">Zerar os {sev["high"]} P1</div>'
        f'<div style="border-top:1px solid #bab6b6;padding-top:6px">Aplicar patches de dependências e hardening de servidores.</div>'
        f'<div style="border-top:1px solid #bab6b6;padding-top:6px">Reteste de controle de acesso, upload e autenticação.</div></div>'
        f'<div style="padding:14px 0 16px 14px;border-left:2px solid #201e1d;display:flex;flex-direction:column;gap:8px">'
        f'<div class="up">31–90 dias · Sustentar</div>'
        f'<div style="font-size:18px;font-weight:800">Reduzir volume sistêmico</div>'
        f'<div style="border-top:1px solid #bab6b6;padding-top:6px">Baseline central de configuração e cabeçalhos ({sys_txt}).</div>'
        f'<div style="border-top:1px solid #bab6b6;padding-top:6px">Hardening de TLS e política de cookies em todas as propriedades.</div></div></div>'
        f'<div class="up" style="padding:22px 0 8px">Decisões requeridas da liderança</div>'
        f'<div class="r2">'
        f'<div class="tr" style="grid-template-columns:36px minmax(0,1fr);gap:12px;align-items:baseline;padding:10px 0">'
        f'<span class="b" style="font-size:18px;color:#1767E5">A</span><span>Aprovar janela emergencial de mudança para os {sev["critical"]} itens P0.</span></div>'
        f'<div class="tr" style="grid-template-columns:36px minmax(0,1fr);gap:12px;align-items:baseline;padding:10px 0">'
        f'<span class="b" style="font-size:18px;color:#1767E5">B</span><span>Definir joias da coroa para ponderar o risco por valor de negócio.</span></div>'
        f'<div class="tr" style="grid-template-columns:36px minmax(0,1fr);gap:12px;align-items:baseline;padding:10px 0;border-bottom:none">'
        f'<span class="b" style="font-size:18px;color:#1767E5">C</span><span>Formalizar SLAs por prioridade e dono por ativo.</span></div></div>'
        f'<div class="kpis" style="grid-template-columns:repeat(3,1fr);margin-top:18px">'
        f'<div style="padding:10px 12px 10px 0"><div class="stat-l">Críticos → meta</div><div style="font-size:22px;font-weight:800">{sev["critical"]} → 0</div></div>'
        f'<div style="padding:10px 12px;border-left:2px solid #201e1d"><div class="stat-l">Altos → meta</div><div style="font-size:22px;font-weight:800">{sev["high"]} → 0</div></div>'
        f'<div style="padding:10px 12px;border-left:2px solid #201e1d"><div class="stat-l">Joias definidas</div><div style="font-size:22px;font-weight:800">{len(jewels)} → ≥ 3</div></div></div>'
    )
    pages.append(("Roadmap", body))

    total_pages = 1 + len(pages)
    cover = _v_cover(company, "Relatório executivo", "Relatório Executivo de Gestão de Vulnerabilidades",
                     "Caminhos de ataque, priorização e conformidade — visão de decisão",
                     escopo_c, _v_ref(scan_id).split(" · ")[0], f"Ciclo #{scan_id} · {n_targets} ativos analisados", total_pages)
    sheets = cover + "".join(_v_sheet(company, sec, body, ref, i + 2, total_pages) for i, (sec, body) in enumerate(pages))
    return _v_shell(f"Relatório Executivo — {company}", sheets)


# ──────────────────────────────────────────────────────────────────────────────
# RELATÓRIO TÉCNICO VALID (v2)
# ──────────────────────────────────────────────────────────────────────────────
def generate_valid_technical_report(
    db: "Session",
    scan_id: int,
    company_name: str | None = None,
    previous_scan_id: int | None = None,
) -> str:
    from app.services.framework_mapping import attack_for_family, csf_for_family
    from app.services.vuln_family import clean_finding_title, family_label

    ctx = _v_common(db, scan_id, company_name)
    if not ctx:
        return "<html><body><h1>Scan não encontrado</h1></body></html>"
    e = _html.escape
    company, sev, grade, score = ctx["company"], ctx["sev"], ctx["grade"], ctx["score"]
    n_targets, frameworks, surface = ctx["n_targets"], ctx["frameworks"], ctx["surface"]
    vuln_class, paths = ctx["vuln_class"], ctx["paths"]
    findings, fam_of, total = ctx["findings"], ctx["fam_of"], ctx["total"]
    verif, rec_catalog, rec_code = ctx["verif"], ctx["rec_catalog"], ctx["rec_code"]
    cve_list, classified = ctx["cve_list"], ctx["classified"]
    ref = _v_ref(scan_id)
    hosts_n = ctx["hosts_n"] or len({str(f.domain or "").strip().lower() for f in findings if f.domain})
    crit_high = sev["critical"] + sev["high"]
    escopo = str(ctx["job"].target_query or "")
    escopo_c = ", ".join([t.strip() for t in re.split(r"[;,\n]+", escopo) if t.strip()][:2]) or f"scan #{scan_id}"
    if len(escopo_c) > 46:
        escopo_c = escopo_c[:45] + "…"
    ids = [f.id for f in findings]
    id_lo, id_hi = (min(ids), max(ids)) if ids else (0, 0)

    pages: list[tuple[str, str]] = []

    # ── P2 · Sumário & base ──────────────────────────────────────────────────
    toc = [
        ("01", "Risco técnico · severidade × classe"), ("02", "Definição de prioridade"),
        ("03", "Caminhos de ataque (attack path)"), ("04", "Vulnerabilidades por ativo"),
        ("05", "Tabela de recomendações"), ("06", "NIST CSF · CIS v8 · ISO 27001"),
        ("07", "CVEs identificados e dicionário"), ("A", "Anexo · críticos e altos"),
        ("B", "Anexo · inventário completo"), ("C", "Anexo · catálogo de recomendações"),
    ]
    toc_html = "".join(
        f'<div style="display:flex;gap:12px;align-items:baseline;padding:5px 0;border-bottom:1px solid #d7d3d3">'
        f'<span class="b" style="font-size:15px;color:#1767E5;min-width:26px">{n}</span>'
        f'<span class="b6" style="font-size:12.5px;line-height:1.25">{e(t)}</span></div>'
        for n, t in toc
    )
    confirmed = sum(1 for f in findings if str(f.verification_status or "").lower() == "confirmed")
    hyp = sum(1 for f in findings if str(f.verification_status or "").lower() == "hypothesis")
    body = (
        f'<div style="padding:16px 0 12px"><div class="eyebrow">Sumário</div>'
        f'<div class="h1" style="font-size:28px;margin-top:4px">Conteúdo técnico</div></div>'
        f'<div class="r2 r2b" style="display:grid;grid-template-columns:1fr 1fr;gap:0 28px">{toc_html}</div>'
        f'<div class="up" style="padding:14px 0 6px">Base de dados desta análise</div>'
        f'<div class="kpis" style="grid-template-columns:repeat(4,1fr)">'
        f'<div style="padding:10px 12px 10px 0"><div class="stat-l">Registros</div>'
        f'<div style="font-size:28px;font-weight:800;line-height:1.1">{_num(total)}</div>'
        f'<div class="stat-l" style="text-transform:none">IDs {id_lo}–{id_hi}</div></div>'
        f'<div style="padding:10px 12px;border-left:2px solid #201e1d"><div class="stat-l">Hosts</div>'
        f'<div style="font-size:28px;font-weight:800;line-height:1.1">{hosts_n}</div>'
        f'<div class="stat-l" style="text-transform:none">de {ctx["scope_n"] or n_targets} no escopo</div></div>'
        f'<div style="padding:10px 12px;border-left:2px solid #201e1d"><div class="stat-l">Críticos + altos</div>'
        f'<div style="font-size:28px;font-weight:800;line-height:1.1;color:#ae1800">{crit_high}</div>'
        f'<div class="stat-l" style="text-transform:none">{sev["critical"]} críticos · {sev["high"]} altos</div></div>'
        f'<div style="padding:10px 12px;border-left:2px solid #201e1d"><div class="stat-l">Confirmados</div>'
        f'<div style="font-size:28px;font-weight:800;line-height:1.1">{confirmed}</div>'
        f'<div class="stat-l" style="text-transform:none">{hyp} hipóteses</div></div></div>'
        f'<div class="lead" style="padding-top:8px">Fonte: findings reais do scan #{scan_id}. Rating consolidado '
        f'<b>{score:.0f} · {grade}</b> (densidade por alvo). Excluídos falsos-positivos e execuções simuladas (BAS).</div>'
    )
    pages.append(("Sumário e base", body))

    # ── P3 · Risco técnico (heatmap família × severidade, com Info) ──────────
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">01 · Risco técnico</div>'
        f'<div class="h2">Distribuição de severidade e classes de maior risco</div></div>'
        f'{_v_distribution_bar(sev)}'
        f'<div class="up" style="padding:12px 0 6px">Heatmap · família × severidade '
        f'<span class="muted" style="text-transform:none;font-weight:400">(cor = risco ponderado, escala log)</span></div>'
        f'{_v_heat_table(vuln_class, "label", "Família", keys=("critical","high","medium","low","info"), cap=19, height="26px")}'
    )
    pages.append(("Risco técnico", body))

    # ── P4 · Definição de prioridade ─────────────────────────────────────────
    prio_rows = "".join(
        f'<div class="tr" style="grid-template-columns:52px 104px minmax(0,1.8fr) 84px 52px;gap:10px;padding:7px 0">'
        f'<span class="sev" style="background:{_PRIO[s][1] if _PRIO[s][1]!="transparent" else "#eae7e7"};color:{_PRIO[s][2]};'
        f'{"box-shadow:inset 0 0 0 1px #201e1d" if _PRIO[s][1]=="transparent" else ""}">{_PRIO[s][0]}</span>'
        f'<span>{_SEV_PT[s]}</span><span class="wrap">{crit}</span>'
        f'<span class="b6">{_PRIO[s][3]}</span><span class="num b">{sev[s]}</span></div>'
        for s, crit in (("critical", "CVSS ≥ 9.0, exploração remota sem autenticação"),
                        ("high", "CVSS 7.0–8.9, ou alto com evidência em ativo de negócio"),
                        ("medium", "CVSS 4.0–6.9; correções sistêmicas de configuração"),
                        ("low", "CVSS &lt; 4.0; tratar em janela de manutenção"),
                        ("info", "Observação de segurança; monitorar recorrência"))
    )
    vmax = 0
    for s in _SEV_KEYS:
        for v in ("confirmed", "hypothesis", "candidate"):
            vmax = max(vmax, verif[s][v])
    vrows = "".join(
        f'<div class="tr" style="grid-template-columns:minmax(0,1.2fr) repeat(3,minmax(0,1fr)) 56px;gap:3px;padding-bottom:3px;border-bottom:none">'
        f'<span class="b6" style="align-self:center;font-size:13px">{_SEV_PT[s]}</span>'
        + "".join(_v_heat(verif[s][v], 1.0, vmax, "34px") for v in ("confirmed", "hypothesis", "candidate"))
        + f'<span class="num b" style="align-self:center">{sum(verif[s].values())}</span></div>'
        for s in _SEV_KEYS
    )
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">02 · Definição de prioridade</div>'
        f'<div class="h2">Severidade define a fila; verificação define o 1º passo</div></div>'
        f'<div class="up" style="padding-bottom:5px">Regra de priorização (SLA de referência)</div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:52px 104px minmax(0,1.8fr) 84px 52px;gap:10px">'
        f'<span>Prio</span><span>Severidade</span><span>Critério</span><span>SLA</span><span class="num">Qtd</span></div>{prio_rows}</div>'
        f'<div class="up" style="padding:16px 0 5px">Matriz severidade × estado de verificação '
        f'<span class="muted" style="text-transform:none;font-weight:400">(cor = volume, log)</span></div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:minmax(0,1.2fr) repeat(3,minmax(0,1fr)) 56px;gap:3px">'
        f'<span>Severidade</span><span>Confirmado</span><span>Hipótese</span><span>Candidato</span><span class="num">Total</span></div>{vrows}</div>'
        f'<div class="lead" style="padding-top:8px"><b>Leitura:</b> {crit_high - confirmed} de {crit_high} críticos/altos ainda '
        f'não confirmados — o 1º passo técnico para P0/P1 é validar e, confirmado, corrigir no SLA.</div>'
    )
    pages.append(("Prioridade", body))

    # ── P5 · Attack path ─────────────────────────────────────────────────────
    plist = paths.get("paths") or []
    path_cards = ""
    for p in plist[:6]:
        steps = p.get("steps") or []
        crit_here = sum(1 for st in steps if str(st.get("severity")) == "critical")
        seq = ""
        for i, st in enumerate(steps[:4]):
            fam = str(st.get("family") or "")
            lbl = st.get("family_label") or family_label(fam)
            hot = fam in ("rce", "sqli", "nosql_injection")
            seq += (f'<div style="border:2px solid {"#7c1405" if hot else "#201e1d"};'
                    f'{"background:#7c1405;color:#fff;" if hot else ""}{"border-left:none;" if i else ""}padding:6px 8px;font-size:11px;line-height:1.3">'
                    f'<div class="b">{e(str(lbl)[:24])}</div><div style="{"color:#605d5d" if not hot else ""}">{e(str(st.get("technique") or ""))}</div></div>')
        reach = p.get("objective_reachable")
        path_cards += (
            f'<div class="r2" style="padding:10px 0 12px;display:flex;flex-direction:column;gap:8px">'
            f'<div style="display:flex;justify-content:space-between;align-items:baseline">'
            f'<span style="font-size:15px;font-weight:800">{e(str(p.get("target") or "—"))}</span>'
            f'<span class="up" style="font-size:10px;color:{"#ae1800" if reach else "#605d5d"}">'
            f'{"alcançável" if reach else "mapeado"}{f" · {crit_here} crítico(s)" if crit_here else ""}</span></div>'
            f'<div style="display:grid;grid-template-columns:repeat({max(1,min(4,len(steps)))},1fr)">{seq}</div></div>')
    if not plist:
        path_cards = '<div class="r2" style="padding:12px 0"><span class="muted">Nenhum caminho de ataque correlacionado neste ciclo.</span></div>'
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">03 · Caminhos de ataque</div>'
        f'<div class="h2">Cadeias correlacionadas por ativo</div>'
        f'<div class="lead" style="padding-top:8px">{paths.get("objectives_reachable", 0)} objetivo(s) alcançável(is) de '
        f'{len(plist)} caminho(s) mapeado(s). Técnicas MITRE derivadas da classe de cada etapa.</div></div>'
        f'{path_cards}'
    )
    pages.append(("Attack path", body))

    # ── P6 · Vulnerabilidades por ativo ──────────────────────────────────────
    perfil = ""
    for r in surface[:11]:
        fams_here: dict[str, int] = {}
        for f in findings:
            if str(f.domain or "").strip() == r["host"]:
                fams_here[family_label(fam_of[f.id])] = fams_here.get(family_label(fam_of[f.id]), 0) + 1
        top = sorted(fams_here.items(), key=lambda kv: -kv[1])[:4]
        perfil += (f'<div class="tr" style="grid-template-columns:120px minmax(0,1fr);gap:10px;padding:5px 0">'
                   f'<span class="b wrap">{e(_host_short(r["host"]))}</span>'
                   f'<span class="wrap">{e(" · ".join(f"{lbl} {n}" for lbl, n in top))}</span></div>')
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">04 · Vulnerabilidades por ativo</div>'
        f'<div class="h2">Concentração por host · severidade e perfil de classe</div></div>'
        f'{_v_heat_table(surface, "host", "Ativo", keys=("critical","high","medium","low","info"), cap=11, name_short=True, height="28px")}'
        f'<div class="up" style="padding:14px 0 5px">Perfil técnico por ativo</div>'
        f'<div class="r2 r2b">{perfil or "<div class=tr>Sem ativos.</div>"}</div>'
    )
    pages.append(("Por ativo", body))

    # ── P7 · Recomendações (top agrupadas) ───────────────────────────────────
    # cada recomendação: severidade máx entre os achados, famílias, hosts
    rec_meta: dict[str, dict] = {}
    for f in findings:
        rec = str(f.recommendation or "").strip()
        if not rec:
            continue
        m = rec_meta.setdefault(rec, {"code": rec_code[rec], "regs": 0, "sev": "info", "fams": {}, "hosts": set()})
        m["regs"] += 1
        s = str(f.severity or "info").lower()
        if _severity_order(s) < _severity_order(m["sev"]):
            m["sev"] = s
        m["fams"][family_label(fam_of[f.id])] = True
        if f.domain:
            m["hosts"].add(_host_short(str(f.domain)))
    rec_top = sorted(rec_meta.values(), key=lambda x: (-x["regs"], x["code"]))[:12]
    rec_rows = "".join(
        f'<div class="tr" style="grid-template-columns:40px minmax(0,2.2fr) minmax(0,1.3fr) 44px 44px;gap:10px;padding:7px 0">'
        f'<span class="sev" style="background:{_SEV_CELL[m["sev"]]};color:{_SEV_FG[m["sev"]]}">{_PRIO[m["sev"]][0]}</span>'
        f'<span class="wrap"><b>{e(m["code"])}</b> {e(_rec_title(_find_rec_text(rec_catalog, m["code"])))}</span>'
        f'<span class="wrap muted">{e(", ".join(list(m["fams"])[:2]))}</span>'
        f'<span class="num b">{m["regs"]}</span><span class="num">{len(m["hosts"])}</span></div>'
        for m in rec_top
    ) or '<div class="tr">Sem recomendações registradas.</div>'
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">05 · Tabela de recomendações</div>'
        f'<div class="h2">Ações que cobrem o maior volume de achados</div></div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:40px minmax(0,2.2fr) minmax(0,1.3fr) 44px 44px;gap:10px">'
        f'<span>Prio</span><span>Recomendação</span><span>Famílias</span><span class="num">Regs</span><span class="num">Hosts</span></div>{rec_rows}</div>'
        f'<div class="lead" style="padding-top:8px">Prio = maior severidade entre os achados da recomendação. '
        f'Catálogo completo ({len(rec_catalog)} recomendações) no Anexo C.</div>'
    )
    pages.append(("Recomendações", body))

    # ── P8 · NIST/CIS/ISO ────────────────────────────────────────────────────
    fw_cards = "".join(
        f'<div style="padding:8px 12px{";border-left:2px solid #201e1d" if i else ""};display:flex;justify-content:space-between;align-items:baseline">'
        f'<span class="up">{_FW_LABEL.get(k, k)}</span>'
        f'<span><span style="font-size:24px;font-weight:800;color:{_v_grade_color(str(fw.get("grade")))}">{e(str(fw.get("grade") or "—"))}</span> '
        f'<span class="b6">{float(fw.get("score") or 0):.0f}</span></span></div>'
        for i, (k, fw) in enumerate((frameworks or {}).items())
    ) or '<div class="muted" style="padding:8px 0">Indisponível.</div>'
    fam_map: dict[str, dict] = {}
    for f in findings:
        fam = fam_of[f.id]
        c = csf_for_family(fam)
        iso, cis = _FAMILY_ISO_CIS.get(fam, ("—", "—"))
        slot = fam_map.setdefault(fam, {"label": family_label(fam), "csf": (c["subcategory"] if c else "—"),
                                        "iso": iso, "cis": cis, "regs": 0, "c": 0, "h": 0})
        slot["regs"] += 1
        s = str(f.severity or "info").lower()
        if s == "critical":
            slot["c"] += 1
        elif s == "high":
            slot["h"] += 1
    fam_rows_l = sorted(fam_map.values(), key=lambda x: (-x["c"], -x["h"], -x["regs"]))[:12]
    fam_rows = "".join(
        f'<div class="tr" style="grid-template-columns:minmax(0,1.5fr) minmax(0,0.9fr) minmax(0,1fr) minmax(0,0.9fr) 40px 50px;gap:8px;padding:6px 0'
        f'{";background:#ffe0d9" if d["c"] else ""}">'
        f'<span class="b6 wrap">{e(d["label"])}</span><span class="wrap">{e(d["csf"])}</span>'
        f'<span class="wrap">{e(d["cis"])}</span><span class="wrap">{e(d["iso"])}</span>'
        f'<span class="num">{d["regs"]}</span>'
        f'<span class="num b" style="color:{"#7c1405" if d["c"] else "#201e1d"}">{d["c"]}·{d["h"]}</span></div>'
        for d in fam_rows_l
    ) or '<div class="tr">Sem mapeamento.</div>'
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">06 · NIST · CIS · ISO</div>'
        f'<div class="h2">Cada família mapeada ao controle a corrigir</div></div>'
        f'<div class="kpis" style="grid-template-columns:repeat({max(1,len(frameworks or {}))},1fr)">{fw_cards}</div>'
        f'<div class="r2 r2b" style="margin-top:12px"><div class="th" style="grid-template-columns:minmax(0,1.5fr) minmax(0,0.9fr) minmax(0,1fr) minmax(0,0.9fr) 40px 50px;gap:8px">'
        f'<span>Família (classe)</span><span>NIST CSF</span><span>CIS v8</span><span>ISO 27001</span><span class="num">Regs</span><span class="num">C·A</span></div>{fam_rows}</div>'
        f'<div class="lead" style="padding-top:8px">Notas por framework conforme a plataforma. Mapeamento de controles '
        f'derivado das classes; status = maior severidade associada.</div>'
    )
    pages.append(("NIST · CIS · ISO", body))

    # ── P9 · CVEs + dicionário ───────────────────────────────────────────────
    cve_rows = "".join(
        f'<div class="tr" style="grid-template-columns:120px minmax(0,2fr) 90px 64px 44px;gap:10px;padding:5px 0">'
        f'<span class="b wrap">{e(c["cve"])}</span><span class="wrap">{e(clean_finding_title(c["title"])[:90])}</span>'
        f'<span class="wrap">{e(_host_short(c["host"]))}</span>{_v_sev(c["severity"])}'
        f'<span class="num b">{(f"{c["cvss"]:.1f}" if c["cvss"] else "—")}</span></div>'
        for c in cve_list[:12]
    ) or '<div class="tr">Nenhum CVE público identificado neste ciclo.</div>'
    dic = [
        ("id · scan_id", "Identificador do registro e do ciclo de varredura."),
        ("host · domínio", "Ativo onde o achado foi observado."),
        ("vulnerabilidade", "Descrição do achado, incluindo path/parâmetro afetado."),
        ("família", "Classe canônica de vulnerabilidade."),
        ("severidade · cvss", "critical/high/medium/low/info · pontuação CVSS v3 quando disponível."),
        ("cve", "Identificador público, quando o achado corresponde a um CVE."),
        ("verificação", "<b>confirmed</b> reproduzido · <b>hypothesis</b> inferido por versão/banner · <b>candidate</b> detecção automática pendente de validação."),
        ("recomendação", "Ação corretiva sugerida (código R## no catálogo do Anexo C)."),
    ]
    dic_html = "".join(
        f'<div class="tr" style="grid-template-columns:120px minmax(0,1fr);gap:10px;padding:4px 0">'
        f'<span class="b">{e(k)}</span><span class="wrap">{v}</span></div>' for k, v in dic
    )
    body = (
        f'<div style="padding:20px 0 12px"><div class="eyebrow">07 · CVEs identificados</div>'
        f'<div class="h2">{len(cve_list)} CVE(s) público(s) no ciclo</div></div>'
        f'<div class="r2 r2b"><div class="th" style="grid-template-columns:120px minmax(0,2fr) 90px 64px 44px;gap:10px">'
        f'<span>CVE</span><span>Descrição</span><span>Host</span><span>Sev</span><span class="num">CVSS</span></div>{cve_rows}</div>'
        f'<div class="up" style="color:#1767E5;padding:16px 0 5px">Dicionário do inventário</div>'
        f'<div class="r2 r2b">{dic_html}</div>'
    )
    pages.append(("CVEs e dicionário", body))

    # ── Anexo A · críticos e altos ───────────────────────────────────────────
    crit_high_f = [f for f in findings if str(f.severity or "").lower() in ("critical", "high")]
    crit_high_f.sort(key=lambda f: (_severity_order(str(f.severity or "info").lower()),
                                    -(_finding_cvss_num(f) or 0.0), f.id))
    _GT_A = "40px 58px minmax(0,1fr) minmax(0,2.6fr) 40px 74px"
    hdr_a = (f'<div class="th" style="grid-template-columns:{_GT_A};gap:8px">'
             f'<span>ID</span><span>Sev</span><span>Host</span><span>Vulnerabilidade</span>'
             f'<span class="num">CVSS</span><span>Verificação</span></div>')

    def _row_a(f):
        return (f'<div class="tr" style="grid-template-columns:{_GT_A};gap:8px;font-size:10.5px;padding:4px 0">'
                f'<span class="muted">{f.id}</span>{_v_sev(str(f.severity or "info").lower())}'
                f'<span class="b6 wrap">{e(_host_short(str(f.domain or "—")))}</span>'
                f'<span class="wrap">{e(clean_finding_title(f.title)[:96])}</span>'
                f'<span class="num b6">{_finding_cvss(f)}</span>'
                f'<span class="muted">{_VERIF_PT.get(str(f.verification_status or "candidate").lower(), "Candidato")}</span></div>')
    for pi, chunk in enumerate(_chunk(crit_high_f, 20)):
        rows = "".join(_row_a(f) for f in chunk)
        body = (
            f'<div style="padding:16px 0 10px"><div class="eyebrow">Anexo A · críticos e altos</div>'
            f'<div class="h2sm">{len(crit_high_f)} registros P0/P1 do inventário</div></div>'
            f'<div class="r2 r2b">{hdr_a}{rows}</div>')
        pages.append((f"Anexo A · {pi + 1}", body))
    if not crit_high_f:
        pages.append(("Anexo A", '<div style="padding:20px 0"><div class="eyebrow">Anexo A · críticos e altos</div>'
                                 '<div class="h2sm">Nenhum achado crítico ou alto neste ciclo.</div></div>'))

    # ── Anexo B · inventário completo (paginado) ─────────────────────────────
    _GT_B = "34px 40px 62px minmax(0,1fr) 28px 58px 28px"
    hdr_b = (f'<div class="th" style="grid-template-columns:{_GT_B};gap:6px;font-size:9px">'
             f'<span>ID</span><span>Sev</span><span>Host</span><span>Vulnerabilidade · família · CVE · URL</span>'
             f'<span class="num">CVSS</span><span>Verif.</span><span>Rec.</span></div>')

    def _row_b(f):
        fam = family_label(fam_of[f.id])
        url = str(f.url or f.domain or "")
        cve_bit = f' · {e(str(f.cve).upper())}' if (f.cve and str(f.cve).upper().startswith("CVE-")) else ""
        rec = str(f.recommendation or "").strip()
        code = rec_code.get(rec, "—")
        return (f'<div class="tr" style="grid-template-columns:{_GT_B};gap:6px;font-size:9.5px;line-height:1.25;padding:4px 0">'
                f'<span class="muted">{f.id}</span>{_v_sev(str(f.severity or "info").lower(), abbr=True)}'
                f'<span class="b6 wrap">{e(_host_short(str(f.domain or "—")))}</span>'
                f'<span class="wrap" style="display:flex;flex-direction:column;gap:1px">'
                f'<span>{e(clean_finding_title(f.title)[:150])}</span>'
                f'<span style="font-size:8.5px;color:#605d5d">{e(fam)}{cve_bit} · {e(url[:60])}</span></span>'
                f'<span class="num b6">{_finding_cvss(f)}</span>'
                f'<span class="muted">{_VERIF_PT.get(str(f.verification_status or "candidate").lower(), "Candidato")}</span>'
                f'<span class="b" style="color:#1767E5">{e(code)}</span></div>')
    b_chunks = list(_chunk(findings, 20))
    for pi, chunk in enumerate(b_chunks):
        rows = "".join(_row_b(f) for f in chunk)
        first_id = chunk[0].id if chunk else 0
        last_id = chunk[-1].id if chunk else 0
        head_extra = (f'<div style="padding:14px 0 8px"><div class="eyebrow">Anexo B · inventário completo</div>'
                      f'<div class="h2sm">Todas as {total} vulnerabilidades, sem omissões</div>'
                      f'<div class="lead" style="padding-top:4px">Texto integral do achado, família, CVE, URL e código da '
                      f'recomendação (catálogo no Anexo C).</div></div>') if pi == 0 else (
            f'<div style="padding:14px 0 8px;display:flex;justify-content:space-between;align-items:baseline">'
            f'<div class="eyebrow">Anexo B · inventário completo</div>'
            f'<span class="small muted">IDs {first_id}–{last_id}</span></div>')
        body = f'{head_extra}<div class="r2 r2b">{hdr_b}{rows}</div>'
        pages.append((f"Anexo B · {pi + 1}/{len(b_chunks)}", body))

    # ── Anexo C · catálogo de recomendações ──────────────────────────────────
    _GT_C = "40px minmax(0,1fr) 54px"
    hdr_c = (f'<div class="th" style="grid-template-columns:{_GT_C};gap:10px;font-size:9px">'
             f'<span>Código</span><span>Recomendação (texto integral)</span><span class="num">Registros</span></div>')

    def _row_c(code, txt, cnt):
        return (f'<div class="tr" style="grid-template-columns:{_GT_C};gap:10px;font-size:10.5px;line-height:1.3;padding:5px 0">'
                f'<span class="b" style="color:#1767E5">{e(code)}</span><span class="wrap">{e(txt)}</span>'
                f'<span class="num b6">{cnt}</span></div>')
    c_chunks = list(_chunk(rec_catalog, 26))
    for pi, chunk in enumerate(c_chunks):
        rows = "".join(_row_c(code, txt, cnt) for code, txt, cnt in chunk)
        head = (f'<div style="padding:14px 0 8px"><div class="eyebrow">Anexo C · catálogo de recomendações</div>'
                f'<div class="h2sm">{len(rec_catalog)} recomendações distintas, por volume</div></div>') if pi == 0 else (
            f'<div style="padding:14px 0 8px"><div class="eyebrow">Anexo C · catálogo de recomendações</div></div>')
        body = f'{head}<div class="r2 r2b">{hdr_c}{rows}</div>'
        pages.append((f"Anexo C · {pi + 1}/{max(1,len(c_chunks))}", body))
    if not rec_catalog:
        pages.append(("Anexo C", '<div style="padding:20px 0"><div class="eyebrow">Anexo C</div>'
                                 '<div class="h2sm">Nenhuma recomendação textual registrada.</div></div>'))

    total_pages = 1 + len(pages)
    cover = _v_cover(company, "Relatório técnico", "Relatório Técnico de Gestão de Vulnerabilidades",
                     "Caminhos de ataque, priorização, recomendações e inventário por ativo",
                     escopo_c, _v_ref(scan_id).split(" · ")[0],
                     f"Scan #{scan_id} · {total} registros · {hosts_n} hosts", total_pages)
    sheets = cover + "".join(_v_sheet(company, sec, body, ref, i + 2, total_pages) for i, (sec, body) in enumerate(pages))
    return _v_shell(f"Relatório Técnico — {company}", sheets)


def _chunk(seq, size):
    seq = list(seq)
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _find_rec_text(catalog, code):
    for c, txt, _cnt in catalog:
        if c == code:
            return txt
    return ""


def _rec_title(txt: str) -> str:
    """Primeira sentença/curto rótulo da recomendação, p/ a tabela resumida."""
    t = str(txt or "").strip()
    for sep in (". ", "; ", ": "):
        if sep in t:
            head = t.split(sep)[0]
            if 8 <= len(head) <= 90:
                return head
    return t[:110]
