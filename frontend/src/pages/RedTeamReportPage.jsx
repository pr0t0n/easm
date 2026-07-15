import { Fragment, useEffect, useMemo, useState } from "react";
import client from "../api/client";
import "../styles/dashboard.css";

/* Relatório de Exposição (Red Team) — dado 100% real de /api/cockpit.
   Sem risco residual e sem dono/prazo/esforço (decisão: plataforma Red Team).
   Plano P0/P1/P2 priorizado por severidade + joia + EPSS + evidência. */

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const STATUS_LABEL = { confirmed: "Confirmado", candidate: "Candidato", hypothesis: "Hipótese", refuted: "Refutado", confirmado: "Confirmado", candidato: "Candidato" };
const HEAT_SEV = ["critical", "high", "medium", "low"];
const HEAT_BASE = { critical: "214,69,69", high: "254,123,2", medium: "212,165,0", low: "34,145,96" };
function heatColor(v, sev, max) {
  if (!v) return "var(--surface-soft)";
  const alpha = 0.15 + (v / Math.max(1, max)) * 0.85;
  return `rgba(${HEAT_BASE[sev]}, ${alpha.toFixed(3)})`;
}

function priorityOf(f) {
  const sev = String(f.severity || "").toLowerCase();
  if (sev === "critical" || (f.isJewel && f.status === "confirmed")) return "P0";
  if (sev === "high") return "P1";
  if (sev === "medium") return "P2";
  return null; // low/info não entram no plano de ação
}

export default function RedTeamReportPage() {
  const [data, setData] = useState(null);
  const [scanId, setScanId] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    const qs = scanId ? `?scan_id=${scanId}` : "";
    client
      .get(`/api/cockpit${qs}`)
      .then(({ data }) => setData(data || null))
      .catch(() => setError("Falha ao carregar o relatório."))
      .finally(() => setLoading(false));
  }, [scanId]);

  const findings = useMemo(() => (Array.isArray(data?.findings) ? data.findings.map((f) => ({
    ...f,
    isJewel: Boolean(f.is_jewel),
    mitreStr: Array.isArray(f.mitre) && f.mitre.length ? f.mitre.map((m) => m.id).join(", ") : "—",
  })) : []), [data]);

  const plan = useMemo(() => {
    const withP = findings.map((f) => ({ ...f, p: priorityOf(f) })).filter((f) => f.p);
    const order = { P0: 0, P1: 1, P2: 2 };
    return withP.sort((a, b) => order[a.p] - order[b.p] || -(a.cvss || 0) - -(b.cvss || 0) || (b.epss || 0) - (a.epss || 0));
  }, [findings]);

  const trend = data?.score?.trend || [];
  const sev = data?.severity || {};
  const kpis = data?.kpis || {};
  const jewels = data?.crown_jewels || [];
  const heatmap = data?.heatmap || null;

  // Exporta vulnerabilidades em CSV (id, url, recomendação, cve, cvss/risco)
  const exportCsv = async () => {
    const sid = data?.scan?.id;
    try {
      const res = await client.get("/api/findings/export.csv", {
        params: sid ? { scan_id: sid } : {},
        responseType: "blob",
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vulnerabilidades${sid ? `-scan-${sid}` : ""}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch {
      window.alert("Falha ao exportar CSV.");
    }
  };

  // Abre o relatório técnico autenticado (via axios c/ JWT) — link direto dava 401
  const openTechReport = async () => {
    const sid = data?.scan?.id;
    if (!sid) return;
    const reportWindow = window.open("", "_blank");
    if (reportWindow) {
      reportWindow.document.write(`
        <!doctype html>
        <html lang="pt-BR">
          <head><title>Gerando relatório técnico...</title></head>
          <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;padding:32px;color:#1f2937">
            <h1 style="font-size:20px;margin:0 0 8px">Gerando relatório técnico completo</h1>
            <p style="margin:0;color:#64748b">Carregando evidências e preparando o HTML...</p>
          </body>
        </html>
      `);
      reportWindow.document.close();
    }
    try {
      const res = await client.get(`/api/scans/${sid}/pentest-report`, {
        responseType: "text",
        transformResponse: [(value) => value],
        _skipToast: true,
      });
      const html = String(res.data || "");
      if (reportWindow && !reportWindow.closed) {
        reportWindow.document.open();
        reportWindow.document.write(html);
        reportWindow.document.close();
      } else {
        const blob = new Blob([html], { type: "text/html;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `pentest-report-scan-${sid}.html`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60000);
      }
    } catch (err) {
      if (reportWindow && !reportWindow.closed) {
        reportWindow.document.open();
        reportWindow.document.write(`
          <!doctype html>
          <html lang="pt-BR">
            <head><title>Falha ao gerar relatório</title></head>
            <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;padding:32px;color:#991b1b">
              <h1 style="font-size:20px;margin:0 0 8px">Falha ao abrir o relatório técnico</h1>
              <p style="margin:0;color:#7f1d1d">${err?.response?.data?.detail || "Endpoint indisponível ou sessão sem permissão."}</p>
            </body>
          </html>
        `);
        reportWindow.document.close();
      }
      window.alert("Não foi possível abrir o relatório técnico (indisponível ou sem permissão).");
    }
  };

  if (loading) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-state"><div><div className="spin" /><p className="st-title">Gerando relatório…</p></div></div></div></main>;
  }
  if (error) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-err">{error}</div></div></main>;
  }

  const score = Number(data?.score?.value || 0);
  const grade = data?.score?.grade || "—";
  const scan = data?.scan;

  return (
    <main className="dash">
      <div className="content report-shell">
        {/* Ações (não imprimem) */}
        <section className="report-actions no-print">
          <select value={scanId} onChange={(e) => setScanId(e.target.value)} aria-label="Selecionar scan do relatório">
            <option value="">Último scan</option>
            {(data?.scans || []).map((s) => (
              <option key={s.id} value={s.id}>#{s.id} {s.target_query}</option>
            ))}
          </select>
          <div className="report-actions-right">
            <button className="sk-btn-ghost" onClick={exportCsv}>Exportar CSV</button>
            <button className="sk-btn-ghost" onClick={() => window.print()}>Imprimir / PDF</button>
            {scan?.id && (
              <button className="sk-btn-primary" onClick={openTechReport}>Relatório técnico completo</button>
            )}
          </div>
        </section>

        {/* Cabeçalho do documento */}
        <header className="report-head">
          <div>
            <div className="sk-eyebrow" style={{ color: "var(--brand-700)" }}>Relatório de Exposição · confidencial</div>
            <h1>O que o time precisa atacar e validar primeiro</h1>
            <p className="report-meta sk-mono">
              {scan?.target_query || "—"} · {scan ? `ciclo #${scan.id}` : "—"} · {scan?.status || ""}
            </p>
          </div>
          <div className="report-rating">
            <div><b className="sk-mono">{grade}</b><span>grade</span></div>
            <i />
            <div><b className="sk-mono">{score.toFixed(1)}</b><span>score</span></div>
          </div>
        </header>

        {/* 01 Sumário executivo */}
        <section className="report-section">
          <div className="sk-eyebrow">01 · Sumário executivo</div>
          <div className="report-summary-grid">
            <p className="report-narrative">
              Neste ciclo foram observados <b>{Number(sev.critical || 0)}</b> achados críticos e <b>{Number(sev.high || 0)}</b> altos
              em <b>{Number(kpis.assets_exposed || 0)}</b> ativo(s) da superfície analisada.
              {" "}<b>{Number(kpis.jewels_at_risk || 0)}</b> de <b>{Number(kpis.jewels_total || 0)}</b> joia(s) da coroa apresentam achado correlacionado.
              {" "}O rating consolidado do alvo é <b>{score.toFixed(1)}</b> (grade <b>{grade}</b>).
            </p>
            <div className="report-kpis">
              <div><span>Críticos + Altos</span><strong className="sk-mono">{Number(kpis.critical_high || 0)}</strong></div>
              <div><span>Achados abertos</span><strong className="sk-mono">{Number(kpis.findings_open || 0)}</strong></div>
              <div><span>Joias em risco</span><strong className="sk-mono">{Number(kpis.jewels_at_risk || 0)}/{Number(kpis.jewels_total || 0)}</strong></div>
              <div><span>Ativos expostos</span><strong className="sk-mono">{Number(kpis.assets_exposed || 0)}</strong></div>
            </div>
          </div>
        </section>

        {/* 02 Plano de ação priorizado */}
        <section className="report-section">
          <div className="sk-eyebrow">02 · Plano de ação priorizado</div>
          <span className="report-sub">ordenado por severidade, valor do alvo (joia), CVSS e EPSS — sem priorização teórica isolada</span>
          <div className="attack-table-wrap">
            <table className="attack-table report-plan">
              <thead>
                <tr><th>Prio</th><th>Achado</th><th>Alvo</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>MITRE</th><th>Evidência</th></tr>
              </thead>
              <tbody>
                {plan.length === 0 && <tr><td colSpan={8}>Sem achados acionáveis (crítico/alto/médio) neste ciclo.</td></tr>}
                {plan.map((f) => (
                  <tr key={f.id}>
                    <td><span className={`prio-badge prio-${f.p}`}>{f.p}</span></td>
                    <td>
                      <b>{f.title}</b>
                      {f.isJewel && <small className="report-jewel-flag">↳ atinge joia da coroa</small>}
                      <small className="report-plan-reco"><b>Recomendação:</b> {f.recommendation || "Sem recomendação registrada."}</small>
                    </td>
                    <td className="sk-mono">{f.target}</td>
                    <td className="sk-mono">{f.cve || "—"}</td>
                    <td className="num sk-mono">{f.cvss ? Number(f.cvss).toFixed(1) : "—"}</td>
                    <td className="num sk-mono">{f.epss ? `${Math.round(f.epss * 100)}%` : "—"}</td>
                    <td className="sk-mono">{f.mitreStr}</td>
                    <td><span className="evidence-pill">{STATUS_LABEL[f.status] || f.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <div className="report-two-col">
          {/* 03 Heatmap superfície × severidade */}
          <section className="report-section">
            <div className="sk-eyebrow">03 · Heatmap superfície × severidade</div>
            <span className="report-sub">onde os achados se acumulam</span>
            {!heatmap || (heatmap.total_findings || 0) === 0 ? (
              <div className="report-empty">Sem achados classificáveis neste ciclo.</div>
            ) : (
              <div className="report-heatgrid">
                <span />
                {HEAT_SEV.map((s) => <b key={s}>{SEV_LABEL[s]}</b>)}
                <b>Tot</b>
                {(heatmap.categories || []).map((cat) => {
                  const row = heatmap.matrix?.[cat] || {};
                  const tot = HEAT_SEV.reduce((a, s) => a + Number(row[s] || 0), 0);
                  return (
                    <Fragment key={cat}>
                      <strong className="report-heat-label">{cat}</strong>
                      {HEAT_SEV.map((s) => {
                        const v = Number(row[s] || 0);
                        const light = heatmap.max > 0 && v / heatmap.max > 0.45;
                        return <span key={s} className="report-heat-cell sk-mono" style={{ background: heatColor(v, s, heatmap.max), color: light ? "#fff" : "var(--ink-soft)" }}>{v || ""}</span>;
                      })}
                      <em className="report-heat-tot sk-mono">{tot}</em>
                    </Fragment>
                  );
                })}
              </div>
            )}
          </section>

          {/* 04 Joias da coroa */}
          <section className="report-section">
            <div className="sk-eyebrow">04 · Joias da coroa</div>
            {jewels.length === 0 ? (
              <div className="report-empty">Nenhuma joia da coroa identificada neste ciclo.</div>
            ) : (
              <ul className="report-jewels">
                {jewels.slice(0, 8).map((j, i) => (
                  <li key={i}>
                    <b className="sk-mono">{j.target || j.asset || j.host || "joia"}</b>
                    <span>{j.label || j.type || j.category || "ativo de alto valor"}{j.findings_total ? ` · ${j.findings_total} achado(s)` : ""}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        {/* 05 Evolução — só com histórico real (≥2 scans do mesmo alvo) */}
        {trend.length >= 2 && (
          <section className="report-section">
            <div className="sk-eyebrow">05 · Evolução entre ciclos</div>
            <div className="report-evolution">
              {trend.map((t) => {
                const h = Math.max(4, Math.min(100, Number(t.rating_score || 0)));
                const tone = h >= 80 ? "low" : h >= 60 ? "medium" : "critical";
                return (
                  <div key={t.scan_id} className="evo-bar">
                    <span className="evo-val sk-mono">{Number(t.rating_score || 0).toFixed(0)}</span>
                    <i className={`evo-fill evo-${tone}`} style={{ height: `${h}%` }} />
                    <span className="evo-scan sk-mono">#{t.scan_id}</span>
                  </div>
                );
              })}
            </div>
          </section>
        )}

        <footer className="report-foot sk-mono">
          ScriptKidd.o · Relatório gerado automaticamente · uso interno confidencial
        </footer>
      </div>
    </main>
  );
}
