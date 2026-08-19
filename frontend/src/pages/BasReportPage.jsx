import { Fragment, useEffect, useState } from "react";
import client from "../api/client";
import "../styles/dashboard.css";

/* Relatório BAS (Breach & Attack Simulation) — dado real de /api/bas/report.
   Cada achado carrega seu próprio flag `simulated`: só é simulado quando a
   técnica foi disparada via um agente stub (bas_agent_stub) -- um agente
   real (certificado mTLS assinado pela CA da plataforma) produz tráfego e
   resultado reais, e conta normalmente. */

const FW_LABEL_ORDER = ["nist", "iso27001", "pci", "cis_v8"];

function riskScoreTone(score) {
  if (score == null) return "neutral";
  if (score >= 60) return "critical";
  if (score >= 30) return "medium";
  return "low";
}

export default function BasReportPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    client
      .get("/api/bas/report")
      .then(({ data }) => setData(data || null))
      .catch(() => setError("Falha ao carregar o relatório BAS."))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-state"><div><div className="spin" /><p className="st-title">Gerando relatório BAS…</p></div></div></div></main>;
  }
  if (error) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-err">{error}</div></div></main>;
  }

  const coverage = data?.framework_coverage || {};
  const exposure = data?.exposure || {};
  const score = data?.risk_score || {};
  const jewels = data?.crown_jewels || [];
  const heatmap = data?.attack_heatmap || [];
  const findings = data?.findings || [];
  const tone = riskScoreTone(score.score);

  const heatmapByCategory = {};
  for (const row of heatmap) {
    heatmapByCategory[row.category] = heatmapByCategory[row.category] || [];
    heatmapByCategory[row.category].push(row);
  }

  return (
    <main className="dash">
      <div className="content report-shell">
        <section className="report-actions no-print">
          <div className="report-actions-right">
            <button className="sk-btn-ghost" onClick={() => window.print()}>Imprimir / PDF</button>
          </div>
        </section>

        <header className="report-head">
          <div>
            <div className="sk-eyebrow" style={{ color: "var(--brand-700)" }}>Relatório BAS · Breach &amp; Attack Simulation · confidencial</div>
            <h1>Cobertura e resiliência frente às técnicas de simulação de ataque</h1>
            <p className="report-meta sk-mono">
              {data?.total_techniques || 0} técnica(s) catalogada(s) · {data?.tested_techniques || 0} já disparada(s)
            </p>
          </div>
          <div className="report-rating">
            <div><b className={`sk-mono prio-badge prio-${tone === "critical" ? "P0" : tone === "medium" ? "P1" : "P2"}`}>{score.score == null ? "—" : score.score}</b><span>risk score</span></div>
          </div>
        </header>

        <section className="report-section">
          <div className="sk-eyebrow">01 · Sumário executivo</div>
          <div className="report-summary-grid">
            <p className="report-narrative">{data?.narrative}</p>
            <div className="report-kpis">
              <div><span>Risk score</span><strong className="sk-mono">{score.score == null ? "—" : `${score.score}/100`}</strong></div>
              <div><span>Disparos resolvidos</span><strong className="sk-mono">{score.resolved_total || 0}</strong></div>
              <div><span>Round-trips reais</span><strong className="sk-mono">{exposure.real_tunnel_roundtrips || 0}</strong></div>
              <div><span>Alvos internos testados</span><strong className="sk-mono">{exposure.distinct_targets_tested || 0}</strong></div>
            </div>
          </div>
          <p className="report-sub" style={{ marginTop: 10 }}>
            Só é simulado o que rodou via um agente stub (bas_agent_stub) — um agente real relaya tráfego e resultado
            de verdade, e conta como qualquer outro achado da plataforma. Veja a coluna "Real/Simulado" na tabela de
            achados abaixo.
          </p>
        </section>

        <div className="report-two-col">
          <section className="report-section">
            <div className="sk-eyebrow">02 · Cobertura por framework</div>
            <span className="report-sub">técnicas relevantes já testadas ao menos uma vez</span>
            <div style={{ display: "grid", gap: 10, marginTop: 10 }}>
              {FW_LABEL_ORDER.filter((k) => coverage[k]).map((key) => {
                const fw = coverage[key];
                return (
                  <div key={key}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 4 }}>
                      <span>{fw.label}</span>
                      <span className="sk-mono muted">{fw.tested}/{fw.total}</span>
                    </div>
                    <div style={{ height: 7, borderRadius: 4, background: "var(--surface-soft)", overflow: "hidden" }}>
                      <div style={{ height: "100%", width: `${fw.coverage_pct}%`, background: fw.coverage_pct >= 50 ? "var(--sev-low, #229160)" : fw.coverage_pct > 0 ? "var(--sev-medium, #d4a500)" : "var(--line)" }} />
                    </div>
                  </div>
                );
              })}
              {Object.keys(coverage).length === 0 && <div className="report-empty">Sem dados de cobertura ainda.</div>}
            </div>
          </section>

          <section className="report-section">
            <div className="sk-eyebrow">03 · Exposição / superfície testada</div>
            <div className="report-kpis">
              <div><span>Categorias testadas</span><strong className="sk-mono">{(exposure.categories_tested || []).length}</strong></div>
              <div><span>Disparos totais</span><strong className="sk-mono">{exposure.total_dispatches || 0}</strong></div>
              <div><span>Falhas de disparo</span><strong className="sk-mono">{exposure.failed_dispatches || 0}</strong></div>
              <div><span>Alvos internos</span><strong className="sk-mono">{exposure.distinct_targets_tested || 0}</strong></div>
            </div>
            <p className="report-sub" style={{ marginTop: 10 }}>
              {(exposure.categories_tested || []).join(", ") || "nenhuma categoria testada ainda"}
            </p>
          </section>
        </div>

        <section className="report-section">
          <div className="sk-eyebrow">04 · Joias da coroa em risco</div>
          {jewels.length === 0 ? (
            <div className="report-empty">Nenhuma joia da coroa identificada nos alvos internos configurados.</div>
          ) : (
            <ul className="report-jewels">
              {jewels.slice(0, 8).map((j, i) => (
                <li key={i}>
                  <b className="sk-mono">{j.target}</b>
                  <span>{j.label} · {j.jobs_run} job(s) executado(s)</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="report-section">
          <div className="sk-eyebrow">05 · Attack Heat Map (MITRE ATT&amp;CK)</div>
          <span className="report-sub">técnicas nunca disparadas são lacunas de cobertura, não "sem risco"</span>
          <div style={{ display: "grid", gap: 14, marginTop: 10 }}>
            {Object.entries(heatmapByCategory).map(([category, rows]) => (
              <div key={category}>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--ink-soft)", marginBottom: 6 }}>{category}</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: 6 }}>
                  {rows.map((row) => (
                    <div key={`${row.mitre_id}-${row.technique_key}`} style={{
                      border: "1px solid var(--line)", borderRadius: 8, padding: "7px 9px",
                      background: row.times_tested === 0 ? "var(--surface-soft)" : "rgba(34,145,96,0.12)",
                    }}>
                      <div className="sk-mono" style={{ fontSize: 11, fontWeight: 700 }}>{row.mitre_id}</div>
                      <div style={{ fontSize: 10, color: "var(--ink-soft)", marginTop: 2 }}>{row.display_name}</div>
                      <div style={{ fontSize: 9.5, color: "var(--ink-soft)", marginTop: 3 }}>
                        {row.availability === "future_agent_required" ? "requer agente real" : `testada ${row.times_tested}x`}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="report-section">
          <div className="sk-eyebrow">06 · Achados (BAS)</div>
          <span className="report-sub">simulado só quando disparado via agente stub — um achado real conta para score/superfície principal</span>
          <div className="attack-table-wrap">
            <table className="attack-table report-plan">
              <thead><tr><th>Achado</th><th>Técnica</th><th>Categoria</th><th>Risco</th><th>Real/Simulado</th><th>Data</th></tr></thead>
              <tbody>
                {findings.length === 0 && <tr><td colSpan={6}>Nenhum achado BAS registrado ainda.</td></tr>}
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td>{f.title}</td>
                    <td className="sk-mono">{f.technique_key}</td>
                    <td>{f.category}</td>
                    <td><span className="evidence-pill">{f.risk_tier}</span></td>
                    <td>{f.simulated ? "Simulado" : "Real"}</td>
                    <td className="sk-mono">{f.created_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="report-foot sk-mono">
          ScriptKidd.o · Relatório BAS gerado automaticamente · uso interno confidencial
        </footer>
      </div>
    </main>
  );
}
