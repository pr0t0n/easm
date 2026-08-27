import { Fragment, useEffect, useState } from "react";
import client from "../api/client";
import "../styles/dashboard.css";

const FW_LABEL_ORDER = ["nist", "iso27001", "pci", "cis_v8"];
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const SEV_COLOR = { critical: "#d64545", high: "#e0793a", medium: "#d4a500", low: "#4a90d9", info: "var(--ink-soft)" };

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
  const [expandedFindingId, setExpandedFindingId] = useState(null);
  const [schedules, setSchedules] = useState([]);
  const [scheduleId, setScheduleId] = useState("");

  useEffect(() => {
    client.get("/api/bas/schedules").then(({ data }) => setSchedules(data || [])).catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    client
      .get("/api/bas/report", { params: scheduleId ? { schedule_id: scheduleId } : {} })
      .then(({ data }) => setData(data || null))
      .catch(() => setError("Falha ao carregar o relatório BAS."))
      .finally(() => setLoading(false));
  }, [scheduleId]);

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
  const actionPriorities = data?.action_priorities || [];
  const chainPaths = data?.chain_attack_paths || [];
  const severityCounts = data?.severity_counts || {};
  const tone = riskScoreTone(score.score);

  const vulnerableFindings = findings.filter((f) => !f.simulated && f.severity !== "info");
  const maxSevCount = Math.max(1, ...SEV_ORDER.map((s) => severityCounts[s] || 0));

  const heatmapByCategory = {};
  for (const row of heatmap) {
    heatmapByCategory[row.category] = heatmapByCategory[row.category] || [];
    heatmapByCategory[row.category].push(row);
  }

  return (
    <main className="dash">
      <div className="content report-shell">
        <section className="report-actions no-print">
          <div>
            <label className="sk-mono muted" style={{ fontSize: 11, marginRight: 8 }}>Relatório:</label>
            <select value={scheduleId} onChange={(e) => setScheduleId(e.target.value)}>
              <option value="">Todos os testes (agregado)</option>
              {schedules.map((s) => (
                <option key={s.id} value={s.id}>{s.name || `agendamento #${s.id}`}</option>
              ))}
            </select>
          </div>
          <div className="report-actions-right">
            <button className="sk-btn-ghost" onClick={() => window.print()}>Imprimir / PDF</button>
          </div>
        </section>

        <header className="report-head">
          <div>
            <div className="sk-eyebrow" style={{ color: "var(--brand-700)" }}>
              Relatório BAS · Breach &amp; Attack Simulation · confidencial
              {data?.schedule_name && <> · {data.schedule_name}</>}
            </div>
            <h1>Cobertura, risco e caminhos de ataque reais observados</h1>
            <p className="report-meta sk-mono">
              {data?.total_techniques || 0} técnica(s) catalogada(s) · {data?.tested_techniques || 0} já disparada(s) ·
              {" "}{vulnerableFindings.length} achado(s) real(is) com risco
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
            de verdade, e conta como qualquer outro achado da plataforma.
          </p>
        </section>

        <section className="report-section">
          <div className="sk-eyebrow">02 · Onde corrigir primeiro</div>
          <span className="report-sub">prioridades extraídas dos resultados reais dos testes, com evidência e próxima ação</span>
          {actionPriorities.length === 0 ? (
            <div className="report-empty" style={{ marginTop: 10 }}>Nenhuma prioridade real extraída dos testes concluídos neste escopo.</div>
          ) : (
            <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
              {actionPriorities.slice(0, 8).map((item) => (
                <div key={item.id} style={{ border: "1px solid var(--line)", borderRadius: 8, padding: "11px 13px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "baseline" }}>
                    <div>
                      <b style={{ fontSize: 13 }}>{item.priority} · {item.title}</b>
                      <div className="report-sub" style={{ marginTop: 3 }}>{item.impact}</div>
                    </div>
                    <span className="sk-mono muted" style={{ fontSize: 11 }}>{item.affected_count} ativo(s)</span>
                  </div>
                  <p style={{ margin: "8px 0 0", fontSize: 12 }}>{item.next_action}</p>
                  {(item.affected_targets || []).length > 0 && (
                    <div className="sk-mono" style={{ fontSize: 11, marginTop: 8 }}>
                      {(item.affected_targets || []).slice(0, 8).join(" · ")}
                    </div>
                  )}
                  <div className="sk-mono muted" style={{ fontSize: 10, marginTop: 6 }}>
                    job #{item.job_id}{(item.source_job_ids || []).length > 1 ? ` · ${item.source_job_ids.length} evidências` : ""} · {item.schedule_name || `agendamento #${item.schedule_id}`} · agente {item.agent_name || `#${item.agent_id}`}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="report-section">
          <div className="sk-eyebrow">03 · Vulnerabilidades por severidade</div>
          <span className="report-sub">severidade derivada do conteúdo real observado por técnica — nunca um valor fixo</span>
          <div style={{ display: "grid", gap: 8, marginTop: 12 }}>
            {SEV_ORDER.filter((s) => s !== "info").map((sev) => {
              const count = severityCounts[sev] || 0;
              return (
                <div key={sev} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ width: 60, fontSize: 12, color: SEV_COLOR[sev], fontWeight: 700 }}>{SEV_LABEL[sev]}</span>
                  <div style={{ flex: 1, height: 10, borderRadius: 5, background: "var(--surface-soft)", overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${(count / maxSevCount) * 100}%`, background: SEV_COLOR[sev], minWidth: count ? 3 : 0 }} />
                  </div>
                  <span className="sk-mono" style={{ width: 24, textAlign: "right", fontSize: 13 }}>{count}</span>
                </div>
              );
            })}
          </div>
          {vulnerableFindings.length === 0 && (
            <div className="report-empty" style={{ marginTop: 10 }}>Nenhum achado real com severidade acima de "info" até agora.</div>
          )}
        </section>

        <div className="report-two-col">
          <section className="report-section">
            <div className="sk-eyebrow">04 · Cobertura por framework</div>
            <span className="report-sub">técnicas relevantes já testadas por um agente real</span>
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
            <div className="sk-eyebrow">05 · Exposição / superfície testada</div>
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
          <div className="sk-eyebrow">06 · Attack Path (chains disparadas)</div>
          <span className="report-sub">sequência real de cada chain disparada — o que foi tentado, em ordem, e o que de fato aconteceu em cada etapa</span>
          {chainPaths.length === 0 ? (
            <div className="report-empty" style={{ marginTop: 10 }}>Nenhuma chain disparada ainda — veja a página de Testes/Agendamento BAS.</div>
          ) : (
            <div style={{ display: "grid", gap: 16, marginTop: 12 }}>
              {chainPaths.map((path) => (
                <div key={path.scan_job_id} style={{ border: "1px solid var(--line)", borderRadius: 10, padding: "12px 14px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
                    <div>
                      <b style={{ fontSize: 13 }}>{path.chain_display_name}</b>
                      <span className="sk-mono muted" style={{ marginLeft: 8, fontSize: 11 }}>alvo: {path.target_hint}</span>
                    </div>
                    <span style={{ fontSize: 10.5, fontWeight: 700, color: path.simulated ? "#d4a500" : "#229160" }}>
                      {path.simulated ? "SIMULADO" : "REAL"}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    {path.steps.map((step, i) => (
                      <Fragment key={step.technique_key + i}>
                        <div style={{
                          padding: "6px 10px", borderRadius: 8, fontSize: 11.5,
                          border: `1px solid ${step.status === "completed" ? "rgba(34,145,96,0.4)" : step.status === "failed" ? "rgba(214,69,69,0.4)" : "var(--line)"}`,
                          background: step.status === "completed" ? "rgba(34,145,96,0.08)" : step.status === "failed" ? "rgba(214,69,69,0.08)" : "var(--surface-soft)",
                        }}>
                          <div style={{ fontWeight: 700 }}>{step.display_name}</div>
                          <div className="sk-mono muted" style={{ fontSize: 9.5, marginTop: 2 }}>
                            {(step.mitre_refs || []).join(", ") || "—"} · {step.status}
                          </div>
                        </div>
                        {i < path.steps.length - 1 && <span style={{ color: "var(--ink-soft)" }}>→</span>}
                      </Fragment>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="report-section">
          <div className="sk-eyebrow">07 · Joias da coroa em risco</div>
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
          <div className="sk-eyebrow">08 · Attack Heat Map (MITRE ATT&amp;CK)</div>
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
          <div className="sk-eyebrow">09 · Achados, vulnerabilidades e recomendações</div>
          <span className="report-sub">clique num achado real para ver o que foi observado de fato e como corrigir</span>
          <div className="attack-table-wrap">
            <table className="attack-table report-plan">
              <thead><tr><th>Achado</th><th>Técnica</th><th>Severidade</th><th>MITRE</th><th>Real/Simulado</th><th>Data</th></tr></thead>
              <tbody>
                {findings.length === 0 && <tr><td colSpan={6}>Nenhum achado BAS registrado ainda.</td></tr>}
                {findings.map((f) => {
                  const expanded = expandedFindingId === f.id;
                  const canExpand = !f.simulated && (f.key_findings?.length > 0 || f.recommendation);
                  return (
                    <Fragment key={f.id}>
                      <tr
                        style={{ cursor: canExpand ? "pointer" : "default" }}
                        onClick={() => canExpand && setExpandedFindingId(expanded ? null : f.id)}
                      >
                        <td>{canExpand ? (expanded ? "▾ " : "▸ ") : ""}{f.title}</td>
                        <td className="sk-mono">{f.technique_key}</td>
                        <td><span style={{ fontSize: 11, fontWeight: 700, color: SEV_COLOR[f.severity] || "inherit" }}>{SEV_LABEL[f.severity] || f.severity}</span></td>
                        <td className="sk-mono" style={{ fontSize: 11 }}>{(f.mitre_refs || []).join(", ") || "—"}</td>
                        <td>{f.simulated ? "Simulado" : "Real"}</td>
                        <td className="sk-mono">{f.created_at}</td>
                      </tr>
                      {expanded && (
                        <tr>
                          <td colSpan={6} style={{ background: "var(--surface-soft)" }}>
                            {f.key_findings?.length > 0 && (
                              <div style={{ marginBottom: 8 }}>
                                <b style={{ fontSize: 12 }}>O que foi observado:</b>
                                <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 12 }}>
                                  {f.key_findings.map((line, i) => <li key={i} className="sk-mono">{line}</li>)}
                                </ul>
                              </div>
                            )}
                            {f.recommendation && (
                              <div>
                                <b style={{ fontSize: 12 }}>Recomendação:</b>
                                <p style={{ margin: "4px 0 0", fontSize: 12 }}>{f.recommendation}</p>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
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
