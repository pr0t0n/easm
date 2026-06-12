import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import ScanSelect from "../components/ScanSelect";
import DomainsPage from "./DomainsPage";
import "../styles/dashboard.css";

/* Vulnerabilidades — lista → detalhe (dado REAL de /api/findings/page).
   Sem dado fabricado: campos ausentes aparecem como "—". */

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const VSTATUS_LABEL = { confirmed: "Confirmado", candidate: "Candidato", hypothesis: "Hipótese", refuted: "Refutado" };

function mitreStr(m) {
  if (!m) return "—";
  if (typeof m === "string") return m;
  if (Array.isArray(m)) return m.map((x) => (typeof x === "string" ? x : x?.id || x?.technique_id || "")).filter(Boolean).join(", ") || "—";
  return m.id || m.technique_id || m.name || "—";
}

export default function VulnerabilitiesPage() {
  const [activeTab, setActiveTab] = useState("achados");
  const [items, setItems] = useState([]);
  const [counts, setCounts] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sevFilter, setSevFilter] = useState("todas");
  const [selected, setSelected] = useState(null);
  const [scanId, setScanId] = useState("");

  useEffect(() => {
    setLoading(true);
    const params = { limit: 500, sort: "severity" };
    if (sevFilter !== "todas") params.severity = sevFilter;
    if (scanId) params.scan_id = scanId;
    client
      .get("/api/findings/page", { params })
      .then(({ data }) => {
        setItems(Array.isArray(data?.items) ? data.items : []);
        setCounts(data?.severity_counts || {});
      })
      .catch(() => setError("Falha ao carregar vulnerabilidades."))
      .finally(() => setLoading(false));
  }, [sevFilter, scanId]);

  const total = useMemo(() => SEV_ORDER.reduce((a, k) => a + Number(counts[k] || 0), 0), [counts]);

  if (loading) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-state"><div><div className="spin" /><p className="st-title">Carregando vulnerabilidades…</p></div></div></div></main>;
  }
  if (error) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-err">{error}</div></div></main>;
  }

  // ── Detalhe ───────────────────────────────────────────────────────────────
  if (selected) {
    const f = selected;
    const sev = String(f.severity || "info").toLowerCase();
    const target = f.target || f.domain || f.target_query || "—";
    const details = f.details || {};
    const evidence = details.evidence || details.payload || details.command || details.proof || details.raw_output || details.request || "";
    const reproSteps = Array.isArray(details.repro_steps) ? details.repro_steps : (Array.isArray(details.reproduction_steps) ? details.reproduction_steps : []);
    const vrank = { hypothesis: 1, candidate: 2, confirmed: 3 };
    const reached = vrank[String(f.verification_status || "").toLowerCase()] || 0;
    const chain = [
      { label: "Descoberta", desc: `Identificado por ${f.tool || "ferramenta"}`, done: true },
      { label: "Hipótese", desc: "Sinal inicial registrado pelo agente", done: reached >= 1 },
      { label: "Candidato", desc: "Evidência parcial coletada", done: reached >= 2 },
      { label: "Confirmado", desc: "Evidência suficiente — risco validado", done: reached >= 3 },
    ];
    return (
      <main className="dash">
        <div className="content report-shell">
          <button className="vuln-back sk-mono" onClick={() => setSelected(null)} type="button">← voltar para a lista</button>
          <header className="vuln-detail-head">
            <div className="vuln-detail-badges">
              <span className={`sk-badge sk-badge--${sev}`}><span className={`sk-dot sk-dot--${sev}`} />{SEV_LABEL[sev]}</span>
              {f.verification_status && <span className="evidence-pill">{VSTATUS_LABEL[f.verification_status] || f.verification_status}</span>}
              {f.vuln_family_label && <span className="sk-badge sk-badge--neutral">{f.vuln_family_label}</span>}
            </div>
            <h1>{f.title}</h1>
            <p className="report-meta sk-mono">
              {target}{f.cve ? ` · ${f.cve}` : ""}{mitreStr(f.mitre_attack) !== "—" ? ` · MITRE ${mitreStr(f.mitre_attack)}` : ""}{f.tool ? ` · ${f.tool}` : ""} · scan #{f.scan_job_id}
            </p>
          </header>

          <div className="report-two-col">
            <div>
              <section className="report-section">
                <div className="sk-eyebrow">Descrição técnica</div>
                <p className="report-narrative">{f.cve_description || details.description || "Sem descrição técnica registrada para este achado."}</p>
              </section>

              <section className="report-section">
                <div className="sk-eyebrow">Evidência reproduzível</div>
                {f.url && <div className="vuln-code sk-mono" style={{ marginBottom: evidence ? 8 : 0 }}>{f.url}</div>}
                {evidence ? (
                  <pre className="vuln-evidence sk-mono">{String(evidence).slice(0, 4000)}</pre>
                ) : (!f.url && (
                  <div className="report-empty">Sem evidência técnica capturada para este achado.</div>
                ))}
                {reproSteps.length > 0 && (
                  <ol className="vuln-repro">
                    {reproSteps.slice(0, 8).map((s, i) => <li key={i}>{String(s)}</li>)}
                  </ol>
                )}
              </section>

              <section className="sk-panel vuln-chain-panel">
                <div className="sk-eyebrow">Cadeia de validação</div>
                <div className="vuln-chain">
                  {chain.map((step, i) => (
                    <div key={step.label} className={`vuln-chain-step${step.done ? " done" : ""}`}>
                      <span className="vuln-chain-dot" />
                      {i < chain.length - 1 && <span className="vuln-chain-line" />}
                      <div>
                        <b>{step.label}</b>
                        <span>{step.desc}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            </div>
            <div>
              <section className="sk-panel vuln-score-panel">
                <div className="sk-eyebrow">Pontuação</div>
                <div className="vuln-score-row"><span>CVSS</span><b className="sk-mono">{f.cvss ? Number(f.cvss).toFixed(1) : "—"}</b></div>
                <div className="vuln-score-row"><span>Confiança</span><b className="sk-mono">{f.confidence_score != null ? `${f.confidence_score}%` : "—"}</b></div>
                <div className="vuln-score-row"><span>Risk score</span><b className="sk-mono">{f.risk_score ?? "—"}</b></div>
                <div className="vuln-score-row"><span>Família</span><b>{f.vuln_family_label || "—"}</b></div>
                <div className="vuln-score-row"><span>Evidência</span><b>{VSTATUS_LABEL[f.verification_status] || f.verification_status || "—"}</b></div>
              </section>
              {f.recommendation && (
                <section className="sk-panel vuln-reco-panel">
                  <div className="sk-eyebrow">Recomendação</div>
                  <p className="report-narrative" style={{ fontSize: 12.5 }}>{f.recommendation}</p>
                </section>
              )}
            </div>
          </div>
        </div>
      </main>
    );
  }

  // ── Por Subdomínio ────────────────────────────────────────────────────────
  if (activeTab === "subdominios") {
    return (
      <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <div style={{ padding: "24px 40px 0", background: "var(--surface)", borderBottom: "1px solid var(--line)" }}>
          <div className="sk-eyebrow" style={{ marginBottom: 4 }}>Vulnerabilidades</div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
            <div className="vuln-tabs">
              <button type="button" className="vuln-tab" onClick={() => setActiveTab("achados")}>Lista de achados</button>
              <button type="button" className="vuln-tab active">Por Subdomínio</button>
            </div>
            <div style={{ paddingBottom: 8 }}>
              <ScanSelect value={scanId} onChange={setScanId} />
            </div>
          </div>
        </div>
        <DomainsPage embedded scanId={scanId} />
      </div>
    );
  }

  // ── Lista ─────────────────────────────────────────────────────────────────
  return (
    <main className="dash">
      <div className="content cockpit-shell">
        <section className="cockpit-page-head" style={{ paddingBottom: 0 }}>
          <div>
            <div className="sk-eyebrow">Vulnerabilidades</div>
            <h1>Achados do ambiente</h1>
            <p className="cockpit-sub">{total} achado(s) · clique para ver evidência e recomendação</p>
          </div>
          <div className="cockpit-actions">
            <ScanSelect value={scanId} onChange={setScanId} />
          </div>
        </section>

        <div className="vuln-tabs" style={{ marginBottom: 16 }}>
          <button type="button" className="vuln-tab active">Lista de achados</button>
          <button type="button" className="vuln-tab" onClick={() => setActiveTab("subdominios")}>Por Subdomínio</button>
        </div>

        <section className="surface-filter-strip">
          <button className={`surface-chip${sevFilter === "todas" ? " active" : ""}`} onClick={() => setSevFilter("todas")} type="button">Todas</button>
          {SEV_ORDER.map((s) => (
            <button key={s} className={`surface-chip${sevFilter === s ? " active" : ""}`} onClick={() => setSevFilter(s)} type="button">
              <span className={`sk-dot sk-dot--${s}`} style={{ marginRight: 6 }} />{SEV_LABEL[s]} {Number(counts[s] || 0)}
            </button>
          ))}
          <span className="surface-count-note">{items.length} no filtro atual</span>
        </section>

        <section className="sk-panel surface-table-panel">
          <div className="attack-table-wrap">
            <table className="attack-table">
              <thead>
                <tr><th>Severidade</th><th>Vulnerabilidade</th><th>Alvo</th><th>CVE</th><th>CVSS</th><th>MITRE</th><th>Evidência</th></tr>
              </thead>
              <tbody>
                {items.length === 0 && <tr><td colSpan={7}>Nenhum achado no filtro atual.</td></tr>}
                {items.map((f) => {
                  const sev = String(f.severity || "info").toLowerCase();
                  return (
                    <tr key={f.id} onClick={() => setSelected(f)} style={{ cursor: "pointer" }}>
                      <td><span className={`sk-badge sk-badge--${sev}`}><span className={`sk-dot sk-dot--${sev}`} />{SEV_LABEL[sev]}</span></td>
                      <td><b>{f.title}</b><small style={{ display: "block", color: "var(--ink-muted)" }}>{f.vuln_family_label || ""}</small></td>
                      <td className="sk-mono">{f.target || f.domain || f.target_query || "—"}</td>
                      <td className="sk-mono">{f.cve || "—"}</td>
                      <td className="num sk-mono">{f.cvss ? Number(f.cvss).toFixed(1) : "—"}</td>
                      <td className="sk-mono">{mitreStr(f.mitre_attack)}</td>
                      <td><span className="evidence-pill">{VSTATUS_LABEL[f.verification_status] || f.verification_status || "—"}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </main>
  );
}
