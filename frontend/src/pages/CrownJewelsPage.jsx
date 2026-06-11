import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import ScanSelect from "../components/ScanSelect";
import "../styles/dashboard.css";

/* Joias da Coroa — ativos de alto valor (dado REAL de /api/cockpit:
   crown_jewels enriquecidas com achados por host + findings reais). Sem
   risco residual (plataforma Red Team). */

const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", info: "Info" };
const JEWEL_TYPE = {
  admin_panel: { label: "Painel administrativo", color: "#7c3aed" },
  data_store: { label: "Repositório de dados", color: "#b45309" },
  payment: { label: "Pagamento / financeiro", color: "#b03333" },
  identity: { label: "Identidade / autenticação", color: "#a83232" },
  cicd: { label: "CI/CD / pipeline", color: "#0e7490" },
  secrets_mgmt: { label: "Gestão de segredos", color: "#9d174d" },
};

function typeInfo(label) {
  return JEWEL_TYPE[label] || { label: String(label || "ativo de alto valor").replace(/_/g, " "), color: "var(--brand-700)" };
}

export default function CrownJewelsPage() {
  const [data, setData] = useState(null);
  const [sel, setSel] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [scanId, setScanId] = useState("");

  useEffect(() => {
    setLoading(true);
    client
      .get("/api/cockpit", { params: scanId ? { scan_id: scanId } : {} })
      .then(({ data }) => { setData(data || null); setSel(0); })
      .catch(() => setError("Falha ao carregar as joias da coroa."))
      .finally(() => setLoading(false));
  }, [scanId]);

  const jewels = useMemo(() => (Array.isArray(data?.crown_jewels) ? data.crown_jewels : []), [data]);
  const findings = useMemo(() => (Array.isArray(data?.findings) ? data.findings : []), [data]);

  const current = jewels[sel] || null;
  const jewelFindings = useMemo(() => {
    if (!current) return [];
    const host = current.host || current.target;
    return findings.filter((f) => f.target === host);
  }, [current, findings]);

  if (loading) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-state"><div><div className="spin" /><p className="st-title">Carregando joias…</p></div></div></div></main>;
  }
  if (error) {
    return <main className="dash"><div className="content" style={{ padding: "32px 40px" }}><div className="dash-err">{error}</div></div></main>;
  }

  return (
    <main className="dash">
      <div className="content cockpit-shell">
        <section className="cockpit-page-head">
          <div>
            <div className="sk-eyebrow">Joias da Coroa</div>
            <h1>Ativos de alto valor</h1>
            <p className="cockpit-sub">{jewels.length} joia(s) identificada(s) · classificação automática (M1)</p>
          </div>
          <div className="cockpit-actions">
            <ScanSelect value={scanId} onChange={setScanId} />
          </div>
        </section>

        {jewels.length === 0 ? (
          <div className="report-empty">Nenhuma joia da coroa identificada no ciclo selecionado.</div>
        ) : (
          <section className="jewels-grid">
            {/* Lista ranqueada */}
            <div className="jewels-list">
              {jewels.map((j, i) => {
                const ti = typeInfo(j.label);
                const top = Number(j.critical || 0) > 0 ? "critical" : Number(j.high || 0) > 0 ? "high" : Number(j.medium || 0) > 0 ? "medium" : null;
                return (
                  <button key={i} className={`jewel-card${i === sel ? " active" : ""}`} onClick={() => setSel(i)} type="button">
                    <div className="jewel-card-head">
                      <b className="sk-mono">{j.target}</b>
                      <strong className="sk-mono">{Number(j.findings_total || 0)}</strong>
                    </div>
                    <span className="jewel-type" style={{ color: ti.color }}>{ti.label}</span>
                    {top && <span className={`sk-dot sk-dot--${top}`} style={{ marginLeft: 6 }} />}
                  </button>
                );
              })}
            </div>

            {/* Detalhe */}
            {current && (
              <div className="sk-panel jewel-detail">
                <div className="jewel-detail-head">
                  <div>
                    <div className="sk-eyebrow" style={{ color: typeInfo(current.label).color }}>{typeInfo(current.label).label}</div>
                    <h3 className="sk-mono">{current.target}</h3>
                  </div>
                </div>
                <div className="jewel-kpis">
                  <div><span>Achados</span><strong className="sk-mono">{Number(current.findings_total || 0)}</strong></div>
                  <div><span>Críticos</span><strong className="sk-mono" style={{ color: "var(--sev-critical-text)" }}>{Number(current.critical || 0)}</strong></div>
                  <div><span>Altos</span><strong className="sk-mono" style={{ color: "var(--sev-high-text)" }}>{Number(current.high || 0)}</strong></div>
                  <div><span>Prioridade</span><strong className="sk-mono">{Number(current.boost || 0) <= -25 ? "máxima" : "alta"}</strong></div>
                </div>
                <div className="sk-eyebrow" style={{ margin: "4px 0 8px" }}>Achados que atingem esta joia</div>
                {jewelFindings.length === 0 ? (
                  <div className="report-empty">Nenhum achado correlacionado a este ativo neste ciclo.</div>
                ) : (
                  <div className="jewel-findings">
                    {jewelFindings.map((f) => {
                      const s = String(f.severity || "info").toLowerCase();
                      return (
                        <div key={f.id} className="jewel-finding">
                          <span className={`sk-dot sk-dot--${s}`} />
                          <div>
                            <b>{f.title}</b>
                            <span className="sk-mono">{f.id} · {f.cvss ? `cvss ${Number(f.cvss).toFixed(1)}` : "sem cvss"}{f.epss ? ` · epss ${Math.round(f.epss * 100)}%` : ""}</span>
                          </div>
                          <span className={`sk-badge sk-badge--${s}`}>{SEV_LABEL[s] || s}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </section>
        )}
      </div>
    </main>
  );
}
