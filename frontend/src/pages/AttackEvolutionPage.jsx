import { useCallback, useEffect, useMemo, useState } from "react";
import client from "../api/client";

const SEV = {
  critical: { color: "#fca5a5", bg: "rgba(185,28,28,0.18)", label: "Critical" },
  high: { color: "#fdba74", bg: "rgba(194,65,12,0.18)", label: "High" },
  medium: { color: "#fde68a", bg: "rgba(161,98,7,0.18)", label: "Medium" },
  low: { color: "#86efac", bg: "rgba(21,128,61,0.18)", label: "Low" },
  info: { color: "#cbd5e1", bg: "rgba(71,85,105,0.24)", label: "Info" },
};
const SEV_KEYS = ["critical", "high", "medium", "low", "info"];

function fmtNum(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  return new Intl.NumberFormat("pt-BR").format(n);
}

function fmtDate(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "-";
  return dt.toLocaleString("pt-BR");
}

function sevBadge(sev) {
  const key = String(sev || "info").toLowerCase();
  const cfg = SEV[key] || SEV.info;
  return {
    color: cfg.color,
    background: cfg.bg,
    border: `1px solid ${cfg.color}40`,
    padding: "3px 8px",
    borderRadius: 999,
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: "0.03em",
    textTransform: "uppercase",
  };
}

function ScoreCard({ overview }) {
  const score = Number(overview?.score || 0);
  const color = score >= 80 ? "#86efac" : score >= 60 ? "#fde68a" : "#fca5a5";
  return (
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Score geral de risco</p>
      <div style={{ display: "flex", alignItems: "end", gap: 8, marginTop: 4 }}>
        <span style={{ fontSize: 42, lineHeight: 1, fontWeight: 800, color }}>{fmtNum(score)}</span>
        <span style={{ fontSize: 13, color: "#94a3b8", marginBottom: 6 }}>/ 100</span>
      </div>
      <div style={{ marginTop: 12, background: "#1e293b", height: 10, borderRadius: 99, overflow: "hidden" }}>
        <div style={{ width: `${Math.max(0, Math.min(100, score))}%`, height: "100%", background: color }} />
      </div>
      <div style={{ display: "grid", gap: 4, marginTop: 10, fontSize: 12, color: "#cbd5e1" }}>
        <div>Total de vulnerabilidades: <strong>{fmtNum(overview?.total_vulnerabilities)}</strong></div>
        <div>Ocorrencias encontradas: <strong>{fmtNum(overview?.findings_total)}</strong></div>
        <div>Alvos afetados: <strong>{fmtNum(overview?.affected_targets)}</strong></div>
      </div>
    </div>
  );
}

function SeverityCard({ summary }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Vulnerabilidades por criticidade</p>
      <div style={{ display: "grid", gap: 8, marginTop: 12 }}>
        {SEV_KEYS.map((sev) => {
          const total = Number(summary?.[sev] || 0);
          const max = Math.max(...SEV_KEYS.map((k) => Number(summary?.[k] || 0)), 1);
          return (
            <div key={sev} style={{ display: "grid", gridTemplateColumns: "80px 1fr 44px", gap: 8, alignItems: "center" }}>
              <span style={{ fontSize: 11, color: SEV[sev].color, fontWeight: 700 }}>{SEV[sev].label}</span>
              <div style={{ background: "#1e293b", height: 8, borderRadius: 99 }}>
                <div style={{ width: `${(total / max) * 100}%`, height: "100%", borderRadius: 99, background: SEV[sev].color }} />
              </div>
              <span style={{ fontSize: 12, color: "#cbd5e1", textAlign: "right" }}>{fmtNum(total)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AgeCard({ age }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Age das vulnerabilidades</p>
      <div style={{ marginTop: 10, display: "grid", gap: 8, fontSize: 12, color: "#cbd5e1" }}>
        <div>
          <strong>Conhecida no ambiente</strong>
          <div>Media: {fmtNum(age?.known_in_environment_avg_days)} dias</div>
          <div>Maximo: {fmtNum(age?.known_in_environment_max_days)} dias</div>
        </div>
        <div>
          <strong>Existencia no mercado (publicacao CVE)</strong>
          <div>Media: {fmtNum(age?.known_in_market_avg_days)} dias</div>
          <div>Maximo: {fmtNum(age?.known_in_market_max_days)} dias</div>
        </div>
      </div>
    </div>
  );
}

function RemediationCard({ remediation }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Historico de correcao</p>
      <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
        <MiniMetric label="Abertas" value={remediation?.open} color="#b91c1c" />
        <MiniMetric label="Corrigidas" value={remediation?.closed} color="#166534" />
        <MiniMetric label="Taxa de fechamento" value={`${fmtNum(remediation?.closure_rate_percent)}%`} color="#a16207" />
      </div>
      <p style={{ marginTop: 10, marginBottom: 0, fontSize: 11, color: "#94a3b8" }}>
        Regra aplicada: se uma vulnerabilidade nao reaparece no scan posterior, ela e considerada finalizada.
      </p>
    </div>
  );
}

function MiniMetric({ label, value, color }) {
  return (
    <div style={{ background: "#111827", border: "1px solid #334155", borderRadius: 8, padding: 10 }}>
      <div style={{ fontSize: 11, color: "#94a3b8" }}>{label}</div>
      <div style={{ marginTop: 3, fontSize: 20, fontWeight: 800, color }}>{value ?? "-"}</div>
    </div>
  );
}

export default function AttackEvolutionPage() {
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [targetInput, setTargetInput] = useState("");
  const [targetFilter, setTargetFilter] = useState("");
  const [severity, setSeverity] = useState("");
  const [selectedKey, setSelectedKey] = useState("");

  const fetchDashboard = useCallback(async (tgt, sev) => {
    setLoading(true);
    setError("");
    try {
      const params = {};
      if (tgt) params.target = tgt;
      if (sev) params.severity = sev;
      const { data } = await client.get("/api/vulnerability-management/dashboard", { params });
      setDashboard(data);
      const rows = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
      if (rows.length > 0 && !rows.find((row) => row.vulnerability_key === selectedKey)) {
        setSelectedKey(rows[0].vulnerability_key);
      }
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar dashboard de vulnerabilidades.");
    } finally {
      setLoading(false);
    }
  }, [selectedKey]);

  useEffect(() => {
    fetchDashboard(targetFilter, severity);
  }, [targetFilter, severity, fetchDashboard]);

  const vulnerabilities = useMemo(
    () => (Array.isArray(dashboard?.vulnerabilities) ? dashboard.vulnerabilities : []),
    [dashboard],
  );

  const selectedVulnerability = useMemo(
    () => vulnerabilities.find((item) => item.vulnerability_key === selectedKey) || vulnerabilities[0] || null,
    [vulnerabilities, selectedKey],
  );

  const availableTargets = dashboard?.filters?.available_targets || [];
  const selectedTargetUrl = dashboard?.filters?.selected_target_url || "";

  return (
    <div style={{ padding: 16, display: "grid", gap: 16 }}>
      <div style={{ background: "#0b1220", border: "1px solid #334155", borderRadius: 12, padding: 12, display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 700 }}>Filtro por alvo/subdominio</span>
        <select
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, minWidth: 220, background: "#111827", color: "#e2e8f0" }}
        >
          <option value="">Selecionar alvo conhecido</option>
          {availableTargets.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
        <input
          type="text"
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          placeholder="ou digite alvo/subdominio"
          onKeyDown={(e) => e.key === "Enter" && setTargetFilter(targetInput.trim())}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, minWidth: 220, background: "#111827", color: "#e2e8f0" }}
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, background: "#111827", color: "#e2e8f0" }}
        >
          <option value="">Todas severidades</option>
          {SEV_KEYS.map((sev) => (
            <option key={sev} value={sev}>{SEV[sev].label}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setTargetFilter(targetInput.trim())}
          style={{ padding: "6px 12px", border: "1px solid #f59e0b", borderRadius: 8, background: "rgba(245,158,11,0.16)", color: "#fcd34d", fontSize: 12, cursor: "pointer" }}
        >
          Aplicar
        </button>
        <button
          type="button"
          onClick={() => {
            setTargetInput("");
            setTargetFilter("");
            setSeverity("");
          }}
          style={{ padding: "6px 12px", border: "1px solid #7f1d1d", borderRadius: 8, background: "rgba(185,28,28,0.16)", color: "#fca5a5", fontSize: 12, cursor: "pointer" }}
        >
          Limpar
        </button>
        <div style={{ flex: 1 }} />
        {loading && <span style={{ fontSize: 12, color: "#94a3b8" }}>Carregando...</span>}
      </div>

      {selectedTargetUrl && (
        <div style={{ background: "rgba(245,158,11,0.14)", border: "1px solid #a16207", color: "#fcd34d", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
          URL do alvo selecionado: <strong>{selectedTargetUrl}</strong>
        </div>
      )}

      {error && (
        <div style={{ background: "rgba(185,28,28,0.16)", border: "1px solid #7f1d1d", color: "#fca5a5", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
          {error}
        </div>
      )}

      <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
        <ScoreCard overview={dashboard?.overview || {}} />
        <SeverityCard summary={dashboard?.overview?.severity_counts || {}} />
        <AgeCard age={dashboard?.age || {}} />
        <RemediationCard remediation={dashboard?.remediation_history || {}} />
      </div>

      <div style={{ display: "grid", gap: 12, gridTemplateColumns: "1.2fr 1fr" }}>
        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ padding: "10px 12px", borderBottom: "1px solid #334155", fontSize: 12, color: "#e2e8f0", fontWeight: 700 }}>
            Vulnerabilidades (clique para detalhar locais e correcao)
          </div>
          <div style={{ maxHeight: 520, overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ background: "#111827", position: "sticky", top: 0 }}>
                  <th style={thStyle}>Vulnerabilidade</th>
                  <th style={thStyle}>Sev</th>
                  <th style={thStyle}>Ocorrencias</th>
                  <th style={thStyle}>Alvos</th>
                  <th style={thStyle}>Status</th>
                </tr>
              </thead>
              <tbody>
                {vulnerabilities.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ padding: 16, textAlign: "center", color: "#94a3b8" }}>Sem vulnerabilidades para os filtros selecionados.</td>
                  </tr>
                )}
                {vulnerabilities.map((row) => {
                  const active = selectedVulnerability?.vulnerability_key === row.vulnerability_key;
                  return (
                    <tr
                      key={row.vulnerability_key}
                      onClick={() => setSelectedKey(row.vulnerability_key)}
                      style={{ background: active ? "rgba(245,158,11,0.15)" : "#0f172a", cursor: "pointer", borderBottom: "1px solid #1e293b" }}
                    >
                      <td style={tdStyle}>
                        <div style={{ fontWeight: 600, color: "#e2e8f0" }}>{row.title}</div>
                        <div style={{ color: "#94a3b8", fontSize: 11 }}>{row.cve || "sem CVE"}</div>
                      </td>
                      <td style={tdStyle}><span style={sevBadge(row.severity)}>{row.severity}</span></td>
                      <td style={tdStyle}>{fmtNum(row.occurrence_count)}</td>
                      <td style={tdStyle}>{fmtNum((row.affected_targets || []).length)}</td>
                      <td style={tdStyle}>{fmtNum(row.open_count)} abertas / {fmtNum(row.closed_count)} fechadas</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 12, display: "grid", gap: 10, alignContent: "start" }}>
          {!selectedVulnerability ? (
            <div style={{ color: "#94a3b8", fontSize: 12 }}>Selecione uma vulnerabilidade para ver todos os subdominios, paths, URLs e recomendacoes.</div>
          ) : (
            <>
              <div>
                <div style={{ fontSize: 11, color: "#94a3b8" }}>Vulnerabilidade selecionada</div>
                <div style={{ marginTop: 3, fontWeight: 700, color: "#e2e8f0" }}>{selectedVulnerability.title}</div>
                <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <span style={sevBadge(selectedVulnerability.severity)}>{selectedVulnerability.severity}</span>
                  {selectedVulnerability.cve && <span style={chipStyle}>{selectedVulnerability.cve}</span>}
                  {selectedVulnerability.tool && <span style={chipStyle}>{selectedVulnerability.tool}</span>}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: "#94a3b8" }}>Correcao recomendada</div>
                <div style={{ marginTop: 4, fontSize: 12, color: "#e2e8f0", background: "#111827", border: "1px solid #334155", borderRadius: 8, padding: 10 }}>
                  {selectedVulnerability.recommendation || "Sem recomendacao registrada para essa vulnerabilidade."}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>Todos os subdominios afetados</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(selectedVulnerability.affected_targets || []).length === 0 && <span style={{ color: "#94a3b8", fontSize: 12 }}>Sem subdominio mapeado.</span>}
                  {(selectedVulnerability.affected_targets || []).map((item) => <span key={item} style={chipStyle}>{item}</span>)}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>Todos os paths afetados</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(selectedVulnerability.affected_paths || []).length === 0 && <span style={{ color: "#94a3b8", fontSize: 12 }}>Sem path mapeado.</span>}
                  {(selectedVulnerability.affected_paths || []).map((item) => <span key={item} style={chipStyle}>{item}</span>)}
                </div>
              </div>

              <div style={{ borderTop: "1px solid #334155", paddingTop: 8 }}>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>Ocorrencias (alvo + path + URL)</div>
                <div style={{ maxHeight: 220, overflow: "auto", border: "1px solid #334155", borderRadius: 8 }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ background: "#111827", position: "sticky", top: 0 }}>
                        <th style={thStyle}>Subdominio</th>
                        <th style={thStyle}>Path</th>
                        <th style={thStyle}>URL</th>
                        <th style={thStyle}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(selectedVulnerability.occurrences || []).map((occ) => (
                        <tr key={`${selectedVulnerability.vulnerability_key}-${occ.finding_id}`} style={{ borderBottom: "1px solid #1e293b" }}>
                          <td style={tdStyle}>{occ.subdomain || "-"}</td>
                          <td style={tdStyle}>{occ.path || "-"}</td>
                          <td style={tdStyle} title={occ.url || ""}>{occ.url || "-"}</td>
                          <td style={tdStyle}>{occ.lifecycle_status || "open"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div style={{ marginTop: 6, fontSize: 11, color: "#94a3b8" }}>
                  Ultima deteccao: {fmtDate(selectedVulnerability.latest_seen_at)}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const thStyle = {
  textAlign: "left",
  padding: "8px 10px",
  fontSize: 11,
  color: "#94a3b8",
  borderBottom: "1px solid #334155",
};

const tdStyle = {
  textAlign: "left",
  padding: "8px 10px",
  color: "#e2e8f0",
  verticalAlign: "top",
};

const chipStyle = {
  padding: "2px 8px",
  borderRadius: 999,
  border: "1px solid #475569",
  background: "#111827",
  fontSize: 11,
  color: "#e2e8f0",
};
