import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

const STATUS_STYLES = {
  executed:                       { className: "ds-badge ds-badge--low",     label: "Executado" },
  partial_coverage:               { className: "ds-badge ds-badge--high",    label: "Parcial" },
  attempted_failed:               { className: "ds-badge ds-badge--critical", label: "Falhou" },
  node_completed_tools_skipped:   { className: "ds-badge ds-badge--info",     label: "Tools puladas" },
  no_tools_installed:             { className: "ds-badge",                   label: "Sem tools" },
  node_completed_no_phase_tools:  { className: "ds-badge ds-badge--high",    label: "Node OK / sem tools" },
  node_visited_no_tools:          { className: "ds-badge ds-badge--info",    label: "Visitou / sem tools" },
  skipped:                        { className: "ds-badge",                   label: "Pulou" },
};

const SEVERITY_COLORS = {
  critical: "#b03333",
  high: "#d6711f",
  medium: "#c25500",
  low: "#2d52e6",
  info: "#6b6b6b",
};

function StatusBadge({ status }) {
  const meta = STATUS_STYLES[status] || STATUS_STYLES.skipped;
  return <span className={meta.className}>{meta.label}</span>;
}

function CapabilityCard({ cap }) {
  const ok = cap.completed;
  const tone = ok ? "#1f8a59" : cap.visited ? "#fe7b02" : "#d8cdc4";
  return (
    <div
      style={{
        background: "#ffffff",
        border: `1px solid ${ok ? tone : "#e5dcd5"}`,
        borderLeft: `3px solid ${tone}`,
        borderRadius: 8,
        padding: "10px 14px",
        minWidth: 220,
        boxShadow: "0 1px 2px rgba(28,28,28,0.04)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <strong style={{ color: "#1c1c1c", fontSize: 13 }}>{cap.label}</strong>
        <span style={{ fontSize: 11, color: tone, fontWeight: 600 }}>
          {ok ? "✓ done" : cap.visited ? "· active" : "— pending"}
        </span>
      </div>
      <div style={{ fontSize: 11, color: "#6b6b6b", marginTop: 6 }}>
        Tools usadas: <strong style={{ color: "#1c1c1c" }}>{cap.tools_attempted.length}</strong>/{cap.tools_expected.length}
        <span style={{ marginLeft: 8 }}>· obs: {cap.observations_count}</span>
      </div>
    </div>
  );
}

export default function PhaseMonitorPage() {
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    client.get("/api/scans").then((r) => {
      setScans(r.data || []);
      if (!scanId && r.data?.length) {
        setScanId(String(r.data[0].id));
      }
    });
  }, []);

  const fetchMonitor = async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const r = await client.get(`/api/scans/${scanId}/phase-monitor`);
      setData(r.data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMonitor();
  }, [scanId]);

  useEffect(() => {
    if (!autoRefresh || !scanId) return;
    const t = setInterval(fetchMonitor, 5000);
    return () => clearInterval(t);
  }, [autoRefresh, scanId]);

  const filteredPhases = useMemo(() => {
    if (!data) return [];
    if (filter === "all") return data.phases;
    if (filter === "issues") return data.phases.filter((p) => p.status !== "executed");
    if (filter === "ok") return data.phases.filter((p) => p.status === "executed");
    return data.phases;
  }, [data, filter]);

  const groupedByNode = useMemo(() => {
    const m = new Map();
    for (const p of filteredPhases) {
      if (!m.has(p.node)) m.set(p.node, []);
      m.get(p.node).push(p);
    }
    return Array.from(m.entries());
  }, [filteredPhases]);

  return (
    <div style={{ padding: "20px 24px", color: "#1c1c1c" }}>
      <div style={{ marginBottom: 18 }}>
        <h2 style={{ fontSize: 24, fontWeight: 700, letterSpacing: "-0.02em", marginBottom: 4 }}>Phase Monitor</h2>
        <p style={{ fontSize: 13, color: "#6b6b6b" }}>22-step pentest pipeline · cobertura por fase, ferramentas usadas e pontos de falha.</p>
      </div>

      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 18, flexWrap: "wrap" }}>
        <select
          value={scanId}
          onChange={(e) => setScanId(e.target.value)}
          style={inputStyle}
        >
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              #{s.id} — {String(s.target_query || "").slice(0, 60)} — {s.status}
            </option>
          ))}
        </select>
        <button onClick={fetchMonitor} disabled={loading} style={primaryBtn}>
          {loading ? "..." : "Refresh"}
        </button>
        <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 13, color: "#3d3d3d" }}>
          <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
          Auto-refresh (5s)
        </label>
        <select value={filter} onChange={(e) => setFilter(e.target.value)} style={inputStyle}>
          <option value="all">Todas as fases</option>
          <option value="ok">Apenas executadas</option>
          <option value="issues">Apenas com problemas</option>
        </select>
      </div>

      {!data && <div style={{ color: "#6b6b6b" }}>Selecione um scan…</div>}

      {data && (
        <>
          {/* HEADER METRICS */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 18 }}>
            <Metric label="Status" value={data.status} />
            <Metric label="Progress" value={`${data.mission_progress}%`} />
            <Metric label="Findings" value={data.metrics.findings_total} />
            <Metric label="Tool runs" value={data.metrics.tool_runs_total} />
            <Metric label="Tools success" value={`${data.metrics.tools_success}/${data.metrics.tools_attempted}`} accent />
            <Metric label="Iterations" value={`${data.metrics.loop_iteration}/${data.metrics.max_iterations}`} />
            <Metric label="Termination" value={data.termination_reason || "-"} />
            <Metric label="Objective met" value={data.objective_met ? "yes" : "no"} />
          </div>

          {/* TOOL INSTALLATION REPORT */}
          {data.installation_report && (
            <div
              style={{
                background: "#ffffff",
                border: "1px solid #e5dcd5",
                borderRadius: 8,
                padding: "10px 14px",
                marginBottom: 16,
                boxShadow: "0 1px 2px rgba(28,28,28,0.04)",
              }}
            >
              <div style={{ fontSize: 12, color: "#6b6b6b", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>
                Inventário de tools (ambiente backend ativo)
              </div>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 13 }}>
                <span><strong style={{ color: "#1f8a59" }}>{data.installation_report.installed.length}</strong> instaladas</span>
                <span><strong style={{ color: "#b03333" }}>{data.installation_report.missing.length}</strong> faltando</span>
                <span><strong>{Math.round((data.installation_report.coverage_ratio || 0) * 100)}%</strong> de cobertura</span>
                <span style={{ color: "#6b6b6b" }}>
                  Used in this scan: <strong>{data.metrics.tools_installed_used_ratio !== undefined ? `${Math.round(data.metrics.tools_installed_used_ratio * 100)}% das instaladas` : "—"}</strong>
                </span>
              </div>
              {data.installation_report.missing.length > 0 && (
                <details style={{ marginTop: 8 }}>
                  <summary style={{ cursor: "pointer", fontSize: 12, color: "#b03333" }}>
                    Tools não instaladas no runtime atual ({data.installation_report.missing.length})
                  </summary>
                  <div style={{ marginTop: 6 }}>
                    {data.installation_report.missing.map((t) => (
                      <span key={t} style={{ ...chip, ...chipMuted }}>{t}</span>
                    ))}
                  </div>
                </details>
              )}
            </div>
          )}

          {/* SEVERITY */}
          <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap" }}>
            {["critical", "high", "medium", "low", "info"].map((sev) => (
              <div
                key={sev}
                style={{
                  background: "#ffffff",
                  border: "1px solid #e5dcd5",
                  padding: "6px 12px",
                  borderRadius: 6,
                  fontSize: 12,
                  color: "#3d3d3d",
                }}
              >
                <strong style={{ color: SEVERITY_COLORS[sev] }}>{sev.toUpperCase()}</strong>
                <span style={{ marginLeft: 6 }}>{data.severity_counts[sev] || 0}</span>
              </div>
            ))}
          </div>

          {/* ISSUES */}
          {data.issues && data.issues.length > 0 && (
            <div
              style={{
                background: "rgba(254,123,2,0.06)",
                border: "1px solid rgba(254,123,2,0.3)",
                borderLeft: "3px solid #fe7b02",
                borderRadius: 8,
                padding: "12px 14px",
                marginBottom: 18,
              }}
            >
              <strong style={{ color: "#c25500", fontSize: 13 }}>Pontos de atenção</strong>
              <ul style={{ margin: "6px 0 0 18px", color: "#3d3d3d" }}>
                {data.issues.map((i, idx) => (
                  <li key={idx} style={{ fontSize: 13, marginBottom: 2 }}>{i}</li>
                ))}
              </ul>
            </div>
          )}

          {/* CAPABILITIES */}
          <h3 style={sectionTitle}>Capabilities (graph nodes)</h3>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 22 }}>
            {data.capabilities.map((c) => <CapabilityCard key={c.id} cap={c} />)}
          </div>

          {/* PHASES BY NODE */}
          <h3 style={sectionTitle}>22 phases (grouped by node)</h3>
          {groupedByNode.map(([node, items]) => (
            <div key={node} style={{ marginBottom: 16 }}>
              <h4 style={{ color: "#1c1c1c", fontSize: 13, fontWeight: 600, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                {node}
              </h4>
              <div style={tableWrap}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead>
                    <tr style={{ background: "#faf8f4", color: "#3d3d3d" }}>
                      <th style={th}>ID</th>
                      <th style={th}>Phase</th>
                      <th style={th}>Status</th>
                      <th style={th}>Tools used</th>
                      <th style={th}>Pendências de tools</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((p) => (
                      <tr key={p.id} style={{ background: "#ffffff", borderTop: "1px solid #efe7e0" }}>
                        <td style={td}><code style={codeStyle}>{p.id}</code></td>
                        <td style={td}>{p.title}</td>
                        <td style={td}><StatusBadge status={p.status} /></td>
                        <td style={td}>
                          {p.tools_used.length > 0 ? (
                            <span>
                              {p.tools_success.map((t) => (
                                <span key={t} style={{ ...chip, ...chipSuccess }}>{t}</span>
                              ))}
                              {p.tools_failed.map((t) => (
                                <span key={t} style={{ ...chip, ...chipDanger }}>{t}</span>
                              ))}
                              {(p.tools_skipped || []).map((t) => (
                                <span key={t} style={{ ...chip, ...chipMuted }} title="Ignorado com justificativa operacional">{t}</span>
                              ))}
                            </span>
                          ) : (
                            <span style={{ color: "#a0958c" }}>—</span>
                          )}
                        </td>
                        <td style={td}>
                          {/* installed-but-unused = red flag (agent skipped) */}
                          {(p.tools_missing_unused || []).slice(0, 6).map((t) => (
                            <span key={t} style={{ ...chip, ...chipDanger }} title="Instalado mas não executado">{t}</span>
                          ))}
                          {/* uninstalled = neutral */}
                          {(p.tools_missing_uninstalled || p.tools_missing || []).slice(0, 6).map((t) => (
                            <span key={t} style={{ ...chip, ...chipMuted }} title="Não instalado">{t}*</span>
                          ))}
                          {(p.tools_missing || []).length > 12 && (
                            <span style={{ color: "#6b6b6b", fontSize: 11 }}>
                              +{(p.tools_missing || []).length - 12}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}

          {/* TOOL INVENTORY */}
          <h3 style={{ ...sectionTitle, marginTop: 24 }}>Tool inventory ({data.tool_inventory.length})</h3>
          <div style={tableWrap}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ background: "#faf8f4", color: "#3d3d3d" }}>
                  <th style={th}>Tool</th>
                  <th style={th}>Attempts</th>
                  <th style={th}>Success</th>
                  <th style={th}>Failed</th>
                  <th style={th}>Skipped</th>
                  <th style={th}>Targets</th>
                  <th style={th}>Time (s)</th>
                  <th style={th}>Findings</th>
                  <th style={th}>Last error</th>
                </tr>
              </thead>
              <tbody>
                {data.tool_inventory.map((t) => (
                  <tr key={t.tool} style={{ background: "#ffffff", borderTop: "1px solid #efe7e0" }}>
                    <td style={td}><code style={codeStyle}>{t.tool}</code></td>
                    <td style={td}>{t.attempts}</td>
                    <td style={{ ...td, color: t.success > 0 ? "#1f8a59" : "#a0958c", fontWeight: 600 }}>{t.success}</td>
                    <td style={{ ...td, color: t.failed > 0 ? "#b03333" : "#a0958c", fontWeight: 600 }}>{t.failed}</td>
                    <td style={{ ...td, color: t.skipped > 0 ? "#c25500" : "#a0958c", fontWeight: 600 }}>{t.skipped || 0}</td>
                    <td style={td}>{t.targets_count}</td>
                    <td style={td}>{t.total_seconds}</td>
                    <td style={td}>{t.findings_generated}</td>
                    <td
                      style={{ ...td, color: "#6b6b6b", fontSize: 11, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                      title={t.last_error}
                    >
                      {t.last_error ? t.last_error : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function Metric({ label, value, accent }) {
  return (
    <div
      style={{
        background: "#ffffff",
        border: "1px solid #e5dcd5",
        padding: "10px 14px",
        borderRadius: 8,
        boxShadow: "0 1px 2px rgba(28,28,28,0.04)",
      }}
    >
      <div style={{ fontSize: 10, color: "#6b6b6b", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, marginTop: 4, color: accent ? "#fe7b02" : "#1c1c1c" }}>{String(value)}</div>
    </div>
  );
}

const inputStyle = {
  background: "#ffffff",
  color: "#1c1c1c",
  border: "1px solid #e5dcd5",
  padding: "6px 10px",
  borderRadius: 6,
  fontSize: 13,
};

const primaryBtn = {
  background: "var(--brand-500)",
  color: "#ffffff",
  border: "none",
  padding: "6px 14px",
  borderRadius: 6,
  cursor: "pointer",
  fontSize: 13,
  fontWeight: 500,
};

const sectionTitle = {
  fontSize: 14,
  fontWeight: 600,
  color: "#1c1c1c",
  marginBottom: 8,
  textTransform: "uppercase",
  letterSpacing: "0.06em",
};

const tableWrap = {
  background: "#ffffff",
  border: "1px solid #e5dcd5",
  borderRadius: 8,
  overflow: "hidden",
  boxShadow: "0 1px 2px rgba(28,28,28,0.04)",
};

const th = {
  textAlign: "left",
  padding: "10px 12px",
  fontWeight: 600,
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.06em",
};

const td = { padding: "10px 12px", verticalAlign: "top" };

const codeStyle = {
  fontFamily: "IBM Plex Mono, ui-monospace, monospace",
  fontSize: 12,
  background: "#f0ebe7",
  color: "#1c1c1c",
  padding: "1px 6px",
  borderRadius: 4,
};

const chip = {
  display: "inline-block",
  padding: "1px 6px",
  marginRight: 4,
  marginBottom: 2,
  borderRadius: 3,
  border: "1px solid",
  fontSize: 11,
  fontWeight: 500,
};

const chipSuccess = { background: "rgba(34,145,96,0.1)", borderColor: "#1f8a59", color: "#1f8a59" };
const chipDanger = { background: "rgba(214,69,69,0.1)", borderColor: "#d64545", color: "#b03333" };
const chipMuted = { background: "#f0ebe7", borderColor: "#d8cdc4", color: "#6b6b6b" };
