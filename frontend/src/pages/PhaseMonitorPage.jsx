import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";

const STATUS_STYLES = {
  completed:                      { className: "ds-badge ds-badge--low",      label: "Completa" },
  queued:                         { className: "ds-badge ds-badge--info",     label: "Na fila" },
  gate_blocked:                   { className: "ds-badge",                    label: "Aguardando gate" },
  failed:                         { className: "ds-badge ds-badge--critical", label: "Falhou" },
  executed:                       { className: "ds-badge ds-badge--low",     label: "Executado" },
  executing:                      { className: "ds-badge ds-badge--high",    label: "Executando" },
  in_progress:                    { className: "ds-badge ds-badge--info",    label: "Em progresso" },
  blocked:                        { className: "ds-badge",                   label: "Bloqueada" },
  partial_coverage:               { className: "ds-badge ds-badge--high",    label: "Parcial" },
  attempted_failed:               { className: "ds-badge ds-badge--critical", label: "Falhou" },
  node_completed_tools_skipped:   { className: "ds-badge ds-badge--info",     label: "Tools puladas" },
  no_tools_installed:             { className: "ds-badge",                   label: "Sem tools" },
  node_completed_no_phase_tools:  { className: "ds-badge ds-badge--high",    label: "Node OK / sem tools" },
  node_visited_no_tools:          { className: "ds-badge ds-badge--info",    label: "Visitou / sem tools" },
  pending:                        { className: "ds-badge",                   label: "Pendente" },
  skipped:                        { className: "ds-badge",                   label: "Ignorada" },
};

// Inline work-queue progress bar across all targets.
// pct = terminal/total (phase finished). The bar is segmented to show quality:
// green = succeeded (done), gray = skipped (tool n/a), red = failed/timeout.
function WqProgress({ wq }) {
  if (!wq || !wq.total) return <span style={{ fontSize: 11, color: "var(--ink-muted)" }}>—</span>;
  const total = wq.total || 1;
  const done = wq.done || 0;
  const skipped = wq.skipped || 0;
  const failed = wq.failed || 0;        // inclui timeout
  const blocked = wq.blocked || 0;
  const running = wq.running || 0;
  const queued = wq.queued || 0;
  const pct = wq.pct ?? 0;               // terminal/total
  const seg = (n) => `${(n / total) * 100}%`;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 150 }}>
      <div style={{ flex: 1, height: 7, borderRadius: 99, background: "var(--bg-muted)", overflow: "hidden", display: "flex" }}>
        <div style={{ width: seg(done), height: "100%", background: "var(--sev-low-solid)" }} title={`${done} ok`} />
        <div style={{ width: seg(skipped), height: "100%", background: "var(--line-strong)" }} title={`${skipped} n/a`} />
        <div style={{ width: seg(failed), height: "100%", background: "var(--sev-critical-solid)" }} title={`${failed} falha/timeout`} />
        <div style={{ width: seg(running), height: "100%", background: "var(--sev-high-solid,#fe7b02)" }} title={`${running} rodando`} />
        <div style={{ width: seg(queued + blocked), height: "100%", background: "transparent" }} />
      </div>
      <span style={{ fontSize: 10, color: pct === 100 ? "var(--sev-low-text)" : "var(--ink-muted)", fontFamily: "var(--font-mono)", whiteSpace: "nowrap", fontWeight: pct === 100 ? 700 : 400 }}>
        {pct}%
      </span>
      <span style={{ fontSize: 9, color: "var(--ink-muted)", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
        {done}✓{skipped > 0 ? ` ${skipped}∅` : ""}{failed > 0 ? ` ${failed}✕` : ""}{blocked > 0 ? ` ${blocked}⊘` : ""}/{total}
      </span>
    </div>
  );
}

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

function ReconObservabilityPanel({ value }) {
  if (!value) return null;
  if (value.error) {
    return (
      <div style={{ ...diagnosticPanel, borderLeft: "3px solid #b03333" }}>
        <strong>Diagnóstico de execução indisponível</strong>
        <div style={{ marginTop: 4, color: "#6b6b6b", fontSize: 12 }}>{value.error}</div>
      </div>
    );
  }

  const inventory = value.inventory || {};
  const qualification = value.qualification || {};
  const gates = Array.isArray(value.gates) ? value.gates : [];
  const locks = value.locks?.locks || [];
  const history = value.comparison?.history || [];
  const events = value.events || [];
  const categoryTone = {
    executed: "#1f8a59",
    platform_orchestration_failure: "#b03333",
    tool_execution_failure: "#b03333",
    interrupted: "#c25500",
    incomplete_or_unverifiable: "#c25500",
  };

  return (
    <section style={diagnosticPanel}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "baseline", flexWrap: "wrap" }}>
        <div>
          <div className="ds-eyebrow" style={{ color: "var(--brand-700)" }}>Diagnóstico de profundidade</div>
          <h3 style={{ fontSize: 17, margin: "4px 0 0", color: "#1c1c1c" }}>
            O alvo mudou ou a plataforma não executou?
          </h3>
        </div>
        <span style={{ fontSize: 11, color: "#6b6b6b" }}>
          contrato de cobertura v{value.contract_version || 0}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 8, marginTop: 14 }}>
        <DiagnosticMetric label="Alvos selecionados" value={inventory.selected_targets ?? 0} />
        <DiagnosticMetric label="Alvos descartados" value={inventory.dead_targets ?? 0} />
        <DiagnosticMetric label="DNS inconclusivo" value={inventory.dns_inconclusive_targets ?? 0} />
        <DiagnosticMetric
          label="Produtores"
          value={inventory.producers_sealed ? "selados" : (inventory.producer_stage || "em aberto")}
          warning={!inventory.producers_sealed}
        />
        <DiagnosticMetric label="P02 com porta aberta" value={qualification.targets_with_open_ports ?? 0} />
        <DiagnosticMetric label="P06 HTTP vivo" value={qualification.http_live ?? 0} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 10, marginTop: 12 }}>
        {gates.map((gate) => {
          const abnormal = gate.normal_wait === false;
          return (
            <div key={gate.phase_id} style={{ border: `1px solid ${abnormal ? "#e0a4a4" : "#e5dcd5"}`, borderRadius: 8, padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                <strong>{gate.phase_id} · {gate.phase_id === "P02" ? "portas" : "HTTP"}</strong>
                <span style={{ ...chip, ...(abnormal ? chipDanger : chipSuccess), margin: 0 }}>{gate.state}</span>
              </div>
              <div style={{ fontSize: 12, color: "#3d3d3d", marginTop: 8, lineHeight: 1.45 }}>{gate.reason}</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, marginTop: 10, fontSize: 11 }}>
                <span>ativos <strong>{gate.active_items}</strong></span>
                <span>terminais <strong>{gate.terminal_items}</strong></span>
                <span>manifesto <strong>{gate.manifest_targets}</strong></span>
                <span>cobertos <strong>{gate.covered_targets}</strong></span>
                <span>qualificados <strong>{gate.qualified_targets}</strong></span>
                <span>bloqueados <strong>{gate.downstream_blocked}</strong></span>
              </div>
            </div>
          );
        })}
      </div>

      {(locks.length > 0 || (value.capacity || []).length > 0) && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 10, marginTop: 12 }}>
          <div>
            <div style={diagnosticSubtitle}>Locks observados agora</div>
            {locks.map((row) => (
              <div key={row.type} style={diagnosticRow}>
                <span>{row.type}</span>
                <span style={{ color: row.held ? "#c25500" : "#1f8a59" }}>
                  {row.held ? `ocupado · TTL ${row.ttl_seconds}s` : "livre"} · {row.interpretation}
                </span>
              </div>
            ))}
          </div>
          <div>
            <div style={diagnosticSubtitle}>Capacidade e espera</div>
            {(value.capacity || []).map((row) => (
              <div key={row.resource_class} style={diagnosticRow}>
                <span>{row.resource_class}</span>
                <span>
                  global {row.global_inflight}/{row.capacity} · scan ativo {row.scan_active} · fila {row.scan_queued}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {history.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={diagnosticSubtitle}>Comparação dos scans do mesmo alvo</div>
          <div style={{ overflowX: "auto", border: "1px solid #e5dcd5", borderRadius: 8 }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11, whiteSpace: "nowrap" }}>
              <thead>
                <tr style={{ background: "#faf8f4" }}>
                  <th style={th}>Scan</th>
                  <th style={th}>Diagnóstico</th>
                  <th style={th}>Alvos</th>
                  <th style={th}>Itens OK</th>
                  <th style={th}>Falhas</th>
                  <th style={th}>Bloqueados</th>
                  <th style={th}>Ativos</th>
                  <th style={th}>Fases</th>
                  <th style={th}>Tools</th>
                  <th style={th}>Skills executadas</th>
                  <th style={th}>Findings</th>
                  <th style={th}>Confirmadas</th>
                </tr>
              </thead>
              <tbody>
                {history.map((row) => {
                  const assessment = row.assessment || {};
                  const tone = categoryTone[assessment.category] || "#6b6b6b";
                  return (
                    <tr key={row.scan_id} style={{ borderTop: "1px solid #efe7e0" }}>
                      <td style={td}><strong>#{row.scan_id}</strong><div style={{ color: "#6b6b6b" }}>{row.status}</div></td>
                      <td style={td} title={(assessment.evidence || []).join(" · ")}>
                        <strong style={{ color: tone }}>{assessment.label || "—"}</strong>
                        <div style={{ color: "#6b6b6b" }}>
                          {assessment.reliable_negative ? "resultado interpretável" : "resultado não conclusivo"}
                        </div>
                      </td>
                      <td style={td}>{row.targets_selected}</td>
                      <td style={td}>{row.successful_items}</td>
                      <td style={td}>{row.failed_items}</td>
                      <td style={td}>{row.blocked_items}</td>
                      <td style={td}>{row.active_items}</td>
                      <td style={td}>{row.phases_with_success}</td>
                      <td style={td}>{row.tools_with_success}</td>
                      <td style={td}>{row.skills_executed}/{row.skills_attributed}</td>
                      <td style={td}>{row.findings}</td>
                      <td style={td}>{row.confirmed_findings}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(value.blocked_reasons || []).length > 0 && (
        <details style={{ marginTop: 12 }}>
          <summary style={{ cursor: "pointer", fontSize: 12, fontWeight: 600 }}>
            Motivos dos bloqueios
          </summary>
          {(value.blocked_reasons || []).map((row, index) => (
            <div key={`${row.reason}-${index}`} style={diagnosticRow}>
              <span style={{ maxWidth: "85%", overflowWrap: "anywhere" }}>{row.reason}</span>
              <strong>{row.count}</strong>
            </div>
          ))}
        </details>
      )}

      {events.length > 0 && (
        <details style={{ marginTop: 12 }}>
          <summary style={{ cursor: "pointer", fontSize: 12, fontWeight: 600 }}>
            Linha do tempo de decisões ({events.length})
          </summary>
          {events.slice(-12).reverse().map((event, index) => (
            <div key={`${event.created_at}-${index}`} style={diagnosticRow}>
              <span>
                <code style={codeStyle}>{event.event || "evento"}</code>
                <span style={{ marginLeft: 8 }}>{event.created_at || event.at || "—"}</span>
              </span>
              <span style={{ color: event.level === "WARNING" ? "#b03333" : "#6b6b6b" }}>{event.level}</span>
            </div>
          ))}
        </details>
      )}
    </section>
  );
}

function DiagnosticMetric({ label, value, warning = false }) {
  return (
    <div style={{ background: "#faf8f4", border: "1px solid #e5dcd5", borderRadius: 7, padding: "8px 10px" }}>
      <div style={{ color: "#6b6b6b", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</div>
      <div style={{ color: warning ? "#c25500" : "#1c1c1c", fontSize: 17, fontWeight: 700, marginTop: 3 }}>{String(value)}</div>
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
  const [accessGroupId, setAccessGroupId] = useState("");

  useEffect(() => {
    client.get("/api/scans").then((r) => {
      setScans(r.data || []);
      if (!scanId && r.data?.length) {
        setScanId(String(r.data[0].id));
      }
    });
  }, []);

  const scopedScans = useMemo(
    () => scans.filter((scan) => !accessGroupId || String(scan.access_group_id || "") === String(accessGroupId)),
    [scans, accessGroupId],
  );

  useEffect(() => {
    if (scopedScans.some((scan) => String(scan.id) === String(scanId))) return;
    setScanId(scopedScans[0]?.id ? String(scopedScans[0].id) : "");
    setData(null);
  }, [scopedScans, scanId]);

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
    const phases = Array.isArray(data?.phases) ? data.phases : [];
    if (filter === "issues") return phases.filter((p) => ["failed"].includes(p.status));
    if (filter === "ok") return phases.filter((p) => ["completed", "executed"].includes(p.status));
    return phases;
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
    <div className="dpage">
      <div className="page-intro">
        <h2>Phase Monitor.</h2>
        <div className="sub">pipeline de análise de vulnerabilidade de 22 passos · cobertura por fase, ferramentas e falhas</div>
      </div>

      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 18, flexWrap: "wrap" }}>
        <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setScanId(""); }} style={{ minWidth: 220 }} />
        <select
          value={scanId}
          onChange={(e) => setScanId(e.target.value)}
          style={inputStyle}
        >
          {scopedScans.map((s) => (
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
          {/* CYBER KILL CHAIN — 9 phases with completion */}
          {data.kill_chain && data.kill_chain.phases && (
            <div
              style={{
                background: "#ffffff",
                border: "1px solid #e5dcd5",
                borderRadius: 12,
                padding: "16px 18px",
                marginBottom: 18,
                boxShadow: "var(--shadow-card)",
              }}
            >
              <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 12 }}>
                <div>
                  <span className="ds-eyebrow" style={{ color: "var(--brand-700)" }}>Cyber Kill Chain</span>
                  <h3 style={{ fontSize: 18, fontWeight: 700, marginTop: 4, color: "#1c1c1c" }}>Pipeline narrativo do scan</h3>
                </div>
                <div style={{ fontSize: 12, color: "#6b6b6b" }}>
                  {data.kill_chain.phases.filter((p) => p.completed).length}/{data.kill_chain.total} fases concluídas
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 8 }}>
                {data.kill_chain.phases.map((p, idx) => {
                  const tone = p.completed ? "#1f8a59" : p.visited ? "var(--brand-500)" : "#d8cdc4";
                  const bg = p.completed ? "rgba(34,145,96,0.08)" : p.visited ? "rgba(233,99,99,0.08)" : "#fafafa";
                  return (
                    <div
                      key={p.phase}
                      style={{
                        background: bg,
                        border: `1px solid ${tone}`,
                        borderLeft: `3px solid ${tone}`,
                        borderRadius: 8,
                        padding: "10px 12px",
                        position: "relative",
                      }}
                      title={p.executive_pitch}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: tone, fontWeight: 600 }}>
                          {String(idx + 1).padStart(2, "0")}
                        </span>
                        <span style={{ fontSize: 13, fontWeight: 600, color: "#1c1c1c", lineHeight: 1.2 }}>{p.label}</span>
                      </div>
                      <div style={{ fontSize: 11, color: "#6b6b6b", marginTop: 4, lineHeight: 1.4 }}>
                        {p.summary}
                      </div>
                      <div style={{ marginTop: 6, display: "flex", justifyContent: "space-between", fontSize: 10, color: "#9a8e83" }}>
                        <span>{p.node || "—"}</span>
                        <span style={{ color: tone, fontWeight: 600 }}>
                          {p.completed ? "✓ done" : p.visited ? "active" : "pending"}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* HEADER METRICS */}
          {(() => {
            const m = data.metrics || {};
            return (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 18 }}>
                <Metric label="Status" value={data.status ?? "—"} />
                <Metric label="Progress" value={`${data.mission_progress ?? 0}%`} />
                <Metric label="Findings" value={m.findings_total ?? 0} />
                <Metric label="Tool runs" value={m.tool_runs_total ?? 0} />
                <Metric label="Tools success" value={`${m.tools_success ?? 0}/${m.tools_attempted ?? 0}`} accent />
                <Metric label="Iterations" value={`${m.loop_iteration ?? 0}/${m.max_iterations ?? 0}`} />
                <Metric label="Termination" value={data.termination_reason || "-"} />
                <Metric label="Objective met" value={data.objective_met ? "yes" : "no"} />
              </div>
            );
          })()}

          <ReconObservabilityPanel value={data.recon_observability} />

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
                Inventário de tools (Kali Runner)
              </div>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap", fontSize: 13 }}>
                <span><strong style={{ color: "#1f8a59" }}>{data.installation_report.installed.length}</strong> prontas</span>
                <span><strong style={{ color: "#b03333" }}>{data.installation_report.missing.length}</strong> sem profile/binario</span>
                <span><strong>{Math.round((data.installation_report.coverage_ratio || 0) * 100)}%</strong> de cobertura</span>
                <span style={{ color: "#6b6b6b" }}>
                  Used in this scan: <strong>{data.metrics.tools_installed_used_ratio !== undefined ? `${Math.round(data.metrics.tools_installed_used_ratio * 100)}% das prontas` : "—"}</strong>
                </span>
                <span style={{ color: "#6b6b6b" }}>
                  Source: <strong>{data.installation_report.source || "kali_runner"}</strong>
                </span>
              </div>
              {data.installation_report.missing.length > 0 && (
                <details style={{ marginTop: 8 }}>
                  <summary style={{ cursor: "pointer", fontSize: 12, color: "#b03333" }}>
                    Tools sem profile/binário no Kali Runner ({data.installation_report.missing.length})
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
                      <th style={th}>Progresso (alvos)</th>
                      <th style={th}>Tools used</th>
                      <th style={th}>Pendências de tools</th>
                      <th style={th}>Business Logic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((p) => (
                      <tr key={p.id} style={{ background: "#ffffff", borderTop: "1px solid #efe7e0" }}>
                        <td style={td}><code style={codeStyle}>{p.id}</code></td>
                        <td style={td}>{p.title}</td>
                        <td style={td}><StatusBadge status={p.status} /></td>
                        <td style={td}><WqProgress wq={p.work_queue} /></td>
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
                          {/* Kali-ready but unused = red flag (agent skipped) */}
                          {(p.tools_missing_unused || []).slice(0, 6).map((t) => (
                            <span key={t} style={{ ...chip, ...chipDanger }} title="Pronto no Kali mas não executado">{t}</span>
                          ))}
                          {/* unavailable in Kali = neutral */}
                          {(p.tools_missing_uninstalled || p.tools_missing || []).slice(0, 6).map((t) => (
                            <span key={t} style={{ ...chip, ...chipMuted }} title="Sem profile/binário no Kali Runner">{t}*</span>
                          ))}
                          {(p.tools_missing || []).length > 12 && (
                            <span style={{ color: "#6b6b6b", fontSize: 11 }}>
                              +{(p.tools_missing || []).length - 12}
                            </span>
                          )}
                        </td>
                        <td style={td}>
                          {p.business_logic ? (
                            <span style={{ ...chip, ...(p.business_logic.state === "finding" ? chipDanger : p.business_logic.state === "executed_no_finding" ? chipSuccess : chipMuted) }}>
                              {p.business_logic.label}
                              {p.business_logic.findings_count ? ` (${p.business_logic.findings_count})` : ""}
                            </span>
                          ) : (
                            <span style={{ color: "#a0958c" }}>—</span>
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
                  <th style={th}>Backend</th>
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
                    <td style={td}><span style={{ ...chip, ...chipMuted }}>{t.backend || "kali"}</span></td>
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

const diagnosticPanel = {
  background: "#ffffff",
  border: "1px solid #e5dcd5",
  borderLeft: "3px solid var(--brand-500)",
  borderRadius: 10,
  padding: "14px 16px",
  marginBottom: 18,
  boxShadow: "var(--shadow-card)",
};

const diagnosticSubtitle = {
  fontSize: 11,
  color: "#6b6b6b",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  fontWeight: 600,
  marginBottom: 5,
};

const diagnosticRow = {
  display: "flex",
  justifyContent: "space-between",
  gap: 12,
  borderTop: "1px solid #efe7e0",
  padding: "6px 2px",
  fontSize: 11,
  color: "#3d3d3d",
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
