import { Fragment, useEffect, useState } from "react";
import client, { getWsBaseUrl } from "../api/client";
import LogTerminal from "../components/LogTerminal";

const SEV_CLASS = {
  critical: "b-critical",
  high: "b-high",
  medium: "b-medium",
  low: "b-low",
  info: "b-info",
};

const STATUS_DOT = {
  completed: "ok",
  running: "run",
  retrying: "warn",
  queued: "idle",
  failed: "crit",
  blocked: "crit",
};

function gradeFromSeverity(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "F";
  if (s === "high") return "D";
  if (s === "medium") return "C";
  if (s === "low") return "B";
  return "A";
}

export default function TargetsPage() {
  const [rows, setRows] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [expandedTarget, setExpandedTarget] = useState(null);
  const [authorizationAccepted, setAuthorizationAccepted] = useState({});
  const [scanMode, setScanMode] = useState("single");
  const [submitting, setSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [scanStatus, setScanStatus] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);

  const fmtDateTime = (value) => {
    if (!value) return "—";
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return "—";
    return dt.toLocaleString("pt-BR");
  };

  const loadScans = async () => {
    const { data } = await client.get("/api/scans");
    setScans(data || []);
  };

  const loadLogs = async (scanId) => {
    const { data } = await client.get(`/api/scans/${scanId}/logs`);
    setLogs(data || []);
  };

  const loadScanStatus = async (scanId) => {
    const { data } = await client.get(`/api/scans/${scanId}/status`);
    setScanStatus(data || null);
  };

  const loadTargets = async () => {
    const { data } = await client.get("/api/targets/summary");
    setRows(data || []);
  };

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        await Promise.all([loadTargets(), loadScans()]);
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar targets.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      loadScans().catch(() => null);
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!selectedScanId) {
      setLogs([]);
      setScanStatus(null);
      setWsConnected(false);
      return;
    }

    loadLogs(selectedScanId);
    loadScanStatus(selectedScanId);

    const wsBase = getWsBaseUrl();
    const token = localStorage.getItem("token") || "";
    const ws = new WebSocket(`${wsBase}/ws/scans/${selectedScanId}/logs?token=${encodeURIComponent(token)}`);

    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => setWsConnected(false);
    ws.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === "logs") {
        setLogs((prev) => {
          const map = new Map(prev.map((l) => [l.id, l]));
          for (const item of payload.items || []) map.set(item.id, item);
          return Array.from(map.values()).sort((a, b) => a.id - b.id);
        });
      }
    };

    const timer = setInterval(() => loadScanStatus(selectedScanId), 2000);
    return () => {
      clearInterval(timer);
      ws.close();
    };
  }, [selectedScanId]);

  const filtered = rows.filter((item) => {
    const target = String(item.target || "").toLowerCase();
    return target.includes(query.trim().toLowerCase());
  });

  const totals = rows.reduce(
    (acc, r) => ({
      scans: acc.scans + Number(r.scans || 0),
      findings: acc.findings + Number(r.findings_total || 0),
      open: acc.open + Number(r.findings_open || 0),
    }),
    { scans: 0, findings: 0, open: 0 }
  );

  const authorizeAndCreateScan = async (targetName) => {
    if (!authorizationAccepted[targetName]) {
      setStatusMessage("Confirme a autorização antes de executar o scan.");
      return;
    }

    setSubmitting(true);
    setStatusMessage("");
    try {
      try {
        await client.post("/api/policy/allowlist", {
          target_pattern: targetName,
          tool_group: "*",
          is_active: true,
        });
      } catch {
        // Allowlist pode já existir
      }

      await client.post("/api/scans", {
        target_query: targetName,
        mode: scanMode,
        access_group_id: null,
      });

      setStatusMessage(`Scan para ${targetName} iniciado com sucesso.`);
      setAuthorizationAccepted({ ...authorizationAccepted, [targetName]: false });
      setExpandedTarget(null);
      setSelectedScanId(null);

      setTimeout(() => {
        const reload = async () => {
          try {
            await Promise.all([loadTargets(), loadScans()]);
          } catch {}
        };
        reload();
      }, 2000);
    } catch (err) {
      setStatusMessage(err?.response?.data?.detail || err?.message || "Falha ao criar scan.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="dpage">
      {/* KPI strip */}
      <section className="grid-4" style={{ marginBottom: 22 }}>
        <div className="kpi">
          <div className="k">Alvos no escopo</div>
          <div className="v">{rows.length}</div>
          <div className="hint">inventário a partir dos scans executados</div>
        </div>
        <div className="kpi">
          <div className="k">Findings abertos</div>
          <div className="v" style={{ color: "var(--brand-500)" }}>{totals.open}</div>
          <div className="hint">aguardando triagem ou correção</div>
        </div>
        <div className="kpi">
          <div className="k">Total de findings</div>
          <div className="v">{totals.findings}</div>
          <div className="hint">consolidado em todos os alvos</div>
        </div>
        <div className="kpi">
          <div className="k">Scans executados</div>
          <div className="v">{totals.scans}</div>
          <div className="hint">recon · vuln · OSINT</div>
        </div>
      </section>

      {error && <div className="err-box" style={{ marginBottom: 16 }}>{error}</div>}
      {statusMessage && (
        <div
          style={{
            marginBottom: 16, padding: "12px 16px", borderRadius: 10, fontSize: 13,
            border: "1px solid var(--sev-medium-border)", background: "var(--sev-medium-bg)", color: "var(--sev-medium-text)",
          }}
        >
          {statusMessage}
        </div>
      )}

      {/* Targets table */}
      <section className="t-wrap">
        <div className="t-head">
          <div>
            <h3>Alvos monitorados</h3>
            <div className="sub">cada linha é um asset autorizado · recon contínuo, vuln e OSINT</div>
          </div>
          <div className="t-tools">
            <div className="search">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></svg>
              <input placeholder="Buscar host, IP, tag…" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
            <button className="filter active">Todos · {filtered.length}</button>
          </div>
        </div>

        {loading && (
          <div className="state"><div><div className="spin" /><p className="st-title">Carregando alvos…</p></div></div>
        )}
        {!loading && filtered.length === 0 && <div className="empty">Nenhum target encontrado.</div>}

        {!loading && filtered.length > 0 && (
          <table className="t">
            <thead>
              <tr>
                <th>Host / Asset</th>
                <th>Rating</th>
                <th>Status</th>
                <th>Risco</th>
                <th>Scans</th>
                <th>Findings</th>
                <th>Abertos</th>
                <th>Último scan</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => {
                const targetScans = scans
                  .filter((scan) => String(scan.target_query || "") === String(item.target || ""))
                  .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
                const grade = gradeFromSeverity(item.highest_severity);
                const isExpanded = expandedTarget === item.target;

                return (
                  <Fragment key={item.target}>
                    <tr>
                      <td>
                        <div style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: "var(--ink)" }}>{item.target}</div>
                        <div className="mono-sm muted" style={{ marginTop: 2 }}>modo {item.last_mode || "—"}</div>
                      </td>
                      <td>
                        <span className={`grade-pill grade-${grade}`}>{grade}</span>
                      </td>
                      <td>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
                          <span className={`dot-state ${STATUS_DOT[item.last_status] || "idle"}`} />
                          <span className="mono-sm">{item.last_status || "—"}</span>
                        </span>
                      </td>
                      <td><span className={`b ${SEV_CLASS[item.highest_severity] || "b-low"}`}>{item.highest_severity || "low"}</span></td>
                      <td className="mono">{item.scans}</td>
                      <td className="mono">{item.findings_total}</td>
                      <td className="mono" style={{ color: "var(--brand-700)", fontWeight: 600 }}>{item.findings_open}</td>
                      <td className="mono-sm muted">{fmtDateTime(item.last_scan_at)}</td>
                      <td>
                        <button
                          className="btn btn-primary"
                          style={{ padding: "6px 12px", fontSize: 12 }}
                          onClick={() => {
                            setExpandedTarget(isExpanded ? null : item.target);
                            setSelectedScanId(null);
                          }}
                        >
                          {isExpanded ? "Fechar" : "Scan"}
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={9} style={{ background: "var(--surface-soft)" }}>
                          <div style={{ display: "grid", gap: 16, gridTemplateColumns: "1fr 1fr" }}>
                            <div>
                              <h4 style={{ fontFamily: "var(--font-display)", fontSize: 13, fontWeight: 600, margin: "0 0 8px" }}>Scans deste target</h4>
                              {targetScans.length === 0 && <p className="mono-sm muted">Nenhum scan encontrado para este target.</p>}
                              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                                {targetScans.slice(0, 8).map((scan) => (
                                  <button
                                    key={scan.id}
                                    onClick={() => setSelectedScanId(scan.id)}
                                    style={{
                                      textAlign: "left", padding: "8px 12px", borderRadius: 7, cursor: "pointer",
                                      border: `1px solid ${selectedScanId === scan.id ? "var(--brand-500)" : "var(--line)"}`,
                                      background: selectedScanId === scan.id ? "rgba(233,99,99,0.06)" : "var(--surface)",
                                    }}
                                  >
                                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                                      <b>Scan #{scan.id}</b>
                                      <span className={`dot-state ${STATUS_DOT[scan.status] || "idle"}`} />
                                    </div>
                                    <div className="mono-sm muted" style={{ marginTop: 3 }}>{fmtDateTime(scan.created_at)} · modo {scan.mode || "—"}</div>
                                  </button>
                                ))}
                              </div>

                              {selectedScanId && (
                                <div style={{ marginTop: 12 }}>
                                  <div className="mono-sm muted" style={{ marginBottom: 6 }}>
                                    Scan #{selectedScanId} · WS{" "}
                                    <span style={{ color: wsConnected ? "var(--sev-low-text)" : "var(--sev-critical-text)" }}>
                                      {wsConnected ? "conectado" : "desconectado"}
                                    </span>
                                    {scanStatus?.status ? ` · ${scanStatus.status}` : ""}
                                  </div>
                                  <LogTerminal logs={logs} />
                                </div>
                              )}
                            </div>

                            <div>
                              <h4 style={{ fontFamily: "var(--font-display)", fontSize: 13, fontWeight: 600, margin: "0 0 8px" }}>Novo scan</h4>
                              <select
                                className="w-full"
                                value={scanMode}
                                onChange={(e) => setScanMode(e.target.value)}
                                style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid var(--line)", fontSize: 13, marginBottom: 10 }}
                              >
                                <option value="single">Unitário</option>
                                <option value="scheduled">Agendado</option>
                              </select>
                              <label style={{ display: "flex", gap: 10, alignItems: "flex-start", fontSize: 12, color: "var(--ink-soft)", padding: "10px 12px", border: "1px solid var(--line)", borderRadius: 8, background: "var(--surface)", marginBottom: 10 }}>
                                <input
                                  type="checkbox"
                                  checked={authorizationAccepted[item.target] || false}
                                  onChange={(e) => setAuthorizationAccepted({ ...authorizationAccepted, [item.target]: e.target.checked })}
                                  style={{ marginTop: 2 }}
                                />
                                <span>Autorizo a execução de scan neste target e confirmo que possuo permissão formal para isso.</span>
                              </label>
                              <button
                                className="btn btn-primary"
                                style={{ width: "100%", justifyContent: "center" }}
                                onClick={() => authorizeAndCreateScan(item.target)}
                                disabled={!authorizationAccepted[item.target] || submitting}
                              >
                                {submitting ? "Iniciando…" : "Iniciar scan"}
                              </button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
