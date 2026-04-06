import { useEffect, useState } from "react";
import client, { getWsBaseUrl } from "../api/client";
import LogTerminal from "../components/LogTerminal";

const RISK_COLOR = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-800 border-yellow-500/40 bg-yellow-100",
  low: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
};

const STATUS_BADGE = {
  completed: "border-emerald-500 bg-emerald-900/40 text-emerald-300",
  running: "border-blue-500 bg-blue-900/40 text-blue-300",
  retrying: "border-amber-500 bg-amber-900/40 text-amber-300",
  queued: "border-slate-600 bg-slate-700 text-slate-300",
  failed: "border-rose-500 bg-rose-900/40 text-rose-300",
  blocked: "border-rose-500 bg-rose-900/40 text-rose-300",
};

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
    if (!value) return "-";
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return "-";
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

      setStatusMessage(`Scan para ${targetName} iniciado com sucesso!`);
      setAuthorizationAccepted({ ...authorizationAccepted, [targetName]: false });
      setExpandedTarget(null);
      setSelectedScanId(null);
      
      // Recarregar targets após criação
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
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold">Targets</h2>
            <p className="mt-1 text-sm text-slate-300">Inventario real de alvos a partir dos scans executados.</p>
          </div>
          <input
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 sm:w-80"
            placeholder="Buscar target"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      {statusMessage && <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">{statusMessage}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando targets...</p>}
        {!loading && filtered.length === 0 && <p className="text-sm text-slate-500">Nenhum target encontrado.</p>}

        <div className="space-y-2">
          {filtered.map((item) => {
            const targetScans = scans
              .filter((scan) => String(scan.target_query || "") === String(item.target || ""))
              .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());

            return (
            <div key={item.target} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex-1">
                  <p className="font-mono text-sm font-semibold">{item.target}</p>
                  <p className="text-xs text-slate-400">
                    ultimo scan: {item.last_scan_at ? new Date(item.last_scan_at).toLocaleString("pt-BR") : "-"}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold uppercase ${STATUS_BADGE[item.last_status] || "border-slate-300 bg-slate-200 text-slate-900"}`}>
                    {item.last_status}
                  </span>
                  <span className={`rounded-md border px-2 py-0.5 text-xs uppercase ${RISK_COLOR[item.highest_severity] || RISK_COLOR.low}`}>
                    risco {item.highest_severity}
                  </span>
                  <button
                    onClick={() => {
                      const willExpand = expandedTarget !== item.target;
                      setExpandedTarget(willExpand ? item.target : null);
                      setSelectedScanId(null);
                    }}
                    className="rounded-md bg-blue-600 px-3 py-1 text-xs font-semibold text-white hover:bg-blue-500"
                  >
                    ▶ Scan
                  </button>
                </div>
              </div>
              <div className="mt-2 grid gap-2 text-xs text-slate-300 sm:grid-cols-4">
                <p>scans: <span className="font-semibold text-white">{item.scans}</span></p>
                <p>findings: <span className="font-semibold text-white">{item.findings_total}</span></p>
                <p>abertos: <span className="font-semibold text-amber-300">{item.findings_open}</span></p>
                <p>modo ultimo scan: <span className="font-semibold text-white">{item.last_mode}</span></p>
              </div>

              {expandedTarget === item.target && (
                <div className="mt-4 border-t border-slate-700 pt-4">
                  <div className="mb-4">
                    <h4 className="text-sm font-semibold text-slate-200">Scans deste target</h4>
                    <p className="mt-1 text-xs text-slate-400">Clique em um scan para acompanhar o log em tempo real.</p>
                    <div className="mt-2 space-y-2">
                      {targetScans.length === 0 && (
                        <p className="text-xs text-slate-500">Nenhum scan encontrado para este target.</p>
                      )}
                      {targetScans.slice(0, 8).map((scan) => {
                        const isSelected = selectedScanId === scan.id;
                        return (
                          <button
                            key={scan.id}
                            onClick={() => setSelectedScanId(scan.id)}
                            className={`w-full rounded-lg border px-3 py-2 text-left text-xs transition-colors ${
                              isSelected
                                ? "border-cyan-500/60 bg-cyan-500/10"
                                : "border-slate-700 bg-slate-900/50 hover:bg-slate-800/70"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-semibold text-slate-100">Scan #{scan.id}</span>
                              <span className={`rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase ${STATUS_BADGE[scan.status] || "border-slate-300 bg-slate-200 text-slate-900"}`}>
                                {scan.status}
                              </span>
                            </div>
                            <div className="mt-1 text-[11px] text-slate-400">
                              criado em {fmtDateTime(scan.created_at)} | modo {scan.mode || "-"}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {selectedScanId && (
                    <div className="mb-4 space-y-2 rounded-xl border border-slate-700 bg-slate-900/40 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <p className="text-slate-300">
                          Acompanhando scan <span className="font-semibold text-cyan-300">#{selectedScanId}</span>
                        </p>
                        <p className="text-slate-400">
                          WS: <span className={wsConnected ? "text-emerald-300" : "text-rose-300"}>{wsConnected ? "conectado" : "desconectado"}</span>
                        </p>
                      </div>
                      <div className="text-xs text-slate-400">
                        status atual: <span className="font-semibold text-slate-200">{scanStatus?.status || "-"}</span>
                        {scanStatus?.current_step ? ` | etapa: ${scanStatus.current_step}` : ""}
                      </div>
                      <LogTerminal logs={logs} />
                    </div>
                  )}

                  <div className="space-y-3">
                    <select
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                      value={scanMode}
                      onChange={(e) => setScanMode(e.target.value)}
                    >
                      <option value="single">Unitario</option>
                      <option value="scheduled">Agendado</option>
                    </select>
                    <label className="flex items-start gap-3 rounded-lg border border-slate-700 bg-slate-800/50 p-3 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        checked={authorizationAccepted[item.target] || false}
                        onChange={(e) => setAuthorizationAccepted({ ...authorizationAccepted, [item.target]: e.target.checked })}
                        className="mt-1"
                      />
                      <span>
                        Autorizo a execução de scan neste target e confirmo que possuo permissão formal para isso.
                      </span>
                    </label>
                    <button
                      onClick={() => authorizeAndCreateScan(item.target)}
                      disabled={!authorizationAccepted[item.target] || submitting}
                      className="w-full rounded-lg bg-green-600 px-4 py-2 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40 hover:bg-green-500"
                    >
                      {submitting ? "Iniciando..." : "Iniciar Scan"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )})}
        </div>
      </section>
    </main>
  );
}
