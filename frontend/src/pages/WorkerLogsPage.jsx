import { useEffect, useRef, useState } from "react";
import client from "../api/client";
import ExecutionCard from "../components/worker-logs/ExecutionCard";
import LogLine from "../components/worker-logs/LogLine";
import { copyText, getMessageText, statusColor, toolColor, toolFromMsg } from "../components/worker-logs/utils";

// ── Main page ─────────────────────────────────────────────────────────────────
export default function WorkerLogsPage() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [toolFilter, setToolFilter] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [activeTab, setActiveTab] = useState("executions"); // executions | logs
  const logEndRef = useRef(null);
  const mountedRef = useRef(true);
  const requestIdRef = useRef(0);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // ── Initial load: fetch scan list ─────────────────────────────────────────
  const fetchScans = async () => {
    try {
      const res = await client.get("/api/admin/worker-logs");
      if (mountedRef.current) {
        setScans(res.data?.scans || []);
      }
    } catch {
      // silently ignore — scan list will be filled on first per-scan fetch
    }
  };

  useEffect(() => { fetchScans(); }, []);

  // ── Fetch verbose logs for selected scan ──────────────────────────────────
  const fetchLogs = async (scanId, tool) => {
    if (!scanId) return;
    const currentRequestId = ++requestIdRef.current;
    setLoading(true);
    setError("");
    try {
      const params = { scan_id: scanId, limit: 2000 };
      if (tool) params.tool = tool;
      const res = await client.get("/api/admin/worker-logs", { params });
      if (!mountedRef.current || currentRequestId !== requestIdRef.current) {
        return;
      }
      setData(res.data);
      if (res.data?.scans?.length) setScans(res.data.scans);
    } catch (err) {
      if (mountedRef.current && currentRequestId === requestIdRef.current) {
        setError(err?.response?.data?.detail || "Falha ao carregar logs.");
      }
    } finally {
      if (mountedRef.current && currentRequestId === requestIdRef.current) {
        setLoading(false);
      }
    }
  };

  // auto-refresh when a scan is running
  useEffect(() => {
    if (!autoRefresh || !selectedScan) return;
    const t = setInterval(() => fetchLogs(selectedScan, toolFilter || undefined), 5000);
    return () => clearInterval(t);
  }, [autoRefresh, selectedScan, toolFilter]);

  // scroll logs to bottom on new data
  useEffect(() => {
    if (activeTab === "logs") logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [data?.logs?.length, activeTab]);

  const onScanChange = (id) => {
    setSelectedScan(id ? Number(id) : null);
    setData(null);
    setToolFilter("");
    if (id) fetchLogs(Number(id));
  };

  const onFilterChange = (tool) => {
    setToolFilter(tool);
    if (selectedScan) fetchLogs(selectedScan, tool || undefined);
  };

  const scanInfo = data?.scan;
  const executions = data?.executions || [];
  const logs = data?.logs || [];
  const toolSummary = data?.tool_summary || [];

  const allTools = [...new Set([
    ...executions.map((entry) => entry.tool),
    ...toolSummary.map((entry) => entry.tool),
  ].filter(Boolean))].sort();

  const filteredExecutions = toolFilter
    ? executions.filter((e) => e.tool === toolFilter)
    : executions;

  const filteredLogs = toolFilter
    ? logs.filter((entry) => {
        const message = getMessageText(entry.message);
        return toolFromMsg(message) === toolFilter || message.includes(`tool=${toolFilter}`);
      })
    : logs;

  const isRunning = scanInfo?.status === "running" || scanInfo?.status === "retrying";

  const tabBtn = (id, label, count) => (
    <button
      onClick={() => setActiveTab(id)}
      className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
        activeTab === id
          ? "bg-[#1A365D] text-white"
          : "border border-slate-700 text-slate-400 hover:text-slate-200"
      }`}
    >
      {label}
      {count != null && (
        <span className="ml-1.5 rounded-full bg-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300">{count}</span>
      )}
    </button>
  );

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <section className="panel p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-100">Worker Logs — Execução Detalhada</h2>
            <p className="mt-1 text-sm text-slate-400">
              Logs completos de stdout/stderr por ferramenta por scan. Verbosidade máxima.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {/* Scan selector */}
            <select
              value={selectedScan || ""}
              onChange={(e) => onScanChange(e.target.value)}
              className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">— selecionar scan —</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} {s.target_query} [{s.status}]
                </option>
              ))}
            </select>

            {/* Tool filter */}
            {allTools.length > 0 && (
              <select
                value={toolFilter}
                onChange={(e) => onFilterChange(e.target.value)}
                className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">todas as ferramentas</option>
                {allTools.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            )}

            {/* Auto-refresh */}
            {isRunning && (
              <label className="flex items-center gap-1.5 cursor-pointer text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                  className="accent-blue-500"
                />
                auto-refresh
              </label>
            )}

            <button
              onClick={() => fetchLogs(selectedScan, toolFilter || undefined)}
              disabled={!selectedScan || loading}
              className="rounded-xl bg-blue-600 px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-50 hover:bg-blue-500 transition-colors"
            >
              {loading ? "…" : "Atualizar"}
            </button>
          </div>
        </div>
      </section>

      {error && (
        <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">
          {error}
        </section>
      )}

      {/* ── Scan info ──────────────────────────────────────────────────────── */}
      {scanInfo && (
        <section className="panel p-4">
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <span className="font-mono font-bold text-slate-100">#{scanInfo.id}</span>
            <span className="text-slate-300">{scanInfo.target_query}</span>
            <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${statusColor(scanInfo.status)}`}>
              {scanInfo.status}
            </span>
            <span className="text-slate-500 text-xs">progresso: {scanInfo.mission_progress}%</span>
            <span className="text-slate-500 text-xs">passo: {scanInfo.current_step}</span>
            <span className="text-slate-500 text-xs">
              {scanInfo.created_at ? new Date(scanInfo.created_at).toLocaleString("pt-BR") : ""}
            </span>
          </div>
        </section>
      )}

      {/* ── Tool summary badges ────────────────────────────────────────────── */}
      {toolSummary.length > 0 && (
        <section className="panel p-4">
          <p className="text-xs text-slate-500 mb-3 uppercase tracking-widest font-semibold">Resumo por ferramenta</p>
          <div className="flex flex-wrap gap-2">
            {toolSummary.map((ts) => (
              <button
                key={ts.tool}
                onClick={() => onFilterChange(toolFilter === ts.tool ? "" : ts.tool)}
                className={`rounded-xl border px-3 py-1.5 text-xs font-mono font-semibold transition-colors ${
                  toolFilter === ts.tool ? toolColor(ts.tool) : "border-slate-700 bg-slate-900 text-slate-400 hover:text-slate-200"
                }`}
              >
                {ts.tool}
                <span className="ml-1 text-[10px]">
                  {ts.executed > 0 && <span className="text-emerald-400 ml-1">✓{ts.executed}</span>}
                  {ts.skipped > 0 && <span className="text-amber-400 ml-1">⊘{ts.skipped}</span>}
                  {ts.failed > 0 && <span className="text-rose-400 ml-1">✗{ts.failed}</span>}
                </span>
              </button>
            ))}
          </div>
        </section>
      )}

      {/* ── Tabs ───────────────────────────────────────────────────────────── */}
      {data && (
        <>
          <div className="flex gap-2">
            {tabBtn("executions", "Execuções", filteredExecutions.length)}
            {tabBtn("logs", "Logs do Worker", filteredLogs.length)}
          </div>

          {/* ── EXECUTIONS tab ────────────────────────────────────────────── */}
          {activeTab === "executions" && (
            <section className="panel p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-base font-semibold text-slate-100">
                  Execuções de Ferramentas{toolFilter ? ` — ${toolFilter}` : ""}
                </h3>
                <button
                  onClick={() => copyText(JSON.stringify(filteredExecutions, null, 2), "JSON das execucoes copiado.")}
                  className="text-xs text-slate-500 hover:text-slate-300 border border-slate-700 rounded px-2 py-0.5 transition-colors"
                >
                  copiar JSON
                </button>
              </div>
              {filteredExecutions.length === 0 ? (
                <p className="text-sm text-slate-500 mt-2">
                  {selectedScan ? "Nenhuma execução registrada para este scan." : "Selecione um scan para ver execuções."}
                </p>
              ) : (
                <div className="space-y-1">
                  {filteredExecutions.map((run) => (
                    <ExecutionCard key={run.id} run={run} />
                  ))}
                </div>
              )}
            </section>
          )}

          {/* ── LOGS tab ──────────────────────────────────────────────────── */}
          {activeTab === "logs" && (
            <section className="panel p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-base font-semibold text-slate-100">
                  Logs do Worker{toolFilter ? ` — ${toolFilter}` : ""}{" "}
                  <span className="text-xs text-slate-500 font-normal ml-2">({filteredLogs.length} linhas)</span>
                </h3>
                <button
                  onClick={() => copyText(filteredLogs.map((entry) => `[${entry.level}] ${getMessageText(entry.message)}`).join("\n"), "Logs copiados.")}
                  className="text-xs text-slate-500 hover:text-slate-300 border border-slate-700 rounded px-2 py-0.5 transition-colors"
                >
                  copiar texto
                </button>
              </div>
              {filteredLogs.length === 0 ? (
                <p className="text-sm text-slate-500">
                  {selectedScan ? "Nenhum log encontrado para este filtro." : "Selecione um scan."}
                </p>
              ) : (
                <div className="bg-slate-950/60 rounded-xl p-3 max-h-[60vh] overflow-y-auto font-mono text-xs">
                  {filteredLogs.map((row) => (
                    <LogLine key={row.id} row={row} />
                  ))}
                  <div ref={logEndRef} />
                </div>
              )}
            </section>
          )}
        </>
      )}
    </main>
  );
}
