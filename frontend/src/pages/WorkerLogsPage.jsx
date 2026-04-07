import { useEffect, useRef, useState } from "react";
import client from "../api/client";

// ── status colours ──────────────────────────────────────────────────────────
const STATUS_COLORS = {
  executed: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  success:  "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  skipped:  "bg-amber-500/20  text-amber-300  border-amber-500/40",
  failed:   "bg-rose-500/20   text-rose-300   border-rose-500/40",
  error:    "bg-rose-500/20   text-rose-300   border-rose-500/40",
  unknown:  "bg-slate-700/60  text-slate-400  border-slate-600",
};
const statusColor = (s) =>
  STATUS_COLORS[String(s || "unknown").toLowerCase()] || STATUS_COLORS.unknown;

// ── log level colours ───────────────────────────────────────────────────────
const LEVEL_COLORS = {
  DEBUG:   "text-slate-400",
  INFO:    "text-sky-300",
  WARNING: "text-amber-300",
  ERROR:   "text-rose-400",
  CRITICAL:"text-rose-500 font-bold",
};
const levelColor = (l) => LEVEL_COLORS[String(l || "INFO").toUpperCase()] || "text-slate-300";

// ── tool badge colours per group ─────────────────────────────────────────────
const TOOL_PALETTE = {
  nmap:         "border-purple-500/50 bg-purple-500/10 text-purple-300",
  "nmap-vulscan": "border-violet-500/50 bg-violet-500/10 text-violet-300",
  amass:        "border-cyan-500/50   bg-cyan-500/10   text-cyan-300",
  massdns:      "border-teal-500/50   bg-teal-500/10   text-teal-300",
  sublist3r:    "border-sky-500/50    bg-sky-500/10    text-sky-300",
  "shodan-cli": "border-orange-500/50 bg-orange-500/10 text-orange-300",
  "burp-cli":   "border-red-500/50    bg-red-500/10    text-red-300",
  nikto:        "border-pink-500/50   bg-pink-500/10   text-pink-300",
  nuclei:       "border-indigo-500/50 bg-indigo-500/10 text-indigo-300",
};
const toolColor = (t) =>
  TOOL_PALETTE[String(t || "").toLowerCase()] ||
  "border-slate-600 bg-slate-800/60 text-slate-300";

// ── parse tool name from a log message  "prefix: tool=nmap status=..." ───────
const _toolFromMsg = (msg) => {
  const m = /tool=([a-z0-9_\-.]+)/i.exec(msg || "");
  return m ? m[1].toLowerCase() : null;
};

// ── split a raw log line into labelled segments ───────────────────────────────
const _segments = (msg) => {
  // Lines starting with a tool log prefix like  "RECON/nmap: tool=nmap ..."
  const kv = /(tool|status|return_code|cmd|stdout|stderr|dispatch_task|dispatch_error|dispatch_id|skipped|findings_extraidas|tool_findings)=/.test(msg);
  if (!kv) return [{ type: "plain", text: msg }];

  const segs = [];
  let rest = msg;

  // prefix (everything before the first kv pair)
  const firstKV = rest.search(/(tool|status|return_code|cmd|stdout|stderr|dispatch_task|dispatch_error|dispatch_id|skipped)=/);
  if (firstKV > 0) {
    segs.push({ type: "prefix", text: rest.slice(0, firstKV).replace(/:\s*$/, "") });
    rest = rest.slice(firstKV);
  }

  // split on known keys
  const re = /\b(tool|status|return_code|cmd|stdout|stderr|dispatch_task|dispatch_error|dispatch_id|skipped|findings_extraidas|tool_findings)=([^\s]*)/g;
  let match;
  while ((match = re.exec(rest)) !== null) {
    segs.push({ type: "kv", key: match[1], val: match[2] });
  }
  return segs;
};

// ── copy to clipboard helper ──────────────────────────────────────────────────  
const copyText = (text) => {
  try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
};

// ── segment renderer ──────────────────────────────────────────────────────────
function LogSegments({ msg }) {
  const segs = _segments(msg);
  return (
    <span className="break-all">
      {segs.map((s, i) => {
        if (s.type === "plain") return <span key={i}>{s.text}</span>;
        if (s.type === "prefix") return <span key={i} className="text-slate-500 mr-1">{s.text}</span>;
        const { key, val } = s;
        const keyColor = {
          tool:           "text-sky-400",
          status:         "text-emerald-400",
          return_code:    "text-yellow-400",
          cmd:            "text-violet-400",
          stdout:         "text-slate-300",
          stderr:         "text-rose-400",
          dispatch_error: "text-rose-400",
          skipped:        "text-amber-400",
        }[key] || "text-slate-400";
        return (
          <span key={i} className="mr-2">
            <span className={`${keyColor} font-semibold`}>{key}</span>
            <span className="text-slate-600">=</span>
            <span className="text-slate-200">{val}</span>
          </span>
        );
      })}
    </span>
  );
}

// ── ExecutionCard: one executed tool run ──────────────────────────────────────
function ExecutionCard({ run }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`rounded-xl border ${toolColor(run.tool)} mb-2`}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex flex-wrap items-center gap-2 px-4 py-2 text-left hover:bg-white/5 transition-colors"
      >
        <span className="font-mono text-sm font-bold">{run.tool}</span>
        <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${statusColor(run.status)}`}>
          {run.status}
        </span>
        <span className="text-xs text-slate-400 font-mono">{run.target}</span>
        {run.execution_time_seconds != null && (
          <span className="ml-auto text-xs text-slate-500">{Number(run.execution_time_seconds).toFixed(1)}s</span>
        )}
        <span className="text-slate-600 text-xs ml-1">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="border-t border-white/10 px-4 pb-3 pt-2 space-y-2 text-xs">
          {run.error_message && (
            <div>
              <p className="text-slate-500 mb-1 font-semibold uppercase tracking-widest text-[10px]">Erro / saída</p>
              <pre className="whitespace-pre-wrap break-all bg-slate-950/70 rounded p-2 text-rose-300 font-mono leading-relaxed max-h-48 overflow-y-auto">
                {run.error_message}
              </pre>
            </div>
          )}
          <p className="text-slate-500">
            Iniciado em: <span className="text-slate-300">{run.created_at ? new Date(run.created_at).toLocaleString("pt-BR") : "-"}</span>
          </p>
        </div>
      )}
    </div>
  );
}

// ── LogLine ───────────────────────────────────────────────────────────────────
function LogLine({ row }) {
  const tool = _toolFromMsg(row.message);
  return (
    <div className="flex items-start gap-2 py-0.5 hover:bg-white/5 rounded px-1">
      <span className="shrink-0 text-slate-600 font-mono text-[10px] w-28 pt-0.5">
        {row.created_at ? new Date(row.created_at).toLocaleTimeString("pt-BR") : ""}
      </span>
      <span className={`shrink-0 text-[10px] w-14 font-bold uppercase pt-0.5 ${levelColor(row.level)}`}>
        {row.level}
      </span>
      {tool && (
        <span className={`shrink-0 text-[10px] rounded border px-1.5 py-0 font-mono ${toolColor(tool)}`}>
          {tool}
        </span>
      )}
      <span className={`text-xs font-mono flex-1 ${levelColor(row.level)}`}>
        <LogSegments msg={row.message} />
      </span>
    </div>
  );
}

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

  // ── Initial load: fetch scan list ─────────────────────────────────────────
  const fetchScans = async () => {
    try {
      const res = await client.get("/api/admin/worker-logs");
      setScans(res.data?.scans || []);
    } catch {
      // silently ignore — scan list will be filled on first per-scan fetch
    }
  };

  useEffect(() => { fetchScans(); }, []);

  // ── Fetch verbose logs for selected scan ──────────────────────────────────
  const fetchLogs = async (scanId, tool) => {
    if (!scanId) return;
    setLoading(true);
    setError("");
    try {
      const params = { scan_id: scanId, limit: 2000 };
      if (tool) params.tool = tool;
      const res = await client.get("/api/admin/worker-logs", { params });
      setData(res.data);
      if (res.data?.scans?.length) setScans(res.data.scans);
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar logs.");
    } finally {
      setLoading(false);
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

  const allTools = [...new Set(executions.map((e) => e.tool))].sort();

  const filteredExecutions = toolFilter
    ? executions.filter((e) => e.tool === toolFilter)
    : executions;

  const filteredLogs = toolFilter
    ? logs.filter((l) => _toolFromMsg(l.message) === toolFilter || l.message.includes(`tool=${toolFilter}`))
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
                  onClick={() => copyText(JSON.stringify(filteredExecutions, null, 2))}
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
                  onClick={() => copyText(filteredLogs.map((l) => `[${l.level}] ${l.message}`).join("\n"))}
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
