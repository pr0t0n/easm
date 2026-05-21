import { useEffect, useMemo, useRef, useState } from "react";
import client from "../api/client";
import ExecutionCard from "../components/worker-logs/ExecutionCard";
import LogLine from "../components/worker-logs/LogLine";
import { copyText, getMessageText, statusColor, toolColor, toolFromMsg } from "../components/worker-logs/utils";

const PHASE_STATUS = {
  executed: { label: "OK", color: "var(--sev-low-text)", bg: "var(--sev-low-bg)" },
  partial_coverage: { label: "Parcial", color: "var(--sev-high-text)", bg: "var(--sev-high-bg)" },
  attempted_failed: { label: "Falha", color: "var(--sev-critical-text)", bg: "var(--sev-critical-bg)" },
  pending: { label: "Pendente", color: "var(--ink-muted)", bg: "var(--surface-soft)" },
  skipped: { label: "Ignorada", color: "var(--ink-muted)", bg: "var(--surface-soft)" },
};

function fmtTime(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "-";
  return dt.toLocaleString("pt-BR");
}

function pct(value) {
  const n = Number(value || 0);
  return Math.max(0, Math.min(100, n));
}

function metricCard(label, value, tone = "var(--ink)") {
  return (
    <div className="kpi">
      <div className="k">{label}</div>
      <div className="v" style={{ color: tone }}>{value}</div>
    </div>
  );
}

function phaseTone(status) {
  return PHASE_STATUS[status] || PHASE_STATUS.pending;
}

function phaseLabel(phase) {
  return `${phase?.id || "--"} ${phase?.title || phase?.phase || ""}`.trim();
}

function CommunicationNode({ label, sub, state = "idle" }) {
  const palette = {
    ok: ["var(--sev-low-bg)", "var(--sev-low-border)", "var(--sev-low-text)"],
    warn: ["var(--sev-high-bg)", "var(--sev-high-border)", "var(--sev-high-text)"],
    crit: ["var(--sev-critical-bg)", "var(--sev-critical-border)", "var(--sev-critical-text)"],
    run: ["rgba(45,82,230,0.08)", "rgba(45,82,230,0.28)", "var(--sev-low-text)"],
    idle: ["var(--surface)", "var(--line)", "var(--ink-soft)"],
  }[state] || ["var(--surface)", "var(--line)", "var(--ink-soft)"];

  return (
    <div
      style={{
        minWidth: 150,
        border: `1px solid ${palette[1]}`,
        background: palette[0],
        borderRadius: 8,
        padding: "10px 12px",
      }}
    >
      <div style={{ color: palette[2], fontSize: 12, fontWeight: 800 }}>{label}</div>
      <div className="mono-sm muted" style={{ marginTop: 3 }}>{sub || "-"}</div>
    </div>
  );
}

function CommunicationMap({ data, health, phaseData }) {
  const executions = data?.executions || [];
  const logs = data?.logs || [];
  const failed = executions.some((run) => String(run.status || "").toLowerCase().includes("fail"));
  const running = ["running", "retrying", "queued"].includes(String(data?.scan?.status || "").toLowerCase());
  const workers = health?.workers || [];
  const onlineWorkers = workers.filter((worker) => worker.online).length;
  const activeWorker = workers.find((worker) => worker.active_scan?.id === data?.scan?.id);
  const kaliMessage = logs.find((row) => /kali|mcp|runner|job/i.test(getMessageText(row.message)));
  const validatorBlocked = /blocked|validator|falha|failed/i.test(data?.scan?.current_step || "");

  const nodes = [
    { label: "Supervisor", sub: `${data?.traces?.length || 0} eventos`, state: failed ? "crit" : running ? "run" : "ok" },
    { label: "Phase Validator", sub: phaseData?.current_pentest_phase_id || data?.scan?.current_step, state: validatorBlocked ? "crit" : "ok" },
    { label: "Workers", sub: `${onlineWorkers}/${workers.length || 0} online${activeWorker ? ` · ${activeWorker.execution_phase}` : ""}`, state: onlineWorkers ? "ok" : "warn" },
    { label: "MCP", sub: `${data?.activities?.length || 0} ciclos agente`, state: failed ? "warn" : "ok" },
    { label: "Kali Runner", sub: kaliMessage ? "respostas detectadas" : "aguardando saída", state: failed ? "warn" : "ok" },
    { label: "Evidências", sub: `${phaseData?.metrics?.findings_total || 0} findings`, state: phaseData?.metrics?.findings_total ? "ok" : "idle" },
  ];

  return (
    <section className="panel p-5">
      <div className="t-head" style={{ padding: 0, border: 0, marginBottom: 12 }}>
        <div>
          <h3>Comunicação operacional</h3>
          <div className="sub">supervisor, validação, workers, MCP, Kali e evidências</div>
        </div>
      </div>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        {nodes.map((node, idx) => (
          <div key={node.label} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <CommunicationNode {...node} />
            {idx < nodes.length - 1 && <span className="mono-sm muted">→</span>}
          </div>
        ))}
      </div>
    </section>
  );
}

function PhaseStrip({ phaseData }) {
  const phases = Array.isArray(phaseData?.phases) ? phaseData.phases : [];
  if (!phases.length) return null;

  return (
    <section className="panel p-5">
      <div className="t-head" style={{ padding: 0, border: 0, marginBottom: 12 }}>
        <div>
          <h3>Fases do teste</h3>
          <div className="sub">visão rápida das 22 fases, status e ponto de bloqueio</div>
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8 }}>
        {phases.map((phase) => {
          const tone = phaseTone(phase.status);
          const active = phase.id === phaseData.current_pentest_phase_id;
          return (
            <div
              key={phase.id}
              title={`${phaseLabel(phase)} · ${tone.label}`}
              style={{
                border: `1px solid ${active ? "var(--brand-500)" : "var(--line)"}`,
                borderLeft: `3px solid ${tone.color}`,
                background: active ? "rgba(254,123,2,0.08)" : tone.bg,
                borderRadius: 8,
                padding: "8px 9px",
                minHeight: 66,
              }}
            >
              <div className="mono-sm" style={{ color: tone.color, fontWeight: 800 }}>{phase.id}</div>
              <div style={{ color: "var(--ink)", fontSize: 11.5, fontWeight: 700, marginTop: 3, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {phase.title || phase.phase || "-"}
              </div>
              <div className="mono-sm muted" style={{ marginTop: 4 }}>{tone.label}</div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function ActivityTimeline({ data }) {
  const traces = data?.traces || [];
  const activities = data?.activities || [];
  const events = [
    ...traces.map((row) => ({
      id: `t-${row.id}`,
      time: row.created_at,
      title: row.event_type,
      detail: [row.from_node, row.to_node].filter(Boolean).join(" → "),
      meta: row.tool_name || row.skill_id || row.capability || row.status,
    })),
    ...activities.map((row) => ({
      id: `a-${row.id}`,
      time: row.created_at,
      title: `iteracao ${row.iteration}`,
      detail: row.tool_selected || row.status,
      meta: row.approved === true ? "aprovado" : row.approved === false ? "reprovado" : row.skill_lookup_source,
    })),
  ].sort((a, b) => new Date(a.time || 0) - new Date(b.time || 0));

  return (
    <section className="panel p-5">
      <div className="t-head" style={{ padding: 0, border: 0, marginBottom: 12 }}>
        <div>
          <h3>Supervisor ↔ agentes</h3>
          <div className="sub">decisões, roteamento e feedback técnico</div>
        </div>
      </div>
      {events.length === 0 ? (
        <div className="empty" style={{ padding: 18 }}>Sem eventos de comunicação para este scan.</div>
      ) : (
        <div style={{ maxHeight: 360, overflowY: "auto", display: "grid", gap: 8 }}>
          {events.slice(-80).map((event) => (
            <div key={event.id} style={{ border: "1px solid var(--line)", borderRadius: 8, padding: "8px 10px", background: "var(--surface)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                <strong style={{ color: "var(--ink)", fontSize: 12 }}>{event.title}</strong>
                <span className="mono-sm muted">{fmtTime(event.time)}</span>
              </div>
              <div className="mono-sm soft" style={{ marginTop: 4 }}>{event.detail || "-"}</div>
              <div className="mono-sm muted" style={{ marginTop: 2 }}>{event.meta || "-"}</div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function CommandFeed({ logs, toolFilter, onCopy }) {
  const commandRows = logs.filter((row) => /cmd=|stdout=|stderr=|return_code=|dispatch|tool=|mcp|kali|runner/i.test(getMessageText(row.message)));

  return (
    <section className="panel p-5">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-base font-semibold text-slate-100">Comandos e respostas{toolFilter ? ` · ${toolFilter}` : ""}</h3>
          <div className="sub">saída operacional de dispatch, retorno, stdout/stderr e falhas</div>
        </div>
        <button onClick={onCopy} className="btn btn-ghost">Copiar</button>
      </div>
      {commandRows.length === 0 ? (
        <p className="text-sm text-slate-500">Nenhuma saída de comando detectada neste filtro.</p>
      ) : (
        <div className="bg-slate-950/60 rounded-xl p-3 max-h-[58vh] overflow-y-auto font-mono text-xs">
          {commandRows.map((row) => <LogLine key={row.id} row={row} />)}
        </div>
      )}
    </section>
  );
}

export default function WorkerLogsPage() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [toolFilter, setToolFilter] = useState("");
  const [data, setData] = useState(null);
  const [phaseData, setPhaseData] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [activeTab, setActiveTab] = useState("cockpit");
  const logEndRef = useRef(null);
  const mountedRef = useRef(true);
  const requestIdRef = useRef(0);

  useEffect(() => () => {
    mountedRef.current = false;
  }, []);

  const fetchLogs = async (scanId, tool) => {
    if (!scanId) return;
    const currentRequestId = ++requestIdRef.current;
    setLoading(true);
    setError("");
    try {
      const params = { scan_id: scanId, limit: 2000 };
      if (tool) params.tool = tool;
      const [logsRes, phaseRes, healthRes] = await Promise.all([
        client.get("/api/admin/worker-logs", { params }),
        client.get(`/api/scans/${scanId}/phase-monitor`),
        client.get("/api/worker-manager/health"),
      ]);
      if (!mountedRef.current || currentRequestId !== requestIdRef.current) return;
      setData(logsRes.data);
      setPhaseData(phaseRes.data);
      setHealth(healthRes.data || null);
      if (logsRes.data?.scans?.length) setScans(logsRes.data.scans);
    } catch (err) {
      if (mountedRef.current && currentRequestId === requestIdRef.current) {
        setError(err?.response?.data?.detail || "Falha ao carregar telemetria operacional.");
      }
    } finally {
      if (mountedRef.current && currentRequestId === requestIdRef.current) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const res = await client.get("/api/admin/worker-logs");
        const rows = res.data?.scans || [];
        if (!mountedRef.current) return;
        setScans(rows);
        const preferred = rows.find((scan) => ["running", "retrying", "queued"].includes(scan.status)) || rows[0];
        if (preferred && !selectedScan) {
          setSelectedScan(preferred.id);
          fetchLogs(preferred.id);
        }
      } catch {
        // the per-scan fetch will expose a useful error if needed
      }
    };
    fetchScans();
  }, []);

  useEffect(() => {
    if (!autoRefresh || !selectedScan) return;
    const t = setInterval(() => fetchLogs(selectedScan, toolFilter || undefined), 5000);
    return () => clearInterval(t);
  }, [autoRefresh, selectedScan, toolFilter]);

  useEffect(() => {
    if (activeTab === "logs") logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [data?.logs?.length, activeTab]);

  const onScanChange = (id) => {
    const next = id ? Number(id) : null;
    setSelectedScan(next);
    setData(null);
    setPhaseData(null);
    setToolFilter("");
    if (next) fetchLogs(next);
  };

  const onFilterChange = (tool) => {
    setToolFilter(tool);
    if (selectedScan) fetchLogs(selectedScan, tool || undefined);
  };

  const scanInfo = data?.scan;
  const executions = data?.executions || [];
  const logs = data?.logs || [];
  const toolSummary = data?.tool_summary || [];
  const isRunning = ["running", "retrying", "queued"].includes(String(scanInfo?.status || "").toLowerCase());
  const failedExecutions = executions.filter((run) => String(run.status || "").toLowerCase().includes("fail"));
  const warningLogs = logs.filter((row) => ["WARNING", "ERROR", "CRITICAL"].includes(String(row.level || "").toUpperCase()));

  const allTools = [...new Set([
    ...executions.map((entry) => entry.tool),
    ...toolSummary.map((entry) => entry.tool),
    ...logs.map((entry) => toolFromMsg(entry.message)),
  ].filter(Boolean))].sort();

  const filteredExecutions = toolFilter ? executions.filter((entry) => entry.tool === toolFilter) : executions;
  const filteredLogs = toolFilter
    ? logs.filter((entry) => {
        const message = getMessageText(entry.message);
        return toolFromMsg(message) === toolFilter || message.includes(`tool=${toolFilter}`);
      })
    : logs;

  const currentPhase = useMemo(() => {
    const phases = Array.isArray(phaseData?.phases) ? phaseData.phases : [];
    return phases.find((phase) => phase.id === phaseData?.current_pentest_phase_id)
      || phases.find((phase) => phase.status === "partial_coverage" || phase.status === "attempted_failed")
      || phases.find((phase) => phase.status !== "executed")
      || phases[phases.length - 1];
  }, [phaseData]);

  const copyCommandRows = () => {
    const text = filteredLogs
      .filter((row) => /cmd=|stdout=|stderr=|return_code=|dispatch|tool=|mcp|kali|runner/i.test(getMessageText(row.message)))
      .map((entry) => `[${entry.level}] ${getMessageText(entry.message)}`)
      .join("\n");
    copyText(text, "Saídas operacionais copiadas.");
  };

  const tabBtn = (id, label, count) => (
    <button onClick={() => setActiveTab(id)} className={`filter${activeTab === id ? " active" : ""}`}>
      {label}{count != null && <span style={{ marginLeft: 6, opacity: 0.7 }}>· {count}</span>}
    </button>
  );

  return (
    <main className="dpage space-y-4">
      <div className="page-intro" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 20, flexWrap: "wrap" }}>
        <div>
          <h2>RedTeam Runtime.</h2>
          <div className="sub">fase, comando, resposta, progresso, falhas e comunicação entre supervisor, workers, MCP e Kali</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select value={selectedScan || ""} onChange={(e) => onScanChange(e.target.value)} className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 focus:outline-none">
            <option value="">selecionar scan</option>
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>#{scan.id} {scan.target_query} [{scan.status}]</option>
            ))}
          </select>
          {allTools.length > 0 && (
            <select value={toolFilter} onChange={(e) => onFilterChange(e.target.value)} className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 focus:outline-none">
              <option value="">todas as ferramentas</option>
              {allTools.map((tool) => <option key={tool} value={tool}>{tool}</option>)}
            </select>
          )}
          <label className="flex items-center gap-1.5 cursor-pointer text-sm text-slate-300">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} className="accent-blue-500" />
            auto-refresh
          </label>
          <button onClick={() => fetchLogs(selectedScan, toolFilter || undefined)} disabled={!selectedScan || loading} className="btn btn-ghost">
            {loading ? "Atualizando..." : "Atualizar"}
          </button>
        </div>
      </div>

      {error && <section className="err-box">{error}</section>}

      {scanInfo && (
        <>
          <section className="panel p-5">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 18 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                  <span className="mono" style={{ fontWeight: 800 }}>#{scanInfo.id}</span>
                  <strong style={{ color: "var(--ink)" }}>{scanInfo.target_query}</strong>
                  <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${statusColor(scanInfo.status)}`}>{scanInfo.status}</span>
                </div>
                <div style={{ marginTop: 12, height: 10, borderRadius: 99, overflow: "hidden", background: "var(--bg-muted)" }}>
                  <div style={{ height: "100%", width: `${pct(scanInfo.mission_progress)}%`, background: failedExecutions.length ? "var(--sev-critical-solid)" : "var(--brand-500)" }} />
                </div>
                <div className="mono-sm muted" style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
                  <span>{scanInfo.current_step || "sem passo atual"}</span>
                  <span>{pct(scanInfo.mission_progress)}%</span>
                </div>
              </div>
              <div style={{ border: "1px solid var(--line)", borderRadius: 8, padding: 12, background: "var(--surface-soft)" }}>
                <div className="mono-sm muted">fase atual</div>
                <div style={{ color: "var(--ink)", fontWeight: 800, marginTop: 4 }}>{currentPhase ? phaseLabel(currentPhase) : "-"}</div>
                <div className="mono-sm soft" style={{ marginTop: 5 }}>
                  criado: {fmtTime(scanInfo.created_at)} · atualizado: {fmtTime(scanInfo.updated_at)}
                </div>
              </div>
            </div>
          </section>

          <section className="grid-4">
            {metricCard("Progresso", `${pct(scanInfo.mission_progress)}%`, "var(--brand-700)")}
            {metricCard("Execuções", executions.length, "var(--ink)")}
            {metricCard("Falhas", failedExecutions.length + warningLogs.length, failedExecutions.length ? "var(--sev-critical-text)" : "var(--sev-high-text)")}
            {metricCard("Findings", phaseData?.metrics?.findings_total || 0, "var(--sev-low-text)")}
          </section>

          <CommunicationMap data={data} health={health} phaseData={phaseData} />

          <div className="t-tools" style={{ marginBottom: 4 }}>
            {tabBtn("cockpit", "Cockpit")}
            {tabBtn("commands", "Comandos", filteredLogs.length)}
            {tabBtn("executions", "Execuções", filteredExecutions.length)}
            {tabBtn("logs", "Eventos", filteredLogs.length)}
          </div>

          {toolSummary.length > 0 && (
            <section className="panel p-4">
              <p className="text-xs text-slate-500 mb-3 uppercase tracking-widest font-semibold">Ferramentas no scan</p>
              <div className="flex flex-wrap gap-2">
                {toolSummary.map((summary) => (
                  <button
                    key={summary.tool}
                    onClick={() => onFilterChange(toolFilter === summary.tool ? "" : summary.tool)}
                    className={`rounded-xl border px-3 py-1.5 text-xs font-mono font-semibold transition-colors ${
                      toolFilter === summary.tool ? toolColor(summary.tool) : "border-slate-700 bg-slate-900 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {summary.tool}
                    <span className="ml-1 text-[10px]">
                      {summary.executed > 0 && <span className="text-emerald-400 ml-1">ok {summary.executed}</span>}
                      {summary.skipped > 0 && <span className="text-amber-400 ml-1">skip {summary.skipped}</span>}
                      {summary.failed > 0 && <span className="text-rose-400 ml-1">fail {summary.failed}</span>}
                    </span>
                  </button>
                ))}
              </div>
            </section>
          )}
        </>
      )}

      {!scanInfo && !loading && <div className="empty">Selecione um scan para abrir a telemetria operacional.</div>}

      {scanInfo && activeTab === "cockpit" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
          <PhaseStrip phaseData={phaseData} />
          <ActivityTimeline data={data} />
        </div>
      )}

      {scanInfo && activeTab === "commands" && (
        <CommandFeed logs={filteredLogs} toolFilter={toolFilter} onCopy={copyCommandRows} />
      )}

      {scanInfo && activeTab === "executions" && (
        <section className="panel p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold text-slate-100">Execuções de ferramentas{toolFilter ? ` · ${toolFilter}` : ""}</h3>
            <button onClick={() => copyText(JSON.stringify(filteredExecutions, null, 2), "JSON das execuções copiado.")} className="btn btn-ghost">Copiar JSON</button>
          </div>
          {filteredExecutions.length === 0 ? (
            <p className="text-sm text-slate-500">Nenhuma execução registrada para este filtro.</p>
          ) : (
            <div className="space-y-1">{filteredExecutions.map((run) => <ExecutionCard key={run.id} run={run} />)}</div>
          )}
        </section>
      )}

      {scanInfo && activeTab === "logs" && (
        <section className="panel p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-semibold text-slate-100">Eventos do scan{toolFilter ? ` · ${toolFilter}` : ""}</h3>
            <button onClick={() => copyText(filteredLogs.map((entry) => `[${entry.level}] ${getMessageText(entry.message)}`).join("\n"), "Eventos copiados.")} className="btn btn-ghost">Copiar texto</button>
          </div>
          {filteredLogs.length === 0 ? (
            <p className="text-sm text-slate-500">Nenhum evento encontrado para este filtro.</p>
          ) : (
            <div className="bg-slate-950/60 rounded-xl p-3 max-h-[60vh] overflow-y-auto font-mono text-xs">
              {filteredLogs.map((row) => <LogLine key={row.id} row={row} />)}
              <div ref={logEndRef} />
            </div>
          )}
        </section>
      )}
    </main>
  );
}
