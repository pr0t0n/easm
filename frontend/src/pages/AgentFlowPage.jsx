import { useEffect, useMemo, useRef, useState } from "react";
import client, { getWsBaseUrl } from "../api/client";

const NODES = {
  supervisor: { label: "Supervisor", x: 50, y: 16, color: "#4b73ff" },
  agent: { label: "Agent Runtime", x: 50, y: 50, color: "#e96363" },
  library: { label: "Learning / MCP", x: 18, y: 72, color: "#8b5cf6" },
  kali: { label: "Kali Runner", x: 82, y: 72, color: "#f59e0b" },
  evidence: { label: "Evidence DB", x: 50, y: 88, color: "#10b981" },
};

const FLOW_EDGES = {
  supervisor_dispatch: { from: "supervisor", to: "agent", label: "dispatch" },
  skill_lookup: { from: "agent", to: "library", label: "lookup" },
  skill_found: { from: "library", to: "agent", label: "skill found" },
  tool_select: { from: "agent", to: "kali", label: "select" },
  tool_usage_lookup: { from: "agent", to: "library", label: "how-to" },
  tool_usage_found: { from: "library", to: "agent", label: "playbook" },
  tool_execute: { from: "agent", to: "kali", label: "execute" },
  result_return: { from: "kali", to: "evidence", label: "evidence" },
  finding_promoted: { from: "evidence", to: "supervisor", label: "finding" },
};

const STATUS_COLOR = {
  success: "#10b981",
  done: "#10b981",
  executed: "#10b981",
  failure: "#ef4444",
  failed: "#ef4444",
  error: "#ef4444",
  pending: "#f59e0b",
  running: "#38bdf8",
  skipped: "#94a3b8",
  info: "#4b73ff",
};

function toneForLevel(level) {
  const value = String(level || "").toLowerCase();
  if (value.includes("error") || value.includes("fail")) return "failed";
  if (value.includes("warn")) return "pending";
  return "info";
}

function actorFromLog(log) {
  const blob = `${log.source || ""} ${log.message || ""}`.toLowerCase();
  if (blob.includes("supervisor")) return "Supervisor";
  if (blob.includes("kali") || blob.includes("tool") || blob.includes("runner")) return "Kali Runner";
  if (blob.includes("worker")) return log.source || "Worker";
  if (blob.includes("learning") || blob.includes("skill") || blob.includes("mcp")) return "Learning / MCP";
  if (blob.includes("finding") || blob.includes("evidence")) return "Evidence DB";
  return log.source || "System";
}

function nodeFromActor(actor) {
  const value = String(actor || "").toLowerCase();
  if (value.includes("supervisor")) return "supervisor";
  if (value.includes("kali") || value.includes("runner") || value.includes("tool")) return "kali";
  if (value.includes("learning") || value.includes("mcp") || value.includes("skill")) return "library";
  if (value.includes("evidence") || value.includes("finding")) return "evidence";
  return "agent";
}

function summarizePayload(payload) {
  if (!payload || typeof payload !== "object") return "";
  const parts = [];
  if (payload.skill_id) parts.push(`Skill: ${payload.skill_id}`);
  if (payload.selected_tool) parts.push(`Ferramenta: ${payload.selected_tool}`);
  if (payload.objective) parts.push(`Objetivo: ${payload.objective}`);
  if (payload.capability) parts.push(`Capacidade: ${payload.capability}`);
  if (payload.phase) parts.push(`Fase: ${payload.phase}`);
  if (payload.target) parts.push(`Alvo: ${payload.target}`);
  if (Array.isArray(payload.tech_stack) && payload.tech_stack.length) {
    parts.push(`Stack: ${payload.tech_stack.slice(0, 6).join(", ")}`);
  }
  if (Array.isArray(payload.matched_by) && payload.matched_by.length) {
    parts.push(`Porque: ${payload.matched_by.slice(0, 4).join(" / ")}`);
  }
  if (payload.score !== undefined && payload.score !== null) {
    parts.push(`Score: ${payload.score}`);
  }
  if (Array.isArray(payload.allowed_tools) && payload.allowed_tools.length) {
    parts.push(`Permitidas: ${payload.allowed_tools.slice(0, 6).join(", ")}`);
  }
  if (Array.isArray(payload.tools) && payload.tools.length) {
    parts.push(`Ferramentas: ${payload.tools.slice(0, 6).join(", ")}`);
  }
  if (payload.extra_args && typeof payload.extra_args === "object" && Object.keys(payload.extra_args).length) {
    const argsSummary = Object.entries(payload.extra_args)
      .slice(0, 3)
      .map(([tool, args]) => `${tool}=${Array.isArray(args) ? args.slice(0, 4).join(" ") : args}`)
      .join(" | ");
    parts.push(`Extra-args: ${argsSummary}`);
  }
  if (payload.reason) parts.push(`Razao: ${payload.reason}`);
  if (payload.findings_count !== undefined) parts.push(`Findings: ${payload.findings_count}`);
  if (payload.findings_added !== undefined) parts.push(`Novos findings: ${payload.findings_added}`);
  return parts.join(" | ");
}

function traceToConversation(ev) {
  const from = ev.from_node || "agent";
  const to = ev.to_node || "agent";
  const title = String(ev.event_type || "trace").replace(/_/g, " ");
  const payloadSummary = summarizePayload(ev.payload);
  const details = [
    ev.capability && `capability=${ev.capability}`,
    ev.skill_id && `skill=${ev.skill_id}`,
    ev.tool_name && `tool=${ev.tool_name}`,
    ev.duration_ms !== null && ev.duration_ms !== undefined && `${Math.round(ev.duration_ms)}ms`,
  ].filter(Boolean);
  return {
    id: `trace-${ev.id}`,
    rawId: ev.id,
    kind: "trace",
    actor: NODES[from]?.label || from,
    target: NODES[to]?.label || to,
    node: from,
    eventType: ev.event_type,
    status: ev.status || "info",
    title,
    body: payloadSummary || details.join(" | ") || "Evento de orquestracao recebido.",
    meta: details.join(" | "),
    payload: ev.payload,
    createdAt: ev.created_at,
    iteration: ev.iteration,
  };
}

function logToConversation(log) {
  const actor = actorFromLog(log);
  return {
    id: `log-${log.id}`,
    rawId: log.id,
    kind: "log",
    actor,
    target: "Timeline",
    node: nodeFromActor(actor),
    eventType: "scan_log",
    status: toneForLevel(log.level),
    title: log.level || "LOG",
    body: log.message || "",
    meta: log.source || "",
    payload: null,
    createdAt: log.created_at,
    iteration: null,
  };
}

function mergeByTime(traceEvents, logEvents) {
  const rows = [
    ...traceEvents.map(traceToConversation),
    ...logEvents.map(logToConversation),
  ];
  rows.sort((a, b) => {
    const ta = new Date(a.createdAt || 0).getTime();
    const tb = new Date(b.createdAt || 0).getTime();
    if (ta !== tb) return ta - tb;
    return String(a.id).localeCompare(String(b.id));
  });
  return rows.slice(-260);
}

function ConnectionBadge({ label, state }) {
  const normalized = state || "idle";
  const color = {
    open: "bg-emerald-400",
    connecting: "bg-sky-400",
    closed: "bg-slate-500",
    error: "bg-rose-500",
    idle: "bg-slate-600",
  }[normalized] || "bg-slate-600";
  return (
    <span className="inline-flex items-center gap-2 rounded border border-slate-700 bg-slate-950/70 px-2 py-1 text-xs text-slate-300">
      <span className={`h-2 w-2 rounded-full ${color}`} />
      {label}: {normalized}
    </span>
  );
}

function Metric({ label, value, accent = "text-white" }) {
  return (
    <div className="border border-slate-800 bg-slate-950/70 p-3">
      <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className={`mt-1 font-mono text-xl font-semibold ${accent}`}>{value}</div>
    </div>
  );
}

function NodeMap({ activeNode, activeEdge, counts }) {
  return (
    <div className="relative min-h-[390px] overflow-hidden border border-slate-800 bg-[#070a12]">
      <div className="absolute inset-0 opacity-60 [background-image:linear-gradient(rgba(75,115,255,.08)_1px,transparent_1px),linear-gradient(90deg,rgba(75,115,255,.08)_1px,transparent_1px)] [background-size:34px_34px]" />
      <svg viewBox="0 0 100 100" className="absolute inset-0 h-full w-full">
        {Object.entries(FLOW_EDGES).map(([key, edge]) => {
          const from = NODES[edge.from];
          const to = NODES[edge.to];
          const active = activeEdge === key || (activeNode === edge.from && activeNode === edge.to);
          const color = active ? STATUS_COLOR.running : "rgba(148,163,184,.32)";
          return (
            <g key={key}>
              <line
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke={color}
                strokeWidth={active ? 0.9 : 0.35}
                strokeDasharray={active ? "0" : "1.5 1.6"}
              />
              {active && (
                <text
                  x={(from.x + to.x) / 2}
                  y={(from.y + to.y) / 2 - 1.8}
                  textAnchor="middle"
                  fontSize="2.7"
                  fill="#e2e8f0"
                >
                  {edge.label}
                </text>
              )}
            </g>
          );
        })}
        {Object.entries(NODES).map(([id, node]) => {
          const active = activeNode === id;
          return (
            <g key={id}>
              <circle
                cx={node.x}
                cy={node.y}
                r={active ? 7.2 : 6.1}
                fill="#0f172a"
                stroke={node.color}
                strokeWidth={active ? 1.3 : 0.65}
              />
              {active && <circle cx={node.x} cy={node.y} r="10" fill="none" stroke={node.color} strokeWidth=".35" opacity=".75" />}
              <text x={node.x} y={node.y + 0.8} textAnchor="middle" fontSize="2.3" fill="#f8fafc" fontWeight="700">
                {node.label}
              </text>
              <text x={node.x} y={node.y + 4.5} textAnchor="middle" fontSize="2" fill="#94a3b8">
                {counts[id] || 0} events
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function ConversationItem({ item, selected, onSelect }) {
  const color = STATUS_COLOR[item.status] || STATUS_COLOR.info;
  const isRight = item.node === "kali" || item.node === "evidence";
  return (
    <button
      type="button"
      onClick={() => onSelect(item)}
      className={`flex w-full text-left ${isRight ? "justify-end" : "justify-start"}`}
    >
      <div
        className={`max-w-[88%] border p-3 transition ${
          selected ? "border-sky-400 bg-sky-950/50" : "border-slate-800 bg-slate-950/80 hover:border-slate-600"
        }`}
      >
        <div className="flex flex-wrap items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
          <span className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-slate-300">{item.actor}</span>
          {item.target && <span className="text-xs text-slate-600">to {item.target}</span>}
          <span className="ml-auto text-[11px] text-slate-500">
            {item.createdAt ? new Date(item.createdAt).toLocaleTimeString() : ""}
          </span>
        </div>
        <div className="mt-2 text-sm font-semibold text-slate-100">{item.title}</div>
        <div className="mt-1 whitespace-pre-wrap break-words text-xs leading-relaxed text-slate-400">{item.body}</div>
        {item.meta && <div className="mt-2 font-mono text-[11px] text-slate-500">{item.meta}</div>}
      </div>
    </button>
  );
}

function WhyPanel({ payload }) {
  if (!payload || typeof payload !== "object") return null;
  const techStack = Array.isArray(payload.tech_stack) ? payload.tech_stack : [];
  const matchedBy = Array.isArray(payload.matched_by) ? payload.matched_by : [];
  const allowedTools = Array.isArray(payload.allowed_tools) ? payload.allowed_tools : [];
  const selectedAll = Array.isArray(payload.selected_tools_all) ? payload.selected_tools_all : [];
  const extraArgs = payload.extra_args && typeof payload.extra_args === "object" ? payload.extra_args : null;
  const hasContent =
    techStack.length || matchedBy.length || payload.reason || payload.score !== undefined ||
    payload.skill_id || payload.selected_tool || extraArgs;
  if (!hasContent) return null;

  return (
    <section className="border border-emerald-800/50 bg-emerald-950/20 p-3">
      <div className="text-[11px] uppercase tracking-[0.18em] text-emerald-300">por que essa escolha</div>
      <div className="mt-2 space-y-2 text-xs text-slate-200">
        {payload.skill_id && (
          <div><span className="text-slate-500">Skill →</span> <span className="font-mono text-violet-200">{payload.skill_id}</span>{payload.score !== undefined && <span className="ml-2 text-amber-300">score {payload.score}</span>}</div>
        )}
        {payload.selected_tool && (
          <div><span className="text-slate-500">Ferramenta →</span> <span className="font-mono text-emerald-200">{payload.selected_tool}</span></div>
        )}
        {techStack.length > 0 && (
          <div>
            <span className="text-slate-500">Tech stack detectado:</span>{" "}
            <span className="font-mono text-sky-200">{techStack.join(", ")}</span>
          </div>
        )}
        {matchedBy.length > 0 && (
          <div>
            <div className="text-slate-500">Razoes do match:</div>
            <ul className="mt-1 ml-3 list-disc space-y-0.5 font-mono text-[11px] text-slate-300">
              {matchedBy.map((m, idx) => <li key={idx}>{m}</li>)}
            </ul>
          </div>
        )}
        {selectedAll.length > 0 && (
          <div>
            <span className="text-slate-500">Ferramentas escolhidas:</span>{" "}
            <span className="font-mono text-emerald-200">{selectedAll.join(", ")}</span>
          </div>
        )}
        {allowedTools.length > 0 && (
          <div>
            <span className="text-slate-500">Permitidas pela skill:</span>{" "}
            <span className="font-mono text-slate-300">{allowedTools.join(", ")}</span>
          </div>
        )}
        {extraArgs && Object.keys(extraArgs).length > 0 && (
          <div>
            <div className="text-slate-500">Extra-args calibrados pelo stack:</div>
            <ul className="mt-1 ml-3 font-mono text-[11px] text-emerald-200">
              {Object.entries(extraArgs).slice(0, 6).map(([tool, args]) => (
                <li key={tool}>
                  <span className="text-amber-200">{tool}</span> {Array.isArray(args) ? args.join(" ") : String(args)}
                </li>
              ))}
            </ul>
          </div>
        )}
        {payload.reason && (
          <div className="border-t border-slate-800 pt-2 text-slate-300">
            <span className="text-slate-500">Resumo:</span> {payload.reason}
          </div>
        )}
      </div>
    </section>
  );
}

function PayloadPanel({ item }) {
  if (!item) {
    return (
      <div className="flex h-full min-h-64 items-center justify-center border border-slate-800 bg-slate-950/70 p-6 text-sm text-slate-500">
        Selecione uma mensagem para ver instrucao, resposta e payload.
      </div>
    );
  }

  return (
    <div className="h-full border border-slate-800 bg-slate-950/70">
      <div className="border-b border-slate-800 p-4">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">pacote selecionado</div>
        <div className="mt-1 text-base font-semibold text-white">{item.title}</div>
        <div className="mt-1 text-xs text-slate-400">
          {item.actor} to {item.target} | {item.status}
        </div>
      </div>
      <div className="space-y-4 p-4">
        <WhyPanel payload={item.payload} />
        <section>
          <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">conteudo</div>
          <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-slate-300">{item.body || "Sem corpo textual."}</p>
        </section>
        <section>
          <div className="text-[11px] uppercase tracking-[0.18em] text-slate-500">resposta bruta</div>
          <pre className="mt-2 max-h-72 overflow-auto border border-slate-800 bg-black/60 p-3 font-mono text-[11px] leading-relaxed text-emerald-200">
            {item.payload ? JSON.stringify(item.payload, null, 2) : "Sem payload estruturado para este evento."}
          </pre>
        </section>
      </div>
    </div>
  );
}

function ScoreBar({ value, color }) {
  const width = Math.max(0, Math.min(100, Number(value || 0)));
  return (
    <div className="h-2 overflow-hidden bg-slate-800">
      <div className="h-full transition-all duration-500" style={{ width: `${width}%`, backgroundColor: color }} />
    </div>
  );
}

export default function AgentFlowPage() {
  const [scanId, setScanId] = useState("");
  const [scans, setScans] = useState([]);
  const [traceEvents, setTraceEvents] = useState([]);
  const [logEvents, setLogEvents] = useState([]);
  const [scores, setScores] = useState([]);
  const [hypotheses, setHypotheses] = useState([]);
  const [killChainStage, setKillChainStage] = useState("");
  const [techStack, setTechStack] = useState([]);
  const [selected, setSelected] = useState(null);
  const [traceState, setTraceState] = useState("idle");
  const [logState, setLogState] = useState("idle");
  const [diagnostic, setDiagnostic] = useState("");
  const traceWsRef = useRef(null);
  const logWsRef = useRef(null);
  const feedRef = useRef(null);

  const conversation = useMemo(() => mergeByTime(traceEvents, logEvents), [traceEvents, logEvents]);
  const activeItem = selected || conversation[conversation.length - 1] || null;
  const activeNode = activeItem?.node || "supervisor";
  const activeEdge = activeItem?.kind === "trace" ? activeItem.eventType : "";
  const counts = useMemo(() => {
    const out = {};
    for (const item of conversation) out[item.node] = (out[item.node] || 0) + 1;
    return out;
  }, [conversation]);

  // Agregar uso de skills a partir dos trace events.
  // Cada evento que carrega skill_id conta como 1 uso. Capability = agente.
  const skillUsage = useMemo(() => {
    const map = new Map();
    const eligibleEvents = new Set([
      "skill_lookup",
      "skill_found",
      "tool_usage_lookup",
      "tool_select",
      "tool_usage_found",
      "tool_execute",
      "result_return",
    ]);
    for (const ev of traceEvents) {
      const skillId = String(ev.skill_id || "").trim();
      if (!skillId) continue;
      if (!eligibleEvents.has(String(ev.event_type || ""))) continue;
      const capability = String(ev.capability || "").trim() || "unknown";
      const tool = String(ev.tool_name || "").trim();
      const entry = map.get(skillId) || {
        skill_id: skillId,
        uses: 0,
        agents: new Map(),
        tools: new Map(),
        lastIteration: 0,
        statuses: { success: 0, failure: 0, pending: 0, skipped: 0, other: 0 },
      };
      entry.uses += 1;
      entry.agents.set(capability, (entry.agents.get(capability) || 0) + 1);
      if (tool) entry.tools.set(tool, (entry.tools.get(tool) || 0) + 1);
      entry.lastIteration = Math.max(entry.lastIteration, Number(ev.iteration || 0));
      const status = String(ev.status || "").toLowerCase();
      if (entry.statuses[status] !== undefined) entry.statuses[status] += 1;
      else entry.statuses.other += 1;
      map.set(skillId, entry);
    }
    return [...map.values()]
      .map((entry) => ({
        ...entry,
        agents: [...entry.agents.entries()].sort((a, b) => b[1] - a[1]),
        tools: [...entry.tools.entries()].sort((a, b) => b[1] - a[1]),
      }))
      .sort((a, b) => b.uses - a.uses);
  }, [traceEvents]);

  const skillTotals = useMemo(() => {
    const totalUses = skillUsage.reduce((acc, s) => acc + s.uses, 0);
    return { distinct: skillUsage.length, totalUses };
  }, [skillUsage]);

  useEffect(() => {
    client.get("/api/scans?limit=30").then((r) => {
      const items = r.data?.items || r.data || [];
      setScans(items);
      if (!scanId && items[0]?.id) setScanId(String(items[0].id));
    }).catch((err) => {
      setDiagnostic(`Falha ao listar scans: ${err?.response?.data?.detail || err.message}`);
    });
  }, []);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [conversation.length]);

  useEffect(() => () => {
    traceWsRef.current?.close();
    logWsRef.current?.close();
  }, []);

  const resetStreams = () => {
    traceWsRef.current?.close();
    logWsRef.current?.close();
    traceWsRef.current = null;
    logWsRef.current = null;
    setTraceState("idle");
    setLogState("idle");
  };

  const loadHistorical = async (id, token) => {
    const [traceResult, logsResult] = await Promise.allSettled([
      client.get(`/api/scans/${id}/trace`, { params: { token, limit: 300 }, _skipToast: true }),
      client.get(`/api/scans/${id}/logs`, { _skipToast: true }),
    ]);

    if (traceResult.status === "fulfilled") {
      setTraceEvents(traceResult.value.data?.trace || []);
      setScores(traceResult.value.data?.scores || []);
      setHypotheses(traceResult.value.data?.hypotheses || []);
      setKillChainStage(String(traceResult.value.data?.kill_chain_stage || ""));
      setTechStack(traceResult.value.data?.detected_tech_stack || []);
    } else {
      setTraceEvents([]);
      setScores([]);
      setHypotheses([]);
      setKillChainStage("");
      setTechStack([]);
    }

    if (logsResult.status === "fulfilled") {
      setLogEvents(logsResult.value.data || []);
    } else {
      setLogEvents([]);
    }

    const traceCount = traceResult.status === "fulfilled" ? (traceResult.value.data?.trace || []).length : 0;
    const logCount = logsResult.status === "fulfilled" ? (logsResult.value.data || []).length : 0;
    if (traceCount === 0 && logCount > 0) {
      setDiagnostic("Este scan nao possui eventos agent_trace_events. A visualizacao esta usando ScanLog como fallback conversacional.");
    } else if (traceCount === 0 && logCount === 0) {
      setDiagnostic("Nenhum evento encontrado ainda. Inicie um scan novo ou aguarde os workers emitirem logs/trace.");
    } else {
      setDiagnostic("");
    }
  };

  const connectTrace = (id, token) => {
    setTraceState("connecting");
    const ws = new WebSocket(`${getWsBaseUrl()}/ws/scans/${id}/trace?token=${encodeURIComponent(token)}`);
    traceWsRef.current = ws;
    ws.onopen = () => setTraceState("open");
    ws.onerror = () => setTraceState("error");
    ws.onclose = (event) => {
      setTraceState(event.code === 1000 ? "closed" : "error");
      if (event.code === 4401 || event.code === 4403) {
        setDiagnostic(`WebSocket trace recusado pelo backend: code=${event.code}. Verifique login/permissao do scan.`);
      }
    };
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type !== "trace") return;
      const items = msg.items || [];
      setTraceEvents((prev) => [...prev, ...items].slice(-220));
      if (items.length) setSelected(traceToConversation(items[items.length - 1]));
    };
  };

  const connectLogs = (id, token) => {
    setLogState("connecting");
    const ws = new WebSocket(`${getWsBaseUrl()}/ws/scans/${id}/logs?token=${encodeURIComponent(token)}`);
    logWsRef.current = ws;
    ws.onopen = () => setLogState("open");
    ws.onerror = () => setLogState("error");
    ws.onclose = (event) => setLogState(event.code === 1000 ? "closed" : "error");
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type !== "logs") return;
      const items = msg.items || [];
      setLogEvents((prev) => {
        const byId = new Map(prev.map((item) => [item.id, item]));
        for (const item of items) byId.set(item.id, item);
        return [...byId.values()].sort((a, b) => Number(a.id) - Number(b.id)).slice(-260);
      });
      if (items.length && !traceEvents.length) setSelected(logToConversation(items[items.length - 1]));
    };
  };

  const handleConnect = async () => {
    if (!scanId) return;
    resetStreams();
    setTraceEvents([]);
    setLogEvents([]);
    setScores([]);
    setSelected(null);
    setDiagnostic("Carregando historico e abrindo WebSockets...");
    const token = localStorage.getItem("token") || "";
    await loadHistorical(scanId, token);
    connectTrace(scanId, token);
    connectLogs(scanId, token);
  };

  const handleDisconnect = () => {
    resetStreams();
    setDiagnostic("Streams desconectados pelo operador.");
  };

  const selectedScan = scans.find((scan) => String(scan.id) === String(scanId));

  return (
    <div className="min-h-screen bg-[#05070d] p-5 text-slate-100">
      <style>{`
        @keyframes flow-scan { 0% { transform: translateX(-100%); opacity: .2; } 50% { opacity: .8; } 100% { transform: translateX(100%); opacity: .2; } }
        .agent-flow-scanline::after { content: ""; position: absolute; inset: 0; background: linear-gradient(90deg, transparent, rgba(56,189,248,.18), transparent); animation: flow-scan 3.2s linear infinite; pointer-events: none; }
      `}</style>

      <div className="mb-5 border border-slate-800 bg-slate-950/80 p-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.28em] text-sky-300">agent telemetry console</div>
            <h1 className="mt-1 text-2xl font-semibold text-white">Fluxo de agentes em tempo real</h1>
            <p className="mt-1 max-w-4xl text-sm text-slate-400">
              Mostra trace estruturado quando existir e usa logs do scan como fallback visual para chamadas,
              respostas, instrucoes, evidencias e descobertas.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={scanId}
              onChange={(event) => setScanId(event.target.value)}
              className="min-w-72 border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
            >
              <option value="">Selecione um scan</option>
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} - {scan.target_query || scan.target} ({scan.status})
                </option>
              ))}
            </select>
            <button onClick={handleConnect} className="border border-emerald-500 bg-emerald-500/15 px-4 py-2 text-sm font-semibold text-emerald-200 hover:bg-emerald-500/25">
              Conectar
            </button>
            <button onClick={handleDisconnect} className="border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-semibold text-slate-200 hover:bg-slate-800">
              Pausar
            </button>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <ConnectionBadge label="trace ws" state={traceState} />
          <ConnectionBadge label="logs ws" state={logState} />
          {selectedScan && (
            <span className="border border-slate-700 bg-slate-950/70 px-2 py-1 text-xs text-slate-300">
              scan #{selectedScan.id} | {selectedScan.status} | {selectedScan.target_query || selectedScan.target}
            </span>
          )}
        </div>
        {diagnostic && (
          <div className="mt-3 border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-100">
            {diagnostic}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <div className="xl:col-span-7">
          <div className="agent-flow-scanline relative overflow-hidden border border-slate-800 bg-slate-950/80 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">topologia operacional</div>
                <div className="text-sm text-slate-300">Supervisor, agentes, biblioteca, Kali e evidencia</div>
              </div>
              <div className="font-mono text-xs text-slate-500">{conversation.length} mensagens</div>
            </div>
            <NodeMap activeNode={activeNode} activeEdge={activeEdge} counts={counts} />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 xl:col-span-5">
          <Metric label="trace events" value={traceEvents.length} accent="text-sky-300" />
          <Metric label="scan logs" value={logEvents.length} accent="text-emerald-300" />
          <Metric label="skill scores" value={scores.length} accent="text-violet-300" />
          <Metric label="last actor" value={activeItem?.actor || "--"} accent="text-amber-200" />
          <div className="col-span-2">
            <PayloadPanel item={activeItem} />
          </div>
        </div>

        <div className="xl:col-span-8">
          <div className="border border-slate-800 bg-slate-950/80">
            <div className="border-b border-slate-800 p-4">
              <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">conversa dos agentes</div>
              <div className="text-sm text-slate-400">Cada bolha representa uma chamada, resposta, instrucao ou observacao operacional.</div>
            </div>
            <div ref={feedRef} className="max-h-[620px] space-y-3 overflow-auto p-4">
              {conversation.length === 0 && (
                <div className="border border-slate-800 bg-slate-950 p-6 text-sm text-slate-500">
                  Sem eventos carregados. Escolha um scan e clique em Conectar.
                </div>
              )}
              {conversation.map((item) => (
                <ConversationItem
                  key={item.id}
                  item={item}
                  selected={activeItem?.id === item.id}
                  onSelect={setSelected}
                />
              ))}
            </div>
          </div>
        </div>

        <div className="xl:col-span-12">
          <div className="border border-emerald-800/50 bg-emerald-950/15">
            <div className="flex flex-wrap items-end justify-between gap-3 border-b border-emerald-800/50 p-4">
              <div>
                <div className="text-[11px] uppercase tracking-[0.2em] text-emerald-300">hipoteses do pentest (recon-driven)</div>
                <div className="text-sm text-slate-300">
                  Cada execucao precisa estar lastreada por uma hipotese. Sem hipotese = sem tool.
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                <span className="border border-emerald-700 bg-emerald-900/30 px-3 py-1 text-emerald-200">
                  stage: <span className="text-amber-200">{killChainStage || "-"}</span>
                </span>
                <span className="border border-slate-700 bg-slate-950 px-3 py-1 text-slate-300">
                  stack: <span className="text-sky-200">{techStack.join(", ") || "-"}</span>
                </span>
                <span className="border border-slate-700 bg-slate-950 px-3 py-1 text-slate-300">
                  hipoteses: <span className="text-violet-200">{hypotheses.length}</span>
                </span>
              </div>
            </div>
            <div className="max-h-[360px] overflow-auto">
              {hypotheses.length === 0 ? (
                <div className="p-6 text-sm text-slate-500">
                  Sem hipoteses ainda. O engine refresca apos cada execucao de ferramenta - aguarde o recon coletar evidencia.
                </div>
              ) : (
                <table className="w-full border-collapse text-left font-mono text-xs">
                  <thead className="sticky top-0 bg-emerald-950/60 text-[11px] uppercase tracking-[0.16em] text-emerald-300">
                    <tr>
                      <th className="border-b border-emerald-800/60 px-3 py-2">#</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">familia</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">alvo</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">param</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">skill</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">ferramenta</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">extra_args</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">conf</th>
                      <th className="border-b border-emerald-800/60 px-3 py-2">razao / sinal esperado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hypotheses.map((h, idx) => (
                      <tr key={h.id || idx} className="hover:bg-slate-900/40">
                        <td className="border-b border-slate-900 px-3 py-2 text-slate-500">{idx + 1}</td>
                        <td className="border-b border-slate-900 px-3 py-2 text-emerald-200 uppercase">{h.family}</td>
                        <td className="border-b border-slate-900 px-3 py-2 text-slate-200 max-w-[300px] truncate" title={h.target}>{h.target}</td>
                        <td className="border-b border-slate-900 px-3 py-2 text-amber-200">{h.target_param || "-"}</td>
                        <td className="border-b border-slate-900 px-3 py-2 text-violet-200">{h.suggested_skill}</td>
                        <td className="border-b border-slate-900 px-3 py-2 text-sky-200">{h.suggested_tool}</td>
                        <td className="border-b border-slate-900 px-3 py-2 text-emerald-300 max-w-[280px] truncate" title={JSON.stringify(h.suggested_extra_args || {})}>
                          {h.suggested_extra_args && Object.keys(h.suggested_extra_args).length
                            ? Object.entries(h.suggested_extra_args).map(([t, args]) => `${t}: ${Array.isArray(args) ? args.slice(0,3).join(" ") : args}`).join(" | ")
                            : "-"}
                        </td>
                        <td className="border-b border-slate-900 px-3 py-2 text-amber-300">{Number(h.confidence || 0).toFixed(2)}</td>
                        <td className="border-b border-slate-900 px-3 py-2 text-slate-300">
                          <div className="text-slate-200">{h.rationale}</div>
                          <div className="mt-1 text-[10px] text-emerald-400">sinal: {h.signal_expected}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>

        <div className="xl:col-span-12">
          <div className="border border-slate-800 bg-slate-950/80">
            <div className="flex flex-wrap items-end justify-between gap-3 border-b border-slate-800 p-4">
              <div>
                <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">skills utilizadas</div>
                <div className="text-sm text-slate-400">
                  Quantas skills foram chamadas, quais foram, quais agentes (capability) e ferramentas as usaram. Uma skill pode aparecer varias vezes.
                </div>
              </div>
              <div className="flex gap-4 font-mono text-xs">
                <span className="border border-slate-700 bg-slate-950 px-3 py-1 text-slate-300">
                  distintas: <span className="text-violet-300">{skillTotals.distinct}</span>
                </span>
                <span className="border border-slate-700 bg-slate-950 px-3 py-1 text-slate-300">
                  invocacoes totais: <span className="text-amber-200">{skillTotals.totalUses}</span>
                </span>
              </div>
            </div>
            <div className="max-h-[420px] overflow-auto">
              {skillUsage.length === 0 ? (
                <div className="p-6 text-sm text-slate-500">
                  Nenhuma skill registrada para este scan ainda. Aguardando trace events com skill_id.
                </div>
              ) : (
                <table className="w-full border-collapse text-left font-mono text-xs">
                  <thead className="sticky top-0 bg-slate-950 text-[11px] uppercase tracking-[0.16em] text-slate-500">
                    <tr>
                      <th className="border-b border-slate-800 px-4 py-2">#</th>
                      <th className="border-b border-slate-800 px-4 py-2">skill_id</th>
                      <th className="border-b border-slate-800 px-4 py-2">usos</th>
                      <th className="border-b border-slate-800 px-4 py-2">agentes (capability x usos)</th>
                      <th className="border-b border-slate-800 px-4 py-2">ferramentas usadas</th>
                      <th className="border-b border-slate-800 px-4 py-2">status</th>
                      <th className="border-b border-slate-800 px-4 py-2">iter</th>
                    </tr>
                  </thead>
                  <tbody>
                    {skillUsage.map((row, idx) => (
                      <tr key={`${row.skill_id}-${idx}`} className="hover:bg-slate-900/60">
                        <td className="border-b border-slate-900 px-4 py-2 text-slate-500">{idx + 1}</td>
                        <td className="border-b border-slate-900 px-4 py-2 text-violet-200">{row.skill_id}</td>
                        <td className="border-b border-slate-900 px-4 py-2 text-amber-200">{row.uses}</td>
                        <td className="border-b border-slate-900 px-4 py-2 text-slate-300">
                          <div className="flex flex-wrap gap-1">
                            {row.agents.map(([agent, count]) => (
                              <span key={agent} className="border border-slate-700 bg-slate-900 px-2 py-[2px]">
                                {agent}<span className="text-slate-500"> x{count}</span>
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="border-b border-slate-900 px-4 py-2 text-slate-300">
                          {row.tools.length === 0 ? (
                            <span className="text-slate-600">-</span>
                          ) : (
                            <div className="flex flex-wrap gap-1">
                              {row.tools.map(([tool, count]) => (
                                <span key={tool} className="border border-emerald-700/60 bg-emerald-900/20 px-2 py-[2px] text-emerald-200">
                                  {tool}<span className="text-emerald-500"> x{count}</span>
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="border-b border-slate-900 px-4 py-2 text-[10px]">
                          <span className="text-emerald-300">ok {row.statuses.success}</span>
                          <span className="ml-2 text-rose-300">fail {row.statuses.failure}</span>
                          <span className="ml-2 text-amber-300">pend {row.statuses.pending}</span>
                          <span className="ml-2 text-slate-400">skip {row.statuses.skipped}</span>
                        </td>
                        <td className="border-b border-slate-900 px-4 py-2 text-slate-400">{row.lastIteration}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>

        <div className="xl:col-span-4">
          <div className="border border-slate-800 bg-slate-950/80">
            <div className="border-b border-slate-800 p-4">
              <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">eficiencia por skill</div>
              <div className="text-sm text-slate-400">Disponivel quando o scan grava skill_scores.</div>
            </div>
            <div className="max-h-[620px] overflow-auto p-4">
              {scores.length === 0 ? (
                <div className="text-sm text-slate-500">Nenhum score para este scan.</div>
              ) : (
                <div className="space-y-3">
                  {scores.map((score) => (
                    <div key={score.id} className="border border-slate-800 bg-slate-950 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate font-mono text-xs text-violet-200">{score.skill_id}</div>
                          <div className="truncate text-xs text-slate-500">{score.capability || "capability"}</div>
                        </div>
                        <div className="font-mono text-xs text-slate-400">iter {score.iteration}</div>
                      </div>
                      <div className="mt-3 space-y-2">
                        <div>
                          <div className="mb-1 flex justify-between text-[11px] text-slate-500">
                            <span>eficiencia</span>
                            <span>{Number(score.efficiency_score || 0).toFixed(0)}%</span>
                          </div>
                          <ScoreBar value={score.efficiency_score} color="#38bdf8" />
                        </div>
                        <div>
                          <div className="mb-1 flex justify-between text-[11px] text-slate-500">
                            <span>produtividade</span>
                            <span>{Number(score.productivity_score || 0).toFixed(0)}%</span>
                          </div>
                          <ScoreBar value={score.productivity_score} color="#10b981" />
                        </div>
                      </div>
                      <div className="mt-3 grid grid-cols-3 gap-2 text-center font-mono text-[11px] text-slate-400">
                        <span className="bg-slate-900 p-2">lib {score.library_hits}</span>
                        <span className="bg-slate-900 p-2">tools {score.tool_successes}/{score.tool_attempts}</span>
                        <span className="bg-slate-900 p-2">find {score.findings_promoted}/{score.findings_raw}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
