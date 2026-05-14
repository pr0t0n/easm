import { useEffect, useRef, useState } from "react";
import client, { getApiBaseUrl, getWsBaseUrl } from "../api/client";

// ── node definitions ──────────────────────────────────────────────────────────
const NODES = {
  supervisor: { label: "Supervisor",     x: 360, y: 60,  color: "#22c55e", icon: "🧠" },
  agent:      { label: "Agente",         x: 360, y: 300, color: "#3b82f6", icon: "🤖" },
  library:    { label: "Biblioteca/MCP", x: 100, y: 180, color: "#a855f7", icon: "📚" },
  kali:       { label: "Repositório Kali", x: 620, y: 180, color: "#f97316", icon: "⚔️" },
};

const FLOW_EDGES = {
  supervisor_dispatch:  { from: "supervisor", to: "agent",    label: "dispatch skill" },
  skill_lookup:         { from: "agent",      to: "library",  label: "buscar skill" },
  skill_found:          { from: "library",    to: "agent",    label: "skill encontrada" },
  tool_select:          { from: "agent",      to: "kali",     label: "selecionar tool" },
  tool_usage_lookup:    { from: "agent",      to: "library",  label: "buscar uso da tool" },
  tool_usage_found:     { from: "library",    to: "agent",    label: "como usar tool" },
  tool_execute:         { from: "agent",      to: "kali",     label: "executar tool" },
  result_return:        { from: "agent",      to: "supervisor", label: "resultado" },
};

const STATUS_COLOR = { success: "#22c55e", failure: "#ef4444", pending: "#f59e0b", skipped: "#6b7280" };

const W = 760, H = 400;

// ── SVG arrow between two nodes ───────────────────────────────────────────────
function Arrow({ from, to, active, label, status }) {
  const fn = NODES[from], tn = NODES[to];
  if (!fn || !tn) return null;

  const r = 44;
  const dx = tn.x - fn.x, dy = tn.y - fn.y;
  const dist = Math.sqrt(dx * dx + dy * dy);
  const ux = dx / dist, uy = dy / dist;
  const x1 = fn.x + ux * r, y1 = fn.y + uy * r;
  const x2 = tn.x - ux * r, y2 = tn.y - uy * r;
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;

  const color = active ? (STATUS_COLOR[status] || "#60a5fa") : "#374151";
  const strokeW = active ? 2.5 : 1;

  return (
    <g>
      <defs>
        <marker id={`arrow-${from}-${to}`} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill={color} />
        </marker>
      </defs>
      <line
        x1={x1} y1={y1} x2={x2} y2={y2}
        stroke={color} strokeWidth={strokeW}
        strokeDasharray={active ? "none" : "4 3"}
        markerEnd={`url(#arrow-${from}-${to})`}
        style={{ transition: "stroke 0.3s, stroke-width 0.3s" }}
      />
      {active && label && (
        <text x={mx} y={my - 8} textAnchor="middle" fill={color} fontSize="10" fontWeight="600">
          {label}
        </text>
      )}
    </g>
  );
}

// ── single node circle ────────────────────────────────────────────────────────
function NodeCircle({ id, active, pulsing }) {
  const n = NODES[id];
  const r = 44;
  return (
    <g>
      {pulsing && (
        <circle cx={n.x} cy={n.y} r={r + 10} fill="none" stroke={n.color} strokeWidth="2" opacity="0.4"
          style={{ animation: "pulse 1.2s infinite" }} />
      )}
      <circle cx={n.x} cy={n.y} r={r} fill={active ? n.color : "#1f2937"} stroke={n.color}
        strokeWidth={active ? 3 : 1.5}
        style={{ transition: "fill 0.3s, stroke-width 0.3s" }} />
      <text x={n.x} y={n.y - 6} textAnchor="middle" fontSize="20">{n.icon}</text>
      <text x={n.x} y={n.y + 12} textAnchor="middle" fill="white" fontSize="10" fontWeight="600">
        {n.label}
      </text>
    </g>
  );
}

// ── skill score bar ───────────────────────────────────────────────────────────
function ScoreBar({ value, color }) {
  return (
    <div className="relative h-2 bg-gray-700 rounded-full overflow-hidden w-full">
      <div className="absolute inset-y-0 left-0 rounded-full transition-all duration-500"
        style={{ width: `${Math.min(100, value || 0)}%`, background: color }} />
    </div>
  );
}

// ── main page ─────────────────────────────────────────────────────────────────
export default function AgentFlowPage() {
  const [scanId, setScanId] = useState("");
  const [scanning, setScanning] = useState(false);
  const [events, setEvents] = useState([]);
  const [scores, setScores] = useState([]);
  const [activeEvent, setActiveEvent] = useState(null);
  const [activeNodes, setActiveNodes] = useState(new Set());
  const [scans, setScans] = useState([]);
  const wsRef = useRef(null);
  const feedRef = useRef(null);

  // load recent scans for selector
  useEffect(() => {
    client.get("/api/scans?limit=20").then(r => setScans(r.data?.items || r.data || [])).catch(() => {});
  }, []);

  const connect = (id) => {
    if (wsRef.current) wsRef.current.close();
    const token = localStorage.getItem("token") || "";
    const ws = new WebSocket(`${getWsBaseUrl()}/ws/scans/${id}/trace?token=${token}`);
    wsRef.current = ws;

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.type !== "trace") return;
      const items = msg.items || [];
      setEvents(prev => {
        const combined = [...prev, ...items];
        return combined.slice(-120);
      });
      if (items.length > 0) {
        const last = items[items.length - 1];
        setActiveEvent(last);
        const edge = FLOW_EDGES[last.event_type];
        if (edge) {
          setActiveNodes(new Set([edge.from, edge.to]));
          setTimeout(() => setActiveNodes(new Set()), 2500);
        }
      }
    };
    ws.onclose = () => setScanning(false);

    // Also fetch historical data
    client.get(`/api/scans/${id}/trace?token=${token}&limit=200`)
      .then(r => {
        setEvents(r.data?.trace || []);
        setScores(r.data?.scores || []);
      })
      .catch(() => {});
  };

  const handleStart = () => {
    if (!scanId) return;
    setScanning(true);
    setEvents([]);
    setScores([]);
    setActiveEvent(null);
    connect(scanId);
  };

  const handleStop = () => {
    wsRef.current?.close();
    setScanning(false);
  };

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [events]);

  // cleanup
  useEffect(() => () => wsRef.current?.close(), []);

  const activeEdge = activeEvent ? FLOW_EDGES[activeEvent.event_type] : null;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <style>{`
        @keyframes pulse { 0%,100% { opacity:0.4; transform:scale(1); } 50% { opacity:0.8; transform:scale(1.15); } }
      `}</style>

      {/* header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Fluxo Supervisor → Agentes</h1>
        <p className="text-gray-400 text-sm mt-1">
          Visualização em tempo real do ciclo: Supervisor → Agente → Biblioteca → Kali → Resultado
        </p>
      </div>

      {/* controls */}
      <div className="flex gap-3 mb-6 items-center">
        <select
          value={scanId}
          onChange={e => setScanId(e.target.value)}
          className="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm text-white min-w-56"
        >
          <option value="">Selecione um scan…</option>
          {scans.map(s => (
            <option key={s.id} value={s.id}>
              #{s.id} — {s.target_query || s.target} ({s.status})
            </option>
          ))}
        </select>
        {!scanning ? (
          <button onClick={handleStart}
            className="px-4 py-2 bg-green-600 hover:bg-green-500 rounded text-sm font-semibold transition">
            Conectar
          </button>
        ) : (
          <button onClick={handleStop}
            className="px-4 py-2 bg-red-600 hover:bg-red-500 rounded text-sm font-semibold transition">
            Desconectar
          </button>
        )}
        {scanning && (
          <span className="flex items-center gap-2 text-green-400 text-sm">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            Conectado
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* SVG flow diagram */}
        <div className="xl:col-span-2 bg-gray-900 rounded-xl border border-gray-700 p-4">
          <h2 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Diagrama de Fluxo</h2>
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 420 }}>

            {/* static background edges */}
            {Object.entries(FLOW_EDGES).map(([type, edge]) => {
              const isActive = activeEdge?.from === edge.from && activeEdge?.to === edge.to;
              return (
                <Arrow key={type}
                  from={edge.from} to={edge.to}
                  active={isActive}
                  label={isActive ? edge.label : ""}
                  status={activeEvent?.status || "success"}
                />
              );
            })}

            {/* nodes */}
            {Object.keys(NODES).map(id => (
              <NodeCircle key={id} id={id}
                active={activeNodes.has(id)}
                pulsing={activeNodes.has(id)} />
            ))}

            {/* active event label */}
            {activeEvent && (
              <g>
                <rect x={W / 2 - 130} y={H - 44} width={260} height={36} rx={8}
                  fill="#1f2937" stroke={STATUS_COLOR[activeEvent.status] || "#60a5fa"} strokeWidth="1.5" />
                <text x={W / 2} y={H - 22} textAnchor="middle" fill="white" fontSize="11" fontWeight="600">
                  {activeEvent.event_type.replace(/_/g, " ")}
                  {activeEvent.skill_id ? ` · ${activeEvent.skill_id}` : ""}
                  {activeEvent.tool_name ? ` · ${activeEvent.tool_name}` : ""}
                </text>
              </g>
            )}
          </svg>

          {/* legend */}
          <div className="flex flex-wrap gap-3 mt-3">
            {Object.entries(NODES).map(([id, n]) => (
              <span key={id} className="flex items-center gap-1 text-xs text-gray-400">
                <span className="w-3 h-3 rounded-full inline-block" style={{ background: n.color }} />
                {n.label}
              </span>
            ))}
          </div>
        </div>

        {/* event feed */}
        <div className="bg-gray-900 rounded-xl border border-gray-700 p-4 flex flex-col">
          <h2 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">
            Feed de Eventos ({events.length})
          </h2>
          <div ref={feedRef} className="flex-1 overflow-y-auto space-y-1.5 max-h-80 pr-1">
            {events.length === 0 && (
              <p className="text-gray-600 text-xs">Aguardando eventos…</p>
            )}
            {events.map((ev, i) => (
              <div key={ev.id ?? i}
                className="flex items-start gap-2 text-xs p-2 rounded-lg bg-gray-800 border border-gray-700">
                <span className="mt-0.5 w-2 h-2 rounded-full flex-shrink-0"
                  style={{ background: STATUS_COLOR[ev.status] || "#60a5fa" }} />
                <div className="min-w-0">
                  <div className="flex items-center gap-1 text-gray-200 font-medium">
                    <span className="text-gray-500">#{ev.iteration}</span>
                    <span>{ev.event_type.replace(/_/g, " ")}</span>
                  </div>
                  <div className="text-gray-500 truncate">
                    {ev.from_node} → {ev.to_node}
                    {ev.skill_id && <span className="text-purple-400 ml-1">[{ev.skill_id}]</span>}
                    {ev.tool_name && <span className="text-orange-400 ml-1">{ev.tool_name}</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* skill scores */}
        <div className="xl:col-span-3 bg-gray-900 rounded-xl border border-gray-700 p-4">
          <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">
            Scores por Skill · Eficiência da Biblioteca e Aprendizado
          </h2>
          {scores.length === 0 ? (
            <p className="text-gray-600 text-sm">Nenhum score disponível ainda. Execute um scan para gerar dados.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-500 text-xs border-b border-gray-700">
                    <th className="text-left pb-2 pr-4">Iter.</th>
                    <th className="text-left pb-2 pr-4">Skill</th>
                    <th className="text-left pb-2 pr-4">Capacidade</th>
                    <th className="text-left pb-2 pr-4">Hits Biblioteca</th>
                    <th className="text-left pb-2 pr-4">Tools (ok/total)</th>
                    <th className="text-left pb-2 pr-4">Findings (prom./total)</th>
                    <th className="text-left pb-2 min-w-36">Eficiência</th>
                    <th className="text-left pb-2 pl-4 min-w-36">Produtividade</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {scores.map((s, i) => (
                    <tr key={s.id ?? i} className="hover:bg-gray-800/50 transition">
                      <td className="py-2 pr-4 text-gray-400">{s.iteration}</td>
                      <td className="py-2 pr-4 text-purple-300 font-mono text-xs">{s.skill_id}</td>
                      <td className="py-2 pr-4 text-blue-300">{s.capability}</td>
                      <td className="py-2 pr-4 text-center text-gray-300">{s.library_hits}</td>
                      <td className="py-2 pr-4 text-gray-300">
                        <span className="text-green-400">{s.tool_successes}</span>
                        <span className="text-gray-600">/{s.tool_attempts}</span>
                      </td>
                      <td className="py-2 pr-4 text-gray-300">
                        <span className="text-yellow-400">{s.findings_promoted}</span>
                        <span className="text-gray-600">/{s.findings_raw}</span>
                      </td>
                      <td className="py-2 pr-4">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-300 w-10 text-right">
                            {s.efficiency_score?.toFixed(0)}%
                          </span>
                          <div className="flex-1 min-w-20">
                            <ScoreBar value={s.efficiency_score} color="#3b82f6" />
                          </div>
                        </div>
                      </td>
                      <td className="py-2 pl-4">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-300 w-10 text-right">
                            {s.productivity_score?.toFixed(0)}%
                          </span>
                          <div className="flex-1 min-w-20">
                            <ScoreBar value={s.productivity_score} color="#22c55e" />
                          </div>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
