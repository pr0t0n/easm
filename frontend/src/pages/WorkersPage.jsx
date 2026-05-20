import { useEffect, useState } from "react";
import client from "../api/client";

// ─── Paleta por agente ────────────────────────────────────────────────────────
const AGENT_PALETTE = {
  cyan:    { border: "border-cyan-500/40",    bg: "bg-cyan-500/10",    text: "text-cyan-300",    badge: "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40" },
  amber:   { border: "border-amber-500/40",   bg: "bg-amber-500/10",   text: "text-amber-300",   badge: "bg-amber-500/20 text-amber-300 border border-amber-500/40" },
  violet:  { border: "border-violet-500/40",  bg: "bg-violet-500/10",  text: "text-violet-300",  badge: "bg-violet-500/20 text-violet-300 border border-violet-500/40" },
  emerald: { border: "border-emerald-500/40", bg: "bg-emerald-500/10", text: "text-emerald-300", badge: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40" },
  rose:    { border: "border-rose-500/40",    bg: "bg-rose-500/10",    text: "text-rose-300",    badge: "bg-rose-500/20 text-rose-300 border border-rose-500/40" },
};

const PHASE_BADGE = {
  reconhecimento:         "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
  analise_vulnerabilidade:"bg-amber-500/20 text-amber-300 border-amber-500/40",
  osint:                  "bg-violet-500/20 text-violet-300 border-violet-500/40",
  governance:             "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  executive_analyst:      "bg-rose-500/20 text-rose-300 border-rose-500/40",
  desconhecido:           "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

// ─── Ícone de seta ────────────────────────────────────────────────────────────
function Arrow() {
  return (
    <div className="hidden shrink-0 items-center justify-center xl:flex">
      <svg viewBox="0 0 24 24" className="h-5 w-5 text-slate-500" fill="none" stroke="currentColor" strokeWidth="2">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
      </svg>
    </div>
  );
}

// ─── Card de um agente do pipeline ───────────────────────────────────────────
function AgentCard({ agent, expanded, onToggle, liveWorkers }) {
  const p = AGENT_PALETTE[agent.color] || AGENT_PALETTE.cyan;
  const workersForAgent = (liveWorkers || []).filter(
    (w) => w.execution_phase === agent.queue_suffix || w.execution_phase === agent.id,
  );
  const onlineCount = workersForAgent.filter((w) => w.online).length;

  return (
    <div className={`flex-1 min-w-[220px] max-w-sm rounded-2xl border ${p.border} ${p.bg} flex flex-col`}>
      {/* Cabeçalho clicável */}
      <button onClick={onToggle} className="w-full text-left p-4">
        <div className="flex items-start justify-between gap-2">
          <div>
            <p className={`text-[11px] font-bold uppercase tracking-widest ${p.text}`}>{agent.label}</p>
            <p className="mt-0.5 text-sm font-semibold text-slate-100">{agent.name}</p>
          </div>
          <div className="flex flex-col items-end gap-1">
            {agent.internal_only ? (
              <span className="rounded-md bg-slate-700/60 px-2 py-0.5 text-[10px] text-slate-400">interno</span>
            ) : (
              <span className={`rounded-md px-2 py-0.5 text-[10px] border ${onlineCount > 0 ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40" : "bg-slate-700/40 text-slate-400 border-slate-700"}`}>
                {onlineCount > 0 ? `${onlineCount} online` : "0 online"}
              </span>
            )}
            <span className={`text-[10px] ${p.text}`}>{expanded ? "▲ fechar" : "▼ detalhes"}</span>
          </div>
        </div>
        <p className="mt-2 text-[11px] leading-relaxed text-slate-400">{agent.purpose}</p>
      </button>

      {/* Detalhe expandido */}
      {expanded && (
        <div className="border-t border-slate-700/50 p-4 space-y-4">
          {/* Workers ao vivo */}
          {workersForAgent.length > 0 && (
            <div>
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400">Workers ao Vivo</p>
              <div className="space-y-1">
                {workersForAgent.map((w) => (
                  <div key={w.worker_name} className="rounded-lg border border-slate-800 bg-slate-900/60 px-2 py-1.5 text-[11px]">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-slate-200 truncate max-w-[140px]">{w.worker_name}</span>
                      <span className={`rounded-md px-1.5 py-0.5 ${w.online ? "bg-emerald-500/20 text-emerald-300" : "bg-rose-500/20 text-rose-300"}`}>
                        {w.online ? "online" : "offline"}
                      </span>
                    </div>
                    {w.active_scan && (
                      <p className="mt-0.5 text-slate-400 truncate">
                        scan #{w.active_scan.id} — {w.active_scan.target_query || "-"} ({w.active_scan.current_step || "…"})
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Ferramentas */}
          {agent.tools.length > 0 && (
            <div>
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400">
                Ferramentas ({agent.tools.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {agent.tools.map((tool) => (
                  <span key={tool} className={`rounded-md px-2 py-0.5 text-[10px] border ${AGENT_PALETTE[agent.color]?.badge}`}>
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Missões / prompts */}
          {agent.mission_items.length > 0 && (
            <div>
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400">
                Missões ({agent.mission_items.length} steps)
              </p>
              <ul className="space-y-0.5 max-h-64 overflow-y-auto pr-1">
                {agent.mission_items.map((item, idx) => (
                  <li key={idx} className="text-[11px] text-slate-300 leading-relaxed">
                    <span className={`mr-1 ${p.text}`}>›</span>{item}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {agent.internal_only && agent.tools.length === 0 && (
            <p className="text-[11px] text-slate-500 italic">Processamento interno Python — sem ferramentas externas.</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Componente principal ─────────────────────────────────────────────────────
export default function WorkersPage() {
  const [activeTab, setActiveTab] = useState("pipeline");
  const [pipeline, setPipeline]   = useState(null);
  const [health, setHealth]       = useState(null);
  const [overview, setOverview]   = useState(null);
  const [kaliCatalog, setKaliCatalog] = useState(null);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState("");
  const [expandedAgent, setExpandedAgent] = useState(null);
  const [missionSearch, setMissionSearch] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [pipelineRes, healthRes, overviewRes, kaliCatalogRes] = await Promise.all([
        client.get("/api/worker-manager/pipeline"),
        client.get("/api/worker-manager/health"),
        client.get("/api/worker-manager/overview"),
        client.get("/api/kali-runner/catalog"),
      ]);
      setPipeline(pipelineRes.data || null);
      setHealth(healthRes.data || null);
      setOverview(overviewRes.data || null);
      setKaliCatalog(kaliCatalogRes.data || null);
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar worker manager.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);
  useEffect(() => {
    if (activeTab !== "workers") return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [activeTab]);

  const liveWorkers = health?.workers || [];
  const agents = pipeline?.agents || [];

  const tabBtn = (id, label) => (
    <button onClick={() => setActiveTab(id)} className={`filter${activeTab === id ? " active" : ""}`}>
      {label}
    </button>
  );

  return (
    <main className="dpage space-y-4">
      {/* Header */}
      <div className="page-intro" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: 24, flexWrap: "wrap" }}>
        <div>
          <h2>Worker Manager.</h2>
          <div className="sub">
            pipeline ScriptKidd.o · {agents.length} agentes · {pipeline?.total_mission_items || 0} missões catalogadas
            {kaliCatalog ? ` · Kali ${kaliCatalog.profiled_tools_ready}/${kaliCatalog.profile_mappings_expected} profiles` : ""}
          </div>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>{loading ? "…" : "Atualizar"}</button>
      </div>

      <div className="t-tools" style={{ marginBottom: 4 }}>
        {tabBtn("pipeline", "Pipeline")}
        {tabBtn("workers", "Workers ao Vivo")}
        {tabBtn("kali", "Kali Catalog")}
        {tabBtn("missions", "Catálogo de Missões")}
        {tabBtn("metrics", "Métricas")}
      </div>

      {error && <div className="err-box">{error}</div>}

      {/* ── TAB: PIPELINE ───────────────────────────────────────────────── */}
      {activeTab === "pipeline" && (
        <>
          {/* Resumo de saúde */}
          {health?.summary && (
            <section className="grid-4">
              <div className="kpi">
                <div className="k">Workers total</div>
                <div className="v">{health.summary.total_workers}</div>
              </div>
              <div className="kpi">
                <div className="k">Online</div>
                <div className="v" style={{ color: "var(--sev-low-text)" }}>{health.summary.online_workers}</div>
              </div>
              <div className="kpi">
                <div className="k">Offline</div>
                <div className="v" style={{ color: "var(--sev-critical-text)" }}>{health.summary.offline_workers}</div>
              </div>
              <div className="kpi">
                <div className="k">Celery inspect</div>
                <div className="v" style={{ fontSize: 22, color: health.summary.inspect_ok ? "var(--sev-low-text)" : "var(--sev-medium-text)" }}>
                  {health.summary.inspect_ok ? "OK" : "indisponível"}
                </div>
              </div>
            </section>
          )}

          {/* Pipeline visual */}
          <section className="panel p-5">
            <h3 className="mb-1 text-base font-semibold text-slate-100">Fluxo de Execução</h3>
            <p className="mb-4 text-xs text-slate-500">
              Pipeline com paralelismo — Asset Discovery dispara ThreatIntel e RiskAssessment simultaneamente, 
              convergindo em Governance → Executive Analysis
            </p>
            {loading && !pipeline && <p className="text-sm text-slate-400">Carregando pipeline…</p>}

            {/* Cards do pipeline — sempre quebram em múltiplas linhas para que
                o fluxo inteiro seja visível, sem overflow horizontal. */}
            <div className="flex flex-wrap items-start gap-2">
              {agents.map((agent, idx) => (
                <div key={agent.id} className="flex items-start gap-2">
                  <AgentCard
                    agent={agent}
                    expanded={expandedAgent === agent.id}
                    onToggle={() => setExpandedAgent(expandedAgent === agent.id ? null : agent.id)}
                    liveWorkers={liveWorkers}
                  />
                  {idx < agents.length - 1 && <Arrow />}
                </div>
              ))}
              {/* END node */}
              {agents.length > 0 && (
                <div className="flex items-start gap-2">
                  <Arrow />
                  <div className="flex h-10 items-center rounded-xl border border-slate-700 bg-slate-900/50 px-3">
                    <span className="text-xs font-bold uppercase tracking-widest text-slate-500">END</span>
                  </div>
                </div>
              )}
            </div>
          </section>

          {/* Tabela de edges */}
          <section className="panel p-5">
            <h3 className="mb-3 text-base font-semibold text-slate-100">Transições do Grafo</h3>
            <div className="overflow-hidden rounded-xl border border-slate-700">
              <div className="grid grid-cols-[1fr_auto_1fr] gap-x-4 bg-slate-800/60 px-4 py-2 text-[11px] font-bold uppercase tracking-widest text-slate-400">
                <span>De</span><span>→</span><span>Para</span>
              </div>
              {(pipeline?.edges || []).map((edge, i) => {
                const from = agents.find((a) => a.id === edge.from);
                const to   = agents.find((a) => a.id === edge.to);
                const fromPalette = AGENT_PALETTE[from?.color] || AGENT_PALETTE.cyan;
                const toPalette   = AGENT_PALETTE[to?.color]   || AGENT_PALETTE.emerald;
                return (
                  <div key={i} className="grid grid-cols-[1fr_auto_1fr] gap-x-4 border-t border-slate-800 px-4 py-2.5 text-sm hover:bg-slate-800/20">
                    <span className={`font-semibold ${fromPalette.text}`}>{from ? `${from.label} — ${from.name}` : edge.from}</span>
                    <span className="text-slate-500">→</span>
                    <span className={`font-semibold ${toPalette ? toPalette.text : "text-slate-300"}`}>{to ? `${to.label} — ${to.name}` : edge.to}</span>
                  </div>
                );
              })}
            </div>
          </section>
        </>
      )}

      {/* ── TAB: KALI CATALOG ───────────────────────────────────────────── */}
      {activeTab === "kali" && (
        <section className="panel p-5">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Kali Runner Catalog</h3>
              <p className="mt-1 text-xs text-slate-500">
                Ferramentas executáveis no Kali, mapeadas para profile, worker, skill e fase de missão.
              </p>
            </div>
            <div className="grid min-w-[280px] grid-cols-2 gap-2 text-xs">
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2">
                <p className="text-slate-500">profiles prontos</p>
                <p className="text-lg font-semibold text-emerald-300">{kaliCatalog?.profiled_tools_ready || 0}</p>
              </div>
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2">
                <p className="text-slate-500">pendentes</p>
                <p className="text-lg font-semibold text-amber-300">{kaliCatalog?.profiled_tools_missing || 0}</p>
              </div>
              <div className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">
                <p className="text-slate-500">binários Kali</p>
                <p className="text-lg font-semibold text-slate-100">{kaliCatalog?.kali_tools_detected || 0}</p>
              </div>
              <div className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">
                <p className="text-slate-500">profiles</p>
                <p className="text-lg font-semibold text-slate-100">{kaliCatalog?.profiles_loaded || 0}</p>
              </div>
            </div>
          </div>

          <div className="mt-4 overflow-hidden rounded-xl border border-slate-800">
            <table className="min-w-full text-xs">
              <thead className="bg-slate-900 text-slate-400">
                <tr className="text-left">
                  <th className="px-3 py-2">Tool</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Profile</th>
                  <th className="px-3 py-2">Worker</th>
                  <th className="px-3 py-2">Skills / fases</th>
                  <th className="px-3 py-2">Uso</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-950/50">
                {(kaliCatalog?.tools || []).map((tool) => (
                  <tr key={tool.name}>
                    <td className="px-3 py-2 font-mono text-slate-100">{tool.name}</td>
                    <td className="px-3 py-2">
                      <span className={`rounded-md px-2 py-0.5 ${tool.available ? "bg-emerald-500/20 text-emerald-300" : "bg-amber-500/20 text-amber-300"}`}>
                        {tool.status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      <span className="font-mono">{tool.profile}</span>
                      {tool.executable && <span className="ml-1 text-slate-500">({tool.executable})</span>}
                    </td>
                    <td className="px-3 py-2 text-slate-300">{tool.worker_group || "unassigned"}</td>
                    <td className="px-3 py-2 text-slate-400">
                      {(tool.skills || []).slice(0, 2).join(", ") || "-"}
                      {(tool.mission_phases || []).length > 0 && <span className="ml-1 text-slate-500">[{tool.mission_phases.join(", ")}]</span>}
                    </td>
                    <td className="max-w-md px-3 py-2 text-slate-400">{tool.need || tool.functionality || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── TAB: WORKERS AO VIVO ────────────────────────────────────────── */}
      {activeTab === "workers" && (
        <>
          <section className="panel p-5">
            <h3 className="mb-3 text-base font-semibold text-slate-100">Instâncias de Workers</h3>
            {loading && <p className="text-sm text-slate-400">Carregando…</p>}
            {!loading && liveWorkers.length === 0 && (
              <p className="text-sm text-slate-500">Nenhum worker registrado.</p>
            )}
            <div className="space-y-2">
              {liveWorkers.map((worker) => (
                <div key={worker.worker_name} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-mono font-semibold text-slate-100">{worker.worker_name}</p>
                    <div className="flex items-center gap-2">
                      <span className={`rounded-md px-2 py-0.5 text-xs ${worker.online ? "bg-emerald-500/20 text-emerald-300" : "bg-rose-500/20 text-rose-300"}`}>
                        {worker.online ? "online" : "offline"}
                      </span>
                      <span className={`rounded-md border px-2 py-0.5 text-xs ${PHASE_BADGE[worker.execution_phase] || PHASE_BADGE.desconhecido}`}>
                        {worker.execution_phase || "desconhecido"}
                      </span>
                    </div>
                  </div>
                  <p className="mt-1 text-xs text-slate-300">
                    modo: {worker.mode} | status: {worker.status} | task: {worker.last_task_name || "—"}
                  </p>
                  <p className="text-xs text-slate-400">
                    last_seen: {worker.last_seen_at ? new Date(worker.last_seen_at).toLocaleString("pt-BR") : "—"}
                    {worker.last_seen_lag_seconds != null ? ` (${worker.last_seen_lag_seconds}s atrás)` : ""}
                  </p>
                  <p className="text-xs text-slate-500">origem: {worker.online_reason || "—"}</p>
                  {worker.active_scan && (
                    <div className="mt-2 rounded-lg border border-slate-700 bg-slate-800/40 p-2 text-xs text-slate-300">
                      <p>scan #{worker.active_scan.id} — alvo: <span className="text-slate-100">{worker.active_scan.target_query || "—"}</span></p>
                      <p>etapa: <span className="text-slate-100">{worker.active_scan.current_step || "—"}</span> | status: <span className="text-slate-100">{worker.active_scan.status || "—"}</span></p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        </>
      )}

      {/* ── TAB: CATÁLOGO DE MISSÕES ─────────────────────────────────────── */}
      {activeTab === "missions" && (
        <section className="panel p-5">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Catálogo Completo de Missões</h3>
              <p className="mt-0.5 text-xs text-slate-400">{pipeline?.total_mission_items || 0} steps — cobertura técnica completa do pipeline ScriptKidd.o</p>
            </div>
            <input
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 md:w-72"
              placeholder="Filtrar missões…"
              value={missionSearch}
              onChange={(e) => setMissionSearch(e.target.value)}
            />
          </div>

          {/* Por agente */}
          <div className="mt-5 space-y-4">
            {agents.map((agent) => {
              if (agent.mission_items.length === 0) return null;
              const filtered = agent.mission_items.filter((item) =>
                item.toLowerCase().includes(missionSearch.toLowerCase()),
              );
              if (missionSearch && filtered.length === 0) return null;
              const p = AGENT_PALETTE[agent.color] || AGENT_PALETTE.cyan;
              return (
                <div key={agent.id} className={`rounded-2xl border ${p.border} ${p.bg} p-4`}>
                  <div className="mb-3 flex items-center gap-2">
                    <span className={`rounded-md px-2 py-0.5 text-[11px] font-bold uppercase tracking-widest border ${p.badge}`}>
                      {agent.label}
                    </span>
                    <span className="text-sm font-semibold text-slate-100">{agent.name}</span>
                    <span className="ml-auto text-xs text-slate-500">{filtered.length} steps</span>
                  </div>
                  <div className="grid gap-x-6 gap-y-0.5 md:grid-cols-2 xl:grid-cols-3">
                    {filtered.map((item, idx) => (
                      <p key={idx} className="text-[11px] text-slate-300 leading-relaxed">
                        <span className={`mr-1 ${p.text}`}>›</span>{item}
                      </p>
                    ))}
                  </div>
                </div>
              );
            })}

            {/* Items sem agente mapeado (agent 4 e 5 internos) */}
            {pipeline?.mission_items_full && (() => {
              const allMapped = agents.flatMap((a) => a.mission_items);
              const unmapped = (pipeline.mission_items_full || []).filter(
                (item) => !allMapped.includes(item) && item.toLowerCase().includes(missionSearch.toLowerCase()),
              );
              if (unmapped.length === 0) return null;
              return (
                <div className="rounded-2xl border border-slate-700 bg-slate-900/40 p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <span className="rounded-md bg-slate-700/60 px-2 py-0.5 text-[11px] font-bold uppercase tracking-widest text-slate-400">Geral</span>
                    <span className="text-xs text-slate-500">{unmapped.length} steps</span>
                  </div>
                  <div className="grid gap-x-6 gap-y-0.5 md:grid-cols-2 xl:grid-cols-3">
                    {unmapped.map((item, idx) => (
                      <p key={idx} className="text-[11px] text-slate-400 leading-relaxed">
                        <span className="mr-1 text-slate-600">›</span>{item}
                      </p>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
        </section>
      )}

      {/* ── TAB: MÉTRICAS ───────────────────────────────────────────────── */}
      {activeTab === "metrics" && (
        <>
          {/* Métricas gerais */}
          {overview?.interaction_metrics && (
            <section className="panel p-5">
              <h3 className="mb-3 text-base font-semibold text-slate-100">Indicadores Gerais</h3>
              <div className="grid gap-2 text-sm md:grid-cols-3">
                <div className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">
                  <p className="text-xs text-slate-500">scans analisados</p>
                  <p className="text-xl font-semibold text-slate-100">{overview.interaction_metrics.scans_analyzed}</p>
                </div>
                <div className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">
                  <p className="text-xs text-slate-500">crescimento lateral médio</p>
                  <p className="text-xl font-semibold text-slate-100">{overview.interaction_metrics.avg_lateral_growth_assets}</p>
                </div>
                <div className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">
                  <p className="text-xs text-slate-500">média de portas descobertas</p>
                  <p className="text-xl font-semibold text-slate-100">{overview.interaction_metrics.avg_discovered_ports}</p>
                </div>
              </div>
            </section>
          )}

          {/* Timing por nó */}
          {overview?.interaction_metrics?.node_timing && Object.keys(overview.interaction_metrics.node_timing).length > 0 && (
            <section className="panel p-5">
              <h3 className="mb-3 text-base font-semibold text-slate-100">Tempo por Agente (ms)</h3>
              <div className="overflow-hidden rounded-xl border border-slate-700">
                <div className="hidden grid-cols-[160px_100px_100px_80px] bg-slate-800/60 px-4 py-2 text-[11px] font-bold uppercase tracking-widest text-slate-400 md:grid">
                  <span>Agente / Nó</span><span>Avg</span><span>Max</span><span>Amostras</span>
                </div>
                {Object.entries(overview.interaction_metrics.node_timing).map(([node, t]) => {
                  const agent = agents.find((a) => a.id === node || a.queue_suffix === node);
                  const palette = AGENT_PALETTE[agent?.color] || { text: "text-slate-300" };
                  return (
                    <div key={node} className="grid gap-2 border-t border-slate-800 px-4 py-2.5 text-sm md:grid-cols-[160px_100px_100px_80px] hover:bg-slate-800/20">
                      <span className={`font-semibold ${palette.text}`}>{node}</span>
                      <span className="text-slate-300">{t.avg_ms} ms</span>
                      <span className="text-slate-400">{t.max_ms} ms</span>
                      <span className="text-slate-500">{t.samples}x</span>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* Contagem de transições */}
          {overview?.interaction_metrics?.transition_counts && Object.keys(overview.interaction_metrics.transition_counts).length > 0 && (
            <section className="panel p-5">
              <h3 className="mb-3 text-base font-semibold text-slate-100">Contagem de Transições</h3>
              <div className="space-y-1">
                {Object.entries(overview.interaction_metrics.transition_counts)
                  .sort(([, a], [, b]) => b - a)
                  .map(([edge, count]) => {
                    const [fromNode, toNode] = edge.split("->").map((s) => s.trim());
                    const ratio = Math.min(1, count / Math.max(...Object.values(overview.interaction_metrics.transition_counts)));
                    return (
                      <div key={edge} className="rounded-lg border border-slate-800 px-3 py-2">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-slate-300">{fromNode} <span className="text-slate-600">→</span> {toNode}</span>
                          <span className="font-mono font-semibold text-slate-100">{count}x</span>
                        </div>
                        <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-slate-800">
                          <div className="h-1 rounded-full bg-blue-500/60" style={{ width: `${Math.round(ratio * 100)}%` }} />
                        </div>
                      </div>
                    );
                  })}
              </div>
            </section>
          )}

          {(!overview?.interaction_metrics || (
            Object.keys(overview.interaction_metrics.node_timing || {}).length === 0 &&
            Object.keys(overview.interaction_metrics.transition_counts || {}).length === 0
          )) && (
            <section className="panel p-5">
              <p className="text-sm text-slate-500">Sem dados de métricas ainda — execute scans para acumular histórico.</p>
            </section>
          )}
        </>
      )}
    </main>
  );
}
