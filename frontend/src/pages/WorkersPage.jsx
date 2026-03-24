import { useEffect, useState } from "react";
import client from "../api/client";

const PHASE_BADGE = {
  reconhecimento: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40",
  analise_vulnerabilidade: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  osint: "bg-violet-500/20 text-violet-300 border-violet-500/40",
  desconhecido: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

export default function WorkersPage() {
  const [health, setHealth] = useState(null);
  const [groups, setGroups] = useState({ unit: {}, scheduled: {} });
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [healthRes, groupsRes, overviewRes] = await Promise.all([
        client.get("/api/worker-manager/health"),
        client.get("/api/worker-manager/groups"),
        client.get("/api/worker-manager/overview"),
      ]);
      setHealth(healthRes.data || null);
      setGroups(groupsRes.data || { unit: {}, scheduled: {} });
      setOverview(overviewRes.data || null);
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar workers.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      load();
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h2 className="text-xl font-semibold">Workers</h2>
            <p className="mt-1 text-sm text-slate-300">Estado operacional em tempo real do worker manager.</p>
          </div>
          <button onClick={load} className="rounded-xl bg-blue-600 px-4 py-2 font-semibold text-white">Atualizar</button>
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando health dos workers...</p>}
        {health?.summary && (
          <div className="grid gap-2 text-sm md:grid-cols-4">
            <p className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">total: {health.summary.total_workers}</p>
            <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2">online: {health.summary.online_workers}</p>
            <p className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2">offline: {health.summary.offline_workers}</p>
            <p className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">stale: {health.summary.stale_after_seconds}s</p>
          </div>
        )}

        {health?.summary?.phase_counts && (
          <div className="mt-3 grid gap-2 text-sm md:grid-cols-4">
            <p className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2">reconhecimento: {health.summary.phase_counts.reconhecimento || 0}</p>
            <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2">analise de vulnerabilidade: {health.summary.phase_counts.analise_vulnerabilidade || 0}</p>
            <p className="rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2">osint: {health.summary.phase_counts.osint || 0}</p>
            <p className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">desconhecido: {health.summary.phase_counts.desconhecido || 0}</p>
          </div>
        )}

        <p className="mt-3 text-xs text-slate-400">
          inspeccao celery: {health?.summary?.inspect_ok ? "ok" : "indisponivel"}
        </p>

        <div className="mt-3 space-y-2">
          {(health?.workers || []).map((worker) => (
            <div key={worker.worker_name} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-mono font-semibold">{worker.worker_name}</p>
                <div className="flex items-center gap-2">
                  <span className={`rounded-md px-2 py-0.5 text-xs ${worker.online ? "bg-emerald-500/20 text-emerald-300" : "bg-rose-500/20 text-rose-300"}`}>
                    {worker.online ? "online" : "offline"}
                  </span>
                  <span className={`rounded-md border px-2 py-0.5 text-xs ${PHASE_BADGE[worker.execution_phase] || PHASE_BADGE.desconhecido}`}>
                    {worker.execution_phase || "desconhecido"}
                  </span>
                </div>
              </div>
              <p className="mt-1 text-xs text-slate-300">modo: {worker.mode} | status: {worker.status} | task: {worker.last_task_name || "-"}</p>
              <p className="text-xs text-slate-400">
                last_seen: {worker.last_seen_at ? new Date(worker.last_seen_at).toLocaleString("pt-BR") : "-"}
                {worker.last_seen_lag_seconds != null ? ` (${worker.last_seen_lag_seconds}s atras)` : ""}
              </p>
              <p className="text-xs text-slate-500">origem status: {worker.online_reason || "-"}</p>
              {worker.active_scan && (
                <div className="mt-2 rounded-lg border border-slate-700 bg-slate-800/40 p-2 text-xs text-slate-300">
                  <p>
                    scan #{worker.active_scan.id} | alvo: <span className="text-slate-100">{worker.active_scan.target_query || "-"}</span>
                  </p>
                  <p>
                    etapa atual: <span className="text-slate-100">{worker.active_scan.current_step || "-"}</span>
                  </p>
                  <p>
                    status scan: <span className="text-slate-100">{worker.active_scan.status || "-"}</span> | modo: <span className="text-slate-100">{worker.active_scan.mode || "-"}</span>
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Grupos Configurados</h3>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {Object.entries(groups || {}).map(([mode, modeGroups]) => (
            <div key={mode} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <p className="font-semibold uppercase">{mode}</p>
              <div className="mt-2 space-y-1 text-xs text-slate-300">
                {Object.entries(modeGroups || {}).map(([name, group]) => (
                  <p key={`${mode}-${name}`}>{name}: fila {group.queue} ({(group.tools || []).join(", ")})</p>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="text-lg font-semibold">Metricas de Interacao</h3>
        {!overview && <p className="text-sm text-slate-400">Sem dados.</p>}
        {overview?.interaction_metrics && (
          <div className="mt-3 grid gap-2 text-sm md:grid-cols-3">
            <p className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">scans analisados: {overview.interaction_metrics.scans_analyzed}</p>
            <p className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">crescimento lateral medio: {overview.interaction_metrics.avg_lateral_growth_assets}</p>
            <p className="rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2">media de portas: {overview.interaction_metrics.avg_discovered_ports}</p>
          </div>
        )}
      </section>
    </main>
  );
}
