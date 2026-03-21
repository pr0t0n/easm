import { useEffect, useState } from "react";
import client from "../api/client";

export default function JobsRegistryPage() {
  const [jobs, setJobs] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [jobsRes, eventsRes] = await Promise.all([
        client.get("/api/jobs/registry", { params: { limit: 300 } }),
        client.get("/api/audit/events", { params: { limit: 80 } }),
      ]);
      setJobs(jobsRes.data || []);
      setEvents(eventsRes.data || []);
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar registro de jobs.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <div className="flex items-center justify-between gap-2">
          <div>
            <h2 className="text-xl font-semibold">Jobs Registry</h2>
            <p className="mt-1 text-sm text-slate-300">Historico real de execucoes e trilha de auditoria.</p>
          </div>
          <button onClick={load} className="rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">Atualizar</button>
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel p-5">
          <h3 className="text-lg font-semibold">Execucoes</h3>
          {loading && <p className="mt-2 text-sm text-slate-400">Carregando jobs...</p>}
          {!loading && jobs.length === 0 && <p className="mt-2 text-sm text-slate-500">Sem jobs registrados.</p>}
          <div className="mt-3 space-y-2">
            {jobs.map((job) => (
              <div key={job.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="font-mono font-semibold">#{job.id} - {job.target_query}</p>
                  <span className="rounded-md border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs uppercase">{job.status}</span>
                </div>
                <p className="mt-1 text-xs text-slate-300">{job.mode} | compliance: {job.compliance_status} | findings: {job.findings_count}</p>
                <p className="text-xs text-slate-400">retry {job.retry_attempt || 0}/{job.retry_max || 0} | progresso {job.mission_progress}%</p>
                <p className="text-xs text-slate-400">duracao: {job.duration_seconds ?? "-"}s | atualizado: {job.updated_at ? new Date(job.updated_at).toLocaleString("pt-BR") : "-"}</p>
                {job.last_error && <p className="mt-1 text-xs text-rose-300">erro: {job.last_error}</p>}
              </div>
            ))}
          </div>
        </section>

        <section className="panel p-5">
          <h3 className="text-lg font-semibold">Eventos de Auditoria</h3>
          {loading && <p className="mt-2 text-sm text-slate-400">Carregando eventos...</p>}
          {!loading && events.length === 0 && <p className="mt-2 text-sm text-slate-500">Sem eventos.</p>}
          <div className="mt-3 space-y-2">
            {events.map((event) => (
              <div key={event.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3 text-xs">
                <p className="font-semibold text-slate-100">{event.event_type}</p>
                <p className="mt-1 text-slate-300">{event.message}</p>
                <p className="mt-1 text-slate-500">{new Date(event.created_at).toLocaleString("pt-BR")}</p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
