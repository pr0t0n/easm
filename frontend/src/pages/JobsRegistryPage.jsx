import { useEffect, useState } from "react";
import client from "../api/client";

const STATUS_DOT = {
  completed: "ok",
  running: "run",
  retrying: "warn",
  queued: "idle",
  failed: "crit",
  blocked: "crit",
};

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
    <main className="dpage">
      <div className="page-intro" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          <h2>Job Registry.</h2>
          <div className="sub">histórico real de execuções Celery e trilha de auditoria</div>
        </div>
        <button className="btn btn-ghost" onClick={load}>Atualizar</button>
      </div>

      {error && <div className="err-box" style={{ marginBottom: 16 }}>{error}</div>}

      <div className="grid-2">
        <section className="t-wrap">
          <div className="t-head"><div><h3>Execuções</h3><div className="sub">jobs por scan</div></div></div>
          {loading && <div className="state" style={{ minHeight: 200 }}><div><div className="spin" /><p className="st-title">Carregando jobs…</p></div></div>}
          {!loading && jobs.length === 0 && <div className="empty">Sem jobs registrados.</div>}
          {!loading && jobs.length > 0 && (
            <div style={{ maxHeight: 540, overflowY: "auto" }}>
              {jobs.map((job) => (
                <div key={job.id} style={{ padding: "14px 22px", borderBottom: "1px solid var(--line-soft)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
                    <span className="mono" style={{ fontWeight: 600 }}>#{job.id} · {job.target_query}</span>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                      <span className={`dot-state ${STATUS_DOT[job.status] || "idle"}`} />
                      <span className="mono-sm">{job.status}</span>
                    </span>
                  </div>
                  <div className="mono-sm muted" style={{ marginTop: 4 }}>
                    {job.mode} · compliance {job.compliance_status} · {job.findings_count} findings · retry {job.retry_attempt || 0}/{job.retry_max || 0} · {job.mission_progress}%
                  </div>
                  {job.last_error && (
                    <div className="mono-sm" style={{ marginTop: 4, color: "var(--sev-critical-text)" }}>erro: {job.last_error}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="t-wrap">
          <div className="t-head"><div><h3>Eventos de auditoria</h3><div className="sub">trilha governada</div></div></div>
          {loading && <div className="state" style={{ minHeight: 200 }}><div><div className="spin" /><p className="st-title">Carregando eventos…</p></div></div>}
          {!loading && events.length === 0 && <div className="empty">Sem eventos.</div>}
          {!loading && events.length > 0 && (
            <div style={{ maxHeight: 540, overflowY: "auto" }}>
              {events.map((event) => (
                <div key={event.id} style={{ padding: "12px 22px", borderBottom: "1px solid var(--line-soft)" }}>
                  <div style={{ fontWeight: 600, fontSize: 12.5 }}>{event.event_type}</div>
                  <div className="mono-sm soft" style={{ marginTop: 3 }}>{event.message}</div>
                  <div className="mono-sm muted" style={{ marginTop: 3 }}>{new Date(event.created_at).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}</div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
