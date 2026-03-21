import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

const SEV_STYLE = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
  low: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
};

export default function VulnerabilitiesPage() {
  const [rows, setRows] = useState([]);
  const [page, setPage] = useState({ total: 0, limit: 50, offset: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("all");
  const [statusFilter, setStatusFilter] = useState("open");
  const [targetQuery, setTargetQuery] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const params = {
        status_filter: statusFilter,
        limit: page.limit,
        offset: page.offset,
      };
      if (severity !== "all") params.severity = severity;
      if (targetQuery.trim()) params.target = targetQuery.trim();

      const { data } = await client.get("/api/findings/page", { params });
      setRows(data?.items || []);
      setPage((prev) => ({
        ...prev,
        total: Number(data?.total || 0),
      }));
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar vulnerabilidades.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [severity, statusFilter, page.offset]);

  const hasPrev = page.offset > 0;
  const hasNext = page.offset + page.limit < page.total;

  const counts = useMemo(() => {
    return rows.reduce(
      (acc, item) => {
        const sev = String(item.severity || "low").toLowerCase();
        if (sev in acc) acc[sev] += 1;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );
  }, [rows]);

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Vulnerabilities</h2>
        <p className="mt-1 text-sm text-slate-300">Base real de findings coletados pelos scans.</p>

        <div className="mt-3 grid gap-2 md:grid-cols-4">
          <input
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            placeholder="Filtrar por target"
            value={targetQuery}
            onChange={(e) => setTargetQuery(e.target.value)}
          />
          <select className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">Todas severidades</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="open">Abertas</option>
            <option value="false_positive">Falsos positivos</option>
            <option value="all">Todas</option>
          </select>
          <button onClick={load} className="rounded-xl bg-brand-500 px-4 py-2 font-semibold text-slate-950">Atualizar</button>
        </div>

        <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
          <p>Mostrando {rows.length} de {page.total} findings</p>
          <div className="flex gap-2">
            <button disabled={!hasPrev} onClick={() => setPage((p) => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))} className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40">Anterior</button>
            <button disabled={!hasNext} onClick={() => setPage((p) => ({ ...p, offset: p.offset + p.limit }))} className="rounded-lg bg-slate-800 px-2 py-1 disabled:opacity-40">Proxima</button>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
          <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-2 py-1">critical: {counts.critical}</p>
          <p className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-2 py-1">high: {counts.high}</p>
          <p className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-2 py-1">medium: {counts.medium}</p>
          <p className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2 py-1">low: {counts.low}</p>
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando vulnerabilidades...</p>}
        {!loading && rows.length === 0 && <p className="text-sm text-slate-500">Nenhuma vulnerabilidade para os filtros atuais.</p>}

        <div className="space-y-2">
          {rows.map((item) => (
            <div key={item.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <p className="font-medium">{item.title}</p>
                  <p className="text-xs text-slate-400">scan #{item.scan_job_id} - {item.target_query}</p>
                </div>
                <span className={`rounded-md border px-2 py-0.5 text-xs uppercase ${SEV_STYLE[item.severity] || SEV_STYLE.low}`}>
                  {item.severity}
                </span>
              </div>
              <div className="mt-2 grid gap-2 text-xs text-slate-300 sm:grid-cols-4">
                <p>risk: <span className="text-white">{item.risk_score ?? "-"}</span></p>
                <p>confidence: <span className="text-white">{item.confidence_score ?? "-"}</span></p>
                <p>cve: <span className="text-white">{item.cve || "-"}</span></p>
                <p>status: <span className="text-white">{item.is_false_positive ? "false_positive" : "open"}</span></p>
                <p>FAIR: <span className="text-cyan-300">{item.fair?.fair_score ?? 0}</span></p>
                <p>ALE: <span className="text-amber-300">USD {Number(item.fair?.annualized_loss_exposure_usd || 0).toLocaleString("en-US", { maximumFractionDigits: 0 })}</span></p>
                <p>AGE ambiente: <span className="text-white">{item.age?.known_in_environment_days ?? 0}d</span></p>
                <p>AGE mercado/exploit: <span className="text-white">{item.age?.known_in_market_days ?? 0}/{item.age?.exploit_published_days ?? 0}d</span></p>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
