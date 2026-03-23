import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

export default function IssuesPage() {
  const [rows, setRows] = useState([]);
  const [page, setPage] = useState({ total: 0, limit: 100, offset: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/findings/page", {
          params: { status_filter: "open", limit: page.limit, offset: page.offset },
        });
        setRows(data?.items || []);
        setPage((prev) => ({ ...prev, total: Number(data?.total || 0) }));
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar issues.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [page.offset]);

  const hasPrev = page.offset > 0;
  const hasNext = page.offset + page.limit < page.total;

  const issuesByTarget = useMemo(() => {
    const map = new Map();
    for (const item of rows) {
      const key = item.target_query || "desconhecido";
      const existing = map.get(key) || { target: key, total: 0, critical: 0, high: 0, medium: 0, low: 0 };
      existing.total += 1;
      const sev = String(item.severity || "low").toLowerCase();
      if (sev in existing) existing[sev] += 1;
      map.set(key, existing);
    }
    return Array.from(map.values()).sort((a, b) => b.total - a.total);
  }, [rows]);

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Issues</h2>
        <p className="mt-1 text-sm text-slate-300">Consolidado de issues abertas por alvo, derivado de findings reais.</p>
        <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
          <p>Mostrando {rows.length} de {page.total} findings abertos</p>
          <div className="flex gap-2">
            <button
              disabled={!hasPrev}
              onClick={() => setPage((p) => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))}
              className="rounded-lg border border-slate-300 bg-white px-2 py-1 text-slate-700 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Anterior
            </button>
            <button
              disabled={!hasNext}
              onClick={() => setPage((p) => ({ ...p, offset: p.offset + p.limit }))}
              className="rounded-lg bg-[#1A365D] px-2 py-1 text-white hover:bg-[#2C5282] disabled:cursor-not-allowed disabled:opacity-40"
            >
              Proxima
            </button>
          </div>
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando issues...</p>}
        {!loading && issuesByTarget.length === 0 && <p className="text-sm text-slate-500">Nenhuma issue aberta no momento.</p>}

        <div className="space-y-2">
          {issuesByTarget.map((entry) => (
            <div key={entry.target} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-mono text-sm font-semibold">{entry.target}</p>
                <p className="text-sm">total: <span className="font-semibold text-white">{entry.total}</span></p>
              </div>
              <div className="mt-2 grid gap-2 text-xs sm:grid-cols-4">
                <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1">critical: {entry.critical}</p>
                <p className="rounded-md border border-orange-500/30 bg-orange-500/10 px-2 py-1">high: {entry.high}</p>
                <p className="rounded-md border border-yellow-500/30 bg-yellow-500/10 px-2 py-1">medium: {entry.medium}</p>
                <p className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1">low: {entry.low}</p>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
