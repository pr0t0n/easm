import { useEffect, useState } from "react";
import client from "../api/client";

const RISK_COLOR = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
  low: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
};

export default function TargetsPage() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/targets/summary");
        setRows(data || []);
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar targets.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const filtered = rows.filter((item) => {
    const target = String(item.target || "").toLowerCase();
    return target.includes(query.trim().toLowerCase());
  });

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold">Targets</h2>
            <p className="mt-1 text-sm text-slate-300">Inventario real de alvos a partir dos scans executados.</p>
          </div>
          <input
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 sm:w-80"
            placeholder="Buscar target"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando targets...</p>}
        {!loading && filtered.length === 0 && <p className="text-sm text-slate-500">Nenhum target encontrado.</p>}

        <div className="space-y-2">
          {filtered.map((item) => (
            <div key={item.target} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <p className="font-mono text-sm font-semibold">{item.target}</p>
                  <p className="text-xs text-slate-400">
                    ultimo scan: {item.last_scan_at ? new Date(item.last_scan_at).toLocaleString("pt-BR") : "-"}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="rounded-md border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs uppercase text-slate-300">
                    {item.last_status}
                  </span>
                  <span className={`rounded-md border px-2 py-0.5 text-xs uppercase ${RISK_COLOR[item.highest_severity] || RISK_COLOR.low}`}>
                    risco {item.highest_severity}
                  </span>
                </div>
              </div>
              <div className="mt-2 grid gap-2 text-xs text-slate-300 sm:grid-cols-4">
                <p>scans: <span className="font-semibold text-white">{item.scans}</span></p>
                <p>findings: <span className="font-semibold text-white">{item.findings_total}</span></p>
                <p>abertos: <span className="font-semibold text-amber-300">{item.findings_open}</span></p>
                <p>modo ultimo scan: <span className="font-semibold text-white">{item.last_mode}</span></p>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
