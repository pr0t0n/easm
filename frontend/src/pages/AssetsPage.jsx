import { useEffect, useState } from "react";
import client from "../api/client";

const RISK_DOT = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-emerald-500",
};

export default function AssetsPage() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/assets");
        setRows(data || []);
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar ativos.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const filtered = rows.filter((item) => String(item.name || "").toLowerCase().includes(query.trim().toLowerCase()));

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold">Assets</h2>
            <p className="mt-1 text-sm text-slate-300">Ativos descobertos a partir do estado real dos scans.</p>
          </div>
          <input
            className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 sm:w-80"
            placeholder="Buscar asset"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </section>

      {error && <section className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-sm text-rose-200">{error}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando assets...</p>}
        {!loading && filtered.length === 0 && <p className="text-sm text-slate-500">Nenhum asset encontrado.</p>}

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {filtered.map((asset) => (
            <div key={asset.name} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="flex items-center gap-2">
                <span className={`h-2.5 w-2.5 rounded-full ${RISK_DOT[asset.risk] || RISK_DOT.low}`} />
                <p className="truncate font-mono text-sm font-semibold">{asset.name}</p>
              </div>
              <div className="mt-2 space-y-1 text-xs text-slate-300">
                <p>tipo: <span className="capitalize text-white">{asset.type}</span></p>
                <p>origem: <span className="text-white">{asset.source_target}</span></p>
                <p>visto em scans: <span className="text-white">{asset.seen_in_scans}</span></p>
                <p>ultima vez: <span className="text-white">{asset.last_seen_at ? new Date(asset.last_seen_at).toLocaleString("pt-BR") : "-"}</span></p>
                {asset.type === "domain" && (
                  <p>subdomínios: <span className="text-white">{asset.subdomain_count || 0}</span></p>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
