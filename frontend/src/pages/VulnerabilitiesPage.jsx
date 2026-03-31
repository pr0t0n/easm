import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

const SEV_STYLE = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-800 border-yellow-500/40 bg-yellow-100",
  low: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
  info: "text-blue-300 border-blue-500/30 bg-blue-500/10",
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const sanitizeText = (value) => {
  if (value == null) return "";
  return String(value)
    .replace(/\u001b\[[0-9;]*m/g, "")
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
};

export default function VulnerabilitiesPage() {
  const [rows, setRows] = useState([]);
  const [targets, setTargets] = useState([]);
  const [page, setPage] = useState({ total: 0, limit: 50, offset: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severitiesFilter, setSeveritiesFilter] = useState(["critical", "high", "medium", "low", "info"]);
  const [statusFilter, setStatusFilter] = useState("open");
  const [targetQuery, setTargetQuery] = useState("");

  const loadTargets = async () => {
    try {
      const { data } = await client.get("/api/targets/summary");
      setTargets((Array.isArray(data) ? data : []).map((t) => t.target).sort());
    } catch (err) {
      console.error("Falha ao carregar targets:", err);
    }
  };

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const params = {
        status_filter: statusFilter,
        limit: page.limit,
        offset: page.offset,
      };
      if (severitiesFilter.length > 0 && severitiesFilter.length < 5) {
        params.severity = severitiesFilter.join(",");
      }
      if (targetQuery.trim()) params.target = targetQuery.trim();

      const { data } = await client.get("/api/findings/page", { params });
      const items = (data?.items || []).sort((a, b) => {
        const sevA = String(a.severity || "low").toLowerCase();
        const sevB = String(b.severity || "low").toLowerCase();
        return (SEV_ORDER[sevA] ?? 99) - (SEV_ORDER[sevB] ?? 99);
      });
      setRows(items);
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
    loadTargets();
  }, []);

  useEffect(() => {
    setPage((p) => ({ ...p, offset: 0 }));
  }, [severitiesFilter, statusFilter, targetQuery]);

  useEffect(() => {
    load();
  }, [severitiesFilter, statusFilter, page.offset, targetQuery]);

  const hasPrev = page.offset > 0;
  const hasNext = page.offset + page.limit < page.total;

  const counts = useMemo(() => {
    return rows.reduce(
      (acc, item) => {
        const sev = String(item.severity || "low").toLowerCase();
        if (sev in acc) acc[sev] += 1;
        return acc;
      },
      { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    );
  }, [rows]);

  const toggleSeverity = (sev) => {
    setSeveritiesFilter((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
  };

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-4 pb-10">
      <section className="panel p-5">
        <h2 className="text-xl font-semibold">Vulnerabilities</h2>
        <p className="mt-1 text-sm text-slate-300">Base real de findings coletados pelos scans.</p>

        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <select
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={targetQuery}
            onChange={(e) => setTargetQuery(e.target.value)}
          >
            <option value="">Todos os targets</option>
            {targets.map((target) => (
              <option key={target} value={target}>
                {target}
              </option>
            ))}
          </select>
          <select className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="open">Abertas</option>
            <option value="closed">Fechadas</option>
            <option value="false_positive">Falsos positivos</option>
            <option value="all">Todas</option>
          </select>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            onClick={() => toggleSeverity("critical")}
            className={`rounded-md border px-3 py-1 text-xs font-semibold transition ${
              severitiesFilter.includes("critical")
                ? "border-red-500 bg-red-500/20 text-red-300"
                : "border-red-500/30 bg-red-500/10 text-red-300/50"
            }`}
          >
            Critical ({counts.critical})
          </button>
          <button
            onClick={() => toggleSeverity("high")}
            className={`rounded-md border px-3 py-1 text-xs font-semibold transition ${
              severitiesFilter.includes("high")
                ? "border-orange-500 bg-orange-500/20 text-orange-300"
                : "border-orange-500/30 bg-orange-500/10 text-orange-300/50"
            }`}
          >
            High ({counts.high})
          </button>
          <button
            onClick={() => toggleSeverity("medium")}
            className={`rounded-md border px-3 py-1 text-xs font-semibold transition ${
              severitiesFilter.includes("medium")
                ? "border-yellow-500 bg-yellow-100 text-yellow-800"
                : "border-yellow-500/30 bg-yellow-50 text-yellow-700/70"
            }`}
          >
            Medium ({counts.medium})
          </button>
          <button
            onClick={() => toggleSeverity("low")}
            className={`rounded-md border px-3 py-1 text-xs font-semibold transition ${
              severitiesFilter.includes("low")
                ? "border-emerald-500 bg-emerald-500/20 text-emerald-300"
                : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300/50"
            }`}
          >
            Low ({counts.low})
          </button>
          <button
            onClick={() => toggleSeverity("info")}
            className={`rounded-md border px-3 py-1 text-xs font-semibold transition ${
              severitiesFilter.includes("info")
                ? "border-blue-500 bg-blue-500/20 text-blue-300"
                : "border-blue-500/30 bg-blue-500/10 text-blue-300/50"
            }`}
          >
            Info ({counts.info})
          </button>
        </div>

        <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
          <p>Mostrando {rows.length} de {page.total} findings</p>
          <div className="flex gap-2">
            <button
              disabled={!hasPrev}
              onClick={() => setPage((p) => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))}
              className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-slate-300 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
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
        {loading && <p className="text-sm text-slate-400">Carregando vulnerabilidades...</p>}
        {!loading && rows.length === 0 && <p className="text-sm text-slate-500">Nenhuma vulnerabilidade para os filtros atuais.</p>}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-xs uppercase text-slate-400">
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Vulnerabilidade</th>
                <th className="px-3 py-2">CVE</th>
                <th className="px-3 py-2">CVSS</th>
                <th className="px-3 py-2">Severidade</th>
                <th className="px-3 py-2">Data</th>
                <th className="px-3 py-2">Alvo</th>
                <th className="px-3 py-2">Dominio</th>
                <th className="px-3 py-2">Ferramenta</th>
                <th className="px-3 py-2">Recomendacao</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => {
                let recSummary = "";
                try {
                  const rec = item.recommendation ? JSON.parse(item.recommendation) : null;
                  recSummary = rec?.resumo || rec?.summary || "";
                } catch {
                  recSummary = item.recommendation || "";
                }
                return (
                  <tr key={item.id} className="border-b border-slate-800 hover:bg-slate-800/50">
                    <td className="px-3 py-2 text-slate-400">{item.id}</td>
                    <td className="max-w-xs truncate px-3 py-2 font-medium">{sanitizeText(item.title)}</td>
                    <td className="px-3 py-2 text-blue-300">{item.cve || "-"}</td>
                    <td className="px-3 py-2 text-amber-300">{item.cvss != null ? Number(item.cvss).toFixed(1) : "-"}</td>
                    <td className="px-3 py-2">
                      <span className={`rounded-md border px-2 py-0.5 text-xs uppercase ${SEV_STYLE[item.severity] || SEV_STYLE.low}`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                      {item.created_at ? new Date(item.created_at).toLocaleDateString("pt-BR") : "-"}
                      <span className="ml-1 text-xs text-slate-500">
                        {item.created_at ? new Date(item.created_at).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }) : ""}
                      </span>
                    </td>
                    <td className="max-w-[140px] truncate px-3 py-2 text-slate-300">{item.target_query || "-"}</td>
                    <td className="max-w-[140px] truncate px-3 py-2 text-slate-300">{item.domain || item.details?.asset || "-"}</td>
                    <td className="px-3 py-2 text-purple-300">{item.tool || item.details?.tool || "-"}</td>
                    <td className="max-w-[200px] truncate px-3 py-2 text-slate-400" title={recSummary}>
                      {recSummary ? recSummary.slice(0, 80) + (recSummary.length > 80 ? "..." : "") : "-"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
