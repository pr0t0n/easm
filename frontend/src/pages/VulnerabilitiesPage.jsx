import { useEffect, useMemo, useState } from "react";
import client from "../api/client";

const SEV_STYLE = {
  critical: "ds-badge ds-badge--critical",
  high: "ds-badge ds-badge--high",
  medium: "ds-badge ds-badge--medium",
  low: "ds-badge ds-badge--low",
  info: "ds-badge ds-badge--info",
};

const sanitizeText = (value) => {
  if (value == null) return "";
  return String(value)
    .replace(/\u001b\[[0-9;]*m/g, "")
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
};

function extractBas(item) {
  const details = item?.details && typeof item.details === "object" ? item.details : {};
  const technique = details.adversary_technique && typeof details.adversary_technique === "object" ? details.adversary_technique : {};
  const pack = details.detection_proof_pack && typeof details.detection_proof_pack === "object" ? details.detection_proof_pack : {};
  const expected = Array.isArray(details.expected_telemetry) ? details.expected_telemetry : [];
  return {
    id: sanitizeText(technique.id || details.adversary_technique_id || ""),
    name: sanitizeText(technique.name || details.adversary_technique_name || ""),
    status: sanitizeText(pack.detection_status || details.detection_status || "unknown"),
    sources: expected.map((item) => sanitizeText(item?.source || "")).filter(Boolean),
  };
}

export default function VulnerabilitiesPage() {
  const [rows, setRows] = useState([]);
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [page, setPage] = useState({ total: 0, limit: 50, offset: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severitiesFilter, setSeveritiesFilter] = useState(["critical", "high", "medium", "low", "info"]);
  const [statusFilter, setStatusFilter] = useState("open");
  const [targetQuery, setTargetQuery] = useState("");
  const [scanFilter, setScanFilter] = useState("");
  const [sortMode, setSortMode] = useState("severity");

  const loadTargets = async () => {
    try {
      const { data } = await client.get("/api/targets/summary");
      setTargets((Array.isArray(data) ? data : []).map((t) => t.target).sort());
    } catch (err) {
      console.error("Falha ao carregar targets:", err);
    }
  };

  const loadScans = async () => {
    try {
      const { data } = await client.get("/api/scans", { params: { limit: 300 } });
      setScans(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Falha ao carregar scans:", err);
    }
  };

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const params = {
        status_filter: statusFilter,
        sort: sortMode,
        limit: page.limit,
        offset: page.offset,
      };
      if (severitiesFilter.length > 0 && severitiesFilter.length < 5) {
        params.severity = severitiesFilter.join(",");
      }
      if (targetQuery.trim()) params.target = targetQuery.trim();
      if (scanFilter) params.scan_id = scanFilter;

      const { data } = await client.get("/api/findings/page", { params });
      const items = Array.isArray(data?.items) ? data.items : [];
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
    loadScans();
  }, []);

  useEffect(() => {
    setPage((p) => ({ ...p, offset: 0 }));
  }, [severitiesFilter, statusFilter, targetQuery, scanFilter, sortMode]);

  useEffect(() => {
    load();
  }, [severitiesFilter, statusFilter, page.offset, targetQuery, scanFilter, sortMode]);

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

        <div className="mt-3 grid gap-2 md:grid-cols-4">
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
          <select
            className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2"
            value={scanFilter}
            onChange={(e) => setScanFilter(e.target.value)}
          >
            <option value="">Todos os scans</option>
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                #{scan.id} · {String(scan.target_query || "(sem alvo)").slice(0, 48)} · {scan.status}
              </option>
            ))}
          </select>
          <select className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="open">Abertas</option>
            <option value="closed">Fechadas</option>
            <option value="false_positive">Falsos positivos</option>
            <option value="all">Todas</option>
          </select>
          <select className="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2" value={sortMode} onChange={(e) => setSortMode(e.target.value)}>
            <option value="severity">Ordenar por risco</option>
            <option value="date_desc">Mais recentes</option>
            <option value="date_asc">Mais antigas</option>
            <option value="scan_desc">Scan mais novo</option>
            <option value="scan_asc">Scan mais antigo</option>
            <option value="target">Alvo</option>
            <option value="tool">Ferramenta</option>
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
                <th className="px-3 py-2">Scan</th>
                <th className="px-3 py-2">Vulnerabilidade</th>
                <th className="px-3 py-2">CVE</th>
                <th className="px-3 py-2">CVSS</th>
                <th className="px-3 py-2">Severidade</th>
                <th className="px-3 py-2">Data</th>
                <th className="px-3 py-2">Alvo</th>
                <th className="px-3 py-2">Dominio</th>
                <th className="px-3 py-2">Ferramenta</th>
                <th className="px-3 py-2">BAS</th>
                <th className="px-3 py-2">Detecção</th>
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
                const bas = extractBas(item);
                return (
                  <tr key={item.id} className="border-b border-slate-800 hover:bg-slate-800/50">
                    <td className="px-3 py-2 text-slate-400">{item.id}</td>
                    <td className="px-3 py-2 text-cyan-300">#{item.scan_job_id || "-"}</td>
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
                    <td className="px-3 py-2">
                      {bas.id || bas.name ? (
                        <div>
                          <div className="font-mono text-xs text-cyan-200">{bas.id || "-"}</div>
                          <div className="max-w-[220px] truncate text-[11px] text-slate-400" title={bas.name}>{bas.name || "-"}</div>
                        </div>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span className="rounded-md border border-sky-700/60 bg-sky-950/40 px-2 py-0.5 text-[11px] uppercase text-sky-200">
                        {bas.status}
                      </span>
                      {bas.sources.length > 0 && (
                        <div className="mt-1 max-w-[180px] truncate text-[10px] text-slate-500" title={bas.sources.join(", ")}>
                          {bas.sources.join(", ")}
                        </div>
                      )}
                    </td>
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
