import { useEffect, useState } from "react";
import client from "../api/client";

const RISK_COLOR = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-800 border-yellow-500/40 bg-yellow-100",
  low: "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
};

const STATUS_BADGE = {
  completed: "border-emerald-300 bg-emerald-200 text-emerald-900",
  running: "border-blue-300 bg-blue-700 text-white",
  retrying: "border-amber-300 bg-amber-200 text-amber-900",
  queued: "border-slate-300 bg-slate-200 text-slate-900",
  failed: "border-rose-300 bg-rose-700 text-white",
  blocked: "border-rose-300 bg-rose-700 text-white",
};

export default function TargetsPage() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [expandedTarget, setExpandedTarget] = useState(null);
  const [authorizationAccepted, setAuthorizationAccepted] = useState({});
  const [scanMode, setScanMode] = useState("single");
  const [submitting, setSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");

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

  const authorizeAndCreateScan = async (targetName) => {
    if (!authorizationAccepted[targetName]) {
      setStatusMessage("Confirme a autorização antes de executar o scan.");
      return;
    }

    setSubmitting(true);
    setStatusMessage("");
    try {
      try {
        await client.post("/api/policy/allowlist", {
          target_pattern: targetName,
          tool_group: "*",
          is_active: true,
        });
      } catch {
        // Allowlist pode já existir
      }

      await client.post("/api/scans", {
        target_query: targetName,
        mode: scanMode,
        access_group_id: null,
      });

      setStatusMessage(`Scan para ${targetName} iniciado com sucesso!`);
      setAuthorizationAccepted({ ...authorizationAccepted, [targetName]: false });
      setExpandedTarget(null);
      
      // Recarregar targets após criação
      setTimeout(() => {
        const reload = async () => {
          try {
            const { data } = await client.get("/api/targets/summary");
            setRows(data || []);
          } catch {}
        };
        reload();
      }, 2000);
    } catch (err) {
      setStatusMessage(err?.response?.data?.detail || err?.message || "Falha ao criar scan.");
    } finally {
      setSubmitting(false);
    }
  };

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

      {statusMessage && <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">{statusMessage}</section>}

      <section className="panel p-5">
        {loading && <p className="text-sm text-slate-400">Carregando targets...</p>}
        {!loading && filtered.length === 0 && <p className="text-sm text-slate-500">Nenhum target encontrado.</p>}

        <div className="space-y-2">
          {filtered.map((item) => (
            <div key={item.target} className="rounded-xl border border-slate-800 bg-slate-900/70 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex-1">
                  <p className="font-mono text-sm font-semibold">{item.target}</p>
                  <p className="text-xs text-slate-400">
                    ultimo scan: {item.last_scan_at ? new Date(item.last_scan_at).toLocaleString("pt-BR") : "-"}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`rounded-md border px-2 py-0.5 text-xs font-semibold uppercase ${STATUS_BADGE[item.last_status] || "border-slate-300 bg-slate-200 text-slate-900"}`}>
                    {item.last_status}
                  </span>
                  <span className={`rounded-md border px-2 py-0.5 text-xs uppercase ${RISK_COLOR[item.highest_severity] || RISK_COLOR.low}`}>
                    risco {item.highest_severity}
                  </span>
                  <button
                    onClick={() => setExpandedTarget(expandedTarget === item.target ? null : item.target)}
                    className="rounded-md bg-blue-600 px-3 py-1 text-xs font-semibold text-white hover:bg-blue-500"
                  >
                    ▶ Scan
                  </button>
                </div>
              </div>
              <div className="mt-2 grid gap-2 text-xs text-slate-300 sm:grid-cols-4">
                <p>scans: <span className="font-semibold text-white">{item.scans}</span></p>
                <p>findings: <span className="font-semibold text-white">{item.findings_total}</span></p>
                <p>abertos: <span className="font-semibold text-amber-300">{item.findings_open}</span></p>
                <p>modo ultimo scan: <span className="font-semibold text-white">{item.last_mode}</span></p>
              </div>

              {expandedTarget === item.target && (
                <div className="mt-4 border-t border-slate-700 pt-4">
                  <div className="space-y-3">
                    <select
                      className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                      value={scanMode}
                      onChange={(e) => setScanMode(e.target.value)}
                    >
                      <option value="single">Unitario</option>
                      <option value="scheduled">Agendado</option>
                    </select>
                    <label className="flex items-start gap-3 rounded-lg border border-slate-700 bg-slate-800/50 p-3 text-xs text-slate-300">
                      <input
                        type="checkbox"
                        checked={authorizationAccepted[item.target] || false}
                        onChange={(e) => setAuthorizationAccepted({ ...authorizationAccepted, [item.target]: e.target.checked })}
                        className="mt-1"
                      />
                      <span>
                        Autorizo a execução de scan neste target e confirmo que possuo permissão formal para isso.
                      </span>
                    </label>
                    <button
                      onClick={() => authorizeAndCreateScan(item.target)}
                      disabled={!authorizationAccepted[item.target] || submitting}
                      className="w-full rounded-lg bg-green-600 px-4 py-2 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40 hover:bg-green-500"
                    >
                      {submitting ? "Iniciando..." : "Iniciar Scan"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
