import { useEffect, useState } from "react";
import client from "../api/client";
import { authStore } from "../store/auth";

const SEV = {
  critical: { bar: "bg-red-500", badge: "border-red-500/40 bg-red-500/10 text-red-400" },
  high: { bar: "bg-orange-500", badge: "border-orange-500/40 bg-orange-500/10 text-orange-400" },
  medium: { bar: "bg-yellow-500", badge: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" },
  low: { bar: "bg-emerald-500", badge: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" },
};

const STATUS_COLOR = {
  completed: "text-emerald-400",
  running: "text-cyan-400",
  retrying: "text-amber-300",
  failed: "text-red-400",
  queued: "text-yellow-400",
  blocked: "text-slate-400",
};

const WORKER_LABEL = {
  recon: "Recon",
  scan: "Portscan",
  fuzzing: "Fuzzing",
  vuln: "Vuln",
  analista_ia: "Analista IA",
};

function RiskBar({ score }) {
  const pct = Math.min((score / 10) * 100, 100);
  const color = score >= 8 ? "bg-red-500" : score >= 6 ? "bg-orange-500" : score >= 4 ? "bg-yellow-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400">{score}/10</span>
    </div>
  );
}

function RecoSection({ data, model }) {
  if (!data) return null;
  return (
    <div className="mt-2 rounded-xl border border-slate-700 bg-slate-800/40 p-3 text-xs">
      <p className="mb-1 font-semibold text-slate-300 uppercase tracking-widest">{model}</p>
      <p className="text-slate-300 mb-2">{data.resumo}</p>
      {data.mitigacoes?.length > 0 && (
        <ul className="space-y-1 list-disc list-inside text-slate-400">
          {data.mitigacoes.map((m, i) => <li key={i}>{m}</li>)}
        </ul>
      )}
      {data.prioridade && (
        <p className="mt-2 font-semibold text-slate-400">
          Prioridade: <span className="text-white">{data.prioridade}</span>
        </p>
      )}
    </div>
  );
}

function FindingCard({ f, isAdmin, onFalsePositive }) {
  const [expanded, setExpanded] = useState(false);
  const sev = SEV[f.severity] || SEV.low;

  return (
    <div className={`rounded-2xl border ${f.is_false_positive ? "opacity-50 border-slate-700" : "border-slate-800"} bg-slate-900/60`}>
      <button
        className="flex w-full items-start gap-3 p-4 text-left"
        onClick={() => setExpanded((v) => !v)}
      >
        <span className={`mt-1 h-2.5 w-2.5 flex-shrink-0 rounded-full ${sev.bar}`} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-medium">{f.title}</p>
            {f.is_false_positive && (
              <span className="rounded-md bg-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">Falso Positivo</span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-xs">
            <span className={`rounded-md border px-2 py-0.5 font-semibold uppercase ${sev.badge}`}>{f.severity}</span>
            <RiskBar score={f.risk_score || 0} />
            <span className="text-slate-500">{WORKER_LABEL[f.details?.source_worker] || f.details?.source_worker || "worker"}</span>
            <span className="text-slate-500">modo: {f.details?.scan_mode || "-"}</span>
          </div>
        </div>
        <span className="text-slate-500 text-sm">{expanded ? "▲" : "▼"}</span>
      </button>

      {expanded && (
        <div className="border-t border-slate-800 px-4 pb-4 pt-3 space-y-3 text-sm">
          {f.details?.url && (
            <p className="font-mono text-xs text-slate-400 break-all">{f.details.url}</p>
          )}
          {f.details?.evidence && (
            <p className="rounded-lg bg-slate-800/60 px-3 py-2 text-xs text-slate-300">{f.details.evidence}</p>
          )}
          {f.details?.payload && (
            <p className="rounded-lg bg-slate-950 px-3 py-2 font-mono text-xs text-emerald-300">
              PAYLOAD: {f.details.payload}
            </p>
          )}
          {f.cve && (
            <p className="text-xs text-slate-500">Referencia: <span className="text-sky-400">{f.cve}</span></p>
          )}

          {f.details?.qwen_recomendacao_pt && (
            <RecoSection data={f.details.qwen_recomendacao_pt} model="Qwen 2.5 — Recomendacao PT-BR" />
          )}
          {f.details?.cloudcode_recomendacao_pt && (
            <RecoSection data={f.details.cloudcode_recomendacao_pt} model="CloudCode (Llama) — Recomendacao PT-BR" />
          )}

          {isAdmin && !f.is_false_positive && (
            <button
              onClick={() => onFalsePositive(f.id)}
              className="rounded-lg bg-emerald-500/20 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-500/30"
            >
              Marcar como Falso Positivo
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default function ReportsPage() {
  const me = authStore.me;
  const isAdmin = Boolean(me?.is_admin);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [report, setReport] = useState(null);
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingReport, setLoadingReport] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");

  useEffect(() => {
    const load = async () => {
      setLoadingScans(true);
      setError("");
      try {
        const { data } = await client.get("/api/scans");
        setScans(data || []);
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar scans.");
      } finally {
        setLoadingScans(false);
      }
    };
    load();
  }, []);

  const openReport = async (scan) => {
    setSelectedScan(scan);
    setLoadingReport(true);
    setError("");
    try {
      const { data } = await client.get(`/api/scans/${scan.id}/report`);
      setReport(data);
    } catch (err) {
      setReport(null);
      setError(err?.response?.data?.detail || "Falha ao carregar relatorio.");
    } finally {
      setLoadingReport(false);
    }
  };

  const markFalsePositive = async (findingId) => {
    try {
      await client.post(`/api/findings/${findingId}/false-positive`, { is_false_positive: true });
      if (selectedScan) {
        await openReport(selectedScan);
      }
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao marcar falso positivo.");
    }
  };

  const filteredFindings = (report?.findings || []).filter((f) => {
    if (filter === "all") return true;
    if (filter === "fp") return Boolean(f.is_false_positive);
    if (filter === "open") return !f.is_false_positive;
    return String(f.severity || "").toLowerCase() === filter;
  });

  const sevCount = (sev) => (report?.findings || []).filter((f) => String(f.severity || "").toLowerCase() === sev && !f.is_false_positive).length;

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-5 pb-12">
      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2 text-xs text-rose-200">
          {error}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[280px_1fr]">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
          <h2 className="font-display text-base font-semibold">Scans Executados</h2>
          <div className="mt-3 space-y-2">
            {loadingScans && <p className="text-sm text-slate-400">Carregando scans...</p>}
            {!loadingScans && scans.length === 0 && <p className="text-sm text-slate-500">Nenhum scan encontrado.</p>}
            {scans.map((scan) => (
              <button
                key={scan.id}
                onClick={() => openReport(scan)}
                className={`w-full rounded-xl border p-3 text-left transition-colors ${
                  selectedScan?.id === scan.id
                    ? "border-brand-500/60 bg-brand-500/10"
                    : "border-slate-800 bg-slate-800/40 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between">
                  <p className="font-mono text-sm font-medium">{scan.target_query}</p>
                  <span className={`text-[10px] font-semibold uppercase ${STATUS_COLOR[scan.status] || "text-slate-400"}`}>
                    {scan.status}
                  </span>
                </div>
                <p className="mt-0.5 text-xs text-slate-400">
                  #{scan.id} &middot; {scan.mode === "unit" ? "Unitario" : "Agendado"} &middot;{" "}
                  {new Date(scan.created_at).toLocaleDateString("pt-BR")}
                </p>
              </button>
            ))}
          </div>
        </section>

        <section className="min-h-64">
          {loadingReport && (
            <div className="flex h-48 items-center justify-center">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />
            </div>
          )}

          {!loadingReport && !report && (
            <div className="flex h-48 items-center justify-center rounded-2xl border border-dashed border-slate-700 text-sm text-slate-500">
              Selecione um scan para visualizar o relatorio
            </div>
          )}

          {!loadingReport && report && selectedScan && (
            <div className="space-y-4">
              <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h2 className="font-display text-2xl font-bold">{selectedScan.target_query}</h2>
                    <p className="mt-1 text-sm text-slate-400">
                      Scan #{selectedScan.id} &middot; {selectedScan.mode === "unit" ? "Execucao Unitaria" : "Execucao Agendada"} &middot;{" "}
                      <span className={STATUS_COLOR[selectedScan.status] || ""}>{selectedScan.status}</span>
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      Iniciado: {new Date(selectedScan.created_at).toLocaleString("pt-BR")}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-slate-400">Progresso da missao</p>
                    <p className="text-2xl font-bold font-display text-brand-500">{selectedScan.mission_progress ?? 0}%</p>
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-4 gap-3">
                  {["critical", "high", "medium", "low"].map((s) => (
                    <button
                      key={s}
                      onClick={() => setFilter(filter === s ? "all" : s)}
                      className={`rounded-xl border p-3 text-center transition-colors ${SEV[s].badge} ${filter === s ? "ring-1 ring-current" : ""}`}
                    >
                      <p className="text-2xl font-bold font-display">{sevCount(s)}</p>
                      <p className="text-[10px] uppercase font-semibold mt-0.5">{s}</p>
                    </button>
                  ))}
                </div>

                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {[
                    { key: "all", label: "Todos" },
                    { key: "open", label: "Abertos" },
                    { key: "fp", label: "Falsos Positivos" },
                  ].map(({ key, label }) => (
                    <button
                      key={key}
                      onClick={() => setFilter(key)}
                      className={`rounded-lg px-3 py-1.5 transition-colors ${
                        filter === key
                          ? "bg-brand-500 text-slate-950 font-semibold"
                          : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                {filteredFindings.length === 0 && (
                  <p className="rounded-xl border border-dashed border-slate-700 py-8 text-center text-sm text-slate-500">
                    Nenhum finding neste filtro
                  </p>
                )}
                {filteredFindings.map((f) => (
                  <FindingCard key={f.id} f={f} isAdmin={isAdmin} onFalsePositive={markFalsePositive} />
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
