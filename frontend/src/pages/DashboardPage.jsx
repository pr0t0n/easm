import { useEffect, useState } from "react";
import client from "../api/client";

const SEV_COLOR = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
};

const STATUS_COLOR = {
  completed: "text-emerald-400",
  running: "text-cyan-400 animate-pulse",
  retrying: "text-amber-300",
  failed: "text-red-400",
  queued: "text-yellow-400",
  blocked: "text-slate-400",
};

const BAR_COLOR = {
  "ISO 27001": "from-cyan-500 to-cyan-400",
  "NIST CSF": "from-violet-500 to-violet-400",
  "CIS v8": "from-emerald-500 to-emerald-400",
  PCI: "from-orange-500 to-yellow-400",
};

const RISK_DOT = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-emerald-500",
};

const PAGINATION_BTN_BASE = "rounded-lg px-2 py-1 text-xs font-semibold transition-colors";
const PAGINATION_BTN_ENABLED = "bg-[#1a365d] text-white hover:bg-[#2c5282]";
const PAGINATION_BTN_DISABLED = "bg-slate-200 text-slate-500 cursor-not-allowed";

const DAY_LABELS = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sab"];

function StatCard({ label, value, sub, color = "text-white" }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4">
      <p className="text-xs uppercase tracking-widest text-slate-400">{label}</p>
      <p className={`mt-1 text-3xl font-bold font-display ${color}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [stats, setStats] = useState(null);
  const [frameworks, setFrameworks] = useState([]);
  const [recentScans, setRecentScans] = useState([]);
  const [topVulns, setTopVulns] = useState([]);
  const [assets, setAssets] = useState([]);
  const [activity, setActivity] = useState([]);
  const [prioritizedActions, setPrioritizedActions] = useState([]);
  const [prioritizedPage, setPrioritizedPage] = useState({ total: 0, limit: 10, offset: 0 });

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/dashboard/insights", {
          params: {
            prioritized_limit: prioritizedPage.limit,
            prioritized_offset: prioritizedPage.offset,
          },
        });
        const dashboard = data || {};

        setStats({
          scans: dashboard.stats?.scans || 0,
          findings_total: dashboard.stats?.findings_total || 0,
          findings_open: dashboard.stats?.findings_open || 0,
          findings_triaged: dashboard.stats?.findings_triaged || 0,
          critical: dashboard.stats?.critical || 0,
          high: dashboard.stats?.high || 0,
          medium: dashboard.stats?.medium || 0,
          low: dashboard.stats?.low || 0,
        });

        setFrameworks([
          { name: "ISO 27001", score: dashboard.frameworks?.iso27001?.score || 0 },
          { name: "NIST CSF", score: dashboard.frameworks?.nist?.score || 0 },
          { name: "CIS v8", score: dashboard.frameworks?.cis_v8?.score || 0 },
          { name: "PCI", score: dashboard.frameworks?.pci?.score || 0 },
        ]);

        setRecentScans(dashboard.recent_scans || []);
        setTopVulns(dashboard.top_vulns || []);
        setAssets(dashboard.assets || []);
        setActivity(dashboard.activity || DAY_LABELS.map((day) => ({ day, scans: 0, findings: 0 })));
        setPrioritizedActions(dashboard.prioritized_actions || []);
        setPrioritizedPage((prev) => ({
          ...prev,
          total: Number(dashboard.prioritized_actions_page?.total || 0),
        }));
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar dashboard.");
      } finally {
        setLoading(false);
      }
    };

    load();
  }, [prioritizedPage.offset]);

  const hasPrevPrioritized = prioritizedPage.offset > 0;
  const hasNextPrioritized = prioritizedPage.offset + prioritizedPage.limit < prioritizedPage.total;

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-brand-500 border-t-transparent" />
      </div>
    );
  }

  if (error) {
    return (
      <main className="mx-auto mt-6 w-[95%] max-w-7xl">
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</div>
      </main>
    );
  }

  const maxFindings = Math.max(...activity.map((a) => a.findings), 1);

  return (
    <main className="mx-auto mt-6 w-[95%] max-w-7xl space-y-5 pb-12">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Total de Scans" value={stats.scans} sub="todos os modos" />
        </div>
        <div className="col-span-2 md:col-span-2">
          <StatCard label="Findings Totais" value={stats.findings_total} sub={`${stats.findings_open} abertos`} />
        </div>
        <StatCard label="Critico" value={stats.critical} color="text-red-400" />
        <StatCard label="Alto" value={stats.high} color="text-orange-400" />
        <StatCard label="Medio" value={stats.medium} color="text-yellow-400" />
        <StatCard label="Baixo" value={stats.low} color="text-emerald-400" />
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="FAIR Medio" value={stats.fair_avg_score || 0} sub="score medio 0-100" color="text-cyan-300" />
        <StatCard label="ALE Total (USD)" value={Number(stats.fair_ale_total_usd || 0).toLocaleString("en-US", { maximumFractionDigits: 0 })} sub="perda anual esperada" color="text-amber-300" />
        <StatCard label="AGE Ambiente" value={`${stats.age_env_avg_days || 0}d`} sub="tempo medio conhecido internamente" />
        <StatCard label="AGE Mercado/Exploit" value={`${stats.age_market_avg_days || 0}d / ${stats.age_exploit_avg_days || 0}d`} sub="mercado / exploit" />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Maturidade por Framework</h2>
          <div className="mt-4 space-y-4">
            {frameworks.map((info) => (
              <div key={info.name}>
                <div className="mb-1 flex items-center justify-between text-sm">
                  <span className="font-medium">{info.name}</span>
                  <span className="font-bold text-white">{info.score}%</span>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-2 rounded-full bg-gradient-to-r transition-all duration-700 ${BAR_COLOR[info.name] || "from-brand-500 to-cyan-400"}`}
                    style={{ width: `${info.score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Atividade (7 dias)</h2>
          <div className="mt-4 flex h-36 items-end gap-2">
            {activity.map((d) => (
              <div key={d.day} className="flex flex-1 flex-col items-center gap-1">
                <span className="text-[10px] text-slate-400">{d.findings}</span>
                <div
                  className="w-full rounded-t-sm bg-gradient-to-t from-brand-500 to-cyan-400"
                  style={{ height: `${Math.round((d.findings / maxFindings) * 100)}%`, minHeight: "4px" }}
                />
                <span className="text-[10px] text-slate-500">{d.day}</span>
              </div>
            ))}
          </div>
          <p className="mt-2 text-xs text-slate-500">Findings detectados por dia de execucao</p>
        </section>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Scans Recentes</h2>
          <div className="mt-3 divide-y divide-slate-800">
            {recentScans.length === 0 && <p className="py-3 text-sm text-slate-500">Sem scans para exibir.</p>}
            {recentScans.map((scan) => (
              <div key={scan.id} className="flex items-center justify-between py-3 text-sm">
                <div>
                  <p className="font-medium">{scan.target_query}</p>
                  <p className="text-xs text-slate-400">
                    #{scan.id} &middot; {scan.mode === "unit" ? "Unitario" : "Agendado"} &middot;{" "}
                    {new Date(scan.created_at).toLocaleString("pt-BR")}
                  </p>
                </div>
                <div className="text-right">
                  <p className={`text-xs font-semibold uppercase ${STATUS_COLOR[scan.status] || "text-slate-300"}`}>
                    {scan.status}
                  </p>
                  <p className="text-xs text-slate-400">progresso {scan.mission_progress}%</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Top Vulnerabilidades</h2>
          <div className="mt-3 space-y-2">
            {topVulns.length === 0 && <p className="text-sm text-slate-500">Sem findings agregados ainda.</p>}
            {topVulns.map((v, i) => (
              <div key={`${v.title}-${i}`} className={`flex items-center justify-between rounded-xl border px-3 py-2 text-sm ${SEV_COLOR[v.severity] || SEV_COLOR.low}`}>
                <span className="flex-1">{v.title}</span>
                <div className="ml-3 flex items-center gap-2">
                  <span className="text-xs uppercase font-semibold">{v.severity}</span>
                  <span className="rounded-full border border-slate-300 bg-slate-200 px-2 py-0.5 text-xs font-semibold text-slate-900">×{v.count}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="font-display text-lg font-semibold">Ativos Externos Descobertos</h2>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {assets.length === 0 && <p className="text-sm text-slate-500">Sem ativos para exibir.</p>}
          {assets.map((asset) => (
            <div key={asset.name} className="rounded-xl border border-slate-700 bg-slate-800/50 p-3">
              <div className="flex items-center gap-2">
                <span className={`mt-0.5 h-2.5 w-2.5 flex-shrink-0 rounded-full ${RISK_DOT[asset.risk] || RISK_DOT.low}`} />
                <p className="truncate font-mono text-sm font-medium">{asset.name}</p>
              </div>
              <p className="mt-1 text-xs text-slate-400 capitalize">{asset.type}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="font-display text-lg font-semibold">Prioridade de Correcao (FAIR + AGE)</h2>
        <p className="mt-1 text-xs text-slate-400">Ordem sugerida por impacto operacional e financeiro (ALE).</p>
        <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
          <p>Mostrando {prioritizedActions.length} de {prioritizedPage.total}</p>
          <div className="flex gap-2">
            <button
              disabled={!hasPrevPrioritized}
              onClick={() => setPrioritizedPage((p) => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))}
              className={`${PAGINATION_BTN_BASE} ${hasPrevPrioritized ? PAGINATION_BTN_ENABLED : PAGINATION_BTN_DISABLED}`}
            >
              Anterior
            </button>
            <button
              disabled={!hasNextPrioritized}
              onClick={() => setPrioritizedPage((p) => ({ ...p, offset: p.offset + p.limit }))}
              className={`${PAGINATION_BTN_BASE} ${hasNextPrioritized ? PAGINATION_BTN_ENABLED : PAGINATION_BTN_DISABLED}`}
            >
              Proxima
            </button>
          </div>
        </div>
        <div className="mt-3 space-y-2">
          {prioritizedActions.length === 0 && <p className="text-sm text-slate-500">Sem recomendacoes priorizadas no momento.</p>}
          {prioritizedActions.map((item, index) => (
            <div key={`${item.finding_id}-${index}`} className="rounded-xl border border-slate-800 bg-slate-800/40 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <p className="font-medium">#{index + 1} {item.title}</p>
                <span className="rounded-md border border-amber-300 bg-amber-200 px-2 py-0.5 text-xs font-semibold text-amber-900">
                  ALE USD {Number(item.annualized_loss_exposure_usd || 0).toLocaleString("en-US", { maximumFractionDigits: 0 })}
                </span>
              </div>
              <div className="mt-1 grid gap-1 text-xs text-slate-300 md:grid-cols-3">
                <p>severidade: <span className="uppercase text-white">{item.severity}</span></p>
                <p>FAIR: <span className="text-white">{item.fair_score}</span></p>
                <p>AGE env/merc/exploit: <span className="text-white">{item.age?.known_in_environment_days ?? 0}d / {item.age?.known_in_market_days ?? 0}d / {item.age?.exploit_published_days ?? 0}d</span></p>
              </div>
              <p className="mt-2 text-xs text-slate-300"><span className="font-semibold text-cyan-300">Operacional:</span> {item.operational_reason}</p>
              <p className="mt-1 text-xs text-slate-300"><span className="font-semibold text-amber-300">Financeiro:</span> {item.financial_reason}</p>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
