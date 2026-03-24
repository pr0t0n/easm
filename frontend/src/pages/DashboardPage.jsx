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
  const [wafSummary, setWafSummary] = useState({ findings_count: 0, assets_count: 0, assets: [], vendors: [] });
  const [securityHeadersSummary, setSecurityHeadersSummary] = useState({ findings_count: 0, assets_count: 0, assets: [], present_headers: [], missing_headers: [], owasp_top10_alignment: [] });

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const { data } = await client.get("/api/dashboard/insights");
        const dashboard = data || {};

        setStats({
          scans: dashboard.stats?.scans || 0,
          findings_total: dashboard.stats?.findings_total || 0,
          findings_open: dashboard.stats?.findings_open || 0,
          findings_triaged: dashboard.stats?.findings_triaged || 0,
          vulnerability_findings: dashboard.stats?.vulnerability_findings || 0,
          recon_findings: dashboard.stats?.recon_findings || 0,
          osint_findings: dashboard.stats?.osint_findings || 0,
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
        setWafSummary(dashboard.waf_summary || { findings_count: 0, assets_count: 0, assets: [], vendors: [] });
        setSecurityHeadersSummary(dashboard.security_headers_summary || { findings_count: 0, assets_count: 0, assets: [], present_headers: [], missing_headers: [], owasp_top10_alignment: [] });
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar dashboard.");
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

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

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-300">
        Tempo esperado de execução: Nuclei e Nmap podem levar em torno de 10 minutos por alvo, dependendo da superfície e conectividade.
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="FAIR Medio" value={stats.fair_avg_score || 0} sub="score medio 0-100" color="text-cyan-300" />
        <StatCard label="ALE Total (USD)" value={Number(stats.fair_ale_total_usd || 0).toLocaleString("en-US", { maximumFractionDigits: 0 })} sub="perda anual esperada" color="text-amber-300" />
        <StatCard label="AGE Ambiente" value={`${stats.age_env_avg_days || 0}d`} sub="tempo medio conhecido internamente" />
        <StatCard label="AGE Mercado/Exploit" value={`${stats.age_market_avg_days || 0}d / ${stats.age_exploit_avg_days || 0}d`} sub="mercado / exploit" />
        <StatCard label="Cobertura Vuln" value={stats.vulnerability_findings || 0} sub="achados de vulnerabilidade" color="text-rose-300" />
        <StatCard label="Cobertura Recon" value={stats.recon_findings || 0} sub="eventos de reconhecimento" color="text-emerald-300" />
        <StatCard label="Cobertura OSINT" value={stats.osint_findings || 0} sub="eventos de inteligencia externa" color="text-sky-300" />
        <StatCard label="WAF Detectado" value={stats.waf_findings || 0} sub="achados no ciclo" color="text-blue-300" />
        <StatCard label="Headers (Issues)" value={stats.security_header_findings || 0} sub="lacunas de hardening" color="text-indigo-300" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">WAF no Ambiente</h2>
          <p className="mt-1 text-xs text-slate-400">Resumo de fornecedores WAF detectados (quais e quantos).</p>
          <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-300">
            <div className="rounded-lg border border-slate-700 bg-slate-800/40 px-2 py-1">Achados: <strong>{wafSummary.findings_count || 0}</strong></div>
            <div className="rounded-lg border border-slate-700 bg-slate-800/40 px-2 py-1">Ativos: <strong>{wafSummary.assets_count || 0}</strong></div>
          </div>
          <div className="mt-3 space-y-2">
            {(wafSummary.vendors || []).length === 0 && <p className="text-sm text-slate-500">Sem WAF identificado no momento.</p>}
            {(wafSummary.vendors || []).map((item, idx) => (
              <div key={`waf-${idx}`} className="flex items-center justify-between rounded-xl border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm">
                <span>{item.name || "WAF nao identificado"}</span>
                <span className="rounded-md border border-slate-600 px-2 py-0.5 text-xs">{item.count || 0}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-400">
            {(wafSummary.vendors || []).length === 0
              ? "Nenhum WAF identificado no ciclo atual."
              : (wafSummary.vendors || []).map((item) => `${item.name || "WAF nao identificado"}: ${item.count || 0}`).join(" | ")}
          </p>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Headers de Segurança</h2>
          <p className="mt-1 text-xs text-slate-400">Headers presentes e ausentes mais recorrentes.</p>
          <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-300">
            <div className="rounded-lg border border-slate-700 bg-slate-800/40 px-2 py-1">Achados: <strong>{securityHeadersSummary.findings_count || 0}</strong></div>
            <div className="rounded-lg border border-slate-700 bg-slate-800/40 px-2 py-1">Ativos: <strong>{securityHeadersSummary.assets_count || 0}</strong></div>
          </div>
          <div className="mt-3 space-y-2">
            {(securityHeadersSummary.present_headers || []).length === 0 && (securityHeadersSummary.missing_headers || []).length === 0 && (
              <p className="text-sm text-slate-500">Sem gaps de headers detectados.</p>
            )}
            {(securityHeadersSummary.present_headers || []).map((item, idx) => (
              <div key={`header-present-${idx}`} className="flex items-center justify-between rounded-xl border border-emerald-700/50 bg-emerald-900/10 px-3 py-2 text-sm">
                <span className="font-mono">{item.header || "header"} (presente)</span>
                <span className="rounded-md border border-emerald-700/60 px-2 py-0.5 text-xs">{item.count || 0}</span>
              </div>
            ))}
            {(securityHeadersSummary.missing_headers || []).length === 0 && (securityHeadersSummary.present_headers || []).length > 0 && (
              <p className="text-sm text-slate-500">Sem headers ausentes detectados no ciclo atual.</p>
            )}
            {(securityHeadersSummary.missing_headers || []).map((item, idx) => (
              <div key={`header-${idx}`} className="flex items-center justify-between rounded-xl border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm">
                <span className="font-mono">{item.header || "header"}</span>
                <span className="rounded-md border border-slate-600 px-2 py-0.5 text-xs">{item.count || 0}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-400">
            {(securityHeadersSummary.owasp_top10_alignment || []).length === 0
              ? "A05 Security Misconfiguration: headers HTTP mitiga configuracao insegura. A03 Injection: CSP reduz impacto de XSS no browser."
              : (securityHeadersSummary.owasp_top10_alignment || []).map((item) => `${item.owasp}: ${item.coverage}`).join(" | ")}
          </p>
        </section>
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
        <h2 className="font-display text-lg font-semibold">Risco Operacional</h2>
        <p className="mt-1 text-xs text-slate-400">Visão resumida por severidade e volume de achados abertos.</p>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-sm">
            <p className="text-xs uppercase text-red-300">Crítico</p>
            <p className="mt-1 text-2xl font-bold text-red-200">{stats.critical || 0}</p>
          </div>
          <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 p-3 text-sm">
            <p className="text-xs uppercase text-orange-300">Alto</p>
            <p className="mt-1 text-2xl font-bold text-orange-200">{stats.high || 0}</p>
          </div>
          <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm">
            <p className="text-xs uppercase text-yellow-300">Médio</p>
            <p className="mt-1 text-2xl font-bold text-yellow-200">{stats.medium || 0}</p>
          </div>
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm">
            <p className="text-xs uppercase text-emerald-300">Baixo</p>
            <p className="mt-1 text-2xl font-bold text-emerald-200">{stats.low || 0}</p>
          </div>
        </div>
        <p className="mt-3 text-xs text-slate-400">Total aberto: {stats.findings_open || 0} | Triados: {stats.findings_triaged || 0}</p>
      </section>
    </main>
  );
}
