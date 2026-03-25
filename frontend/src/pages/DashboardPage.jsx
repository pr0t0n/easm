import { useEffect, useState } from "react";
import client from "../api/client";
import {
  EASMRatingCard,
  FAIRPillarsCard,
  TemporalCurveCard,
  ExecutiveSummaryCard,
  AlertsCard,
  AssetListCard,
} from "../components/EASMDashboard";

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
  const [vulnToolExecution, setVulnToolExecution] = useState({ scan_id: null, scan_target: "", scan_status: "", summary: { requested_count: 0, attempted_count: 0, executed_count: 0 }, tools: [] });
  const [continuousRating, setContinuousRating] = useState({ score: 0, grade: "F", factors: [] });
  const [ratingTimeline, setRatingTimeline] = useState([]);
  
  // EASM Enterprise
  const [easmRating, setEasmRating] = useState({ score: 0, grade: "F", pillars: [] });
  const [easmTrends, setEasmTrends] = useState(null);
  const [easmAlerts, setEasmAlerts] = useState([]);
  const [easmAssets, setEasmAssets] = useState([]);
  
  // Filters
  const [domainOptions, setDomainOptions] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [isSearching, setIsSearching] = useState(false);

  const handleSearch = () => {
    setIsSearching(true);
    setSelectedTarget(searchInput);
  };

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        // Monta query params com filtros
        const params = new URLSearchParams();
        if (selectedTarget.trim()) {
          params.append("target", selectedTarget.trim());
        }

        const { data } = await client.get(`/api/dashboard/insights?${params.toString()}`);
        const dashboard = data || {};
        const easmFallback = dashboard.easm_fallback || {};
        setDomainOptions(Array.isArray(dashboard.targets) ? dashboard.targets : []);

        setStats({
          scans: dashboard.stats?.scans || 0,
          findings_total: dashboard.stats?.findings_total || 0,
          findings_open: dashboard.stats?.findings_open || 0,
          findings_triaged: dashboard.stats?.findings_triaged || 0,
          fair_avg_score: dashboard.stats?.fair_avg_score || 0,
          fair_ale_total_usd: dashboard.stats?.fair_ale_total_usd || 0,
          age_env_avg_days: dashboard.stats?.age_env_avg_days || 0,
          age_market_avg_days: dashboard.stats?.age_market_avg_days || 0,
          age_exploit_avg_days: dashboard.stats?.age_exploit_avg_days || 0,
          external_rating_score: dashboard.stats?.external_rating_score || 0,
          external_rating_grade: dashboard.stats?.external_rating_grade || "F",
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
        setVulnToolExecution(dashboard.vuln_tool_execution || { scan_id: null, scan_target: "", scan_status: "", summary: { requested_count: 0, attempted_count: 0, executed_count: 0 }, tools: [] });
        setContinuousRating(dashboard.continuous_rating || { score: 0, grade: "F", factors: [] });
        setRatingTimeline(dashboard.rating_timeline || []);

        // Fallback EASM summary from latest scan state when enterprise tables are empty
        if (easmFallback?.rating) {
          setEasmRating({
            score: Number(easmFallback.rating.score || 0),
            grade: String(easmFallback.rating.grade || "F"),
            pillars: [],
          });
        }
        if (easmFallback?.executive_summary) {
          setEasmTrends((prev) => ({
            ...(prev || {}),
            temporal_narrative: easmFallback.executive_summary,
            historical_ratings: [
              {
                pillars: easmFallback.fair_decomposition || {},
              },
            ],
          }));
        }

        // Load EASM data
        try {
          const [assetsResp, alertsResp] = await Promise.all([
            client.get("/api/dashboard/assets").catch(() => ({ data: [] })),
            client.get("/api/easm/alerts").catch(() => ({ data: [] })),
          ]);
          
          setEasmAssets(assetsResp.data || []);
          setEasmAlerts(alertsResp.data || []);
          
          // Get latest asset for trends
          if (assetsResp.data && assetsResp.data.length > 0) {
            const topAsset = assetsResp.data[0];
            try {
              const trendsResp = await client.get(`/api/dashboard/trends/${topAsset.id}`);
              setEasmTrends(trendsResp.data);
              setEasmRating({
                score: topAsset.easm_rating,
                grade: topAsset.easm_grade,
                pillars: [],
              });
            } catch (e) {
              // Silent fail
            }
          } else if (easmFallback?.scan_target) {
            // Surface latest scan target as pseudo-asset when EASM asset table has no rows yet
            setEasmAssets([
              {
                id: `fallback-${easmFallback.scan_id || "latest"}`,
                domain_or_ip: easmFallback.scan_target,
                open_critical: dashboard.stats?.critical || 0,
                open_high: dashboard.stats?.high || 0,
                easm_grade: easmFallback?.rating?.grade || "F",
                easm_rating: Number(easmFallback?.rating?.score || 0),
              },
            ]);
          }
        } catch (e) {
          // EASM endpoints may not be available yet
          console.log("EASM endpoints not available");
        }
      } catch (err) {
        setError(err?.response?.data?.detail || "Falha ao carregar dashboard.");
      } finally {
        setLoading(false);
        setIsSearching(false);
      }
    };

    load();
  }, [selectedTarget]);

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-950">
        <div className="text-center">
          <div className="mb-6 flex justify-center">
            <div className="h-12 w-12 animate-spin rounded-full border-4 border-slate-700 border-t-blue-500" />
          </div>
          <p className="text-lg font-semibold text-slate-200">Aguardando análise do LLM...</p>
          <p className="mt-2 text-sm text-slate-400">Processando dados do dashboard</p>
        </div>
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
      <section className="rounded-2xl border border-slate-700 bg-slate-800/40 p-4">
        <h2 className="text-sm font-semibold text-slate-200 mb-3">Filtros</h2>
        <div className="grid gap-3 md:grid-cols-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-2">Domínios</label>
            <select
              value={selectedTarget}
              onChange={(e) => {
                const val = String(e.target.value || "");
                setSelectedTarget(val);
                setSearchInput(val);
              }}
              className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Todos os domínios</option>
              {domainOptions.map((domain) => (
                <option key={domain} value={domain}>
                  {domain}
                </option>
              ))}
            </select>
          </div>
          
          <div className="md:col-span-2">
            <label className="block text-xs font-semibold text-slate-400 mb-2">Domínio/Alvo</label>
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  handleSearch();
                }
              }}
              placeholder="Filtrar por domínio..."
              className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div className="flex items-end gap-2">
            <button
              onClick={handleSearch}
              disabled={loading || isSearching}
              className="flex-1 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 px-3 py-2 text-sm font-medium text-white transition-colors"
            >
              {isSearching || loading ? "Buscando..." : "Buscar"}
            </button>
            <button
              onClick={() => {
                setSelectedTarget("");
                setSearchInput("");
              }}
              className="flex-1 rounded-lg bg-slate-700 hover:bg-slate-600 px-3 py-2 text-sm font-medium text-slate-100 transition-colors"
            >
              Limpar Filtros
            </button>
          </div>
        </div>
        {selectedTarget && (
          <p className="mt-3 text-xs text-slate-400">
            <span className="text-slate-300">Filtros ativos:</span>
            {selectedTarget && ` | Domínio: "${selectedTarget}"`}
          </p>
        )}

        {selectedTarget && stats && stats.scans === 0 && (
          <div className="mt-3 rounded-lg border border-slate-600 bg-slate-800/50 px-3 py-2">
            <p className="text-xs text-slate-300">
              ℹ️ Nenhum scan encontrado com esse domínio. Ele pode não ter análises executadas ainda.
            </p>
          </div>
        )}
      </section>

      {/* EASM Enterprise Section - Highlighted after filters */}
      <div className="rounded-2xl border-2 border-blue-500/40 bg-gradient-to-br from-blue-950/60 to-slate-900/60 p-6 shadow-lg shadow-blue-500/10">
        <div className="mb-6 flex items-center justify-between">
          <h2 className="font-display text-2xl font-semibold text-blue-300">EASM Enterprise Dashboard</h2>
          <div className="text-sm text-slate-400">Visão consolidada de ativos e riscos</div>
        </div>
        
        <div className="mb-6 rounded-xl border border-blue-500/30 bg-blue-900/20 p-4">
          <ExecutiveSummaryCard 
            summary={easmTrends?.temporal_narrative} 
            easm_rating={easmRating.score}
          />
        </div>

        <div className="grid gap-4 lg:grid-cols-2 mb-6">
          <EASMRatingCard rating={easmRating.score} grade={easmRating.grade} />
          <AlertsCard alerts={easmAlerts} />
        </div>

        <div className="grid gap-4 lg:grid-cols-2 mb-6">
          <FAIRPillarsCard decomposition={easmTrends?.historical_ratings?.[easmTrends.historical_ratings.length - 1]?.pillars} />
          <TemporalCurveCard trends={easmTrends} />
        </div>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <h3 className="font-display text-lg font-semibold mb-4">Asset Inventory</h3>
          <AssetListCard assets={easmAssets} />
        </section>
      </div>

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
        <StatCard
          label="Rating Externo"
          value={Number(continuousRating?.score ?? stats.external_rating_score ?? 0).toFixed(1)}
          sub={`grade ${continuousRating?.grade || stats.external_rating_grade || "-"}`}
          color="text-fuchsia-300"
        />
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
          <h2 className="font-display text-lg font-semibold">Decomposição Formal do Rating</h2>
          <p className="mt-1 text-xs text-slate-400">Fatores com peso, evidência e impacto na nota final.</p>
          <div className="mt-3 space-y-3">
            {(continuousRating?.factors || []).length === 0 && <p className="text-sm text-slate-500">Sem fatores calculados.</p>}
            {(continuousRating?.factors || []).map((f) => (
              <div key={f.id} className="rounded-xl border border-slate-700 bg-slate-800/40 p-3">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold text-slate-100">{f.name}</p>
                  <p className="text-xs text-slate-300">peso {Math.round((Number(f.weight || 0) * 100))}%</p>
                </div>
                <div className="mt-1 flex items-center justify-between text-xs text-slate-400">
                  <span>Score: {Number(f.score || 0).toFixed(2)}</span>
                  <span>Impacto: {Number(f.impact_points || 0).toFixed(2)} pts</span>
                </div>
                <div className="mt-2 text-[11px] text-slate-400 break-all">Evidência: {JSON.stringify(f.evidence || {})}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Curva Temporal do Rating</h2>
          <p className="mt-1 text-xs text-slate-400">Evolução por scan com penalidade por persistência de risco.</p>
          <div className="mt-3 space-y-2 max-h-72 overflow-y-auto pr-1">
            {(ratingTimeline || []).length === 0 && <p className="text-sm text-slate-500">Sem histórico temporal suficiente.</p>}
            {(ratingTimeline || []).slice(-15).reverse().map((row) => (
              <div key={`rt-${row.scan_id}`} className="rounded-xl border border-slate-700 bg-slate-800/40 px-3 py-2 text-xs">
                <div className="flex items-center justify-between text-slate-200">
                  <span>Scan #{row.scan_id}</span>
                  <span className="font-semibold text-fuchsia-300">{Number(row.rating_score || 0).toFixed(2)}</span>
                </div>
                <div className="mt-1 flex items-center justify-between text-slate-400">
                  <span>Base: {Number(row.base_score || 0).toFixed(2)}</span>
                  <span>Penalidade persistência: {Number(row.persistence_penalty || 0).toFixed(2)}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
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

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="font-display text-lg font-semibold">Execução de Ferramentas (Vulnerabilidade)</h2>
        <p className="mt-1 text-xs text-slate-400">
          Evidência operacional do último scan processado
          {vulnToolExecution?.scan_id ? ` (#${vulnToolExecution.scan_id} - ${vulnToolExecution.scan_target || "-"}, status ${vulnToolExecution.scan_status || "-"})` : ""}.
        </p>
        <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-slate-300 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-3 py-2">
            <p className="uppercase tracking-wider text-slate-400">Previstas</p>
            <p className="mt-1 text-base font-semibold text-slate-100">{vulnToolExecution?.summary?.requested_count || 0}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-3 py-2">
            <p className="uppercase tracking-wider text-slate-400">Tentadas</p>
            <p className="mt-1 text-base font-semibold text-slate-100">{vulnToolExecution?.summary?.attempted_count || 0}</p>
          </div>
          <div className="rounded-xl border border-slate-700 bg-slate-800/50 px-3 py-2">
            <p className="uppercase tracking-wider text-slate-400">Executadas</p>
            <p className="mt-1 text-base font-semibold text-emerald-300">{vulnToolExecution?.summary?.executed_count || 0}</p>
          </div>
        </div>
        <div className="mt-4 overflow-x-auto rounded-xl border border-slate-700 bg-slate-800/30">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-slate-800/80 text-[11px] uppercase tracking-wider text-slate-300">
              <tr>
                <th className="px-3 py-2">Ferramenta</th>
                <th className="px-3 py-2">Targets</th>
                <th className="px-3 py-2">Executada</th>
                <th className="px-3 py-2">RC</th>
              </tr>
            </thead>
            <tbody>
              {(vulnToolExecution?.tools || []).length === 0 && (
                <tr>
                  <td className="px-3 py-3 text-slate-500" colSpan={4}>Sem telemetria de execução para o último scan.</td>
                </tr>
              )}
              {(vulnToolExecution?.tools || []).map((row, idx) => (
                <tr key={`vuln-tool-${idx}`} className="border-t border-slate-700/70 text-slate-200 transition-colors hover:bg-slate-800/50">
                  <td className="px-3 py-2">
                    <span className="rounded-md border border-slate-600 bg-slate-900/50 px-2 py-0.5 font-mono text-xs text-cyan-300">
                      {row.tool || "-"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-100">{row.targets_count || 0}</td>
                  <td className="px-3 py-2">
                    {(row.executed_events || 0) > 0 ? (
                      <span className="inline-flex rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-xs font-semibold text-emerald-300">Sim</span>
                    ) : (
                      <span className="inline-flex rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-xs font-semibold text-rose-300">Não</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {Number(row.last_return_code) === 0 ? (
                      <span className="inline-flex rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-xs font-semibold text-emerald-300">0</span>
                    ) : row.last_return_code == null ? (
                      <span className="text-slate-500">-</span>
                    ) : (
                      <span className="inline-flex rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-semibold text-amber-300">{row.last_return_code}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

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
