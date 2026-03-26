import { useEffect, useMemo, useState } from "react";
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

const FACTOR_VISUAL = {
  "Exposição Técnica": {
    icon: (
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8">
        <path d="M4 7h16M4 12h10M4 17h7" />
      </svg>
    ),
    accent: "text-rose-300 border-rose-500/40 bg-rose-500/10",
  },
  "Persistência Temporal (AGE)": {
    icon: (
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8">
        <circle cx="12" cy="12" r="8" />
        <path d="M12 8v5l3 2" />
      </svg>
    ),
    accent: "text-amber-300 border-amber-500/40 bg-amber-500/10",
  },
  "Impacto Econômico (FAIR)": {
    icon: (
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8">
        <path d="M12 3v18M16 7.5c0-1.9-1.8-3.5-4-3.5s-4 1.6-4 3.5 1.8 3.5 4 3.5 4 1.6 4 3.5-1.8 3.5-4 3.5-4-1.6-4-3.5" />
      </svg>
    ),
    accent: "text-emerald-300 border-emerald-500/40 bg-emerald-500/10",
  },
  "Resiliência Operacional": {
    icon: (
      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8">
        <path d="M12 3l8 4v5c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V7l8-4z" />
      </svg>
    ),
    accent: "text-cyan-300 border-cyan-500/40 bg-cyan-500/10",
  },
};

function formatFactorEvidence(name, evidence) {
  const ev = evidence || {};
  if (name === "Exposição Técnica") {
    return [
      `Críticas: ${Number(ev.critical || 0)}`,
      `Altas: ${Number(ev.high || 0)}`,
      `Médias: ${Number(ev.medium || 0)}`,
      `Baixas: ${Number(ev.low || 0)}`,
    ];
  }
  if (name === "Persistência Temporal (AGE)") {
    return [
      `Média ambiente: ${Number(ev.age_env_avg_days || 0)} dias`,
      `Média mercado: ${Number(ev.age_market_avg_days || 0)} dias`,
      `Recorrências: ${Number(ev.recurring_findings || 0)}`,
    ];
  }
  if (name === "Impacto Econômico (FAIR)") {
    return [
      `FAIR médio: ${Number(ev.fair_avg_score || 0).toFixed(2)}`,
      `ALE total: USD ${Number(ev.ale_total_usd || 0).toLocaleString("en-US", { maximumFractionDigits: 0 })}`,
    ];
  }
  if (name === "Resiliência Operacional") {
    return [
      `Abertos: ${Number(ev.open || 0)}`,
      `Novos: ${Number(ev.new || 0)}`,
      `Corrigidos: ${Number(ev.corrected || 0)}`,
    ];
  }
  return Object.entries(ev).map(([k, v]) => `${k}: ${v}`);
}


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

function aggregationLabel(mode) {
  if (mode === "target") return "Visão por Alvo";
  if (mode === "group_avg") return "Média do Grupo";
  return "Visão Global (média dos scanners)";
}

function gradeFromScore(score) {
  const s = Number(score || 0);
  if (s >= 90) return "A";
  if (s >= 80) return "B";
  if (s >= 70) return "C";
  if (s >= 60) return "D";
  return "F";
}

function targetHost(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const parsed = new URL(raw.includes("://") ? raw : `http://${raw}`);
    return String(parsed.hostname || "").toLowerCase();
  } catch {
    return raw.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].toLowerCase();
  }
}

function RatingBadge({ letter, score, label }) {
  const numeric = Number(score || 0);
  const tone =
    numeric >= 80
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
      : numeric >= 60
        ? "border-amber-500/40 bg-amber-500/10 text-amber-100"
        : "border-rose-500/40 bg-rose-500/10 text-rose-100";

  return (
    <div className={`rounded-2xl border p-4 shadow-lg ${tone}`}>
      <p className="text-[11px] uppercase tracking-[0.18em] opacity-80">{label}</p>
      <div className="mt-3 flex items-end justify-between gap-3">
        <div>
          <p className="text-4xl font-black leading-none">{letter || "F"}</p>
          <p className="mt-1 text-sm font-semibold opacity-90">Rating</p>
        </div>
        <p className="text-3xl font-black tabular-nums">{numeric.toFixed(1)}</p>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-black/20">
        <div className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-blue-500" style={{ width: `${Math.max(0, Math.min(100, numeric))}%` }} />
      </div>
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
  const [globalEasmRating, setGlobalEasmRating] = useState({ score: 0, grade: "F", pillars: [] });
  const [scopedEasmRating, setScopedEasmRating] = useState({ score: 0, grade: "F", pillars: [] });
  const [easmTrends, setEasmTrends] = useState(null);
  const [easmAlerts, setEasmAlerts] = useState([]);
  
  // Filters
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState("");
  const [domainOptions, setDomainOptions] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const hasScopedSelection = Boolean(selectedGroup || selectedTarget.trim());
  const [globalVasmMeta, setGlobalVasmMeta] = useState({ aggregationTargets: 1, scanCount: 0 });
  const [prioritizedActions, setPrioritizedActions] = useState([]);

  const handleSearch = () => {
    setIsSearching(true);
    setSelectedGroup("");
    setSelectedTarget(searchInput);
  };

  // Carrega grupos disponíveis para o usuário
  useEffect(() => {
    client.get("/api/access-groups")
      .then(({ data }) => setGroups(Array.isArray(data) ? data : []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        // Monta query params com filtros
        const params = new URLSearchParams();
        if (selectedGroup) {
          params.append("access_group_id", selectedGroup);
        }
        if (selectedTarget.trim()) {
          params.append("target", selectedTarget.trim());
        }

        const { data } = await client.get(`/api/dashboard/insights?${params.toString()}`);
        const dashboard = data || {};
        let globalDashboard = dashboard;
        if (selectedGroup || selectedTarget.trim()) {
          try {
            const { data: globalData } = await client.get("/api/dashboard/insights");
            globalDashboard = globalData || dashboard;
          } catch (e) {
            globalDashboard = dashboard;
          }
        }
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
          waf_findings: dashboard.stats?.waf_findings || 0,
          security_header_findings: dashboard.stats?.security_header_findings || 0,
          critical: dashboard.stats?.critical || 0,
          high: dashboard.stats?.high || 0,
          medium: dashboard.stats?.medium || 0,
          low: dashboard.stats?.low || 0,
          aggregation_mode: dashboard.stats?.aggregation_mode || "global",
          aggregation_targets: dashboard.stats?.aggregation_targets || 1,
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
        setPrioritizedActions(Array.isArray(dashboard.prioritized_actions) ? dashboard.prioritized_actions : []);
        const resolvedContinuous = dashboard.continuous_rating || { score: 0, grade: "F", factors: [] };
        const resolvedTimeline = dashboard.rating_timeline || [];
        setContinuousRating(resolvedContinuous);
        setRatingTimeline(resolvedTimeline);

        const scopedTimelineAvgScore = resolvedTimeline.length
          ? (resolvedTimeline.reduce((acc, item) => acc + Number(item?.rating_score || 0), 0) / resolvedTimeline.length)
          : null;
        const scopedPreferredScore = Number(
          scopedTimelineAvgScore
          ?? resolvedContinuous?.score
          ?? easmFallback?.rating?.score
          ?? 0
        );
        const scopedPreferredGrade = String(
          gradeFromScore(scopedPreferredScore)
          || resolvedContinuous?.grade
          || easmFallback?.rating?.grade
          || "F"
        );

        const globalContinuous = globalDashboard.continuous_rating || { score: 0, grade: "F", factors: [] };
        const globalTimeline = globalDashboard.rating_timeline || [];
        const globalTimelineAvgScore = globalTimeline.length
          ? (globalTimeline.reduce((acc, item) => acc + Number(item?.rating_score || 0), 0) / globalTimeline.length)
          : null;
        const globalPreferredScore = Number(
          globalTimelineAvgScore
          ?? globalContinuous?.score
          ?? easmFallback?.rating?.score
          ?? 0
        );
        const globalPreferredGrade = String(
          gradeFromScore(globalPreferredScore)
          || globalContinuous?.grade
          || easmFallback?.rating?.grade
          || "F"
        );
        setGlobalVasmMeta({
          aggregationTargets: Number(globalDashboard.stats?.aggregation_targets || 1),
          scanCount: Number(globalTimeline.length || 0),
        });
        setScopedEasmRating({
          score: scopedPreferredScore,
          grade: scopedPreferredGrade,
          pillars: [],
        });
        setGlobalEasmRating({
          score: globalPreferredScore,
          grade: globalPreferredGrade,
          pillars: [],
        });

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

        const hasActiveFilter = Boolean(selectedGroup || selectedTarget.trim());

        // Load EASM data
        try {
          if (hasActiveFilter) {
            setEasmAlerts([]);
            return;
          }

          const [assetsResp, alertsResp] = await Promise.all([
            client.get("/api/dashboard/assets").catch(() => ({ data: [] })),
            client.get("/api/easm/alerts").catch(() => ({ data: [] })),
          ]);
          
          setEasmAlerts(alertsResp.data || []);
          
          // Get latest asset for trends
          if (assetsResp.data && assetsResp.data.length > 0) {
            const topAsset = assetsResp.data[0];
            try {
              const trendsResp = await client.get(`/api/dashboard/trends/${topAsset.id}`);
              setEasmTrends(trendsResp.data);
            } catch (e) {
              // Silent fail
            }
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
  }, [selectedTarget, selectedGroup]);

  const distributedRows = useMemo(() => {
    const byTarget = new Map();
    for (const item of prioritizedActions) {
      const target = String(item?.target_query || "").trim();
      if (!target) continue;
      byTarget.set(target, (byTarget.get(target) || 0) + 1);
    }

    const rows = [...byTarget.entries()]
      .map(([target, vulnCount]) => {
        const host = targetHost(target);
        const subdomainCount = (domainOptions || []).filter((opt) => {
          const h = targetHost(opt);
          return h && host && h !== host && h.endsWith(`.${host}`);
        }).length;
        const score = Math.max(0, 100 - vulnCount * 4 - subdomainCount * 2);
        return {
          target,
          vulnCount,
          subdomainCount,
          score,
          grade: gradeFromScore(score),
        };
      })
      .sort((a, b) => b.vulnCount - a.vulnCount)
      .slice(0, 5);

    return rows;
  }, [prioritizedActions, domainOptions]);

  const distributedScore = distributedRows.length
    ? distributedRows.reduce((acc, row) => acc + row.score, 0) / distributedRows.length
    : Number(scopedEasmRating?.score || 0);
  const distributedGrade = gradeFromScore(distributedScore);

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
            <label className="block text-xs font-semibold text-slate-400 mb-2">Grupo / Cliente</label>
            <select
              value={selectedGroup}
              onChange={(e) => {
                setSelectedGroup(e.target.value);
                setSelectedTarget("");
                setSearchInput("");
              }}
              className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none"
            >
              <option value="">Todos os grupos</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-2">Domínios</label>
            <select
              value={selectedTarget}
              onChange={(e) => {
                const val = String(e.target.value || "");
                setSelectedGroup("");
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
          
          <div>
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
                setSelectedGroup("");
              }}
              className="flex-1 rounded-lg bg-slate-700 hover:bg-slate-600 px-3 py-2 text-sm font-medium text-slate-100 transition-colors"
            >
              Limpar Filtros
            </button>
          </div>
        </div>
        {(selectedGroup || selectedTarget) && (
          <p className="mt-3 text-xs text-slate-400">
            <span className="text-slate-300">Filtros ativos:</span>
            {selectedGroup && ` | Grupo: "${groups.find((g) => String(g.id) === String(selectedGroup))?.name || selectedGroup}"`}
            {selectedTarget && ` | Domínio: "${selectedTarget}"`}
          </p>
        )}

        {!!stats && (
          <div className="mt-3 flex items-center justify-between rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-2">
            <p className="text-xs font-semibold text-blue-200">
              {aggregationLabel(stats.aggregation_mode)}
            </p>
            <p className="text-[11px] text-blue-100/80">
              {Number(stats.aggregation_targets || 1)} alvo(s) considerados
            </p>
          </div>
        )}

        {selectedTarget && stats && stats.scans === 0 && (
          <div className="mt-3 rounded-lg border border-slate-600 bg-slate-800/50 px-3 py-2">
            <p className="text-xs text-slate-300">
              ℹ️ Nenhum scan encontrado com esse domínio. Ele pode não ter análises executadas ainda.
            </p>
          </div>
        )}
      </section>

      <section className="rounded-2xl border-2 border-cyan-500/30 bg-gradient-to-br from-slate-950 via-slate-900 to-blue-950/60 p-6 shadow-[0_22px_60px_rgba(2,6,23,0.5)]">
        <div className="mb-5 flex items-center justify-between">
          <h2 className="font-display text-2xl font-extrabold tracking-tight text-cyan-200">vASM Enterprise Dashboard</h2>
          <p className="text-xs uppercase tracking-[0.2em] text-cyan-100/70">Visão consolidada de risco e maturidade</p>
        </div>

        <div className="grid gap-4 xl:grid-cols-12">
          <div className="xl:col-span-3">
            <RatingBadge
              label="Rating Atual do Alvo"
              letter={scopedEasmRating.grade}
              score={scopedEasmRating.score}
            />
          </div>
          <div className="xl:col-span-3">
            <RatingBadge
              label="Rating Atual do Grupo"
              letter={globalEasmRating.grade}
              score={globalEasmRating.score}
            />
          </div>
          <div className="xl:col-span-6 rounded-2xl border border-cyan-500/30 bg-slate-900/70 p-4">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <p className="text-[11px] uppercase tracking-[0.18em] text-cyan-100/80">Rating Distribuído</p>
                <p className="text-xs text-slate-400">Top 5 alvos/subdomínios com maior volume de vulnerabilidades</p>
              </div>
              <div className="text-right">
                <p className="text-3xl font-black text-cyan-200">{distributedGrade} {Number(distributedScore || 0).toFixed(1)}</p>
              </div>
            </div>
            <div className="overflow-x-auto rounded-xl border border-slate-700/80">
              <table className="min-w-full text-left text-xs">
                <thead className="bg-slate-800/90 text-slate-300">
                  <tr>
                    <th className="px-3 py-2">Alvo</th>
                    <th className="px-3 py-2">Subdomínios</th>
                    <th className="px-3 py-2">Vulnerabilidades</th>
                    <th className="px-3 py-2">Rating</th>
                  </tr>
                </thead>
                <tbody>
                  {distributedRows.length === 0 && (
                    <tr>
                      <td className="px-3 py-3 text-slate-500" colSpan={4}>Sem dados suficientes para distribuição.</td>
                    </tr>
                  )}
                  {distributedRows.map((row) => (
                    <tr key={`dist-${row.target}`} className="border-t border-slate-700/70 bg-slate-900/40">
                      <td className="px-3 py-2 font-mono text-cyan-100">{row.target}</td>
                      <td className="px-3 py-2">{row.subdomainCount}</td>
                      <td className="px-3 py-2">{row.vulnCount}</td>
                      <td className="px-3 py-2 font-semibold">{row.grade} {row.score.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <section className="rounded-2xl border border-indigo-500/30 bg-indigo-950/20 p-4">
            <h3 className="text-sm font-semibold text-indigo-200">Maturidade por Framework</h3>
            <p className="mt-1 text-xs text-slate-400">Conformidade por framework de segurança</p>
            <div className="mt-4 space-y-4">
              {frameworks.map((info) => (
                <div key={`secure-${info.name}`}>
                  <div className="mb-1 flex items-center justify-between text-sm">
                    <span className="font-medium text-slate-200">{info.name}</span>
                    <span className="font-bold text-indigo-100">{info.score}%</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={`h-2 rounded-full bg-gradient-to-r transition-all duration-700 ${BAR_COLOR[info.name] || "from-cyan-500 to-blue-400"}`}
                      style={{ width: `${info.score}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="rounded-2xl border border-fuchsia-500/30 bg-fuchsia-950/20 p-4">
            <h3 className="text-sm font-semibold text-fuchsia-200">Atividade Operacional</h3>
            <p className="mt-1 text-xs text-slate-400">Atividade dos últimos 7 dias</p>
            <div className="mt-4 flex h-40 items-end gap-2">
              {activity.map((d) => (
                <div key={`bitsight-${d.day}`} className="flex flex-1 flex-col items-center gap-1">
                  <span className="text-[10px] text-slate-400">{d.findings}</span>
                  <div
                    className="w-full rounded-t-sm bg-gradient-to-t from-fuchsia-500 via-purple-500 to-cyan-400"
                    style={{ height: `${Math.round((d.findings / maxFindings) * 100)}%`, minHeight: "4px" }}
                  />
                  <span className="text-[10px] text-slate-500">{d.day}</span>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="mt-5">
          <section className="rounded-2xl border border-rose-500/30 bg-slate-900/70 p-4">
            <h3 className="text-sm font-semibold text-rose-200">Risco Operacional</h3>
            <p className="mt-1 text-xs text-slate-400">Rossio operacional por severidade</p>
            <div className="mt-4 grid grid-cols-2 gap-3">
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
          </section>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="font-display text-lg font-semibold">Decomposição Formal do Rating</h2>
          <p className="mt-1 text-xs text-slate-400">Fatores com peso, evidência e impacto na nota final.</p>
          <div className="mt-3 space-y-3">
            {(continuousRating?.factors || []).length === 0 && <p className="text-sm text-slate-500">Sem fatores calculados.</p>}
            {(continuousRating?.factors || []).map((f) => (
              <div key={f.id} className="rounded-xl border border-slate-700 bg-slate-800/40 p-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className={`inline-flex h-7 w-7 items-center justify-center rounded-lg border ${FACTOR_VISUAL[f.name]?.accent || "text-slate-300 border-slate-600 bg-slate-700/40"}`}>
                      {FACTOR_VISUAL[f.name]?.icon || (
                        <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8">
                          <circle cx="12" cy="12" r="8" />
                        </svg>
                      )}
                    </span>
                    <p className="text-sm font-semibold text-slate-100">{f.name}</p>
                  </div>
                  <p className="rounded-md border border-slate-600 bg-slate-900/60 px-2 py-0.5 text-xs text-slate-300">
                    peso {Math.round((Number(f.weight || 0) * 100))}%
                  </p>
                </div>

                <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded-lg border border-slate-700 bg-slate-900/50 px-2 py-1">
                    <p className="text-slate-400">Score</p>
                    <p className="font-semibold text-slate-100">{Number(f.score || 0).toFixed(2)}</p>
                  </div>
                  <div className="rounded-lg border border-slate-700 bg-slate-900/50 px-2 py-1">
                    <p className="text-slate-400">Impacto</p>
                    <p className="font-semibold text-slate-100">{Number(f.impact_points || 0).toFixed(2)} pts</p>
                  </div>
                </div>

                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-700/70">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400"
                    style={{ width: `${Math.max(0, Math.min(100, Number(f.score || 0)))}%` }}
                  />
                </div>

                <div className="mt-2 rounded-lg border border-slate-700/80 bg-slate-900/40 px-2 py-2 text-[11px] text-slate-300">
                  <p className="mb-1 text-slate-400">Evidências</p>
                  <div className="flex flex-wrap gap-1.5">
                    {formatFactorEvidence(f.name, f.evidence).map((line) => (
                      <span key={`${f.id}-${line}`} className="rounded-md border border-slate-600 bg-slate-800/60 px-2 py-0.5">
                        {line}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
      </section>

    </main>
  );
}
