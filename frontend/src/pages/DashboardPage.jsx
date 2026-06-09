import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import "../styles/dashboard.css";

const DAY_LABELS = ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sab"];

const EMPTY_BAS = {
  summary: {},
  attack_detection_funnel: [],
  detection: { counts: {}, telemetry_sources: [] },
  tools: [],
  agent_flow: [],
  workers: { total: 0, active: 0, stale: 0, by_mode: {}, by_status: {}, rows: [] },
  learning: { total: 0, accepted: 0, pending: 0, rejected: 0, recent: [] },
};

function aggregationLabel(mode) {
  if (mode === "target") return "Visão por Alvo";
  if (mode === "group_avg") return "Média do Grupo";
  return "Visão Global · média dos scanners";
}

function gradeFromScore(score) {
  const s = Number(score || 0);
  if (s >= 90) return "A";
  if (s >= 80) return "B";
  if (s >= 70) return "C";
  if (s >= 60) return "D";
  return "F";
}

function ratingTone(score) {
  const s = Number(score || 0);
  if (s >= 80) return "t-green";
  if (s >= 60) return "t-amber";
  return "t-red";
}

function effColor(value) {
  const v = Number(value || 0);
  if (v >= 70) return "var(--sev-low-solid)";
  if (v >= 45) return "var(--sev-medium-solid)";
  return "var(--sev-critical-solid)";
}

function calculateGeneralHealthScore({ critical = 0, high = 0 }) {
  const criticalCount = Number(critical || 0);
  const highCount = Number(high || 0);

  let health = 100;
  if (criticalCount >= 1) {
    health = 40 - ((criticalCount - 1) * 5);
  }
  if (highCount >= 1) {
    if (criticalCount === 0) {
      health = 60;
    }
    health = health - ((highCount - 1) * 2);
  }

  return Math.max(5, Math.round(health));
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

function findingTarget(item) {
  const affected = Array.isArray(item?.affected_targets) ? item.affected_targets.filter(Boolean) : [];
  return (
    item?.url
    || item?.subdomain
    || item?.target
    || affected[0]
    || item?.asset
    || item?.target_query
    || "-"
  );
}

function findingTargetSummary(item) {
  if (item?.target_summary) return item.target_summary;
  const affected = Array.isArray(item?.affected_targets) ? item.affected_targets.filter(Boolean) : [];
  if (affected.length > 0) {
    return `${affected.slice(0, 3).join(", ")}${affected.length > 3 ? ` +${affected.length - 3}` : ""}`;
  }
  return findingTarget(item);
}

function sevLabel(severity) {
  const normalized = String(severity || "info").toLowerCase();
  return {
    critical: "Crítico",
    high: "Alto",
    medium: "Médio",
    low: "Baixo",
    info: "Info",
  }[normalized] || normalized;
}

export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [stats, setStats] = useState(null);
  const [frameworks, setFrameworks] = useState([]);
  const [recentScans, setRecentScans] = useState([]);
  const [scanRows, setScanRows] = useState([]);
  const [topVulns, setTopVulns] = useState([]);
  const [assets, setAssets] = useState([]);
  const [activity, setActivity] = useState([]);
  const [wafSummary, setWafSummary] = useState({ findings_count: 0, assets_count: 0, assets: [], vendors: [] });
  const [securityHeadersSummary, setSecurityHeadersSummary] = useState({ findings_count: 0, assets_count: 0, assets: [], present_headers: [], missing_headers: [], owasp_top10_alignment: [] });
  const [continuousRating, setContinuousRating] = useState({ score: 0, grade: "F", factors: [] });
  const [ratingTimeline, setRatingTimeline] = useState([]);

  // Vulnerability analysis enterprise metrics
  const [globalVulnerabilityRating, setGlobalVulnerabilityRating] = useState({ score: 0, grade: "F", pillars: [] });
  const [scopedVulnerabilityRating, setScopedVulnerabilityRating] = useState({ score: 0, grade: "F", pillars: [] });
  const [vulnerabilityTrends, setVulnerabilityTrends] = useState(null);
  const [vulnerabilityAlerts, setVulnerabilityAlerts] = useState([]);

  // Filters
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState("");
  const [domainOptions, setDomainOptions] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [globalVasmMeta, setGlobalVasmMeta] = useState({ aggregationTargets: 1, scanCount: 0 });
  const [prioritizedActions, setPrioritizedActions] = useState([]);
  const [targetStatistics, setTargetStatistics] = useState([]);
  const [basCommandCenter, setBasCommandCenter] = useState(EMPTY_BAS);
  const [subdomainInventory, setSubdomainInventory] = useState([]);
  const [selectedSubdomainScanId, setSelectedSubdomainScanId] = useState(null);

  // ── Intelligence widgets (M1 crown jewels, L1 OSINT, T1 verification gate) ──
  const [crownJewels, setCrownJewels] = useState([]);
  const [osintPhaseZero, setOsintPhaseZero] = useState(null);
  const [verificationStats, setVerificationStats] = useState({ confirmed: 0, candidate: 0, hypothesis: 0, refuted: 0, none: 0, total: 0 });

  // ── Crown Jewels + OSINT Phase Zero (per selected scan) ──────────────────
  useEffect(() => {
    if (!selectedSubdomainScanId) return;
    client.get(`/api/scans/${selectedSubdomainScanId}/crown-jewels`)
      .then(({ data }) => setCrownJewels(Array.isArray(data?.crown_jewels) ? data.crown_jewels : []))
      .catch(() => setCrownJewels([]));
    client.get(`/api/scans/${selectedSubdomainScanId}/osint`)
      .then(({ data }) => setOsintPhaseZero(data?.osint || null))
      .catch(() => setOsintPhaseZero(null));
  }, [selectedSubdomainScanId]);

  // ── Verification status breakdown (T1 Evidence Gate) ─────────────────────
  useEffect(() => {
    const params = new URLSearchParams();
    if (selectedTarget.trim()) params.append("target", selectedTarget.trim());
    client.get(`/api/findings/verification-stats?${params.toString()}`)
      .then(({ data }) => setVerificationStats({
        confirmed: data?.counts?.confirmed || 0,
        candidate: data?.counts?.candidate || 0,
        hypothesis: data?.counts?.hypothesis || 0,
        refuted: data?.counts?.refuted || 0,
        none: data?.counts?.none || 0,
        total: data?.total || 0,
      }))
      .catch(() => {});
  }, [selectedTarget, selectedGroup]);

  const handleSearch = () => {
    setIsSearching(true);
    setSelectedGroup("");
    setSelectedTarget(searchInput);
  };

  const clearFilters = () => {
    setSelectedTarget("");
    setSearchInput("");
    setSelectedGroup("");
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
        if (!selectedGroup && selectedTarget.trim()) {
          try {
            const { data: globalData } = await client.get("/api/dashboard/insights");
            globalDashboard = globalData || dashboard;
          } catch (e) {
            globalDashboard = dashboard;
          }
        }
        const vulnerabilityFallback = dashboard.vulnerability_fallback || {};
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
        try {
          const { data: scanList } = await client.get("/api/scans");
          setScanRows(Array.isArray(scanList) ? scanList : []);
        } catch {
          setScanRows([]);
        }
        setTopVulns(dashboard.top_vulns || []);
        setAssets(dashboard.assets || []);
        setActivity(dashboard.activity || DAY_LABELS.map((day) => ({ day, scans: 0, findings: 0 })));
        setWafSummary(dashboard.waf_summary || { findings_count: 0, assets_count: 0, assets: [], vendors: [] });
        setSecurityHeadersSummary(dashboard.security_headers_summary || { findings_count: 0, assets_count: 0, assets: [], present_headers: [], missing_headers: [], owasp_top10_alignment: [] });
        setBasCommandCenter(dashboard.bas_command_center || EMPTY_BAS);
        setPrioritizedActions(Array.isArray(dashboard.prioritized_actions) ? dashboard.prioritized_actions : []);
        setTargetStatistics(Array.isArray(dashboard.target_statistics) ? dashboard.target_statistics : []);
        const inventoryRows = Array.isArray(dashboard.subdomain_inventory) ? dashboard.subdomain_inventory : [];
        setSubdomainInventory(inventoryRows);
        setSelectedSubdomainScanId((current) => {
          if (current && inventoryRows.some((row) => Number(row.scan_id) === Number(current))) return current;
          return inventoryRows[0]?.scan_id || null;
        });
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
          ?? vulnerabilityFallback?.rating?.score
          ?? 0
        );
        const scopedPreferredGrade = String(
          gradeFromScore(scopedPreferredScore)
          || resolvedContinuous?.grade
          || vulnerabilityFallback?.rating?.grade
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
          ?? vulnerabilityFallback?.rating?.score
          ?? 0
        );
        const globalPreferredGrade = String(
          gradeFromScore(globalPreferredScore)
          || globalContinuous?.grade
          || vulnerabilityFallback?.rating?.grade
          || "F"
        );
        setGlobalVasmMeta({
          aggregationTargets: Number(globalDashboard.stats?.aggregation_targets || 1),
          scanCount: Number(globalTimeline.length || 0),
        });
        setScopedVulnerabilityRating({
          score: scopedPreferredScore,
          grade: scopedPreferredGrade,
          pillars: [],
        });
        setGlobalVulnerabilityRating({
          score: globalPreferredScore,
          grade: globalPreferredGrade,
          pillars: [],
        });

        if (vulnerabilityFallback?.executive_summary) {
          setVulnerabilityTrends((prev) => ({
            ...(prev || {}),
            temporal_narrative: vulnerabilityFallback.executive_summary,
            historical_ratings: [
              {
                pillars: vulnerabilityFallback.fair_decomposition || {},
              },
            ],
          }));
        }

        const hasActiveFilter = Boolean(selectedGroup || selectedTarget.trim());

        try {
          if (hasActiveFilter) {
            setVulnerabilityAlerts([]);
            return;
          }

          const [assetsResp, alertsResp] = await Promise.all([
            client.get("/api/dashboard/assets").catch(() => ({ data: [] })),
            client.get("/api/vulnerability-alerts").catch(() => ({ data: [] })),
          ]);

          setVulnerabilityAlerts(alertsResp.data || []);

          if (assetsResp.data && assetsResp.data.length > 0) {
            const topAsset = assetsResp.data[0];
            try {
              const trendsResp = await client.get(`/api/dashboard/trends/${topAsset.id}`);
              setVulnerabilityTrends(trendsResp.data);
            } catch (e) {
              // Silent fail
            }
          }
        } catch (e) {
          console.log("Vulnerability posture endpoints not available");
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
    if (targetStatistics && targetStatistics.length > 0) {
      return targetStatistics.map((stat) => {
        const vulnCount = stat.vulnerabilities_total || 0;
        const score = calculateGeneralHealthScore({
          critical: stat.critical,
          high: stat.high,
        });
        return {
          target: stat.target,
          vulnCount,
          score,
          grade: gradeFromScore(score),
        };
      });
    }

    const byTarget = new Map();
    for (const item of prioritizedActions) {
      const target = String(item?.target_query || "").trim();
      if (!target) continue;
      byTarget.set(target, (byTarget.get(target) || 0) + 1);
    }

    return [...byTarget.entries()]
      .map(([target, vulnCount]) => {
        const host = targetHost(target);
        const subdomainCount = (domainOptions || []).filter((opt) => {
          const h = targetHost(opt);
          return h && host && h !== host && h.endsWith(`.${host}`);
        }).length;
        const score = Math.max(0, 100 - vulnCount * 4 - subdomainCount * 2);
        return { target, vulnCount, subdomainCount, score, grade: gradeFromScore(score) };
      })
      .sort((a, b) => b.vulnCount - a.vulnCount)
      .slice(0, 5);
  }, [targetStatistics, prioritizedActions, domainOptions]);

  const distributedScore = distributedRows.length
    ? distributedRows.reduce((acc, row) => acc + row.score, 0) / distributedRows.length
    : Number(scopedVulnerabilityRating?.score || 0);
  const distributedGrade = gradeFromScore(distributedScore);

  if (loading) {
    return (
      <main className="dash">
        <div className="content" style={{ padding: "32px 40px 56px" }}>
          <div className="dash-state">
            <div>
              <div className="spin" />
              <p className="st-title">Aguardando análise do LLM…</p>
              <p className="st-sub">Processando dados do dashboard</p>
            </div>
          </div>
        </div>
      </main>
    );
  }

  if (error) {
    return (
      <main className="dash">
        <div className="content" style={{ padding: "32px 40px 56px" }}>
          <div className="dash-err">{error}</div>
        </div>
      </main>
    );
  }

  const basSummary = basCommandCenter?.summary || {};
  const basDetection = basCommandCenter?.detection?.counts || {};
  const basFunnel = Array.isArray(basCommandCenter?.attack_detection_funnel) ? basCommandCenter.attack_detection_funnel : [];
  const maxFunnel = Math.max(...basFunnel.map((item) => Number(item.value || 0)), 1);
  const basTelemetry = Array.isArray(basCommandCenter?.detection?.telemetry_sources) ? basCommandCenter.detection.telemetry_sources : [];
  const basTools = Array.isArray(basCommandCenter?.tools) ? basCommandCenter.tools : [];
  const basAgentFlow = Array.isArray(basCommandCenter?.agent_flow) ? basCommandCenter.agent_flow : [];
  const basWorkers = basCommandCenter?.workers || EMPTY_BAS.workers;
  const basLearning = basCommandCenter?.learning || EMPTY_BAS.learning;

  const resilience = Number(basSummary.bas_resilience_index || 0);
  const controlEff = Number(basSummary.control_efficacy_index || 0);
  const gapCount = Number(basSummary.detection_gap_count || 0);
  const detectedCount = Number(basDetection.detected || 0);
  const partialCount = Number(basDetection.partial || 0);
  const unknownCount = Number(basDetection.unknown || 0);
  const selectedSubdomainScan = (
    subdomainInventory.find((row) => Number(row.scan_id) === Number(selectedSubdomainScanId))
    || subdomainInventory[0]
    || null
  );
  const totalDiscoveredSubdomains = subdomainInventory.reduce((acc, scan) => acc + Number(scan?.subdomain_count || 0), 0);
  const selectedSubdomains = Array.isArray(selectedSubdomainScan?.subdomains) ? selectedSubdomainScan.subdomains : [];

  const basMetrics = [
    {
      label: "Resiliência BAS",
      value: resilience.toFixed(1),
      unit: "%",
      sub: "eficácia + ferramentas + aprendizagem",
      tone: resilience >= 70 ? "tone-green" : "tone-amber",
    },
    {
      label: "Eficácia do ataque",
      value: Number(basSummary.attack_success_index || 0).toFixed(1),
      unit: "%",
      sub: `${Number(basSummary.attack_success_count || 0)} evidências ofensivas`,
      tone: "tone-blue",
    },
    {
      label: "Controle detectou",
      value: controlEff.toFixed(1),
      unit: "%",
      sub: "detectado + parcial ponderado",
      tone: controlEff >= 70 ? "tone-green" : "tone-red",
    },
    {
      label: "Gaps de detecção",
      value: String(gapCount),
      unit: "",
      sub: `${detectedCount} detectados · ${partialCount} parciais · ${unknownCount} sem confirmação`,
      tone: gapCount > 0 ? "tone-red" : "tone-green",
    },
    {
      label: "Aprendizagem",
      value: Number(basSummary.learning_coverage_percent || 0).toFixed(1),
      unit: "%",
      sub: `${Number(basLearning.learned_techniques || 0)} técnicas aprendidas`,
      tone: "tone-green",
    },
  ];

  const redteamFindings = (Array.isArray(prioritizedActions) && prioritizedActions.length > 0
    ? prioritizedActions
    : (Array.isArray(topVulns) ? topVulns : [])
  ).slice(0, 6);
  const criticalHighCount = Number(stats?.critical || 0) + Number(stats?.high || 0);
  const scanStatusCounts = scanRows.reduce((acc, scan) => {
    const status = String(scan?.status || "unknown").toLowerCase();
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, {});
  const scansRunning = Number(scanStatusCounts.running || 0) + Number(scanStatusCounts.retrying || 0);
  const scansQueued = Number(scanStatusCounts.queued || 0);
  const scansStopped = Number(scanStatusCounts.stopped || 0) + Number(scanStatusCounts.paused || 0);
  const scansCompleted = Number(scanStatusCounts.completed || 0);
  const scansFailed = Number(scanStatusCounts.failed || 0) + Number(scanStatusCounts.blocked || 0);
  const scansExecuting = scansRunning + scansQueued;
  const weakFrameworks = frameworks
    .slice()
    .sort((a, b) => Number(a.score || 0) - Number(b.score || 0))
    .slice(0, 4);
  const attackQueue = redteamFindings.map((item, idx) => ({
    id: item.finding_id || item.id || idx,
    title: item.title || item.name || item.problem || "Achado sem titulo",
    severity: item.severity || "info",
    target: findingTarget(item),
    reason: item.operational_reason || item.financial_reason || item.recommendation || `${item.count || 1} ocorrência(s) no ambiente`,
  }));

  const showEmptyScanNote = Boolean(selectedTarget) && stats && stats.scans === 0;

  return (
    <main className="dash">
      <div className="content" style={{ padding: "32px 40px 56px" }}>

        {/* ===== Filters ===== */}
        <section className="filters">
          <h2>Filtros</h2>
          <div className="filters-grid">
            <div className="ctrl">
              <label>Grupo / Cliente</label>
              <select
                value={selectedGroup}
                onChange={(e) => {
                  setSelectedGroup(e.target.value);
                  setSelectedTarget("");
                  setSearchInput("");
                }}
              >
                <option value="">Todos os grupos</option>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>{g.name}</option>
                ))}
              </select>
            </div>
            <div className="ctrl">
              <label>Domínios</label>
              <select
                value={selectedTarget}
                onChange={(e) => {
                  const val = String(e.target.value || "");
                  setSelectedGroup("");
                  setSelectedTarget(val);
                  setSearchInput(val);
                }}
              >
                <option value="">Todos os domínios</option>
                {domainOptions.map((domain) => (
                  <option key={domain} value={domain}>{domain}</option>
                ))}
              </select>
            </div>
            <div className="ctrl">
              <label>Domínio / Alvo</label>
              <input
                type="text"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleSearch(); }}
                placeholder="Filtrar por domínio…"
              />
            </div>
            <div className="actions">
              <button className="btn btn-primary" onClick={handleSearch} disabled={loading || isSearching}>
                {isSearching || loading ? "Buscando…" : "Buscar"}
              </button>
              <button className="btn btn-ghost" onClick={clearFilters}>Limpar</button>
            </div>
          </div>

          {!!stats && (
            <div className="agg-note">
              <span><b>{aggregationLabel(stats.aggregation_mode)}</b></span>
              <span><b>{Number(stats.aggregation_targets || 1)} alvo(s)</b> considerados</span>
            </div>
          )}

          {showEmptyScanNote && (
            <div className="scope-empty">
              Nenhum scan encontrado com esse domínio. Ele pode não ter análises executadas ainda.
            </div>
          )}
        </section>

        {/* ===== Red Team Cockpit ===== */}
        <section className="redteam">
          <div className="redteam-head">
            <div>
              <div className="eb">Red Team Cockpit</div>
              <h2>O que atacar primeiro, por quê e com qual evidência.</h2>
            </div>
            <p>Foco operacional para o executor: riscos exploráveis, alvos com maior retorno, cobertura de ferramenta e lacunas que o Blue Team precisa enxergar.</p>
          </div>

          <div className="redteam-kpis">
            <div className="rt-kpi danger">
              <span>Críticos + Altos</span>
              <strong>{criticalHighCount}</strong>
              <small>prioridade de exploração e validação</small>
            </div>
            <div className="rt-kpi">
              <span>Achados abertos</span>
              <strong>{Number(stats?.findings_open || stats?.vulnerability_findings || 0)}</strong>
              <small>superfície ainda acionável</small>
            </div>
            <div className="rt-kpi warn">
              <span>Gaps de detecção</span>
              <strong>{gapCount}</strong>
              <small>telemetria ausente/parcial</small>
            </div>
          </div>

          <div className="scan-state-card">
            <div className="scan-state-head">
              <div>
                <h3>Estado dos scans</h3>
                <span>fila operacional agora</span>
              </div>
              <strong>{scanRows.length}</strong>
            </div>
            <div className="scan-state-grid">
              <div className="run"><span>Rodando</span><b>{scansRunning}</b></div>
              <div className="queue"><span>Executando / fila</span><b>{scansExecuting}</b></div>
              <div className="stop"><span>Parados / pausados</span><b>{scansStopped}</b></div>
              <div className="done"><span>Concluídos</span><b>{scansCompleted}</b></div>
              <div className="fail"><span>Falhos / bloqueados</span><b>{scansFailed}</b></div>
            </div>
          </div>

          <div className="subdomain-card">
            <div className="subdomain-head">
              <div>
                <h3>Subdomínios encontrados</h3>
                <span>{subdomainInventory.length} scans · {totalDiscoveredSubdomains} subdomínios</span>
              </div>
              {!!selectedSubdomainScan && <strong>{Number(selectedSubdomainScan.subdomain_count || 0)}</strong>}
            </div>
            {subdomainInventory.length === 0 ? (
              <div className="rt-empty">Nenhum subdomínio descoberto nos scans carregados.</div>
            ) : (
              <>
                <div className="subdomain-tabs">
                  {subdomainInventory.map((scan) => (
                    <button
                      key={scan.scan_id}
                      className={Number(scan.scan_id) === Number(selectedSubdomainScan?.scan_id) ? "active" : ""}
                      onClick={() => setSelectedSubdomainScanId(scan.scan_id)}
                      type="button"
                    >
                      <b>#{scan.scan_id}</b>
                      <em title={scan.target_query || ""}>{scan.target_query || "alvo não informado"}</em>
                      <span>{Number(scan.subdomain_count || 0)} subs</span>
                    </button>
                  ))}
                </div>
                <div className="subdomain-summary">
                  <div className="status-descoberto"><span>Descoberto</span><b>{Number(selectedSubdomainScan?.status_counts?.Descoberto || 0)}</b></div>
                  <div><span>BackLog</span><b>{Number(selectedSubdomainScan?.status_counts?.BackLog || 0)}</b></div>
                  <div className="status-em-analise"><span>Em Análise</span><b>{Number(selectedSubdomainScan?.status_counts?.["Em Análise"] || 0)}</b></div>
                  <div className="status-executado"><span>Executado</span><b>{Number(selectedSubdomainScan?.status_counts?.Executado || 0)}</b></div>
                  <div className="status-finalizado"><span>Finalizado</span><b>{Number(selectedSubdomainScan?.status_counts?.Finalizado || 0)}</b></div>
                  <div><span>Crítico/Alto</span><b>{Number(selectedSubdomainScan?.severity?.critical || 0) + Number(selectedSubdomainScan?.severity?.high || 0)}</b></div>
                </div>
                {selectedSubdomainScan?.subdomain_count > 0 && (() => {
                  const pct = Number(selectedSubdomainScan?.progress_pct || 0);
                  const done = Number(selectedSubdomainScan?.status_counts?.Executado || 0) + Number(selectedSubdomainScan?.status_counts?.Finalizado || 0);
                  const total = Number(selectedSubdomainScan?.subdomain_count || 0);
                  const createdAt = selectedSubdomainScan?.created_at;
                  const updatedAt = selectedSubdomainScan?.updated_at;
                  const scanStatus = selectedSubdomainScan?.scan_status || "";
                  const isRunning = ["running","queued","retrying"].includes(scanStatus);
                  const startMs = createdAt ? new Date(createdAt).getTime() : null;
                  const endMs = !isRunning && updatedAt ? new Date(updatedAt).getTime() : null;
                  const elapsedMs = startMs ? (endMs || Date.now()) - startMs : null;
                  const etaMs = isRunning && pct > 0 && pct < 100 && elapsedMs ? (elapsedMs / pct) * (100 - pct) : null;
                  const fmt = (ms) => {
                    const s = Math.floor(ms / 1000);
                    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60;
                    return h > 0 ? `${h}h ${String(m).padStart(2,"0")}m` : m > 0 ? `${m}m ${String(ss).padStart(2,"0")}s` : `${ss}s`;
                  };
                  return (
                    <div className="subdomain-progress">
                      <div className="subdomain-progress-bar">
                        <div className="subdomain-progress-fill" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="subdomain-progress-label">
                        <strong>{pct.toFixed(1)}%</strong> · {done}/{total} hosts escaneados
                        {elapsedMs !== null && <> · ⏱ {fmt(elapsedMs)}</>}
                        {etaMs !== null && <> · ⏳ ~{fmt(etaMs)}</>}
                        {!isRunning && elapsedMs !== null && <> · ✓ concluído</>}
                      </span>
                    </div>
                  );
                })()}
                <div className="subdomain-list">
                  {selectedSubdomains.length === 0 ? (
                    <div className="rt-empty">Sem subdomínios detalhados para este scan.</div>
                  ) : selectedSubdomains.map((row) => {
                    const statusCls = {
                      "Descoberto": "status-descoberto",
                      "Em Análise": "status-em-analise",
                      "Executado":  "status-executado",
                      "Finalizado": "status-finalizado",
                      "BackLog":    "status-backlog",
                    }[row.status] || "";
                    return (
                      <div key={`${selectedSubdomainScan.scan_id}-${row.subdomain}`} className="subdomain-row">
                        <div>
                          <b>{row.subdomain}</b>
                          <span>
                            <em className={`subdomain-status-badge ${statusCls}`}>{row.status}</em>
                            &nbsp;·&nbsp;{Number(row.tool_runs || 0)} execuções
                          </span>
                        </div>
                        <div className="sev-mini">
                          <span className="crit">{Number(row.severity?.critical || 0)}</span>
                          <span className="high">{Number(row.severity?.high || 0)}</span>
                          <span className="med">{Number(row.severity?.medium || 0)}</span>
                          <span className="low">{Number(row.severity?.low || 0)}</span>
                          <strong>{Number(row.findings_total || 0)}</strong>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>

          <div className="redteam-grid">
            <div className="rt-card rt-priority">
              <div className="rt-card-head">
                <h3>Fila de ataque recomendada</h3>
                <span>{attackQueue.length} itens</span>
              </div>
              {attackQueue.length === 0 ? (
                <div className="rt-empty">Sem vulnerabilidades priorizadas no escopo atual.</div>
              ) : attackQueue.map((item, idx) => (
                <div key={`${item.id}-${idx}`} className="rt-finding">
                  <div className={`sev-dot sev-${String(item.severity).toLowerCase()}`}>{sevLabel(item.severity)}</div>
                  <div>
                    <b>{item.title}</b>
                    <span>{item.target}</span>
                    <p>{item.reason}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="rt-card">
              <div className="rt-card-head">
                <h3>Frameworks mais pressionados</h3>
                <span>Blue Team</span>
              </div>
              {weakFrameworks.map((fw) => (
                <div key={fw.name} className="rt-framework">
                  <div><b>{fw.name}</b><span>{Number(fw.score || 0).toFixed(0)}%</span></div>
                  <div className="rt-bar"><div style={{ width: `${Math.max(0, Math.min(100, Number(fw.score || 0)))}%` }} /></div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ===== Intelligence — Crown Jewels · OSINT · Evidence Gate ===== */}
        <section className="intel-section">
          <div className="intel-head">
            <div>
              <div className="eb">Inteligência Ofensiva</div>
              <h2>Crown Jewels · OSINT Phase Zero · Evidence Gate</h2>
            </div>
            <p>Alvos de alto valor priorizados, exposições passivas detectadas e qualidade de evidência por achado.</p>
          </div>

          <div className="intel-grid">
            {/* ── Crown Jewels widget ── */}
            <div className="intel-card">
              <div className="intel-card-head">
                <h3>⭐ Crown Jewels</h3>
                <span>{crownJewels.length} alvo(s) crítico(s)</span>
              </div>
              {crownJewels.length === 0 ? (
                <div className="intel-empty">
                  Nenhum Crown Jewel identificado ainda.
                  <br /><small>Execute um scan com M1 habilitado para detectar alvos de alto valor.</small>
                </div>
              ) : (
                <div className="cj-list">
                  {crownJewels.slice(0, 8).map((cj, idx) => {
                    const label = String(cj.label || cj.type || "high_value");
                    const colorMap = {
                      "identity/auth": "#ef4444",
                      "payment/financial": "#dc2626",
                      "admin_panel": "#f97316",
                      "data_store": "#8b5cf6",
                      "cicd": "#3b82f6",
                      "secrets_mgmt": "#ec4899",
                      "api_gateway": "#06b6d4",
                      "monitoring": "#84cc16",
                      "mail": "#f59e0b",
                      "staging_dev": "#6b7280",
                    };
                    const color = colorMap[label] || "#64748b";
                    const delta = Number(cj.priority_delta || 0);
                    return (
                      <div key={`cj-${idx}-${cj.target}`} className="cj-row">
                        <div className="cj-target">
                          <b>{cj.target || cj.subdomain || "?"}</b>
                          <span
                            className="cj-label"
                            style={{ background: `${color}22`, color, border: `1px solid ${color}55` }}
                          >
                            {label.replace(/_/g, " ")}
                          </span>
                        </div>
                        <div className="cj-delta" style={{ color: "#ef4444" }}>
                          ↑ {Math.abs(delta)} prioridade
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* ── OSINT Phase Zero widget ── */}
            <div className="intel-card">
              <div className="intel-card-head">
                <h3>🔍 OSINT Phase Zero</h3>
                <span>recon passivo antes do P01</span>
              </div>
              {!osintPhaseZero ? (
                <div className="intel-empty">
                  OSINT Phase Zero não executado.
                  <br /><small>Disponível após o próximo scan completo com L1 ativado.</small>
                </div>
              ) : (
                <div className="osint-summary">
                  {/* HIBP */}
                  {osintPhaseZero.hibp && (
                    <div className="osint-block">
                      <div className="osint-block-head">
                        <span className="osint-icon">📧</span>
                        <b>HIBP — Vazamentos de senha</b>
                      </div>
                      <div className="osint-stats">
                        <div>
                          <span>Emails verificados</span>
                          <b>{Number(osintPhaseZero.hibp.emails_checked || 0)}</b>
                        </div>
                        <div className={Number(osintPhaseZero.hibp.breached_count || 0) > 0 ? "osint-hit" : ""}>
                          <span>Comprometidos</span>
                          <b>{Number(osintPhaseZero.hibp.breached_count || 0)}</b>
                        </div>
                        <div>
                          <span>Breaches</span>
                          <b>{Number(osintPhaseZero.hibp.breach_names?.length || 0)}</b>
                        </div>
                      </div>
                      {Array.isArray(osintPhaseZero.hibp.breach_names) && osintPhaseZero.hibp.breach_names.length > 0 && (
                        <div className="osint-tags">
                          {osintPhaseZero.hibp.breach_names.slice(0, 4).map((b) => (
                            <span key={b} className="osint-tag osint-tag-red">{b}</span>
                          ))}
                          {osintPhaseZero.hibp.breach_names.length > 4 && (
                            <span className="osint-tag">+{osintPhaseZero.hibp.breach_names.length - 4}</span>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* GitHub Dorks */}
                  {osintPhaseZero.github_dorks && (
                    <div className="osint-block">
                      <div className="osint-block-head">
                        <span className="osint-icon">🐙</span>
                        <b>GitHub — Segredos expostos</b>
                      </div>
                      <div className="osint-stats">
                        <div>
                          <span>Queries executadas</span>
                          <b>{Number(osintPhaseZero.github_dorks.queries_run || 0)}</b>
                        </div>
                        <div className={Number(osintPhaseZero.github_dorks.results_count || 0) > 0 ? "osint-hit" : ""}>
                          <span>Resultados</span>
                          <b>{Number(osintPhaseZero.github_dorks.results_count || 0)}</b>
                        </div>
                        <div className={Number(osintPhaseZero.github_dorks.high_risk_count || 0) > 0 ? "osint-hit" : ""}>
                          <span>Alto risco</span>
                          <b>{Number(osintPhaseZero.github_dorks.high_risk_count || 0)}</b>
                        </div>
                      </div>
                      {Array.isArray(osintPhaseZero.github_dorks.repos_found) && osintPhaseZero.github_dorks.repos_found.length > 0 && (
                        <div className="osint-tags">
                          {osintPhaseZero.github_dorks.repos_found.slice(0, 3).map((r) => (
                            <span key={r} className="osint-tag osint-tag-amber">{String(r).split("/").slice(-1)[0]}</span>
                          ))}
                          {osintPhaseZero.github_dorks.repos_found.length > 3 && (
                            <span className="osint-tag">+{osintPhaseZero.github_dorks.repos_found.length - 3}</span>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Shodan ASN */}
                  {osintPhaseZero.shodan && (
                    <div className="osint-block">
                      <div className="osint-block-head">
                        <span className="osint-icon">🌐</span>
                        <b>Shodan — ASN sweep</b>
                      </div>
                      <div className="osint-stats">
                        <div>
                          <span>ASN</span>
                          <b>{osintPhaseZero.shodan.asn || "—"}</b>
                        </div>
                        <div>
                          <span>IPs descobertos</span>
                          <b>{Number(osintPhaseZero.shodan.ip_count || 0)}</b>
                        </div>
                        <div className={Number(osintPhaseZero.shodan.vulns_found || 0) > 0 ? "osint-hit" : ""}>
                          <span>CVEs expostos</span>
                          <b>{Number(osintPhaseZero.shodan.vulns_found || 0)}</b>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* ── Evidence Gate — Verification Status Breakdown ── */}
            <div className="intel-card">
              <div className="intel-card-head">
                <h3>🔬 Evidence Gate</h3>
                <span>{verificationStats.total} achados categorizados</span>
              </div>
              {verificationStats.total === 0 ? (
                <div className="intel-empty">
                  Nenhum achado com status de verificação.
                  <br /><small>Os achados serão classificados automaticamente após scans com T1 ativado.</small>
                </div>
              ) : (() => {
                const total = verificationStats.total || 1;
                const pctConf = Math.round((verificationStats.confirmed / total) * 100);
                const pctCand = Math.round((verificationStats.candidate / total) * 100);
                const pctHyp = Math.round((verificationStats.hypothesis / total) * 100);
                const pctRef = Math.round((verificationStats.refuted / total) * 100);
                return (
                  <div className="vgate-breakdown">
                    {/* stacked bar */}
                    <div className="vgate-bar">
                      {verificationStats.confirmed > 0 && (
                        <div style={{ width: `${pctConf}%`, background: "#10b981" }} title={`Confirmado: ${verificationStats.confirmed}`} />
                      )}
                      {verificationStats.candidate > 0 && (
                        <div style={{ width: `${pctCand}%`, background: "#f59e0b" }} title={`Candidato: ${verificationStats.candidate}`} />
                      )}
                      {verificationStats.hypothesis > 0 && (
                        <div style={{ width: `${pctHyp}%`, background: "#6366f1" }} title={`Hipótese: ${verificationStats.hypothesis}`} />
                      )}
                      {verificationStats.refuted > 0 && (
                        <div style={{ width: `${pctRef}%`, background: "#6b7280" }} title={`Refutado: ${verificationStats.refuted}`} />
                      )}
                    </div>
                    <div className="vgate-legend">
                      <div className="vgate-item">
                        <div className="vgate-dot" style={{ background: "#10b981" }} />
                        <div>
                          <b>{verificationStats.confirmed}</b>
                          <span>Confirmado</span>
                        </div>
                        <div className="vgate-pct">{pctConf}%</div>
                      </div>
                      <div className="vgate-item">
                        <div className="vgate-dot" style={{ background: "#f59e0b" }} />
                        <div>
                          <b>{verificationStats.candidate}</b>
                          <span>Candidato</span>
                        </div>
                        <div className="vgate-pct">{pctCand}%</div>
                      </div>
                      <div className="vgate-item">
                        <div className="vgate-dot" style={{ background: "#6366f1" }} />
                        <div>
                          <b>{verificationStats.hypothesis}</b>
                          <span>Hipótese</span>
                        </div>
                        <div className="vgate-pct">{pctHyp}%</div>
                      </div>
                      <div className="vgate-item">
                        <div className="vgate-dot" style={{ background: "#6b7280" }} />
                        <div>
                          <b>{verificationStats.refuted}</b>
                          <span>Refutado</span>
                        </div>
                        <div className="vgate-pct">{pctRef}%</div>
                      </div>
                      {verificationStats.none > 0 && (
                        <div className="vgate-item vgate-item-muted">
                          <div className="vgate-dot" style={{ background: "#d1d5db" }} />
                          <div>
                            <b>{verificationStats.none}</b>
                            <span>Sem status</span>
                          </div>
                        </div>
                      )}
                    </div>
                    <div className="vgate-summary">
                      <div className="vgate-quality">
                        <span>Qualidade de evidência</span>
                        <b style={{ color: pctConf >= 50 ? "#10b981" : pctConf >= 25 ? "#f59e0b" : "#ef4444" }}>
                          {pctConf >= 50 ? "Alta" : pctConf >= 25 ? "Média" : "Baixa"}
                        </b>
                      </div>
                      <div className="vgate-quality">
                        <span>Taxa de confirmação</span>
                        <b>{pctConf}%</b>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>
        </section>

        {/* ===== BAS Command Center ===== */}
        <section className="bas">
          <div className="bas-head">
            <div>
              <div className="eb">BAS Command Center</div>
              <h2>Visão viva do ambiente, ataques simulados, <em>detecção</em> e aprendizagem.</h2>
            </div>
            <p>Consolida execução de scans, fluxo dos agentes, ferramentas Kali/MCP, telemetria esperada, gaps de controle, RAG e risco validado.</p>
          </div>

          {/* 6 BAS metrics */}
          <div className="bas-metrics">
            {basMetrics.map((m) => (
              <div key={m.label} className={`bas-m ${m.tone}`}>
                <div className="lbl">{m.label}</div>
                <div className="val">{m.value}{m.unit && <span className="u">{m.unit}</span>}</div>
                <div className="sub">{m.sub}</div>
              </div>
            ))}
          </div>

          {/* Row 1: Funnel · Telemetry · RAG */}
          <div className="bas-grid-1">
            <div className="bas-sect">
              <div className="bas-sect-head">
                <div>
                  <h3>Funil ataque × detecção</h3>
                  <div className="sh-sub">da técnica planejada ao gap confirmado</div>
                </div>
                <span className="sh-meta">{Number(basSummary.techniques_exercised || 0)} técnicas</span>
              </div>
              <div className="funnel">
                {basFunnel.length === 0 && <div className="bas-empty">Sem funil BAS calculado.</div>}
                {basFunnel.map((item) => {
                  const value = Number(item.value || 0);
                  const width = Math.round((value / maxFunnel) * 100);
                  const isGap = String(item.label || "").toLowerCase().includes("gap");
                  return (
                    <div key={item.label} className={`funnel-row${isGap ? " gap" : ""}`}>
                      <div className="top"><span>{item.label}</span><b>{value}</b></div>
                      <div className="funnel-bar">
                        <div style={{ width: `${width}%`, minWidth: value > 0 ? "8px" : 0 }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="bas-sect">
              <h3>Eficácia por fonte de telemetria</h3>
              <div className="sh-sub">onde o controle enxerga, parcializa ou falha</div>
              <table className="basT">
                <thead>
                  <tr><th>Fonte</th><th style={{ width: 60 }}>Eventos</th><th style={{ width: 160 }}>Eficácia</th></tr>
                </thead>
                <tbody>
                  {basTelemetry.length === 0 && (
                    <tr><td colSpan={3} className="bas-empty">Sem dados BAS suficientes.</td></tr>
                  )}
                  {basTelemetry.map((row) => {
                    // effectiveness === null → fonte só com eventos passivos
                    // (recon/OSINT): nada a detectar, não é falha de controle → N/A.
                    const isNA = row.effectiveness === null || row.effectiveness === undefined;
                    const eff = Number(row.effectiveness || 0);
                    const detectable = Number(row.detectable || 0);
                    return (
                      <tr key={row.source}>
                        <td><b>{row.source}</b></td>
                        <td>{Number(row.total || 0).toLocaleString("pt-BR")}</td>
                        <td>
                          {isNA ? (
                            <span title="Recon/OSINT passivo — sem evento detectável para o controle"
                                  style={{ color: "var(--ink-muted)", fontSize: 12 }}>N/A (passivo)</span>
                          ) : (
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}
                                 title={`${detectable} detectável(is): ${row.detected || 0} detectado · ${row.partial || 0} parcial · ${row.gap || 0} falha`}>
                              <span style={{ fontWeight: 600, width: 32, textAlign: "right" }}>{eff.toFixed(0)}%</span>
                              <div className="progress-line"><div style={{ width: `${eff}%`, background: effColor(eff) }} /></div>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="bas-sect">
              <h3>Aprendizagem e RAG</h3>
              <div className="sh-sub">reuso de conhecimento em técnicas e skills</div>
              <div className="rag-stat">
                <div className="top"><span>Cobertura do catálogo</span><b>{Number(basLearning.coverage_percent || 0).toFixed(1)}%</b></div>
                <div className="progress-line"><div style={{ width: `${Number(basLearning.coverage_percent || 0)}%`, background: "var(--sev-low-solid)" }} /></div>
              </div>
              <div className="rag-stat">
                <div className="top"><span>Utilização em traces</span><b>{Number(basLearning.utilization_percent || 0).toFixed(1)}%</b></div>
                <div className="progress-line"><div style={{ width: `${Number(basLearning.utilization_percent || 0)}%`, background: "var(--brand-500)" }} /></div>
              </div>
              <div className="rag-grid">
                <div><div className="lbl">Aceitos</div><div className="vv" style={{ color: "var(--sev-low-text)" }}>{Number(basLearning.accepted || 0)}</div></div>
                <div><div className="lbl">Revisão</div><div className="vv" style={{ color: "var(--sev-medium-text)" }}>{Number(basLearning.pending || 0)}</div></div>
                <div><div className="lbl">RAG hits</div><div className="vv" style={{ color: "var(--brand-700)" }}>{Number(basLearning.rag_trace_hits || 0)}</div></div>
              </div>
            </div>
          </div>

          {/* Row 2: Tools · AgentFlow · Workers */}
          <div className="bas-grid-2">
            <div className="bas-sect">
              <div className="bas-sect-head">
                <div>
                  <h3>Utilização de ferramentas</h3>
                  <div className="sh-sub">eficiência, falhas e achados por ferramenta</div>
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--ink-muted)" }}>{basTools.length} linhas</span>
              </div>
              <table className="basT">
                <thead>
                  <tr><th>Ferramenta</th><th>Exec.</th><th>Sucesso</th><th>Achados</th><th>Tempo</th></tr>
                </thead>
                <tbody>
                  {basTools.length === 0 && (
                    <tr><td colSpan={5} className="bas-empty">Sem execuções de ferramentas no escopo.</td></tr>
                  )}
                  {basTools.map((tool) => (
                    <tr key={tool.tool}>
                      <td className="tool">{tool.tool}</td>
                      <td>{Number(tool.attempts || 0).toLocaleString("pt-BR")}</td>
                      <td><b>{Number(tool.success_rate || 0).toFixed(0)}%</b></td>
                      <td>{Number(tool.findings || 0)}</td>
                      <td>{Number(tool.avg_duration_seconds || 0).toFixed(1)}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="bas-sect">
              <h3>Fluxo de agentes</h3>
              <div className="sh-sub">eventos, sucesso e latência por fase / capability</div>
              <div style={{ marginTop: 14 }}>
                {basAgentFlow.length === 0 && <div className="bas-empty">Sem traces de agentes no escopo.</div>}
                {basAgentFlow.slice(0, 6).map((flow) => {
                  const rate = Number(flow.success_rate || 0);
                  // latência média por estágio (avg_duration_ms pode ser null quando
                  // a ferramenta não registrou tempo de execução → mostra "—").
                  const lat = flow.avg_duration_ms;
                  const latLabel = (lat === null || lat === undefined)
                    ? "—"
                    : (lat >= 1000 ? `${(lat / 1000).toFixed(1)}s` : `${Math.round(lat)}ms`);
                  return (
                    <div key={flow.stage} className="af-tile">
                      <div className="top">
                        <b>{flow.stage}</b>
                        <span className="ev">
                          {Number(flow.events || 0)} eventos
                          <span style={{ marginLeft: 8, color: "var(--ink-muted)", fontFamily: "var(--font-mono)" }}
                                title="latência média de execução">· {latLabel}</span>
                        </span>
                      </div>
                      <div className="bar-row">
                        <div className="progress-line"><div style={{ width: `${rate}%`, background: rate >= 80 ? "var(--sev-low-solid)" : "var(--sev-medium-solid)" }} /></div>
                        <span className="pct">{rate.toFixed(0)}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="bas-sect">
              <h3>Workers</h3>
              <div className="sh-sub">saúde da execução distribuída</div>
              <div className="w-mini" style={{ marginTop: 14 }}>
                <div><div className="lbl">Total</div><div className="vv">{Number(basWorkers.total || 0)}</div></div>
                <div className="act"><div className="lbl">Ativos</div><div className="vv">{Number(basWorkers.active || 0)}</div></div>
                <div className="stl"><div className="lbl">Stale</div><div className="vv">{Number(basWorkers.stale || 0)}</div></div>
              </div>
              <div className="w-list">
                {(basWorkers.rows || []).length === 0 && <div className="bas-empty">Sem workers registrados.</div>}
                {(basWorkers.rows || []).slice(0, 5).map((worker) => (
                  <div key={worker.name} className="it">
                    <div className="l">
                      <b>{worker.name}</b>
                      <span>{worker.mode} · {worker.last_task_name || "sem tarefa"}</span>
                    </div>
                    <span className="st">{worker.status}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Row 3: Validated risk + Top vulns */}
          <div className="bas-grid-3">
            <div className="bas-sect">
              <h3>Risco validado por BAS</h3>
              <div className="sh-sub">achados críticos / altos com evidência operacional</div>
              <div className="vr-card">
                <div>
                  <div className="big">{Number(basSummary.validated_risk_findings || 0)}</div>
                  <div className="big-sub">riscos críticos / altos</div>
                </div>
                <div className="small">
                  <div className="v">{Number(basSummary.open_findings || 0)}</div>
                  <div className="v-sub">achados abertos</div>
                </div>
              </div>
            </div>

            <div className="bas-sect">
              <h3>Top vulnerabilidades e controles</h3>
              <div className="sh-sub">priorização rápida para engenharia de detecção e correção</div>
              <div className="tv-grid" style={{ marginTop: 14 }}>
                {(topVulns || []).length === 0 && <div className="bas-empty">Sem vulnerabilidades recorrentes no escopo.</div>}
                {(topVulns || []).slice(0, 6).map((vuln) => (
                  <div key={`${vuln.title}-${vuln.severity}-${findingTargetSummary(vuln)}`} className="it">
                    <div className="l">
                      <b>{vuln.title}</b>
                      <span>{vuln.severity} · {findingTargetSummary(vuln)}</span>
                    </div>
                    <span className="ct">{vuln.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* ===== Risco, Rating e Maturidade ===== */}
        <section className="rrm">
          <div className="rrm-head">
            <h2>Risco, Rating e Maturidade</h2>
            <div className="eb">camada executiva após evidências BAS</div>
          </div>

          <div className="rrm-grid">
            <div className={`rrm-rating ${ratingTone(scopedVulnerabilityRating.score)}`}>
              <div className="lbl">Rating atual do alvo</div>
              <div className="body">
                <div>
                  <div className="letter">{scopedVulnerabilityRating.grade || "F"}</div>
                  <div className="sublabel">Rating</div>
                </div>
                <div className="score-num">{Number(scopedVulnerabilityRating.score || 0).toFixed(1)}</div>
              </div>
              <div className="bar"><div style={{ width: `${Math.max(0, Math.min(100, Number(scopedVulnerabilityRating.score || 0)))}%` }} /></div>
            </div>

            <div className={`rrm-rating ${ratingTone(globalVulnerabilityRating.score)}`}>
              <div className="lbl">Rating atual do grupo</div>
              <div className="body">
                <div>
                  <div className="letter">{globalVulnerabilityRating.grade || "F"}</div>
                  <div className="sublabel">Rating</div>
                </div>
                <div className="score-num">{Number(globalVulnerabilityRating.score || 0).toFixed(1)}</div>
              </div>
              <div className="bar"><div style={{ width: `${Math.max(0, Math.min(100, Number(globalVulnerabilityRating.score || 0)))}%` }} /></div>
            </div>

            <div className="rrm-dist">
              <div className="head-line">
                <div>
                  <h4>Rating distribuído</h4>
                  <div className="top-sub">top 5 alvos · maior volume de vulnerabilidades</div>
                </div>
                <div className="agg">{distributedGrade} <span>{Number(distributedScore || 0).toFixed(1)}</span></div>
              </div>
              <table className="distT">
                <thead>
                  <tr><th>Alvo</th><th style={{ width: 80 }}>Vulns</th><th style={{ width: 70 }}>Rating</th></tr>
                </thead>
                <tbody>
                  {distributedRows.length === 0 && (
                    <tr><td colSpan={3} className="bas-empty">Sem dados suficientes para distribuição.</td></tr>
                  )}
                  {distributedRows.map((row) => (
                    <tr key={row.target}>
                      <td className="hst">{row.target}</td>
                      <td>{row.vulnCount}</td>
                      <td><b>{row.grade} · {row.score.toFixed(0)}</b></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </section>

      </div>
    </main>
  );
}
