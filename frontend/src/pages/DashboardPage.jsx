import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
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

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABELS = {
  critical: "Crítico",
  high: "Alto",
  medium: "Médio",
  low: "Baixo",
  info: "Info",
};

function clampPct(value) {
  return Math.max(0, Math.min(100, Number(value || 0)));
}

function formatDateTime(value) {
  if (!value) return "sem data";
  try {
    return new Intl.DateTimeFormat("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));
  } catch {
    return "sem data";
  }
}

function SeverityBadge({ severity }) {
  const normalized = String(severity || "info").toLowerCase();
  return (
    <span className={`sk-badge sk-badge--${normalized}`}>
      <span className={`sk-dot sk-dot--${normalized}`} />
      {SEVERITY_LABELS[normalized] || normalized}
    </span>
  );
}

function SeverityBar({ stats = {} }) {
  const total = SEVERITY_ORDER.reduce((acc, key) => acc + Number(stats?.[key] || 0), 0) || 1;
  return (
    <div className="cockpit-severity-bar" aria-label="Distribuição por severidade">
      {SEVERITY_ORDER.map((key) => {
        const count = Number(stats?.[key] || 0);
        if (!count) return null;
        return (
          <span
            key={key}
            className={`sev-fill sev-fill-${key}`}
            style={{ width: `${(count / total) * 100}%` }}
            title={`${SEVERITY_LABELS[key]}: ${count}`}
          />
        );
      })}
    </div>
  );
}

function MiniSparkline({ data = [] }) {
  const values = data
    .map((item) => Number(item?.rating_score ?? item?.score ?? item ?? 0))
    .filter((item) => Number.isFinite(item));
  const series = values.length > 1 ? values.slice(-8) : [0, Number(values[0] || 0)];
  const min = Math.min(...series);
  const max = Math.max(...series);
  const points = series.map((value, index) => {
    const x = 4 + (index / Math.max(1, series.length - 1)) * 116;
    const y = 30 - ((value - min) / Math.max(1, max - min)) * 24;
    return `${x},${y}`;
  }).join(" ");
  return (
    <svg viewBox="0 0 124 34" className="cockpit-spark" role="img" aria-label="Tendência do rating">
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function AttackGraphPanel({ paths = [], jewels = [] }) {
  const visiblePaths = paths.slice(0, 5);
  const visibleJewels = jewels.slice(0, 4);
  // Sem fabricação: só rótulos de dado REAL. Vazio → estado honesto.
  const jewelLabels = visibleJewels.map((item) => String(item.target || item.subdomain || item.label || "joia"));
  const surfaceLabels = visiblePaths.map((item) => String(item.target || "-").split("/")[0]).slice(0, 5);
  const hasGraph = surfaceLabels.length > 0 && jewelLabels.length > 0;
  const severityFor = (index) => String(visiblePaths[index]?.severity || "medium").toLowerCase();

  return (
    <div className="cockpit-panel attack-graph-panel">
      <div className="cockpit-panel-head">
        <div>
          <h3>Caminhos de ataque até as joias</h3>
          <span>grafo operacional do ciclo selecionado</span>
        </div>
        <div className="graph-head-actions">
          <Link to="/attack-graph">abrir explorer</Link>
          <div className="graph-legend">
            {["critical", "high", "medium"].map((sev) => (
              <span key={sev}><i className={`line-${sev}`} />{SEVERITY_LABELS[sev]}</span>
            ))}
          </div>
        </div>
      </div>
      {!hasGraph ? (
        <div className="attack-graph-empty">
          {visibleJewels.length === 0
            ? "Nenhuma joia da coroa identificada neste ciclo."
            : "Nenhum caminho de ataque validado até as joias neste ciclo."}
        </div>
      ) : (
      <svg viewBox="0 0 760 360" className="attack-graph" role="img" aria-label="Grafo de caminhos de ataque">
        <text x="82" y="32">ORIGEM</text>
        <text x="360" y="32">SUPERFÍCIE</text>
        <text x="646" y="32">JOIAS</text>
        {surfaceLabels.map((label, index) => {
          const y = 74 + index * 58;
          const jewelY = 80 + (index % jewelLabels.length) * 68;
          const sev = severityFor(index);
          return (
            <g key={`${label}-${index}`}>
              <path className="graph-line graph-line-low" d={`M 82 188 C 190 188, 210 ${y}, 322 ${y}`} />
              <path className={`graph-line graph-line-${sev}`} d={`M 398 ${y} C 490 ${y}, 510 ${jewelY}, 612 ${jewelY}`} />
              <circle cx="360" cy={y} r="21" className="graph-node graph-node-surface" />
              <text x="360" y={y + 4} className="graph-node-label">{label.slice(0, 13)}</text>
            </g>
          );
        })}
        <circle cx="82" cy="188" r="28" className="graph-node graph-node-origin" />
        <text x="82" y="192" className="graph-node-label origin">WAN</text>
        {jewelLabels.map((label, index) => {
          const y = 80 + index * 68;
          return (
            <g key={`${label}-${index}`}>
              <circle cx="646" cy={y} r="25" className="graph-node graph-node-jewel" />
              <text x="646" y={y + 4} className="graph-node-label jewel">{label.slice(0, 10)}</text>
            </g>
          );
        })}
      </svg>
      )}
      <div className="attack-path-chips">
        {visiblePaths.length === 0 ? (
          <span>Sem caminho validado no escopo atual.</span>
        ) : visiblePaths.map((item) => (
          <span key={item.id || item.title}>
            <i className={`sk-dot sk-dot--${String(item.severity || "info").toLowerCase()}`} />
            <b>{item.id || "SK"}</b>
            {item.title}
          </span>
        ))}
      </div>
    </div>
  );
}

const RUNNING_STATES = ["running", "queued", "retrying"];

function MissionFeedPanel({ scans = [], tools = [], flows = [], selectedScan }) {
  const feed = useMemo(() => [
    ...scans.slice(0, 3).map((scan) => ({
      t: formatDateTime(scan.updated_at || scan.created_at),
      actor: `scan #${scan.id}`,
      msg: `${scan.target_query || "alvo"} · ${scan.current_step || scan.status || "em execução"}`,
      sev: String(scan.status || "").toLowerCase() === "failed" ? "critical" : "info",
    })),
    ...tools.slice(0, 3).map((tool) => ({
      t: "tool",
      actor: tool.tool || "kali",
      msg: `${Number(tool.attempts || 0)} execuções · ${Number(tool.success_rate || 0).toFixed(0)}% sucesso`,
      sev: Number(tool.success_rate || 0) >= 70 ? "low" : "medium",
    })),
    ...flows.slice(0, 2).map((flow) => ({
      t: "agent",
      actor: flow.stage || "supervisor",
      msg: `${Number(flow.events || 0)} eventos · ${Number(flow.success_rate || 0).toFixed(0)}% sucesso`,
      sev: "info",
    })),
  ].slice(0, 8), [scans, tools, flows]);

  // Feed ao vivo: revela as linhas progressivamente (efeito "chegando agora")
  const [visible, setVisible] = useState(feed.length || 1);
  useEffect(() => {
    if (feed.length <= 1) { setVisible(feed.length); return; }
    setVisible(1);
    const iv = setInterval(() => {
      setVisible((n) => {
        if (n >= feed.length) { clearInterval(iv); return n; }
        return n + 1;
      });
    }, 1100);
    return () => clearInterval(iv);
  }, [feed.length]);

  // Técnica/atividade em execução — dado REAL do scan rodando (current_step + progresso)
  const runningScan =
    scans.find((s) => RUNNING_STATES.includes(String(s.status || "").toLowerCase())) ||
    (RUNNING_STATES.includes(String(selectedScan?.status || "").toLowerCase()) ? selectedScan : null);

  return (
    <div className="mission-feed">
      <div className="mission-feed-head">
        <strong>Acontecendo agora</strong>
        <span><i />ao vivo</span>
      </div>

      <div className="mission-technique">
        {runningScan ? (
          <>
            <span className="mission-technique-label">Em execução · scan #{runningScan.id}</span>
            <strong className="sk-mono">{runningScan.current_step || "iniciando…"}</strong>
            <div className="mission-progress"><i style={{ width: `${clampPct(runningScan.mission_progress)}%` }} /></div>
            <span className="mission-technique-meta">{clampPct(runningScan.mission_progress)}% · {runningScan.target_query || "alvo"}</span>
          </>
        ) : (
          <span className="mission-technique-idle">Nenhum scan em execução no momento.</span>
        )}
      </div>

      <div className="mission-scan-stack">
        {scans.slice(0, 3).map((scan) => (
          <div key={scan.id} className={Number(scan.id) === Number(selectedScan?.id) ? "active" : ""}>
            <div><b>#{scan.id} {scan.target_query || "alvo"}</b><span>{scan.status}</span></div>
            <div className="mission-progress"><i style={{ width: `${clampPct(scan.mission_progress)}%` }} /></div>
          </div>
        ))}
      </div>
      <div className="mission-feed-lines">
        {feed.length === 0 && <p>Sem eventos recentes para exibir.</p>}
        {feed.slice(0, visible).map((item, index) => (
          <div key={`${item.actor}-${index}`} className={index === visible - 1 ? "feed-new" : ""}>
            <time>{item.t}</time>
            <b>{item.actor}</b>
            <span className={`feed-${item.sev}`}>{item.msg}</span>
          </div>
        ))}
        <em>▍</em>
      </div>
    </div>
  );
}

function SurfaceHeatmap({ rows = [] }) {
  const columns = ["critical", "high", "medium", "low"];
  // Escala FIXA (= protótipo): saturação total em 12 achados por célula. Escala
  // dinâmica fazia poucos achados parecerem máximos (cor "errada" vs layout).
  const maxCell = 12;
  return (
    <div className="cockpit-panel heatmap-panel">
      <div className="cockpit-panel-head">
        <div>
          <h3>Heatmap · superfície × severidade</h3>
          <span>onde os achados se acumulam</span>
        </div>
      </div>
      <div className="heatmap-grid">
        <span />
        {columns.map((col) => <b key={col}>{SEVERITY_LABELS[col]}</b>)}
        <b>Total</b>
        {rows.map((row) => (
          <div className="heatmap-row" key={row.label}>
            <strong>{row.label}</strong>
            {columns.map((col) => {
              const value = Number(row?.[col] || 0);
              const ratio = value / maxCell;
              const intensity = value ? 0.15 + ratio * 0.85 : 0;
              return (
                <span
                  key={col}
                  className={`heat-cell heat-${col}`}
                  style={{
                    "--heat-alpha": intensity,
                    color: ratio > 0.45 ? "#fff" : "var(--ink-soft)",
                    ...(value ? {} : { background: "var(--surface-soft)" }),
                  }}
                  title={`${row.label} · ${SEVERITY_LABELS[col]}: ${value}`}
                >
                  {value || ""}
                </span>
              );
            })}
            <em>{columns.reduce((acc, col) => acc + Number(row?.[col] || 0), 0)}</em>
          </div>
        ))}
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
  const [cockpitData, setCockpitData] = useState(null);

  // ── Crown Jewels + OSINT Phase Zero (per selected scan) ──────────────────
  useEffect(() => {
    if (!selectedSubdomainScanId) return;
    client.get(`/api/scans/${selectedSubdomainScanId}/crown-jewels`)
      .then(({ data }) => setCrownJewels(Array.isArray(data?.crown_jewels) ? data.crown_jewels : []))
      .catch(() => setCrownJewels([]));
    client.get(`/api/scans/${selectedSubdomainScanId}/osint`, { _skipToast: true })
      .then(({ data }) => setOsintPhaseZero(data?.osint || null))
      .catch(() => setOsintPhaseZero(null));
  }, [selectedSubdomainScanId]);

  // ── Cockpit consolidado — dado REAL por scan (/api/cockpit): heatmap,
  //    fila com EPSS+MITRE, joias, score. Sem fabricar nada. ────────────────
  useEffect(() => {
    const qs = selectedSubdomainScanId ? `?scan_id=${selectedSubdomainScanId}` : "";
    client.get(`/api/cockpit${qs}`)
      .then(({ data }) => setCockpitData(data || null))
      .catch(() => setCockpitData(null));
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
          external_rating_grade: dashboard.stats?.external_rating_grade || null,
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
          aggregation_targets: dashboard.stats?.aggregation_targets || 0,
        });

        setFrameworks([
          { name: "ISO 27001", score: dashboard.frameworks?.iso27001?.score ?? null },
          { name: "NIST CSF", score: dashboard.frameworks?.nist?.score ?? null },
          { name: "CIS v8", score: dashboard.frameworks?.cis_v8?.score ?? null },
          { name: "PCI", score: dashboard.frameworks?.pci?.score ?? null },
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
          aggregationTargets: Number(globalDashboard.stats?.aggregation_targets || 0),
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

  const resilienceDefined = basSummary.bas_resilience_index !== null && basSummary.bas_resilience_index !== undefined;
  const resilience = Number(basSummary.bas_resilience_index || 0);
  const confirmedSkillCount = Number(basSummary.confirmed_skill_count || 0);
  const activeSkillCount = Number(basSummary.active_skill_count || 0);
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
      value: resilienceDefined ? resilience.toFixed(1) : "—",
      unit: resilienceDefined ? "%" : "",
      sub: resilienceDefined
        ? `${confirmedSkillCount}/${activeSkillCount} skills confirmadas`
        : "nenhuma skill executada com confirmação",
      tone: !resilienceDefined ? "tone-muted" : resilience >= 70 ? "tone-green" : "tone-amber",
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
    .sort((a, b) => Number(a.score ?? 101) - Number(b.score ?? 101))
    .slice(0, 4);
  // Fila de ataque: prioriza dado REAL do /api/cockpit (EPSS FIRST.org, MITRE
  // derivado, verification_status, flag de joia). Fallback ao insights só
  // enquanto o cockpit não respondeu — sem inventar EPSS/MITRE.
  const cockpitFindings = Array.isArray(cockpitData?.findings) ? cockpitData.findings : [];
  const attackQueue = cockpitFindings.length
    ? cockpitFindings.map((f) => ({
        id: f.finding_id || f.id,
        title: f.title || "Achado sem título",
        severity: String(f.severity || "info").toLowerCase(),
        target: f.target || "—",
        cve: f.cve || "—",
        cvss: Number(f.cvss || 0),
        epss: f.epss == null ? 0 : Number(f.epss),
        mitre: Array.isArray(f.mitre) && f.mitre.length ? f.mitre.map((m) => m.id).join(", ") : "—",
        status: f.status || "candidato",
        isJewel: Boolean(f.is_jewel),
        reason: f.is_jewel
          ? "↳ atinge joia da coroa"
          : (f.tool ? `via ${f.tool}` : `${SEVERITY_LABELS[String(f.severity || "info").toLowerCase()] || ""} no ambiente`),
      }))
    : redteamFindings.map((item, idx) => ({
        id: item.finding_id || item.id || idx,
        title: item.title || item.name || item.problem || "Achado sem titulo",
        severity: item.severity || "info",
        target: findingTarget(item),
        cve: item.cve || item.cve_id || item.cve_ids?.[0] || "—",
        cvss: Number(item.cvss || item.cvss_score || item.score || 0),
        epss: null,  // insights não tem EPSS — honesto: "—"
        mitre: "—",  // insights não tem MITRE por achado — honesto: "—"
        status: item.supervisor_validation?.status || item.verification_status || item.status || "candidato",
        reason: item.operational_reason || item.financial_reason || item.recommendation || `${item.count || 1} ocorrência(s) no ambiente`,
      }));

  // Joias reais do cockpit (escopadas por scan, sempre carregadas via /api/cockpit)
  const cockpitJewels = Array.isArray(cockpitData?.crown_jewels) && cockpitData.crown_jewels.length
    ? cockpitData.crown_jewels
    : crownJewels;

  const showEmptyScanNote = Boolean(selectedTarget) && stats && stats.scans === 0;
  const selectedScan = (
    scanRows.find((scan) => Number(scan.id) === Number(selectedSubdomainScanId))
    || scanRows[0]
    || null
  );
  const selectedScanId = selectedSubdomainScanId || selectedScan?.id || "";
  // Sem execução no escopo não há rating: ausência de dados não é nota "F".
  const hasScanData = Number(stats?.scans || 0) > 0;
  const cockpitScore = Number(stats?.external_rating_score || scopedVulnerabilityRating?.score || 0);
  const cockpitGrade = hasScanData
    ? (stats?.external_rating_grade || scopedVulnerabilityRating?.grade || gradeFromScore(cockpitScore))
    : "—";
  const cockpitTone = hasScanData ? ratingTone(cockpitScore) : "t-muted";
  const activeScanRows = scanRows.filter((scan) => ["running", "queued", "retrying"].includes(String(scan?.status || "").toLowerCase()));
  const scanOptions = scanRows.slice(0, 80);
  // Heatmap: dado REAL por finding vindo de /api/cockpit (classificação por
  // sinal real do achado: domínio, url, ferramenta, título). Sem fabricar
  // distribuição — se o backend ainda não respondeu, a matriz fica zerada.
  const HEAT_CATEGORIES = [
    "Aplicações web",
    "APIs",
    "Infraestrutura / IPs",
    "Painéis & consoles",
    "DNS / certificados",
  ];
  const heatMatrix = cockpitData?.heatmap?.matrix || {};
  const heatmapRows = (cockpitData?.heatmap?.categories || HEAT_CATEGORIES).map((label) => {
    const cell = heatMatrix[label] || {};
    return {
      label,
      critical: Number(cell.critical || 0),
      high: Number(cell.high || 0),
      medium: Number(cell.medium || 0),
      low: Number(cell.low || 0),
    };
  });
  const exportSelectedReport = async () => {
    if (selectedScan?.id) {
      const sid = selectedScan.id;
      const reportWindow = window.open("", "_blank");
      if (reportWindow) {
        reportWindow.document.write(`
          <!doctype html>
          <html lang="pt-BR">
            <head><title>Gerando relatório técnico...</title></head>
            <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;padding:32px;color:#1f2937">
              <h1 style="font-size:20px;margin:0 0 8px">Gerando relatório técnico completo</h1>
              <p style="margin:0;color:#64748b">Carregando evidências e preparando o HTML...</p>
            </body>
          </html>
        `);
        reportWindow.document.close();
      }
      try {
        const res = await client.get(`/api/scans/${sid}/pentest-report`, {
          responseType: "text",
          transformResponse: [(value) => value],
          _skipToast: true,
        });
        const html = String(res.data || "");
        if (reportWindow && !reportWindow.closed) {
          reportWindow.document.open();
          reportWindow.document.write(html);
          reportWindow.document.close();
        } else {
          const blob = new Blob([html], { type: "text/html;charset=utf-8" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `pentest-report-scan-${sid}.html`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 60000);
        }
      } catch (err) {
        if (reportWindow && !reportWindow.closed) {
          reportWindow.document.open();
          reportWindow.document.write(`
            <!doctype html>
            <html lang="pt-BR">
              <head><title>Falha ao gerar relatório</title></head>
              <body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;padding:32px;color:#991b1b">
                <h1 style="font-size:20px;margin:0 0 8px">Falha ao abrir o relatório técnico</h1>
                <p style="margin:0;color:#7f1d1d">${err?.response?.data?.detail || "Endpoint indisponível ou sessão sem permissão."}</p>
              </body>
            </html>
          `);
          reportWindow.document.close();
        }
        window.alert("Não foi possível abrir o relatório técnico (indisponível ou sem permissão).");
      }
      return;
    }
    window.location.assign("/relatorios");
  };
  const handleScanSelect = (event) => {
    const value = event.target.value;
    if (!value) {
      setSelectedSubdomainScanId(null);
      setSelectedTarget("");
      setSearchInput("");
      return;
    }
    const scan = scanRows.find((row) => Number(row.id) === Number(value));
    setSelectedSubdomainScanId(value);
    if (scan?.target_query) {
      setSelectedGroup("");
      setSelectedTarget(scan.target_query);
      setSearchInput(scan.target_query);
    }
  };

  return (
    <main className="dash">
      <div className="content cockpit-shell">
        <section className="cockpit-page-head">
          <div>
            <div className="sk-eyebrow">Cockpit RedTeam</div>
            <h1>O que atacar primeiro</h1>
          </div>
          <div className="cockpit-actions">
            <select value={selectedScanId || ""} onChange={handleScanSelect} aria-label="Selecionar scan do cockpit">
              <option value="">Todos os scans</option>
              {scanOptions.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} · {scan.target_query || "alvo"} · {scan.status}
                </option>
              ))}
            </select>
            <button type="button" className="btn btn-ghost" onClick={exportSelectedReport}>Exportar relatório</button>
            <button type="button" className="btn btn-primary" onClick={() => window.location.assign("/scan")}>Novo scan</button>
          </div>
        </section>

        <section className="cockpit-filter-strip">
          <div className="ctrl">
            <label>Grupo / Cliente</label>
            <select
              value={selectedGroup}
              onChange={(e) => {
                setSelectedGroup(e.target.value);
                setSelectedTarget("");
                setSearchInput("");
                setSelectedSubdomainScanId(null);
              }}
            >
              <option value="">Todos os grupos</option>
              {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
            </select>
          </div>
          <div className="ctrl">
            <label>Alvo</label>
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleSearch(); }}
              placeholder="domínio, subdomínio ou URL…"
            />
          </div>
          <div className="cockpit-filter-actions">
            <button type="button" className="btn btn-primary" onClick={handleSearch} disabled={loading || isSearching}>
              {isSearching || loading ? "Buscando…" : "Buscar"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={clearFilters}>Limpar</button>
          </div>
          {!!stats && (
            <div className="cockpit-scope-note">
              <b>{Number(stats.aggregation_targets || 0)}</b> alvo(s) · {Number(stats.scans || 0)} ciclo(s)
            </div>
          )}
        </section>

        {showEmptyScanNote && (
          <div className="scope-empty">
            Nenhum scan encontrado com esse domínio. Ele pode não ter análises executadas ainda.
          </div>
        )}

        <section className="cockpit-hero">
          <div className="cockpit-score">
            <div className="score-ring">
              <strong>{hasScanData ? cockpitScore.toFixed(0) : "—"}</strong>
              <span>rating</span>
            </div>
            <div>
              <div className={`score-grade ${cockpitTone}`}>
                <b>{cockpitGrade}</b>
                <span>{Number(ratingTimeline?.length || 0)} scans no histórico</span>
              </div>
              <MiniSparkline data={ratingTimeline} />
            </div>
          </div>
          <div className="cockpit-kpi danger">
            <span>Críticos + Altos</span>
            <strong>{criticalHighCount}</strong>
            <small>exploráveis ou aguardando validação</small>
          </div>
          <div className="cockpit-kpi">
            <span>Ativos expostos</span>
            <strong>{Number(selectedSubdomainScan?.subdomain_count || totalDiscoveredSubdomains || 0)}</strong>
            <small>hosts na superfície analisada</small>
          </div>
          <div className="cockpit-kpi warn">
            <span>Joias em risco</span>
            <strong>{cockpitJewels.length}</strong>
            <small>com achado ou caminho correlacionado</small>
          </div>
          <div className="cockpit-kpi ok">
            <span>Resiliência BAS</span>
            <strong>{resilienceDefined ? `${resilience.toFixed(0)}%` : "—"}</strong>
            <small>{resilienceDefined ? `${gapCount} gap(s) de detecção` : "sem skill confirmada"}</small>
          </div>
          <div className="cockpit-severity">
            <span>Severidade</span>
            <SeverityBar stats={stats} />
            <small>
              {Number(stats?.critical || 0)}C · {Number(stats?.high || 0)}A · {Number(stats?.medium || 0)}M · {Number(stats?.low || 0)}B
            </small>
          </div>
        </section>

        <section className="cockpit-main-grid">
          <AttackGraphPanel paths={attackQueue} jewels={cockpitJewels} />
          <MissionFeedPanel scans={activeScanRows.length ? activeScanRows : scanRows} tools={basTools} flows={basAgentFlow} selectedScan={selectedScan} />
        </section>

        <section className="cockpit-lower-grid">
          <SurfaceHeatmap rows={heatmapRows} />
          <div className="cockpit-panel frameworks-panel">
            <div className="cockpit-panel-head">
              <div>
                <h3>Frameworks pressionados</h3>
                <span>MITRE, OWASP, CIS e controles executivos</span>
              </div>
            </div>
            {weakFrameworks.map((fw) => {
              const hasFwData = fw.score !== null && fw.score !== undefined;
              const score = clampPct(fw.score);
              return (
                <div key={fw.name} className="framework-row">
                  <div><b>{fw.name}</b><span>{hasFwData ? `${score.toFixed(0)}%` : "—"}</span></div>
                  <i><em style={{ width: `${hasFwData ? score : 0}%` }} /></i>
                </div>
              );
            })}
            <div className="framework-callout">
              <b>{gapCount}</b> lacuna(s) de detecção e <b>{Number(basSummary.validated_risk_findings || 0)}</b> risco(s) validados no ciclo.
            </div>
          </div>
        </section>

        <section className="cockpit-panel attack-queue-panel">
          <div className="attack-queue-head">
            <div>
              <h3>Fila de ataque recomendada</h3>
              <span>ordenada por severidade, alvo, evidência e valor operacional</span>
            </div>
            <b>{attackQueue.length} itens</b>
          </div>
          <div className="attack-table-wrap">
            <table className="attack-table">
              <thead>
                <tr>
                  <th>Severidade</th>
                  <th>Vulnerabilidade</th>
                  <th>Alvo</th>
                  <th>CVE</th>
                  <th>CVSS</th>
                  <th>EPSS</th>
                  <th>MITRE</th>
                  <th>Evidência</th>
                </tr>
              </thead>
              <tbody>
                {attackQueue.length === 0 && (
                  <tr><td colSpan={8}>Sem vulnerabilidades priorizadas no escopo atual.</td></tr>
                )}
                {attackQueue.map((item, idx) => (
                  <tr key={`${item.id}-${idx}`}>
                    <td><SeverityBadge severity={item.severity} /></td>
                    <td><b>{item.title}</b><small>{item.reason}</small></td>
                    <td className="mono">{item.target}</td>
                    <td className="mono">{item.cve}</td>
                    <td className="num">{item.cvss ? item.cvss.toFixed(1) : "—"}</td>
                    <td className="num">{item.epss ? `${Math.round(item.epss * 100)}%` : "—"}</td>
                    <td className="mono">{item.mitre}</td>
                    <td><span className="evidence-pill">{String(item.status).replace(/_/g, " ")}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </main>
  );

}
