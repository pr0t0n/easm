import { useCallback, useEffect, useMemo, useState } from "react";
import client from "../api/client";
import CompanyScopeSelect from "../components/CompanyScopeSelect";
import { TV, SEVERITY_COLOR } from "../theme/basDark";

const ACTIVE = new Set(["queued", "running", "retrying"]);
const TERMINAL = new Set(["completed", "completed_with_gaps", "failed", "cancelled", "stopped", "blocked"]);
const SEVERITIES = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo" };

function Panel({ title, right, children, span = 1 }) {
  return (
    <section style={{
      background: TV.surface,
      border: `1px solid ${TV.border}`,
      borderRadius: 12,
      padding: "13px 16px",
      minWidth: 0,
      gridColumn: `span ${span}`,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12, marginBottom: 11 }}>
        <span style={{ color: TV.text, fontSize: 12, fontWeight: 700 }}>{title}</span>
        {right && <span style={{ color: TV.muted, fontFamily: "var(--font-mono)", fontSize: 10 }}>{right}</span>}
      </div>
      {children}
    </section>
  );
}

function Kpi({ value, label, color = TV.text, note }) {
  return (
    <div style={{ background: "#000", borderBottom: `1px solid ${TV.border}`, padding: "15px 10px 13px", textAlign: "center", minWidth: 0 }}>
      <div style={{ color, fontFamily: "var(--font-mono)", fontSize: 28, fontWeight: 700, lineHeight: 1 }}>{value}</div>
      <div style={{ color: TV.muted, fontSize: 9.5, letterSpacing: "0.07em", marginTop: 7, textTransform: "uppercase" }}>{label}</div>
      {note && <div style={{ color: TV.label, fontFamily: "var(--font-mono)", fontSize: 9, marginTop: 4 }}>{note}</div>}
    </div>
  );
}

function Progress({ value, color = "#7fe0b0" }) {
  const pct = Math.max(0, Math.min(100, Number(value) || 0));
  return (
    <div style={{ background: TV.surface2, borderRadius: 99, height: 7, overflow: "hidden" }}>
      <div style={{ background: color, borderRadius: 99, height: "100%", transition: "width 300ms", width: `${pct}%` }} />
    </div>
  );
}

function fmtTime(value) {
  if (!value) return "—";
  try { return new Date(value).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }); } catch { return "—"; }
}

function statusColor(status) {
  if (ACTIVE.has(status)) return "#7fe0b0";
  if (status === "failed" || status === "blocked") return "#ff8a8a";
  if (status === "completed" || status === "completed_with_gaps") return "#9db4ff";
  return TV.muted;
}

function severityColor(severity) {
  return SEVERITY_COLOR[severity] || TV.muted;
}

export default function ApiOperationsCenterPage() {
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [workerHealth, setWorkerHealth] = useState({ summary: {}, capacity: {} });
  const [platformHealth, setPlatformHealth] = useState({});
  const [accessGroupId, setAccessGroupId] = useState("");
  const [selectedScan, setSelectedScan] = useState("todos");
  const [interval, setInterval] = useState(1);
  const [countdown, setCountdown] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(() => fmtTime(new Date()));

  const loadData = useCallback(async () => {
    const findingParams = { limit: 500, offset: 0, status_filter: "open", sort: "date_desc", source_module: "api" };
    if (accessGroupId) findingParams.access_group_id = accessGroupId;
    const [sr, fr, wh, ph] = await Promise.all([
      client.get("/api/apitest", { _skipToast: true }).catch(() => ({ data: [] })),
      client.get("/api/findings/page", { params: findingParams, _skipToast: true }).catch(() => ({ data: {} })),
      client.get("/api/worker-manager/health", { _skipToast: true }).catch(() => ({ data: {} })),
      client.get("/api/platform/health", { _skipToast: true }).catch(() => ({ data: {} })),
    ]);
    setScans(Array.isArray(sr.data) ? sr.data : []);
    setFindings(Array.isArray(fr.data?.items) ? fr.data.items : []);
    setWorkerHealth(wh.data || {});
    setPlatformHealth(ph.data || {});
    setLastRefresh(fmtTime(new Date()));
  }, [accessGroupId]);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    if (!interval) { setCountdown(0); return undefined; }
    const seconds = interval * 60;
    setCountdown(seconds);
    const timer = window.setInterval(() => {
      setCountdown((current) => {
        if (current <= 1) { loadData(); return seconds; }
        return current - 1;
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [interval, loadData]);

  const scopedScans = useMemo(() => scans.filter((scan) => !accessGroupId || String(scan.access_group_id || "") === String(accessGroupId)), [scans, accessGroupId]);
  const scanIds = useMemo(() => new Set(scopedScans.map((scan) => Number(scan.id))), [scopedScans]);
  const scopedFindings = useMemo(() => findings.filter((finding) => scanIds.has(Number(finding.scan_job_id))), [findings, scanIds]);
  const activeScans = scopedScans.filter((scan) => ACTIVE.has(String(scan.status).toLowerCase()));
  const completedScans = scopedScans.filter((scan) => TERMINAL.has(String(scan.status).toLowerCase()));
  const failedScans = scopedScans.filter((scan) => ["failed", "blocked"].includes(String(scan.status).toLowerCase()));
  const selected = selectedScan === "todos" ? null : scopedScans.find((scan) => String(scan.id) === selectedScan);
  const effectiveFindings = selected ? scopedFindings.filter((finding) => Number(finding.scan_job_id) === Number(selected.id)) : scopedFindings;

  const severityCounts = useMemo(() => effectiveFindings.reduce((acc, finding) => {
    const severity = String(finding.severity || "info").toLowerCase();
    if (severity in acc) acc[severity] += 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 }), [effectiveFindings]);

  const observability = useMemo(() => scopedScans.map((scan) => {
    const state = scan.state_data || {};
    const api = state.api_scan_observability || {};
    const totals = api.totals || {};
    const config = state.api_scan_config || {};
    return {
      scan,
      config,
      api,
      imported: Number(totals.imported_url_count || 0),
      alerts: Number(totals.alert_count || 0),
      findingCount: Number(totals.finding_count || 0),
      contexts: Array.isArray(api.execution_contexts) ? api.execution_contexts : (Array.isArray(config.execution_contexts) ? config.execution_contexts : ["anonymous"]),
    };
  }), [scopedScans]);
  const metricScans = selected ? [selected] : scopedScans;
  const metricObservability = selected ? observability.filter((item) => item.scan.id === selected.id) : observability;
  const endpointTotal = metricObservability.reduce((sum, item) => sum + item.imported, 0);
  const alertTotal = metricObservability.reduce((sum, item) => sum + item.alerts, 0);
  const specConfigured = metricObservability.filter((item) => item.config.enabled || item.config.spec_url || item.api.spec_url).length;
  const authenticatedRuns = metricObservability.filter((item) => item.contexts.some((context) => String(context).startsWith("authenticated"))).length;
  const contractCoverage = metricScans.length ? Math.round((specConfigured / metricScans.length) * 100) : 0;
  const authCoverage = metricScans.length ? Math.round((authenticatedRuns / metricScans.length) * 100) : 0;
  const avgProgress = activeScans.length ? Math.round(activeScans.reduce((sum, scan) => sum + Number(scan.mission_progress || 0), 0) / activeScans.length) : 0;
  const capacity = workerHealth.capacity || {};
  const workers = workerHealth.summary || {};
  const workerPct = Number(workers.total_workers) ? Math.round((Number(workers.online_workers || 0) / Number(workers.total_workers)) * 100) : 0;
  const containerAlerts = Array.isArray(platformHealth.containers) ? platformHealth.containers.filter((item) => item.is_alert) : [];
  const platformOk = platformHealth.all_healthy !== false && containerAlerts.length === 0;
  const effectiveFamilyCounts = useMemo(() => {
    const grouped = new Map();
    effectiveFindings.forEach((finding) => {
      const key = finding.vuln_family || finding.vuln_family_label || "api";
      const current = grouped.get(key) || { family: key, label: finding.vuln_family_label || key, critical: 0, high: 0, medium: 0, low: 0, count: 0 };
      const severity = String(finding.severity || "info").toLowerCase();
      if (severity in current) current[severity] += 1;
      current.count += 1;
      grouped.set(key, current);
    });
    return Array.from(grouped.values()).sort((left, right) => right.count - left.count);
  }, [effectiveFindings]);
  const heat = effectiveFamilyCounts.filter((row) => SEVERITIES.some((severity) => Number(row[severity] || 0) > 0)).slice(0, 8);
  const maxHeat = Math.max(1, ...heat.flatMap((row) => SEVERITIES.map((severity) => Number(row[severity] || 0))));
  const missionStages = [
    ["Inventário / spec", specConfigured, metricScans.length],
    ["Contrato / endpoints", endpointTotal > 0 ? 100 : 0, 100],
    ["Contextos de autenticação", authenticatedRuns, metricScans.length],
    ["OWASP API Top 20", alertTotal + effectiveFindings.length, Math.max(endpointTotal, 1)],
    ["Evidência / remediação", effectiveFindings.length, Math.max(endpointTotal, 1)],
  ];
  const refresh = () => {
    setRefreshing(true);
    loadData().finally(() => window.setTimeout(() => setRefreshing(false), 350));
  };
  const cd = `${String(Math.floor(countdown / 60)).padStart(2, "0")}:${String(countdown % 60).padStart(2, "0")}`;

  return (
    <div style={{ background: "#000", color: TV.text, display: "flex", flex: 1, flexDirection: "column", minHeight: "100vh", width: "100%" }}>
      <div style={{ alignItems: "center", borderBottom: `1px solid ${TV.border}`, display: "flex", flexWrap: "wrap", gap: 12, padding: "16px 24px" }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700 }}>Centro Operacional de APIs</div>
          <div style={{ color: TV.muted, fontFamily: "var(--font-mono)", fontSize: 10.5, marginTop: 3 }}>telemetria de contratos, endpoints e testes OWASP API</div>
        </div>
        <CompanyScopeSelect value={accessGroupId} onChange={(value) => { setAccessGroupId(value); setSelectedScan("todos"); }} className="ops-company-scope company-scope-select" style={{ minWidth: 210 }} />
        <select value={selectedScan} onChange={(event) => setSelectedScan(event.target.value)} className="ops-tv-select" style={{ background: TV.surface, border: `1px solid ${TV.border}`, borderRadius: 8, color: TV.text, fontFamily: "var(--font-mono)", fontSize: 11, padding: "6px 10px" }}>
          <option value="todos">todos os testes API</option>
          {scopedScans.slice(0, 40).map((scan) => <option key={scan.id} value={String(scan.id)}>#{scan.id} · {String(scan.target_query || "").slice(0, 32)}</option>)}
        </select>
        <span style={{ color: TV.muted, fontFamily: "var(--font-mono)", fontSize: 10.5, marginLeft: "auto" }}>atualizado {lastRefresh} BRT</span>
        <div style={{ background: TV.surface, border: `1px solid ${TV.border}`, borderRadius: 9, display: "flex", gap: 3, padding: 3 }}>
          {[[0, "manual"], [1, "1 min"], [5, "5 min"]].map(([value, label]) => <button key={value} onClick={() => setInterval(value)} style={{ background: interval === value ? "var(--brand-500)" : "transparent", border: 0, borderRadius: 6, color: interval === value ? "#fff" : TV.muted, cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: 10, padding: "4px 9px" }}>{label}</button>)}
        </div>
        <button onClick={refresh} style={{ background: TV.surface, border: `1px solid ${TV.border}`, borderRadius: 8, color: TV.text, cursor: "pointer", fontFamily: "var(--font-mono)", fontSize: 10.5, minWidth: 102, padding: "6px 11px" }}>{refreshing ? "atualizando…" : interval && countdown ? cd : "Atualizar"}</button>
        <span style={{ color: activeScans.length ? "#7fe0b0" : TV.muted, fontFamily: "var(--font-mono)", fontSize: 10.5 }}>● {activeScans.length ? `${activeScans.length} ativo(s)` : "sem execução ativa"}</span>
      </div>

      <div style={{ background: TV.border, display: "grid", gridTemplateColumns: "repeat(8, minmax(0, 1fr))" }}>
        <Kpi value={scopedScans.length} label="testes API" />
        <Kpi value={activeScans.length} label="em execução" color="#7fe0b0" note={`${avgProgress}% progresso médio`} />
        <Kpi value={endpointTotal} label="endpoints importados" color="#9db4ff" note="soma dos testes" />
        <Kpi value={alertTotal} label="alertas do scanner" color="#ffb377" />
        <Kpi value={severityCounts.critical} label="críticos abertos" color="#ff8a8a" />
        <Kpi value={severityCounts.high} label="altos abertos" color="#ffb377" />
        <Kpi value={`${contractCoverage}%`} label="cobertura de contrato" color="#7fe0b0" note={`${specConfigured}/${scopedScans.length || 0} com spec`} />
        <Kpi value={`${authCoverage}%`} label="contexto autenticado" color="#9db4ff" note={`${authenticatedRuns}/${scopedScans.length || 0} testes`} />
      </div>

      <main style={{ flex: 1, minWidth: 0, overflowY: "auto", padding: 16 }}>
        <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(3, minmax(0, 1fr))", alignContent: "start" }}>
          <Panel title="Pipeline API · da especificação à prova" right={selected ? `scan #${selected.id}` : "execução real"} span={2}>
            <div style={{ display: "grid", gap: 8, gridTemplateColumns: "repeat(5, minmax(0, 1fr))" }}>
              {missionStages.map(([label, value, total], index) => {
                const pct = total ? Math.min(100, Math.round((Number(value) / Number(total)) * 100)) : 0;
                return <div key={label} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, minWidth: 0, padding: "10px 9px" }}>
                  <div style={{ color: index === 4 && effectiveFindings.length ? "#ffb377" : TV.text, fontFamily: "var(--font-mono)", fontSize: 19, fontWeight: 700 }}>{index === 3 || index === 4 ? value : `${pct}%`}</div>
                  <div style={{ color: TV.muted, fontSize: 10, lineHeight: 1.25, minHeight: 27, margin: "5px 0 8px" }}>{label}</div>
                  <Progress value={pct} color={index === 4 && effectiveFindings.length ? "#ffb377" : "#7fe0b0"} />
                </div>;
              })}
            </div>
            <div style={{ borderTop: `1px solid ${TV.border}`, color: TV.muted, display: "flex", flexWrap: "wrap", gap: 15, fontSize: 10.5, marginTop: 12, paddingTop: 10 }}>
              <span>Concluídos: <b style={{ color: TV.text }}>{completedScans.length}</b></span>
              <span>Falhas/bloqueios: <b style={{ color: failedScans.length ? "#ff8a8a" : TV.text }}>{failedScans.length}</b></span>
              <span>Escopo: <b style={{ color: "#9db4ff" }}>{selected ? `#${selected.id}` : accessGroupId ? `empresa #${accessGroupId}` : "global"}</b></span>
            </div>
          </Panel>

          <Panel title="Saúde do runtime API" right={platformOk && workerPct >= 50 ? "saudável" : "atenção"}>
            <div style={{ display: "grid", gap: 9 }}>
              <div style={{ alignItems: "center", background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, display: "flex", justifyContent: "space-between", padding: "10px 11px" }}><span style={{ color: TV.muted, fontSize: 10.5 }}>Workers online</span><b style={{ color: workerPct >= 50 ? "#7fe0b0" : "#ff8a8a", fontFamily: "var(--font-mono)" }}>{workers.online_workers || 0}/{workers.total_workers || 0}</b></div>
              <Progress value={workerPct} color={workerPct >= 50 ? "#7fe0b0" : "#ff8a8a"} />
              <div style={{ alignItems: "center", background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, display: "flex", justifyContent: "space-between", padding: "10px 11px" }}><span style={{ color: TV.muted, fontSize: 10.5 }}>Slots de execução</span><b style={{ color: TV.text, fontFamily: "var(--font-mono)" }}>{activeScans.length}/{capacity.total_slots || "—"}</b></div>
              <div style={{ alignItems: "center", background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, display: "flex", justifyContent: "space-between", padding: "10px 11px" }}><span style={{ color: TV.muted, fontSize: 10.5 }}>Plataforma</span><b style={{ color: platformOk ? "#7fe0b0" : "#ff8a8a", fontFamily: "var(--font-mono)" }}>{platformOk ? "OK" : `${containerAlerts.length} alerta(s)`}</b></div>
            </div>
          </Panel>

          <Panel title="Heatmap · famílias API × severidade" right={selected ? `scan #${selected.id}` : "achados abertos"} span={2}>
            {heat.length === 0 ? <div style={{ color: TV.muted, fontSize: 11, padding: "12px 0" }}>Nenhum achado API aberto no escopo atual.</div> : <div style={{ display: "grid", gap: 4, gridTemplateColumns: "minmax(150px, 1.5fr) repeat(4, minmax(46px, 1fr)) 42px" }}>
              <span />{SEVERITIES.map((severity) => <span key={severity} style={{ color: TV.muted, fontSize: 9, textAlign: "center", textTransform: "uppercase" }}>{SEVERITY_LABEL[severity]}</span>)}<span style={{ color: TV.muted, fontSize: 9, textAlign: "center", textTransform: "uppercase" }}>Total</span>
              {heat.flatMap((row) => [<span key={`${row.family}-label`} style={{ color: TV.text, fontSize: 10.5, fontWeight: 600, padding: "9px 5px 9px 0" }}>{row.label || row.family}</span>, ...SEVERITIES.map((severity) => { const count = Number(row[severity] || 0); return <div key={`${row.family}-${severity}`} style={{ alignItems: "center", background: count ? `rgba(${severity === "critical" ? "214,69,69" : severity === "high" ? "254,123,2" : severity === "medium" ? "212,165,0" : "34,145,96"},${(0.18 + (count / maxHeat) * 0.82).toFixed(2)})` : TV.surface2, borderRadius: 6, color: count / maxHeat > 0.45 ? "#fff" : count ? TV.text : TV.label, display: "grid", fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, minHeight: 31, placeItems: "center" }}>{count || ""}</div>; }), <span key={`${row.family}-total`} style={{ alignSelf: "center", color: TV.muted, fontFamily: "var(--font-mono)", fontSize: 11, textAlign: "center" }}>{SEVERITIES.reduce((sum, severity) => sum + Number(row[severity] || 0), 0)}</span>])}
            </div>}
          </Panel>

          <Panel title="Contratos e contextos de teste" right={`${specConfigured} com especificação`}>
            <div style={{ display: "grid", gap: 12 }}>
              <div><div style={{ color: TV.muted, display: "flex", fontSize: 10.5, justifyContent: "space-between", marginBottom: 5 }}><span>OpenAPI/Swagger configurado</span><b style={{ color: "#7fe0b0", fontFamily: "var(--font-mono)" }}>{contractCoverage}%</b></div><Progress value={contractCoverage} /></div>
              <div><div style={{ color: TV.muted, display: "flex", fontSize: 10.5, justifyContent: "space-between", marginBottom: 5 }}><span>Anonimizado + autenticado</span><b style={{ color: "#9db4ff", fontFamily: "var(--font-mono)" }}>{authCoverage}%</b></div><Progress value={authCoverage} color="#9db4ff" /></div>
              <div style={{ borderTop: `1px solid ${TV.border}`, color: TV.muted, fontSize: 10.5, lineHeight: 1.5, paddingTop: 10 }}>O centro contabiliza os contextos declarados no scan: anônimo, usuário A e usuário B quando credenciais de teste estão disponíveis.</div>
            </div>
          </Panel>

          <Panel title="Testes API em execução" right={`${activeScans.length} ativos`} span={2}>
            {activeScans.length === 0 ? <div style={{ color: TV.muted, fontSize: 11, padding: "12px 0" }}>Nenhum teste API em execução.</div> : <div style={{ display: "grid", gap: 8 }}>{activeScans.slice(0, 8).map((scan) => { const obs = observability.find((item) => item.scan.id === scan.id); const pct = Number(scan.mission_progress || 0); return <div key={scan.id} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, padding: "9px 11px" }}><div style={{ alignItems: "baseline", display: "flex", gap: 9, justifyContent: "space-between" }}><span style={{ color: TV.text, fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700 }}>#{scan.id} <span style={{ color: TV.muted, fontWeight: 400 }}>{String(scan.target_query || "").slice(0, 36)}</span></span><span style={{ color: statusColor(scan.status), fontFamily: "var(--font-mono)", fontSize: 10 }}>{scan.status} · {pct}%</span></div><div style={{ margin: "7px 0" }}><Progress value={pct} color={statusColor(scan.status)} /></div><div style={{ color: TV.label, display: "flex", fontFamily: "var(--font-mono)", fontSize: 9.5, gap: 14 }}><span>{scan.current_step || "fase não informada"}</span><span>{obs?.imported || 0} endpoints</span><span>C:{scan.open_critical || 0} A:{scan.open_high || 0} M:{scan.open_medium || 0}</span></div></div>; })}</div>}
          </Panel>

          <Panel title="Inventário de contratos" right="últimos testes">
            {observability.length === 0 ? <div style={{ color: TV.muted, fontSize: 11, padding: "12px 0" }}>Nenhum teste API registrado.</div> : <div style={{ display: "grid", gap: 7, maxHeight: 250, overflowY: "auto" }}>{observability.slice(0, 8).map((item) => <div key={item.scan.id} style={{ borderBottom: `1px solid ${TV.border}`, paddingBottom: 7 }}><div style={{ alignItems: "baseline", display: "flex", gap: 8, justifyContent: "space-between" }}><span style={{ color: TV.text, fontFamily: "var(--font-mono)", fontSize: 10.5, fontWeight: 700 }}>#{item.scan.id} · {String(item.scan.target_query || "").slice(0, 24)}</span><span style={{ color: statusColor(item.scan.status), fontFamily: "var(--font-mono)", fontSize: 9.5 }}>{item.scan.status}</span></div><div style={{ color: TV.muted, fontFamily: "var(--font-mono)", fontSize: 9.5, marginTop: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.api.spec_url || item.config.spec_url || "spec inline / não informada"}</div><div style={{ color: TV.label, display: "flex", fontFamily: "var(--font-mono)", fontSize: 9, gap: 12, marginTop: 4 }}><span>{item.imported} endpoints</span><span>{item.contexts.join(" + ")}</span><span>último {fmtTime(item.scan.updated_at)}</span></div></div>)}</div>}
          </Panel>

          <Panel title="Achados API · evidência para correção" right={`${effectiveFindings.length} abertos`} span={3}>
            {effectiveFindings.length === 0 ? <div style={{ color: TV.muted, fontSize: 11, padding: "12px 0" }}>Nenhum achado API aberto no escopo atual.</div> : <div style={{ overflowX: "auto" }}><table style={{ borderCollapse: "collapse", fontSize: 10.5, minWidth: 760, width: "100%" }}><thead><tr>{["Severidade", "Achado / família", "Endpoint", "Método", "Evidência", "Scan", "Atualizado"].map((heading) => <th key={heading} style={{ borderBottom: `1px solid ${TV.border}`, color: TV.muted, fontSize: 9, fontWeight: 600, padding: "5px 6px", textAlign: "left", textTransform: "uppercase" }}>{heading}</th>)}</tr></thead><tbody>{effectiveFindings.slice(0, 12).map((finding) => { const artifact = finding.evidence_artifact_id || (finding.api_scan_observability || {}).evidence_artifact_id; const evidence = artifact ? "artefato" : (finding.verification_status || "pendente"); return <tr key={finding.id}><td style={{ borderBottom: `1px solid ${TV.border}`, color: severityColor(finding.severity), fontFamily: "var(--font-mono)", fontWeight: 700, padding: "8px 6px", whiteSpace: "nowrap" }}>{SEVERITY_LABEL[finding.severity] || finding.severity}</td><td style={{ borderBottom: `1px solid ${TV.border}`, color: TV.text, maxWidth: 235, padding: "8px 6px" }}><div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{finding.title || "Achado sem título"}</div><div style={{ color: TV.muted, fontSize: 9.5, marginTop: 2 }}>{finding.vuln_family_label || finding.vuln_family || "API"}</div></td><td style={{ borderBottom: `1px solid ${TV.border}`, color: TV.muted, maxWidth: 210, overflow: "hidden", padding: "8px 6px", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{finding.path || finding.url || finding.target || "—"}</td><td style={{ borderBottom: `1px solid ${TV.border}`, color: "#9db4ff", fontFamily: "var(--font-mono)", padding: "8px 6px" }}>{finding.method || "—"}</td><td style={{ borderBottom: `1px solid ${TV.border}`, color: artifact ? "#7fe0b0" : evidence === "pendente" ? "#ffb377" : TV.muted, fontFamily: "var(--font-mono)", padding: "8px 6px" }}>{evidence}</td><td style={{ borderBottom: `1px solid ${TV.border}`, color: TV.muted, fontFamily: "var(--font-mono)", padding: "8px 6px" }}>#{finding.scan_job_id}</td><td style={{ borderBottom: `1px solid ${TV.border}`, color: TV.label, fontFamily: "var(--font-mono)", padding: "8px 6px" }}>{fmtTime(finding.created_at)}</td></tr>; })}</tbody></table></div>}
          </Panel>

          <Panel title="Escopo operacional e segurança" right="somente leitura">
            <div style={{ color: TV.muted, fontSize: 10.5, lineHeight: 1.55 }}>Este painel observa testes já autorizados e não dispara requests contra alvos. A execução continua sujeita ao gate de escopo, aos contextos de autenticação e à política de mutações do módulo API.</div>
            <div style={{ borderTop: `1px solid ${TV.border}`, display: "grid", gap: 7, marginTop: 10, paddingTop: 10 }}>
              <div style={{ color: TV.muted, display: "flex", justifyContent: "space-between", fontSize: 10.5 }}><span>Spec configurada</span><b style={{ color: "#7fe0b0", fontFamily: "var(--font-mono)" }}>{specConfigured}/{metricScans.length || 0}</b></div>
              <div style={{ color: TV.muted, display: "flex", justifyContent: "space-between", fontSize: 10.5 }}><span>Alertas encontrados</span><b style={{ color: alertTotal ? "#ffb377" : "#7fe0b0", fontFamily: "var(--font-mono)" }}>{alertTotal}</b></div>
              <div style={{ color: TV.muted, display: "flex", justifyContent: "space-between", fontSize: 10.5 }}><span>Última atualização</span><b style={{ color: TV.text, fontFamily: "var(--font-mono)" }}>{fmtTime(scopedScans[0]?.updated_at)}</b></div>
            </div>
          </Panel>
        </div>
      </main>
    </div>
  );
}
