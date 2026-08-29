// BAS Control Center — replaces BasDashboardPage + BasTestMenuPage with a
// single 4-tab page (Painel / Implantação / CMDB / Vulnerabilidades),
// following the "Central de controle BAS" design (Claude Design project
// dab3e9b1-36e0-4c52-b227-a6a78d392f5e). Re-skinned onto this platform's real
// graphite/brand-red dark palette (frontend/src/theme/basDark.js, already
// used by BasOperationsCenterPage.jsx) instead of the mockup's own black/
// purple identity, per explicit user decision.
//
// Every number on this page traces to a real query (see
// backend/app/services/bas_reporting.py) or is shown as an honest empty
// state -- no mockup constants, no fabricated "detected" outcome, no
// invented industry-median benchmark. See the plan's "Report back to the
// user" section for the one deliberately-dropped mockup element.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import client from "../api/client";
import { authStore } from "../store/auth";
import { toastError, toastSuccess } from "../utils/toast";
import { TV, SEVERITY_COLOR, RISK_COLOR, OUTCOME_COLOR } from "../theme/basDark";

const HEARTBEAT_INTERVAL_MS = 60_000;
const RUN_POLL_INTERVAL_MS = 2_000;
const RUN_TERMINAL_STATUSES = new Set(["completed", "done", "finished", "failed", "stopped"]);
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function isCallbackHostStale(cfg, browserHost) {
  if (!cfg?.callback_host || cfg.callback_host === "backend") return false;
  return cfg.callback_host !== browserHost && !LOOPBACK_HOSTS.has(browserHost);
}

const fieldStyle = {
  width: "100%", padding: "9px 12px", borderRadius: 8,
  border: `1px solid ${TV.border}`, background: TV.surface2, fontSize: 13, color: TV.text,
};

const RISK_TIER_META = {
  safe: { label: "Safe", desc: "Padrão — só leitura/enumeração", color: "#1f8a59" },
  elevated: { label: "Elevated", desc: "Kerberoasting, etc.", color: "#d4a500" },
  high_risk: { label: "High risk", desc: "NTLM relay, etc.", color: "#d64545" },
};
const CONTROL_MATRIX_STATUS_LABEL = { tested: "testado", prevented: "prevenido", detected: "detectado", missed: "perdido", not_applicable: "sem teste" };
const CONTROL_MATRIX_STATUS_COLOR = { tested: TV.muted, prevented: "#1f8a59", detected: "#4b73ff", missed: "#d64545", not_applicable: TV.label };
const RISK_TIER_ORDER = { safe: 0, elevated: 1, high_risk: 2 };
const FREQ_LABEL = { daily: "Diário", weekly: "Semanal", monthly: "Mensal", every_3_hours: "A cada 3 horas", every_6_hours: "A cada 6 horas", every_12_hours: "A cada 12 horas" };
const CONTROL_MATRIX_PAGE_SIZE = 25;

function Card({ children, style, ...rest }) {
  return (
    <div style={{ background: TV.surface, border: `1px solid ${TV.border}`, borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", gap: 14, minWidth: 0, ...style }} {...rest}>
      {children}
    </div>
  );
}

function CardTitle({ children, sub }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
      <span style={{ fontWeight: 700, fontSize: 14, lineHeight: "18px", color: TV.text }}>{children}</span>
      {sub && <span style={{ fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.muted }}>{sub}</span>}
    </div>
  );
}

function Bar({ pct, color, height = 6, bg = TV.border }) {
  return (
    <div style={{ height, borderRadius: 999, background: bg, overflow: "hidden" }}>
      <div style={{ height: "100%", width: `${Math.max(0, Math.min(100, pct || 0))}%`, background: color, transition: "width .3s ease" }} />
    </div>
  );
}

function Pill({ children, color }) {
  return (
    <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color, border: `1px solid ${color}`, borderRadius: 999, padding: "3px 8px", textTransform: "uppercase", letterSpacing: ".5px" }}>
      {children}
    </span>
  );
}

function Empty({ children }) {
  return <div style={{ fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.muted, padding: "16px 0", textAlign: "center" }}>{children}</div>;
}

function ScoreRing({ score, color }) {
  const size = 96, r = 42, circ = 2 * Math.PI * r;
  const value = score == null ? 0 : score;
  return (
    <div style={{ position: "relative", width: size, height: size, flex: "none" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ display: "block", transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={TV.border} strokeWidth={9} />
        {score != null && (
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={9} strokeLinecap="round"
            strokeDasharray={circ} strokeDashoffset={circ * (1 - value / 100)} style={{ transition: "stroke-dashoffset .5s ease" }} />
        )}
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <span style={{ fontWeight: 700, fontSize: 26, lineHeight: "28px", color: TV.text }}>{score == null ? "—" : score}</span>
        <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "12px", color: TV.muted, letterSpacing: ".6px" }}>/ 100</span>
      </div>
    </div>
  );
}

function scoreColorFor(score) {
  if (score == null) return TV.muted;
  return score >= 75 ? "#1f8a59" : score >= 55 ? "#d4a500" : "#fe7b02";
}

function TrendChart({ points }) {
  const withScore = points.filter((p) => p.score != null);
  if (withScore.length < 2) return <Empty>Dados insuficientes para uma tendência ainda (poucas semanas com jobs resolvidos).</Empty>;
  const W = 100, H = 100;
  const scores = withScore.map((p) => p.score);
  const min = Math.min(...scores) - 5, max = Math.max(...scores) + 5;
  const span = Math.max(1, max - min);
  const step = W / (points.length - 1);
  let segments = [];
  let current = [];
  points.forEach((p, i) => {
    const x = i * step;
    if (p.score == null) {
      if (current.length > 1) segments.push(current);
      current = [];
      return;
    }
    current.push([x, H - ((p.score - min) / span) * H]);
  });
  if (current.length > 1) segments.push(current);
  return (
    <div style={{ position: "relative", height: 120 }}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }}>
        {segments.map((seg, i) => (
          <polyline key={i} points={seg.map((p) => p.join(",")).join(" ")} fill="none" stroke="#e96363" strokeWidth={1.4} vectorEffect="non-scaling-stroke" />
        ))}
      </svg>
    </div>
  );
}

export default function BasControlCenterPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = ["panel", "runs", "deploy", "cmdb", "vulns"].includes(searchParams.get("tab")) ? searchParams.get("tab") : "panel";
  const setTab = (next) => setSearchParams((prev) => { const p = new URLSearchParams(prev); p.set("tab", next); return p; });

  const isAdmin = Boolean(authStore.me?.is_admin);

  const [cc, setCc] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [agents, setAgents] = useState([]);
  const [techniques, setTechniques] = useState([]);
  const [chains, setChains] = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [segments, setSegments] = useState([]);
  const [ops, setOps] = useState(null);
  const activeRunCount = cc?.active_runs?.length || 0;

  const loadAll = useCallback(async (silent = false) => {
    try {
      const [{ data: c }, { data: a }, { data: t }, { data: ch }, { data: s }, { data: seg }] = await Promise.all([
        client.get("/api/bas/control-center"),
        client.get("/api/bas/agents"),
        client.get("/api/bas/techniques"),
        client.get("/api/bas/chains"),
        client.get("/api/bas/schedules"),
        client.get("/api/bas/network-segments"),
      ]);
      const { data: o } = await client.get("/api/bas/operations-center").catch(() => ({ data: null }));
      setCc(c);
      setAgents(a);
      setTechniques(t);
      setChains(ch);
      setSchedules(s);
      setSegments(seg);
      setOps(o);
      setLastUpdated(new Date());
    } catch (error) {
      if (silent) return;
      const detail = error?.response?.data?.detail;
      toastError(typeof detail === "string" ? detail : "Falha ao carregar o BAS Control Center.");
    }
  }, []);

  useEffect(() => {
    loadAll();
    const heartbeat = setInterval(() => loadAll(true), activeRunCount > 0 ? RUN_POLL_INTERVAL_MS : HEARTBEAT_INTERVAL_MS);
    return () => clearInterval(heartbeat);
  }, [loadAll, activeRunCount]);

  // minHeight: 100vh (not "100%") on purpose -- .app-shell switches from
  // flex (which stretches .main-column to fill it) to display:block below
  // the 900px breakpoint (index.css), which breaks a percentage-based
  // height here. 100vh has no such dependency on an ancestor's layout mode.
  return (
    <main className="dpage space-y-4" style={{ background: TV.bg, minHeight: "100vh", borderRadius: 0, padding: 20, color: TV.text }}>
      <header style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 16, lineHeight: "20px", color: TV.text }}>BAS Control Center</div>
          <div style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.muted }}>Breach &amp; Attack Simulation</div>
        </div>
        <div style={{ display: "flex", gap: 2, padding: 3, background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8 }}>
          {[["panel", "Painel"], ["runs", "Execuções"], ["deploy", "Implantação & agendamento"], ["cmdb", "CMDB"], ["vulns", "Vulnerabilidades"]].map(([key, label]) => (
            <button key={key} onClick={() => setTab(key)} style={{
              border: 0, cursor: "pointer", fontWeight: 600, fontSize: 12, lineHeight: "16px", padding: "8px 14px", borderRadius: 6,
              background: tab === key ? "#e96363" : "transparent", color: tab === key ? "#fff" : TV.muted,
            }}>{label}</button>
          ))}
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.muted }}>
            {lastUpdated ? `atualizado ${lastUpdated.toLocaleTimeString()}` : "carregando…"}
          </span>
          <button className="btn" onClick={() => loadAll()} style={{ background: "transparent", border: `1px solid ${TV.border}`, color: TV.text, borderRadius: 8, padding: "8px 14px", cursor: "pointer" }}>
            Atualizar
          </button>
        </div>
      </header>

      {tab === "panel" && <PanelTab cc={cc} agents={agents} schedules={schedules} ops={ops} setTab={setTab} />}
      {tab === "runs" && <RunsTab cc={cc} ops={ops} agents={agents} schedules={schedules} setTab={setTab} />}
      {tab === "deploy" && (
        <DeployTab
          isAdmin={isAdmin} agents={agents} techniques={techniques} chains={chains} schedules={schedules}
          reload={loadAll}
        />
      )}
      {tab === "cmdb" && <CmdbTab cc={cc} segments={segments} reload={loadAll} />}
      {tab === "vulns" && <VulnsTab cc={cc} />}
    </main>
  );
}

// ── Painel ────────────────────────────────────────────────────────────────

function PanelTab({ cc, agents, schedules, ops, setTab }) {
  const [controlMatrixPage, setControlMatrixPage] = useState(1);
  const controlMatrixCellCount = cc?.control_matrix?.cells?.length || 0;

  useEffect(() => {
    setControlMatrixPage(1);
  }, [controlMatrixCellCount]);

  if (!cc) return <Empty>Carregando…</Empty>;
  const score = cc.resilience_score;
  const color = scoreColorFor(score.score);

  const findings = cc.findings || [];
  const realFindings = findings.filter((f) => !f.simulated && f.proof_valid);
  const openBySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  realFindings.forEach((f) => { if (openBySeverity[f.severity] != null) openBySeverity[f.severity]++; });
  const categoryTotals = (cc.category_coverage || []).reduce((acc, c) => ({ tested: acc.tested + c.tested, total: acc.total + c.total }), { tested: 0, total: 0 });
  const categoriesWithCoverage = (cc.category_coverage || []).filter((c) => c.tested > 0).length;
  const controlMatrix = cc.control_matrix || {};
  const controlMatrixSummary = controlMatrix.summary || {};
  const controlMatrixFrameworks = controlMatrix.frameworks || [];
  const controlMatrixCells = controlMatrix.cells || [];
  const controlMatrixPageCount = Math.max(1, Math.ceil(controlMatrixCells.length / CONTROL_MATRIX_PAGE_SIZE));
  const controlMatrixSafePage = Math.min(controlMatrixPage, controlMatrixPageCount);
  const controlMatrixPageStart = (controlMatrixSafePage - 1) * CONTROL_MATRIX_PAGE_SIZE;
  const controlMatrixPageCells = controlMatrixCells.slice(controlMatrixPageStart, controlMatrixPageStart + CONTROL_MATRIX_PAGE_SIZE);
  const activeRuns = cc.active_runs || [];
  const cmdbAssets = cc.cmdb?.cmdb_assets || [];
  const observedAssets = cmdbAssets.filter((asset) => (asset.observations || []).length > 0).length;
  const reachableAssets = cmdbAssets.filter((asset) => (asset.services || []).length > 0).length;
  const validatedAssets = cmdbAssets.filter((asset) => (asset.vulnerabilities || []).length > 0).length;
  const unprovenFindings = findings.filter((f) => !f.simulated && !f.proof_valid).length;

  const kpis = [
    { label: "Achados reais abertos", value: realFindings.length, sub: `${openBySeverity.critical} críticos · ${openBySeverity.high} altos`, color: "#d64545", pct: realFindings.length ? 100 : 0 },
    { label: "Técnicas testadas", value: categoryTotals.tested, unit: `/ ${categoryTotals.total}`, sub: `${categoriesWithCoverage}/${(cc.category_coverage || []).length} categorias com cobertura`, color: "#e96363", pct: categoryTotals.total ? Math.round(100 * categoryTotals.tested / categoryTotals.total) : 0 },
    { label: "Ativos no CMDB", value: cc.cmdb?.summary?.assets ?? 0, sub: `${cc.cmdb?.summary?.high_risk_assets ?? 0} de risco alto`, color: "#4b73ff", pct: cc.cmdb?.summary?.assets ? 100 : 0 },
    { label: "Agentes online", value: agents.filter((a) => a.status === "online").length, unit: `/ ${agents.length}`, sub: `${agents.filter((a) => a.status === "pending").length} pendente(s)`, color: "#1f8a59", pct: agents.length ? Math.round(100 * agents.filter((a) => a.status === "online").length / agents.length) : 0 },
  ];

  const outcomeTotals = (cc.attack_heatmap || []).reduce((acc, r) => {
    if (r.outcome === "proven") acc.proven += 1;
    else if (r.outcome === "unproven") acc.unproven += 1;
    else if (r.outcome === "blocked") acc.blocked += 1;
    return acc;
  }, { proven: 0, unproven: 0, blocked: 0 });
  const outcomeResolved = outcomeTotals.proven + outcomeTotals.unproven + outcomeTotals.blocked;

  const topMitigations = [...realFindings]
    .filter((f) => f.recommendation)
    .sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 }[a.severity] ?? 9) - ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 }[b.severity] ?? 9))
    .filter((f, i, arr) => arr.findIndex((x) => x.recommendation === f.recommendation) === i)
    .slice(0, 4);

  const timeline = [
    ...realFindings.slice(0, 8).map((f) => ({ time: f.created_at, title: `Achado: ${f.title}`, detail: f.category || "", color: SEVERITY_COLOR[f.severity] || TV.muted })),
    ...schedules.filter((s) => s.last_run_at).map((s) => ({ time: s.last_run_at, title: `Execução: ${s.name || "agendamento"}`, detail: s.last_job_status || "", color: s.last_job_status === "completed" ? "#1f8a59" : s.last_job_status === "failed" ? "#d64545" : TV.muted })),
  ].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, 10);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <section style={{ display: "grid", gridTemplateColumns: "300px repeat(4, minmax(0,1fr))", gap: 16 }}>
        <Card style={{ flexDirection: "row", alignItems: "center", gap: 18 }}>
          <ScoreRing score={score.score} color={color} />
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".8px", textTransform: "uppercase" }}>Resilience score</span>
            <span style={{ fontWeight: 700, fontSize: 13, lineHeight: "16px", color }}>
              {score.score == null ? "sem dados suficientes" : score.score >= 75 ? "Resilient" : score.score >= 55 ? "Needs hardening" : "At risk"}
            </span>
            <span style={{ fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.muted }}>
              {score.delta == null ? "sem janela anterior comparável" : `${score.delta > 0 ? "+" : ""}${score.delta} pts vs janela anterior`}
            </span>
            <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.label }}>Últimos {score.window_days} dias · jobs reais resolvidos</span>
            <IndustryBenchmarkLine benchmark={cc.industry_benchmark} />
          </div>
        </Card>
        {kpis.map((k) => (
          <Card key={k.label}>
            <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".8px", textTransform: "uppercase" }}>{k.label}</span>
            <div style={{ display: "flex", alignItems: "flex-end", gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 26, lineHeight: "28px", color: k.color }}>{k.value}</span>
              {k.unit && <span style={{ fontWeight: 400, fontSize: 12, lineHeight: "18px", color: TV.muted }}>{k.unit}</span>}
            </div>
            <span style={{ fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.muted }}>{k.sub}</span>
            <Bar pct={k.pct} color={k.color} height={4} />
          </Card>
        ))}
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "minmax(0,1.15fr) minmax(0,1fr)", gap: 16 }}>
        <ActiveRunsPanel activeRuns={activeRuns} setTab={setTab} />

        <AgentFleetPanel agents={agents} fleet={ops?.agent_fleet} setTab={setTab} />

        <Card>
          <CardTitle sub="Proven = prova validada · Bloqueado = falhou · Não confirmado = completou sem prova">Test depth · kill chain</CardTitle>
          {(cc.kill_chain_stages || []).map((s) => (
            <div key={s.stage} style={{ display: "grid", gridTemplateColumns: "132px minmax(0,1fr) 100px", gap: 12, alignItems: "center" }}>
              <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", color: s.tested ? TV.text : TV.muted }}>{s.label}</span>
              <div style={{ display: "flex", height: 12, borderRadius: 4, overflow: "hidden", background: TV.border }}>
                <div style={{ width: `${s.proven_pct}%`, background: OUTCOME_COLOR.proven }} />
                <div style={{ width: `${s.unproven_pct}%`, background: OUTCOME_COLOR.unproven }} />
                <div style={{ width: `${s.blocked_pct}%`, background: OUTCOME_COLOR.blocked }} />
              </div>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, textAlign: "right" }}>{s.tested}/{s.total} técnicas</span>
            </div>
          ))}
          <div style={{ marginTop: "auto", display: "flex", gap: 18, paddingTop: 12, borderTop: `1px solid ${TV.border}` }}>
            <Legend color={OUTCOME_COLOR.proven} label="Proven" />
            <Legend color={OUTCOME_COLOR.unproven} label="Não confirmado" />
            <Legend color={OUTCOME_COLOR.blocked} label="Bloqueado" />
          </div>
        </Card>
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0,1fr))", gap: 12 }}>
        {[
          ["Ativos observados", observedAssets, "target/log/stdout"],
          ["Alcançáveis", reachableAssets, "serviço/fingerprint"],
          ["Com achado validado", validatedAssets, "prova BAS"],
          ["Sem prova suficiente", unprovenFindings, "execução sem finding"],
        ].map(([label, value, sub]) => (
          <Card key={label} style={{ padding: 14 }}>
            <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".6px" }}>{label}</span>
            <span style={{ fontWeight: 800, fontSize: 24, lineHeight: "28px", color: label === "Com achado validado" ? "#d64545" : label === "Alcançáveis" ? "#4b73ff" : TV.text }}>{value}</span>
            <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.muted }}>{sub}</span>
          </Card>
        ))}
      </section>

      <Card>
        <CardTitle sub={`${categoryTotals.tested}/${categoryTotals.total} técnicas testadas em ${(cc.category_coverage || []).length} categorias`}>Tipos de teste · cobertura por categoria</CardTitle>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0,1fr))", gap: 12 }}>
          {(cc.category_coverage || []).map((c) => {
            const pct = c.total ? Math.round(100 * c.tested / c.total) : 0;
            const color = c.tested === 0 ? TV.label : c.tested >= c.total ? "#1f8a59" : pct >= 50 ? "#d4a500" : "#fe7b02";
            return (
              <div key={c.category} style={{ display: "flex", flexDirection: "column", gap: 6, background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 10, padding: "12px 14px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px" }}>{c.category}</span>
                  <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "16px", color: TV.muted }}>{c.tested}/{c.total}</span>
                </div>
                <Bar pct={pct} color={color} />
                <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: TV.label }}>{c.safe} safe · {c.elevated} elevated · {c.high_risk} high risk</span>
              </div>
            );
          })}
        </div>
      </Card>

      <Card>
        <CardTitle sub="Coluna por categoria (o catálogo não anota tática MITRE por técnica) · cor = melhor resultado real já observado">MITRE ATT&amp;CK · cobertura por categoria</CardTitle>
        <MitreHeatmap rows={cc.attack_heatmap || []} />
        <div style={{ display: "flex", gap: 16, paddingTop: 8, borderTop: `1px solid ${TV.border}` }}>
          <Legend color={OUTCOME_COLOR.proven} label="Proven" />
          <Legend color={OUTCOME_COLOR.unproven} label="Não confirmado" />
          <Legend color={OUTCOME_COLOR.blocked} label="Bloqueado" />
          <Legend color={OUTCOME_COLOR.not_tested} label="Não testado" />
        </div>
      </Card>

      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <CardTitle sub={`${controlMatrixSummary.controls || 0} controle(s) · ${controlMatrixSummary.cells || 0} célula(s)`}>Control Matrix</CardTitle>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "15px", color: TV.muted }}>
              {controlMatrixCells.length ? `${controlMatrixPageStart + 1}-${Math.min(controlMatrixPageStart + CONTROL_MATRIX_PAGE_SIZE, controlMatrixCells.length)} de ${controlMatrixCells.length}` : "0 de 0"}
            </span>
            <button type="button" className="btn" disabled={controlMatrixSafePage <= 1} onClick={() => setControlMatrixPage((page) => Math.max(1, page - 1))} style={{ padding: "5px 9px", background: "transparent", border: `1px solid ${TV.border}`, color: controlMatrixSafePage <= 1 ? TV.label : TV.text, opacity: controlMatrixSafePage <= 1 ? .5 : 1 }}>
              Anterior
            </button>
            <span style={{ fontWeight: 700, fontSize: 11, lineHeight: "15px", color: TV.text }}>{controlMatrixSafePage}/{controlMatrixPageCount}</span>
            <button type="button" className="btn" disabled={controlMatrixSafePage >= controlMatrixPageCount} onClick={() => setControlMatrixPage((page) => Math.min(controlMatrixPageCount, page + 1))} style={{ padding: "5px 9px", background: "transparent", border: `1px solid ${TV.border}`, color: controlMatrixSafePage >= controlMatrixPageCount ? TV.label : TV.text, opacity: controlMatrixSafePage >= controlMatrixPageCount ? .5 : 1 }}>
              Próxima
            </button>
          </div>
        </div>
        <section style={{ display: "grid", gridTemplateColumns: "minmax(220px,.65fr) minmax(0,1.35fr)", gap: 14 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 460, overflowY: "auto", paddingRight: 4 }}>
            {controlMatrixFrameworks.length === 0 && <Empty>Nenhuma matriz de controle calculada ainda.</Empty>}
            {controlMatrixFrameworks.map((fw) => (
              <div key={fw.framework} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 10, padding: "10px 12px", display: "flex", flexDirection: "column", gap: 7 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <span style={{ fontWeight: 700, fontSize: 12, lineHeight: "16px" }}>{fw.label}</span>
                  <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "16px", color: TV.muted }}>{fw.tested}/{fw.applicable}</span>
                </div>
                <Bar pct={fw.coverage_pct || 0} color={(fw.coverage_pct || 0) >= 60 ? "#1f8a59" : (fw.coverage_pct || 0) > 0 ? "#d4a500" : TV.border} />
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                  {Object.entries(fw.status_counts || {}).filter(([, count]) => count > 0).map(([status, count]) => (
                    <span key={status} style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: CONTROL_MATRIX_STATUS_COLOR[status] || TV.muted, border: `1px solid ${TV.border}`, borderRadius: 999, padding: "2px 7px" }}>
                      {CONTROL_MATRIX_STATUS_LABEL[status] || status} {count}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div style={{ overflowX: "auto", maxHeight: 460, overflowY: "auto", border: `1px solid ${TV.border}`, borderRadius: 10 }}>
            <div style={{ display: "grid", gridTemplateColumns: "92px 160px minmax(220px,1fr) 92px 70px", gap: 10, minWidth: 720, padding: "8px 10px", borderBottom: `1px solid ${TV.border}`, background: TV.surface2, position: "sticky", top: 0, zIndex: 1 }}>
              {["Framework", "Controle", "Técnica", "Estado", "Runs"].map((h) => (
                <span key={h} style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".6px" }}>{h}</span>
              ))}
            </div>
            {controlMatrixPageCells.map((cell) => (
              <div key={`${cell.framework}-${cell.control_id}-${cell.technique_key}`} style={{ display: "grid", gridTemplateColumns: "92px 160px minmax(220px,1fr) 92px 70px", gap: 10, alignItems: "center", minWidth: 720, padding: "9px 10px", borderBottom: `1px solid ${TV.border}` }}>
                <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "15px", color: TV.text }}>{cell.framework_label}</span>
                <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "15px", color: TV.text }}>{cell.control_id}</span>
                <span style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                  <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "15px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{cell.technique_name}</span>
                  <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: TV.label, fontFamily: "var(--font-mono,monospace)" }}>{cell.technique_key}</span>
                </span>
                <Pill color={CONTROL_MATRIX_STATUS_COLOR[cell.status] || TV.muted}>{CONTROL_MATRIX_STATUS_LABEL[cell.status] || cell.status}</Pill>
                <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "15px", color: TV.muted, textAlign: "right" }}>{cell.times_tested || 0}</span>
              </div>
            ))}
            {controlMatrixPageCells.length === 0 && <Empty>Nenhuma célula para exibir.</Empty>}
          </div>
        </section>
      </Card>

      <section style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr) 300px", gap: 16 }}>
        <Card>
          <CardTitle sub="Prevented % = job bloqueado · Missed % = job funcionou sem barreira (sem estado 'detectado' fabricado)">Protection layers</CardTitle>
          {(cc.protection_layers || []).length === 0 && <Empty>Nenhum controle mapeado ainda — cadastre segmentos de rede na aba CMDB para começar a medir isto.</Empty>}
          {(cc.protection_layers || []).map((l) => (
            <div key={`${l.name}-${l.vendor}`} style={{ display: "grid", gridTemplateColumns: "112px minmax(0,1fr) 90px", gap: 12, alignItems: "center" }}>
              <div style={{ display: "flex", flexDirection: "column" }}>
                <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "15px" }}>{l.name}</span>
                <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: TV.label }}>{l.vendor}</span>
              </div>
              <div style={{ display: "flex", height: 14, borderRadius: 4, overflow: "hidden", background: TV.border }}>
                <div style={{ width: `${l.prevented_pct ?? 0}%`, background: "#1f8a59" }} />
                <div style={{ width: `${l.missed_pct ?? 0}%`, background: "#d64545" }} />
              </div>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, textAlign: "right" }}>
                {l.sample_size} amostra(s){l.low_confidence ? " · baixa confiança" : ""}
              </span>
            </div>
          ))}
        </Card>

        <Card>
          <CardTitle sub={`${cc.score_trend?.length || 0} semanas`}>Score trend</CardTitle>
          <TrendChart points={cc.score_trend || []} />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0,1fr))", gap: 10, paddingTop: 8, borderTop: `1px solid ${TV.border}` }}>
            {[
              { label: "Proven", value: outcomeTotals.proven, color: OUTCOME_COLOR.proven },
              { label: "Não confirmado", value: outcomeTotals.unproven, color: OUTCOME_COLOR.unproven },
              { label: "Bloqueado", value: outcomeTotals.blocked, color: OUTCOME_COLOR.blocked },
            ].map((o) => (
              <div key={o.label} style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                <span style={{ fontWeight: 700, fontSize: 20, lineHeight: "24px", color: o.color }}>{outcomeResolved ? Math.round(100 * o.value / outcomeResolved) : 0}%</span>
                <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.muted, textTransform: "uppercase" }}>{o.label}</span>
                <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.label }}>{o.value} técnica(s)</span>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <CardTitle>Findings by severity</CardTitle>
          {["critical", "high", "medium", "low"].map((sev) => (
            <div key={sev} style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", color: SEVERITY_COLOR[sev] }}>{sev}</span>
                <span style={{ marginLeft: "auto", fontWeight: 700, fontSize: 14, lineHeight: "18px" }}>{openBySeverity[sev]}</span>
              </div>
              <Bar pct={realFindings.length ? Math.round(100 * openBySeverity[sev] / realFindings.length) : 0} color={SEVERITY_COLOR[sev]} />
            </div>
          ))}
          <div style={{ marginTop: 6, paddingTop: 12, borderTop: `1px solid ${TV.border}`, display: "flex", flexDirection: "column", gap: 9 }}>
            <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".8px", textTransform: "uppercase" }}>Top mitigações</span>
            {topMitigations.length === 0 && <Empty>Nenhuma recomendação registrada ainda.</Empty>}
            {topMitigations.map((f) => (
              <div key={f.id} style={{ display: "flex", gap: 9, alignItems: "flex-start" }}>
                <span style={{ flex: "none", marginTop: 4, width: 6, height: 6, borderRadius: 999, background: SEVERITY_COLOR[f.severity] }} />
                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px" }}>{f.title}</span>
                  <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.label }}>{f.recommendation}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "minmax(0,1.55fr) minmax(0,1fr)", gap: 16 }}>
        <Card>
          <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
            <CardTitle sub={`${cc.cmdb?.summary?.assets ?? 0} ativo(s) tocado(s)`}>CMDB · affected assets</CardTitle>
            <button onClick={() => setTab("cmdb")} style={{ marginLeft: "auto", border: 0, background: "transparent", cursor: "pointer", fontWeight: 600, fontSize: 12, lineHeight: "16px", color: "#e96363" }}>
              Ver CMDB completo
            </button>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1.4fr) 100px 110px 86px 74px", gap: 12, padding: "0 12px 8px", borderBottom: `1px solid ${TV.border}` }}>
            {["Asset", "Status", "Business unit", "Risco", "Findings"].map((h) => (
              <span key={h} style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, letterSpacing: ".7px", textTransform: "uppercase" }}>{h}</span>
            ))}
          </div>
          {(cc.cmdb?.cmdb_assets || []).length === 0 && <Empty>Nenhum ativo descoberto por BAS ainda.</Empty>}
          {(cc.cmdb?.cmdb_assets || []).slice(0, 8).map((a) => (
            <div key={a.ip} style={{ display: "grid", gridTemplateColumns: "minmax(0,1.4fr) 100px 110px 86px 74px", gap: 12, alignItems: "center", padding: "11px 12px", borderBottom: `1px solid ${TV.border}` }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{a.hostname || a.ip}</span>
                <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: TV.label }}>{a.ip} · {a.os || "SO desconhecido"}</span>
              </div>
              <Pill color={assetStatus(a).color}>{assetStatus(a).label}</Pill>
              <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.text }}>{a.business_unit || "não classificado"}</span>
              <Pill color={RISK_COLOR[a.risk_level] || TV.muted}>{a.risk_level}</Pill>
              <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", color: a.vulnerabilities?.length ? "#d64545" : TV.muted, textAlign: "right" }}>{a.vulnerabilities?.length || 0}</span>
            </div>
          ))}
        </Card>

        <Card>
          <CardTitle>Activity timeline</CardTitle>
          {timeline.length === 0 && <Empty>Nenhuma atividade real registrada ainda.</Empty>}
          {timeline.map((e, i) => (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "auto 16px minmax(0,1fr)", gap: 10, padding: "9px 0" }}>
              <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "16px", color: TV.label, fontVariantNumeric: "tabular-nums" }}>{e.time ? new Date(e.time).toLocaleString() : "—"}</span>
              <span style={{ width: 9, height: 9, borderRadius: 999, background: e.color, marginTop: 4 }} />
              <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", color: e.color }}>{e.title}</span>
                <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "15px", color: TV.muted }}>{e.detail}</span>
              </div>
            </div>
          ))}
        </Card>
      </section>
    </div>
  );
}

// Real, sourced external reference (Wavestone Cyber Benchmark 2026) --
// NEVER the same measurement as our resilience_score (that's a real BAS
// attack-outcome ratio; Wavestone is consultant-assessed maturity against
// NIST CSF/ISO 27001). Shown side-by-side, explicitly labeled, never merged
// into one number. See backend/app/services/external_benchmarks.py.
function IndustryBenchmarkLine({ benchmark }) {
  if (!benchmark) return null;
  const title = `Fonte: ${benchmark.source.name} (${benchmark.source.sample}). Metodologia: ${benchmark.source.methodology}`;
  if (benchmark.sector_maturity_pct != null) {
    return (
      <span title={title} style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.label, cursor: "help" }}>
        Benchmark {benchmark.sector_label} (Wavestone 2026): {benchmark.sector_maturity_pct}% · global {benchmark.global_average_pct}%
      </span>
    );
  }
  return (
    <span title={title} style={{ fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.label, cursor: "help" }}>
      Média global (Wavestone 2026): {benchmark.global_average_pct}% · setor não classificado (configure em Usuários → Empresas)
    </span>
  );
}

function ActiveRunsPanel({ activeRuns, setTab }) {
  if (!activeRuns.length) {
    return (
      <Card style={{ gridColumn: "1 / -1", padding: "14px 18px", background: TV.surface2 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ width: 9, height: 9, borderRadius: 999, background: TV.label }} />
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontWeight: 700, fontSize: 13, lineHeight: "17px", color: TV.text }}>Nenhum teste BAS em andamento</span>
            <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "15px", color: TV.muted }}>O painel entra em atualização rápida automaticamente quando uma execução começa.</span>
          </div>
          <button onClick={() => setTab("deploy")} style={{ marginLeft: "auto", border: `1px solid ${TV.border}`, background: "transparent", borderRadius: 8, cursor: "pointer", fontWeight: 600, fontSize: 12, lineHeight: "16px", color: TV.text, padding: "7px 11px" }}>
            Ver agendamentos
          </button>
        </div>
      </Card>
    );
  }
  const averageProgress = Math.round(activeRuns.reduce((sum, run) => sum + Number(run.mission_progress || 0), 0) / activeRuns.length);
  const failedJobs = activeRuns.reduce((sum, run) => sum + Number(run.jobs_failed || 0), 0);
  const resolvedJobs = activeRuns.reduce((sum, run) => sum + Number(run.jobs_resolved || 0), 0);
  return (
    <Card style={{ gridColumn: "1 / -1", borderColor: "#4b73ff", background: "#111827" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <CardTitle sub={`${activeRuns.length} execução(ões) ativa(s) · polling 2s`}>Testes em andamento agora</CardTitle>
        <span style={{ marginLeft: "auto", fontWeight: 700, fontSize: 18, lineHeight: "22px", color: "#4b73ff" }}>{averageProgress}%</span>
      </div>
      <Bar pct={averageProgress} color="#4b73ff" height={7} bg="#263246" />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0,1fr))", gap: 10 }}>
        {[
          ["Runs ativos", activeRuns.length],
          ["Jobs vistos", activeRuns.reduce((sum, run) => sum + Number(run.jobs_total_seen || 0), 0)],
          ["Jobs resolvidos", resolvedJobs],
          ["Falhas", failedJobs],
        ].map(([label, value]) => (
          <div key={label} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, padding: "9px 11px", display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".5px" }}>{label}</span>
            <span style={{ fontWeight: 700, fontSize: 18, lineHeight: "22px", color: label === "Falhas" && value ? "#d64545" : TV.text }}>{value}</span>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {activeRuns.slice(0, 5).map((run) => {
          const progress = Math.max(0, Math.min(99, Number(run.mission_progress || 0)));
          return (
            <div key={run.scan_job_id} style={{ display: "grid", gridTemplateColumns: "minmax(0,1.25fr) minmax(0,1fr) 84px", gap: 12, alignItems: "center", background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, padding: "10px 12px" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 999, background: "#4b73ff", boxShadow: "0 0 0 3px #4b73ff22", flex: "none" }} />
                  <span style={{ fontWeight: 700, fontSize: 12, lineHeight: "16px", color: TV.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{run.schedule_name || `scan BAS #${run.scan_job_id}`}</span>
                </div>
                <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", color: TV.label, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  Scan #{run.scan_job_id} · {run.agent_label || `agente #${run.agent_id || "—"}`} · {run.active_target || run.target_query || "alvo em preparo"}
                </span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, minWidth: 0 }}>
                <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "15px", color: "#4b73ff", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{run.current_step || "Preparando execução"}</span>
                <Bar pct={progress} color="#4b73ff" height={5} bg="#263246" />
                <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: TV.label }}>{run.jobs_resolved || 0}/{run.total_hint || run.jobs_total_seen || 1} unidade(s) resolvida(s){run.active_technique_key ? ` · ${run.active_technique_key}` : ""}</span>
              </div>
              <button onClick={() => setTab("runs")} style={{ border: `1px solid ${TV.border}`, background: "transparent", borderRadius: 8, cursor: "pointer", fontWeight: 700, fontSize: 10.5, lineHeight: "14px", color: "#4b73ff", padding: "6px 8px" }}>
                {progress}%
              </button>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function healthColor(grade) {
  if (grade === "healthy") return "#1f8a59";
  if (grade === "degraded") return "#d4a500";
  if (grade === "critical") return "#d64545";
  return TV.muted;
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString();
}

function assetStatus(asset) {
  if ((asset.vulnerabilities || []).length > 0) return { label: "validado", color: "#d64545" };
  if ((asset.services || []).length > 0) return { label: "alcançável", color: "#4b73ff" };
  if ((asset.observations || []).length > 0) return { label: "observado", color: "#d4a500" };
  return { label: "sem evidência", color: TV.muted };
}

function AgentFleetPanel({ agents, fleet, setTab }) {
  const rows = fleet?.agents || agents.map((agent) => ({ ...agent, ...(agent.fleet || {}) }));
  const summary = fleet?.summary || {
    agents: rows.length,
    online: rows.filter((agent) => agent.status === "online").length,
    healthy: rows.filter((agent) => agent.health?.grade === "healthy").length,
    degraded: rows.filter((agent) => agent.health?.grade === "degraded").length,
    critical: rows.filter((agent) => agent.health?.grade === "critical").length,
  };
  return (
    <Card>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <CardTitle sub={`${summary.online || 0}/${summary.agents || 0} online · ${summary.healthy || 0} healthy · ${summary.degraded || 0} degraded · ${summary.critical || 0} critical`}>Agent fleet</CardTitle>
        <button onClick={() => setTab("deploy")} style={{ marginLeft: "auto", border: 0, background: "transparent", cursor: "pointer", fontWeight: 600, fontSize: 12, lineHeight: "16px", color: "#e96363" }}>
          Implantar / configurar
        </button>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 330, overflowY: "auto", paddingRight: 4 }}>
        {rows.length === 0 && <Empty>Nenhum agente enrolado ainda.</Empty>}
        {rows.map((agent) => {
          const health = agent.health || agent.fleet?.health || {};
          const capabilities = agent.capabilities || agent.fleet?.capabilities || {};
          const tools = Array.isArray(capabilities.tools) ? capabilities.tools.length : Object.keys(capabilities.tools || {}).length;
          return (
            <div key={agent.id} style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) 58px", gap: 10, alignItems: "center", padding: "11px 12px", borderRadius: 10, background: TV.surface2, border: `1px solid ${TV.border}` }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 5, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 999, background: agent.status === "online" ? "#1f8a59" : agent.status === "pending" ? "#d4a500" : TV.muted, flex: "none" }} />
                  <span style={{ fontWeight: 700, fontSize: 12.5, lineHeight: "16px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{agent.label || agent.hostname || `agente #${agent.id}`}</span>
                  <Pill color={healthColor(health.grade)}>{health.grade || "unknown"}</Pill>
                </div>
                <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", color: TV.label, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {agent.os || "SO"} {agent.os_version || ""} · {agent.arch || "arch n/a"} · v{agent.agent_version || "n/a"} · {agent.local_network_cidr || "sem rede"}
                </span>
                <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", color: TV.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  IP {agent.last_seen_ip || "—"} · heartbeat {formatDateTime(agent.last_heartbeat_at)} · tools {tools || "n/a"} · {(agent.tags || []).join(", ") || agent.site || agent.agent_group || "sem tags"}
                </span>
              </div>
              <span style={{ fontWeight: 800, fontSize: 18, lineHeight: "22px", color: healthColor(health.grade), textAlign: "right" }}>{health.score ?? 0}</span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

function RunsTab({ cc, ops, agents, schedules, setTab }) {
  const activeRuns = cc?.active_runs || [];
  const activeJobs = ops?.active_jobs || [];
  const recentJobs = ops?.recent_jobs || [];
  const agentById = useMemo(() => Object.fromEntries((agents || []).map((agent) => [agent.id, agent])), [agents]);
  const scheduleById = useMemo(() => Object.fromEntries((schedules || []).map((schedule) => [schedule.id, schedule])), [schedules]);
  const pipeline = [
    ["Schedule", schedules.length],
    ["ScanJob", activeRuns.length],
    ["BasJob", activeJobs.length + recentJobs.length],
    ["Kali Task", activeJobs.filter((job) => job.status === "dispatched_to_kali" || job.status === "running").length],
    ["Evidence", recentJobs.filter((job) => job.proof_status && job.proof_status !== "missing").length],
    ["Proof", recentJobs.filter((job) => job.proof_valid).length],
    ["Finding", (cc?.findings || []).filter((finding) => finding.proof_valid).length],
    ["CMDB", cc?.cmdb?.summary?.assets || 0],
  ];
  const rows = [
    ...activeJobs.map((job) => ({ ...job, live: true, created_at: job.dispatched_at })),
    ...recentJobs.map((job) => ({ ...job, live: false })),
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <ActiveRunsPanel activeRuns={activeRuns} setTab={setTab} />
      <Card>
        <CardTitle sub="Schedule → ScanJob → BasJob → Kali → Evidence → Proof → Finding → CMDB">Fluxo integrado</CardTitle>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(8, minmax(0,1fr))", gap: 8 }}>
          {pipeline.map(([label, value], index) => (
            <div key={label} style={{ display: "flex", flexDirection: "column", gap: 6, padding: "10px 12px", background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 17, lineHeight: "21px", color: index >= 5 ? "#1f8a59" : "#4b73ff" }}>{value}</span>
              <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".5px" }}>{label}</span>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <CardTitle sub={`${rows.length} job(s) visíveis`}>Timeline técnica</CardTitle>
        <div style={{ display: "grid", gridTemplateColumns: "80px minmax(0,1fr) 130px 130px 110px 95px", gap: 12, padding: "0 12px 8px", borderBottom: `1px solid ${TV.border}` }}>
          {["Job", "Técnica / alvo", "Agente", "Schedule", "Status", "Prova"].map((h) => (
            <span key={h} style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".6px" }}>{h}</span>
          ))}
        </div>
        {rows.length === 0 && <Empty>Nenhum job BAS registrado ainda.</Empty>}
        <div style={{ maxHeight: 520, overflowY: "auto" }}>
          {rows.map((job) => {
            const agent = agentById[job.agent_id] || {};
            const schedule = scheduleById[job.schedule_id] || {};
            const proofColor = job.proof_valid ? "#1f8a59" : job.proof_status === "insufficient_evidence" ? "#d4a500" : TV.muted;
            return (
              <div key={`${job.live ? "active" : "recent"}-${job.id}`} style={{ display: "grid", gridTemplateColumns: "80px minmax(0,1fr) 130px 130px 110px 95px", gap: 12, alignItems: "center", padding: "10px 12px", borderBottom: `1px solid ${TV.border}` }}>
                <span style={{ fontWeight: 700, fontSize: 11.5, lineHeight: "15px", color: job.live ? "#4b73ff" : TV.text, fontFamily: "var(--font-mono,monospace)" }}>#{job.id}</span>
                <span style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                  <span style={{ fontWeight: 700, fontSize: 11.5, lineHeight: "15px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{job.technique_key}</span>
                  <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", color: TV.label, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{job.target || "sem alvo"} · {formatDateTime(job.created_at || job.dispatched_at)}</span>
                  {job.last_error && <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: "#d64545", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{job.last_error}</span>}
                </span>
                <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "15px", color: TV.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{agent.label || agent.hostname || `#${job.agent_id || "—"}`}</span>
                <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "15px", color: TV.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{schedule.name || job.schedule_id || "—"}</span>
                <Pill color={job.status === "completed" ? "#1f8a59" : job.status === "failed" ? "#d64545" : job.live ? "#4b73ff" : TV.muted}>{job.status}</Pill>
                <Pill color={proofColor}>{job.proof_valid ? "validada" : job.proof_status || "missing"}</Pill>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}

function Legend({ color, label }) {
  return (
    <span style={{ display: "flex", alignItems: "center", gap: 6, fontWeight: 400, fontSize: 11, lineHeight: "14px", color: TV.muted }}>
      <span style={{ width: 9, height: 9, borderRadius: 3, background: color }} />{label}
    </span>
  );
}

function MitreHeatmap({ rows }) {
  const byCategory = useMemo(() => {
    const map = {};
    for (const r of rows) {
      map[r.category] = map[r.category] || [];
      map[r.category].push(r);
    }
    return Object.entries(map);
  }, [rows]);
  if (byCategory.length === 0) return <Empty>Nenhuma técnica catalogada.</Empty>;
  return (
    <div style={{ display: "grid", gridTemplateColumns: `repeat(${Math.min(byCategory.length, 7)}, minmax(0,1fr))`, gap: 10, overflowX: "auto" }}>
      {byCategory.map(([category, cells]) => (
        <div key={category} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.text, height: 26 }}>{category}</span>
          {cells.map((c) => (
            <div key={c.mitre_id} title={`${c.mitre_id} — ${c.display_name}: ${c.outcome}`} style={{
              height: 24, borderRadius: 4, background: OUTCOME_COLOR[c.outcome], border: `1px solid ${TV.border}`,
              display: "flex", alignItems: "center", padding: "0 6px", overflow: "hidden",
            }}>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: c.outcome === "not_tested" ? TV.muted : "#0b0e12", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.mitre_id}</span>
            </div>
          ))}
          <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: TV.label }}>{cells.filter((c) => c.outcome !== "not_tested").length}/{cells.length} testadas</span>
        </div>
      ))}
    </div>
  );
}

// ── Implantação & agendamento ────────────────────────────────────────────

function DeployTab({ isAdmin, agents, techniques, chains, schedules, reload }) {
  const emptyForm = {
    name: "", agent_id: "", target_hint: "", technique_keys: [], chain_key: null,
    frequency: "daily", run_time: "00:00", day_of_week: "monday", day_of_month: 1,
    max_authorized_risk_tier: "safe", authorization_attested: false,
  };
  const [form, setForm] = useState(emptyForm);
  const [editingId, setEditingId] = useState(null);
  const [targetError, setTargetError] = useState("");

  const [runs, setRuns] = useState({}); // schedule_id -> { scanJobId, status, currentStep, missionProgress }
  const pollTimers = useRef({}); // schedule_id -> interval id

  useEffect(() => () => { Object.values(pollTimers.current).forEach(clearInterval); }, []);

  const pollRun = useCallback((scheduleId, scanJobId) => {
    clearInterval(pollTimers.current[scheduleId]);
    const tick = async () => {
      try {
        const { data } = await client.get(`/api/scans/${scanJobId}/status`);
        setRuns((prev) => ({
          ...prev,
          [scheduleId]: { scanJobId, status: data.status, currentStep: data.current_step, missionProgress: data.mission_progress },
        }));
        if (RUN_TERMINAL_STATUSES.has(String(data.status || "").toLowerCase())) {
          clearInterval(pollTimers.current[scheduleId]);
          delete pollTimers.current[scheduleId];
          await reload();
        }
      } catch {
        clearInterval(pollTimers.current[scheduleId]);
        delete pollTimers.current[scheduleId];
      }
    };
    tick();
    pollTimers.current[scheduleId] = setInterval(tick, RUN_POLL_INTERVAL_MS);
  }, [reload]);

  // Rehydrates "still running" on mount/return -- runNow()'s polling only
  // lives in this component's in-memory state, so navigating away from the
  // BAS screen and back (or a plain reload) during a run made the schedule
  // row look stopped even though it was still actively dispatching
  // (2026-08-28). last_scan_status comes from the shadow ScanJob itself,
  // which stays "running" for the run's whole duration -- unlike the last
  // individual BasJob's status, which flips per host/technique.
  const rehydrated = useRef(new Set());
  useEffect(() => {
    for (const s of schedules) {
      if (!s.last_scan_job_id || rehydrated.current.has(s.last_scan_job_id)) continue;
      if (pollTimers.current[s.id]) continue;
      if (!RUN_TERMINAL_STATUSES.has(String(s.last_scan_status || "").toLowerCase())) {
        rehydrated.current.add(s.last_scan_job_id);
        pollRun(s.id, s.last_scan_job_id);
      }
    }
  }, [schedules, pollRun]);

  const [installConfig, setInstallConfig] = useState(null);
  const [newToken, setNewToken] = useState(null);
  const [tokenUsername, setTokenUsername] = useState("bas-agent");
  const [editingCallback, setEditingCallback] = useState(false);
  const [callbackHostInput, setCallbackHostInput] = useState("");
  const [callbackPortInput, setCallbackPortInput] = useState("");
  const [installHeartbeat, setInstallHeartbeat] = useState({ probing: false, reachable: [] });

  const loadInstallConfig = useCallback(async () => {
    const { data } = await client.get("/api/bas/install-config", { params: { browser_host: window.location.hostname } });
    setInstallConfig(data);
    return data;
  }, []);

  useEffect(() => {
    loadInstallConfig().catch(() => {});
  }, [loadInstallConfig]);

  const grouped = useMemo(() => {
    const byCategory = {};
    // port_service_scan is a mandatory CMDB pre-req now (always runs first,
    // against every target, regardless of what's picked below) -- not a
    // choice, so it's not offered as one. See bas_scheduler.execute_schedule_run.
    for (const t of techniques) {
      if (t.technique_key === "port_service_scan") continue;
      byCategory[t.category] = byCategory[t.category] || [];
      byCategory[t.category].push(t);
    }
    return byCategory;
  }, [techniques]);

  const techniqueSelectable = (t) => {
    if (!["available", "simulated"].includes(t.availability)) return false;
    if (RISK_TIER_ORDER[t.risk_tier] === 0) return true;
    return RISK_TIER_ORDER[t.risk_tier] <= RISK_TIER_ORDER[form.max_authorized_risk_tier] && form.authorization_attested;
  };
  const toggleTechnique = (key) => setForm((prev) => ({
    ...prev, technique_keys: prev.technique_keys.includes(key) ? prev.technique_keys.filter((k) => k !== key) : [...prev.technique_keys, key],
  }));

  const submit = async (e) => {
    e.preventDefault();
    setTargetError("");
    try {
      if (editingId) { await client.patch(`/api/bas/schedules/${editingId}`, form); toastSuccess("Agendamento BAS atualizado."); }
      else { await client.post("/api/bas/schedules", form); toastSuccess("Agendamento BAS criado."); }
      setForm(emptyForm); setEditingId(null);
      await reload();
    } catch (error) {
      const detail = error?.response?.data?.detail;
      const message = typeof detail === "string" ? detail : "Falha ao salvar agendamento BAS.";
      // This specific validation is about the "Alvo" field itself (a
      // selected technique needs an explicit URL/domain and target_hint is
      // blank) -- a toast alone disappears and isn't tied to the field that
      // caused it, so it's shown inline next to the field's description too.
      if (message.includes("target_hint")) setTargetError(message);
      toastError(message);
    }
  };
  const editRow = (row) => {
    setEditingId(row.id);
    setForm({
      name: row.name || "", agent_id: row.agent_id, target_hint: row.target_hint || "",
      technique_keys: row.technique_keys || [], chain_key: row.chain_key || null,
      frequency: row.frequency, run_time: row.run_time,
      day_of_week: row.day_of_week || "monday", day_of_month: row.day_of_month || 1,
      max_authorized_risk_tier: row.max_authorized_risk_tier, authorization_attested: row.authorization_attested,
    });
  };
  const deleteRow = async (id) => {
    if (!window.confirm("Excluir este teste? Isso também apaga o histórico de execuções e todos os achados que ele gerou.")) return;
    try { await client.delete(`/api/bas/schedules/${id}`); await reload(); toastSuccess("Agendamento removido."); }
    catch (error) { toastError(error?.response?.data?.detail || "Falha ao excluir agendamento."); }
  };
  const runNow = async (id) => {
    setRuns((prev) => ({ ...prev, [id]: { scanJobId: null, status: "starting", currentStep: "", missionProgress: 0 } }));
    try {
      const { data } = await client.post(`/api/bas/schedules/${id}/run-now`);
      if (data?.queued && data?.scan_job_id) {
        toastSuccess("Execução iniciada — acompanhe o progresso na lista.");
        pollRun(id, data.scan_job_id);
      } else {
        // Not queued: every technique was skipped up front (e.g. agent
        // network unknown) -- nothing is running, so there's no run to poll.
        setRuns((prev) => { const next = { ...prev }; delete next[id]; return next; });
        toastError(`Nenhuma técnica executada · ${(data?.skipped || []).length} pulada(s)`);
        await reload();
      }
    } catch (error) {
      setRuns((prev) => { const next = { ...prev }; delete next[id]; return next; });
      toastError(error?.response?.data?.detail?.message || "Falha ao executar agora.");
    }
  };

  const stopRun = async (id) => {
    try {
      await client.post(`/api/bas/schedules/${id}/stop`);
      toastSuccess("Interrompendo o teste…");
      // The backend flip is cooperative (the dispatch loop notices on its
      // next check, not instantly) -- keep polling instead of clearing
      // `runs` here, so the row stays on "executando…" until the in-flight
      // status genuinely reaches "stopped" and pollRun's own terminal check
      // takes it from there.
    } catch (error) {
      toastError(error?.response?.data?.detail || "Falha ao interromper o teste.");
    }
  };

  const continueRun = async (id) => {
    setRuns((prev) => ({ ...prev, [id]: { scanJobId: null, status: "starting", currentStep: "", missionProgress: 0 } }));
    try {
      const { data } = await client.post(`/api/bas/schedules/${id}/resume`);
      if (data?.queued && data?.scan_job_id) {
        toastSuccess("Retomando o que faltava do teste…");
        pollRun(id, data.scan_job_id);
      } else {
        setRuns((prev) => { const next = { ...prev }; delete next[id]; return next; });
        toastError(`Nada retomado · ${(data?.skipped || []).length} pulada(s)`);
        await reload();
      }
    } catch (error) {
      setRuns((prev) => { const next = { ...prev }; delete next[id]; return next; });
      toastError(error?.response?.data?.detail || "Falha ao continuar o teste.");
    }
  };

  const generateToken = async () => {
    try {
      const { data } = await client.post("/api/bas/enrollment-tokens", { username: tokenUsername, max_uses: 1 });
      setNewToken(data);
      toastSuccess("Token gerado — copie agora, não será mostrado de novo.");
    } catch (error) { toastError(error?.response?.data?.detail || "Falha ao gerar token."); }
  };
  const downloadAgent = async (os) => {
    try {
      const res = await client.get(`/api/bas/download/agent/${os}`, { responseType: "blob" });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url; a.download = os === "windows" ? "bas-agent.exe" : `bas-agent-${os}`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (error) { toastError(error?.response?.data?.detail || `Agente ${os} ainda não disponível.`); }
  };
  const copy = (value) => { if (navigator.clipboard) navigator.clipboard.writeText(String(value || "")); };
  const probeInstallHost = async (host, port) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    try {
      await fetch(`http://${host}:${port}/health`, { mode: "no-cors", cache: "no-store", signal: controller.signal });
      return true;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  };
  const runInstallHeartbeat = async (config = installConfig) => {
    if (!config) return [];
    const port = config.callback_port || "8001";
    const candidates = [
      ...(config.callback_host && config.callback_host !== "backend" ? [{ host: config.callback_host, port, source: "saved" }] : []),
      ...(config.host_candidates || []),
    ].filter((candidate, index, list) => candidate.host && list.findIndex((item) => item.host === candidate.host) === index);
    setInstallHeartbeat({ probing: true, reachable: [] });
    const results = [];
    for (const candidate of candidates) {
      if (candidate.confidence === "docker_only") continue;
      if (await probeInstallHost(candidate.host, candidate.port || port)) {
        results.push({ ...candidate, port: candidate.port || port });
      }
    }
    setInstallHeartbeat({ probing: false, reachable: results });
    return results;
  };
  useEffect(() => {
    if (!installConfig) return;
    runInstallHeartbeat(installConfig);
  }, [installConfig?.callback_host, installConfig?.callback_port]);
  const saveCallback = async (hostOverride, portOverride) => {
    try {
      const host = String(hostOverride ?? callbackHostInput).trim();
      const port = String(portOverride ?? callbackPortInput).trim();
      await client.put("/api/bas/install-config", { callback_host: host, callback_port: port });
      setEditingCallback(false);
      await loadInstallConfig();
      toastSuccess("IP/porta de instalação atualizados.");
    } catch (error) { toastError(error?.response?.data?.detail || "Falha ao salvar IP/porta."); }
  };

  const browserHost = window.location.hostname;
  const isAutoDetectedHost = installConfig?.callback_host === "backend";
  const effectiveHost = isAutoDetectedHost ? "" : (installConfig?.callback_host || "");
  const overrideLooksStale = isCallbackHostStale(installConfig, browserHost);
  const hostCandidates = installConfig?.host_candidates || [];
  const reachableInstallHosts = installHeartbeat.reachable || [];
  const heartbeatHost = reachableInstallHosts[0]?.host || "";
  const installHostForCommand = effectiveHost || heartbeatHost || "<IP_DA_PLATAFORMA>";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <section style={{ display: "grid", gridTemplateColumns: "minmax(0,1.4fr) minmax(0,1fr)", gap: 16 }}>
        <Card>
          <div>
            <span style={{ fontWeight: 700, fontSize: 15, lineHeight: "20px" }}>{editingId ? "Editar agendamento" : "Novo agendamento"}</span>
            <div style={{ fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.muted, marginTop: 2 }}>Selecione o agente, as técnicas e a recorrência</div>
          </div>
          <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <Field label="Nome do agendamento">
              <input className="ops-tv-select" style={fieldStyle} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="ex.: SMB & AD — varredura diária" />
            </Field>
            <Field label="Agente">
              <select className="ops-tv-select" style={fieldStyle} value={form.agent_id} onChange={(e) => setForm({ ...form, agent_id: Number(e.target.value) })}>
                <option value="">Selecione o agente</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.label || a.hostname || `agente #${a.id}`} ({a.status} · {a.kind === "real" ? "real" : "stub"}{a.local_network_cidr ? ` · ${a.local_network_cidr}` : ""})
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Alvo (host/IP, CIDR, URL ou domínio)">
              <textarea className="ops-tv-select" rows={2} style={{ ...fieldStyle, resize: "vertical", ...(targetError ? { borderColor: "#d64545" } : {}) }} value={form.target_hint}
                onChange={(e) => { setForm({ ...form, target_hint: e.target.value }); if (targetError) setTargetError(""); }}
                placeholder="Deixe em branco para usar a máscara de rede do agente. Nunca use 127.0.0.1." />
              {targetError && (
                <span style={{ fontWeight: 500, fontSize: 11, lineHeight: "15px", color: "#d64545" }}>{targetError}</span>
              )}
            </Field>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, padding: 14, border: `1px solid ${TV.border}`, borderRadius: 10, background: TV.surface2 }}>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".6px", textTransform: "uppercase" }}>Escopo — nível de risco autorizado</span>
              <div style={{ display: "flex", gap: 8 }}>
                {Object.entries(RISK_TIER_META).map(([key, meta]) => {
                  const active = form.max_authorized_risk_tier === key;
                  return (
                    <button key={key} type="button" onClick={() => setForm({ ...form, max_authorized_risk_tier: key })} style={{
                      flex: 1, cursor: "pointer", textAlign: "left", borderRadius: 8, padding: "10px 12px",
                      border: `1px solid ${active ? meta.color : TV.border}`, background: active ? `${meta.color}22` : "transparent", color: active ? meta.color : TV.muted,
                    }}>
                      <div style={{ fontWeight: 700, fontSize: 12, lineHeight: "16px" }}>{meta.label}</div>
                      <div style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", opacity: .85, marginTop: 2 }}>{meta.desc}</div>
                    </button>
                  );
                })}
              </div>
              {form.max_authorized_risk_tier !== "safe" && (
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.text, marginTop: 4 }}>
                  <input type="checkbox" checked={form.authorization_attested} onChange={(e) => setForm({ ...form, authorization_attested: e.target.checked })} />
                  Atesto autorização explícita para rodar técnicas deste nível de risco
                </label>
              )}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".6px", textTransform: "uppercase" }}>Técnicas por categoria</span>
              <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "15px", color: TV.label }}>
                Port &amp; Service Scanning roda sempre primeiro, automaticamente, como pré-requisito (CMDB) — outras técnicas que exigem uma porta específica (SMB, LDAP, etc.) só rodam nos hosts em que ela apareceu aberta.
              </span>
              <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 280, overflowY: "auto", opacity: form.chain_key ? .45 : 1, pointerEvents: form.chain_key ? "none" : "auto" }}>
                {Object.entries(grouped).map(([category, items]) => (
                  <div key={category} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <span style={{ fontWeight: 700, fontSize: 10.5, lineHeight: "14px", color: TV.muted, letterSpacing: ".6px", textTransform: "uppercase" }}>{category}</span>
                    {items.map((t) => {
                      const selectable = techniqueSelectable(t);
                      return (
                        <label key={t.technique_key} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: 8, border: `1px solid ${TV.border}`, opacity: selectable ? 1 : .5 }}>
                          <input type="checkbox" disabled={!selectable} checked={form.technique_keys.includes(t.technique_key)} onChange={() => toggleTechnique(t.technique_key)} />
                          <span style={{ flex: 1, fontWeight: 400, fontSize: 12.5, lineHeight: "16px" }}>{t.display_name}</span>
                          <Pill color={RISK_TIER_META[t.risk_tier]?.color || TV.muted}>{t.risk_tier}</Pill>
                        </label>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".6px", textTransform: "uppercase" }}>Chain (opcional)</span>
              <select className="ops-tv-select" style={fieldStyle} value={form.chain_key || ""} onChange={(e) => {
                const chainKey = e.target.value || null;
                const chain = chains.find((c) => c.chain_key === chainKey);
                setForm((prev) => ({ ...prev, chain_key: chainKey, technique_keys: chain ? chain.technique_keys : prev.technique_keys }));
              }}>
                <option value="">Nenhuma — selecionar técnicas manualmente</option>
                {chains.map((c) => <option key={c.chain_key} value={c.chain_key}>{c.display_name}</option>)}
              </select>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <select className="ops-tv-select" style={fieldStyle} value={form.frequency} onChange={(e) => setForm({ ...form, frequency: e.target.value })}>
                {Object.entries(FREQ_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
              </select>
              <input className="ops-tv-select" type="time" style={fieldStyle} value={form.run_time} onChange={(e) => setForm({ ...form, run_time: e.target.value })} />
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <button className="btn btn-primary" type="submit" disabled={!form.agent_id || form.technique_keys.length === 0}>
                {editingId ? "Salvar edição" : "Criar agendamento"}
              </button>
              {editingId && <button type="button" className="btn" onClick={() => { setEditingId(null); setForm(emptyForm); }} style={{ background: "transparent", border: `1px solid ${TV.border}`, color: TV.text }}>Cancelar</button>}
            </div>
          </form>
        </Card>

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <Card>
            <CardTitle sub={`${agents.length} agente(s)`}>Agentes instalados</CardTitle>
            {agents.map((a) => (
              <div key={a.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: TV.surface2, border: `1px solid ${TV.border}`, borderRadius: 8, padding: "9px 12px" }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                  <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px" }}>{a.label || a.hostname}</span>
                  <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", color: TV.label }}>{a.os} · {a.local_network_cidr || "sem rede"}</span>
                </div>
                <span style={{ fontWeight: 600, fontSize: 10.5, lineHeight: "14px" }}>{a.status}</span>
              </div>
            ))}
            <div style={{ marginTop: 6, paddingTop: 12, borderTop: `1px solid ${TV.border}`, display: "flex", flexDirection: "column", gap: 8 }}>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".6px", textTransform: "uppercase" }}>Implantar novo agente</span>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button className="btn" onClick={() => downloadAgent("windows")} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, color: TV.text }}>Windows</button>
                <button className="btn" onClick={() => downloadAgent("linux-amd64")} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, color: TV.text }}>Linux amd64</button>
                <button className="btn" onClick={() => downloadAgent("linux-arm64")} style={{ background: TV.surface2, border: `1px solid ${TV.border}`, color: TV.text }}>Linux arm64</button>
              </div>
              {installConfig && (
                <div style={{ fontWeight: 400, fontSize: 11, lineHeight: "16px", color: TV.muted }}>
                  {overrideLooksStale && isAdmin && (
                    <div style={{ marginBottom: 6, color: "#fe7b02" }}>
                      IP salvo diferente do usado agora ({browserHost}).{" "}
                      <button className="btn" style={{ padding: "2px 8px" }} onClick={() => saveCallback(browserHost, installConfig.callback_port || "")}>Salvar {browserHost}</button>
                    </div>
                  )}
                  {isAutoDetectedHost && (
                    <div style={{ marginBottom: 6, color: "#fe7b02" }}>
                      IP externo do backend ainda não foi salvo. A Central vai testar `/health` na porta {installConfig.callback_port} e usar o candidato que responder.
                    </div>
                  )}
                  {!editingCallback ? (
                    <>
                      IP salvo: <span style={{ cursor: effectiveHost ? "pointer" : "default", fontFamily: "var(--font-mono,monospace)", color: effectiveHost ? TV.text : "#fe7b02" }} onClick={() => effectiveHost && copy(effectiveHost)}>{effectiveHost || "não configurado"}</span> · porta:{" "}
                      <span style={{ cursor: "pointer", fontFamily: "var(--font-mono,monospace)" }} onClick={() => copy(installConfig.callback_port)}>{installConfig.callback_port}</span>
                      {isAdmin && <button className="btn" style={{ marginLeft: 8, padding: "2px 8px" }} onClick={() => { setCallbackHostInput(effectiveHost); setCallbackPortInput(installConfig.callback_port || ""); setEditingCallback(true); }}>Editar</button>}
                      <button className="btn" style={{ marginLeft: 6, padding: "2px 8px" }} onClick={() => runInstallHeartbeat(installConfig, false)} disabled={installHeartbeat.probing}>
                        {installHeartbeat.probing ? "testando..." : "Heartbeat"}
                      </button>
                      {reachableInstallHosts.length > 0 && (
                        <div style={{ marginTop: 6, color: "#1f8a59" }}>
                          heartbeat OK: {reachableInstallHosts.map((candidate) => `${candidate.host}:${candidate.port}`).join(", ")}
                        </div>
                      )}
                      {hostCandidates.length > 0 && (
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 7 }}>
                          {hostCandidates.map((candidate) => {
                            const heartbeatOk = reachableInstallHosts.some((item) => item.host === candidate.host);
                            const disabled = candidate.confidence === "docker_only" || (!heartbeatOk && candidate.reachable_from_backend === false);
                            return (
                              <button key={`${candidate.source}-${candidate.host}`} className="btn" disabled={disabled} style={{ padding: "2px 8px", background: TV.surface2, border: `1px solid ${TV.border}`, color: heartbeatOk ? "#1f8a59" : candidate.reachable_from_backend === false ? "#d64545" : candidate.confidence === "docker_only" ? TV.label : TV.text, opacity: disabled ? .55 : 1 }} onClick={() => saveCallback(candidate.host, candidate.port)}>
                                {heartbeatOk ? "Salvar heartbeat" : candidate.reachable_from_backend === false ? "Indisponível" : candidate.confidence === "docker_only" ? "Docker" : "Salvar"} {candidate.host}:{candidate.port}
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </>
                  ) : (
                    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                      <input className="ops-tv-select" style={{ ...fieldStyle, maxWidth: 160 }} value={callbackHostInput} onChange={(e) => setCallbackHostInput(e.target.value)} />
                      <input className="ops-tv-select" style={{ ...fieldStyle, maxWidth: 90 }} value={callbackPortInput} onChange={(e) => setCallbackPortInput(e.target.value)} />
                      <button className="btn btn-primary" onClick={saveCallback}>Salvar</button>
                    </div>
                  )}
                </div>
              )}
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input className="ops-tv-select" style={{ ...fieldStyle, maxWidth: 180 }} value={tokenUsername} onChange={(e) => setTokenUsername(e.target.value)} placeholder="nome do agente" />
                <button className="btn btn-primary" onClick={generateToken}>Gerar token</button>
              </div>
              {newToken && (
                <div style={{ padding: "10px 12px", borderRadius: 8, border: "1px solid #fe7b02", background: "#fe7b0222", fontWeight: 400, fontSize: 11, lineHeight: "16px" }}>
                  {newToken.warning}
                  <div style={{ display: "flex", gap: 10, marginTop: 6, fontFamily: "var(--font-mono,monospace)" }}>
                    <span onClick={() => copy(newToken.username)} style={{ cursor: "pointer" }}>{newToken.username}</span>
                    <span onClick={() => copy(newToken.password)} style={{ cursor: "pointer" }}>{newToken.password}</span>
                    <span onClick={() => copy(newToken.code)} style={{ cursor: "pointer" }}>{newToken.code}</span>
                  </div>
                  <div style={{ marginTop: 6, color: TV.muted, fontFamily: "var(--font-mono,monospace)" }}>
                    Usuário={newToken.username} · Token={newToken.code} · IP={installHostForCommand} · Porta={installConfig?.callback_port || ""}
                  </div>
                  <div style={{ marginTop: 4, color: TV.label, fontFamily: "var(--font-mono,monospace)" }}>
                    primeiro: ./bas-agent-linux-arm64 · depois: ./bas-agent-linux-arm64 install
                  </div>
                </div>
              )}
            </div>
          </Card>
        </div>
      </section>

      <Card>
        <CardTitle sub={`${schedules.length} configurado(s)`}>Agendamentos</CardTitle>
        {schedules.length === 0 && <Empty>Nenhum agendamento BAS configurado.</Empty>}
        {schedules.map((s) => {
          const run = runs[s.id];
          const isActive = run && !RUN_TERMINAL_STATUSES.has(String(run.status || "").toLowerCase());
          return (
          <div key={s.id} style={{ display: "flex", flexDirection: "column", gap: 8, padding: 12, borderBottom: `1px solid ${TV.border}` }}>
            <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1.5fr) 110px 130px 130px 190px", gap: 12, alignItems: "center" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                <span style={{ fontWeight: 600, fontSize: 13, lineHeight: "16px" }}>{s.name || "sem nome"}</span>
                <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", color: TV.label }}>{(s.technique_keys || []).length} técnica(s) · {s.target_hint || "rede do agente"}</span>
              </div>
              <Pill color={RISK_TIER_META[s.max_authorized_risk_tier]?.color || TV.muted}>{s.max_authorized_risk_tier}</Pill>
              <span style={{ fontWeight: 400, fontSize: 11.5, lineHeight: "16px", color: TV.text }}>{FREQ_LABEL[s.frequency]} · {s.run_time}</span>
              <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "16px", color: isActive ? "#4b73ff" : s.last_scan_status === "stopped" ? "#fe7b02" : s.last_job_status === "completed" ? "#1f8a59" : s.last_job_status === "failed" ? "#d64545" : TV.muted }}>
                {isActive ? "executando…" : s.last_scan_status === "stopped" ? "interrompido" : s.last_job_status ? `último: ${s.last_job_status}` : "nunca executado"}
              </span>
              <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                <button className="btn btn-primary" style={{ padding: "6px 10px", fontSize: 12, opacity: isActive ? 0.6 : 1, cursor: isActive ? "default" : "pointer" }} disabled={isActive} onClick={() => runNow(s.id)}>
                  {isActive ? `Executando… ${run.missionProgress ?? 0}%` : "Executar agora"}
                </button>
                {isActive && (
                  <button className="btn" style={{ padding: "6px 10px", fontSize: 12, background: "transparent", border: "1px solid #d64545", color: "#d64545" }} onClick={() => stopRun(s.id)}>Parar</button>
                )}
                {!isActive && s.last_scan_status === "stopped" && (
                  <button className="btn" style={{ padding: "6px 10px", fontSize: 12, background: "transparent", border: "1px solid #fe7b02", color: "#fe7b02" }} onClick={() => continueRun(s.id)}>Continuar</button>
                )}
                <button className="btn" style={{ padding: "6px 10px", fontSize: 12, background: "transparent", border: `1px solid ${TV.border}`, color: TV.text }} onClick={() => editRow(s)}>Editar</button>
                <button className="btn" style={{ padding: "6px 10px", fontSize: 12, background: "transparent", border: "1px solid #d64545", color: "#d64545" }} onClick={() => deleteRow(s.id)}>Excluir</button>
              </div>
            </div>
            {isActive && (
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <Bar pct={run.missionProgress ?? 0} color="#4b73ff" />
                <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "14px", color: TV.label }}>{run.currentStep || "iniciando…"}</span>
              </div>
            )}
          </div>
          );
        })}
      </Card>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <span style={{ fontWeight: 600, fontSize: 11, lineHeight: "14px", color: TV.muted, letterSpacing: ".6px", textTransform: "uppercase" }}>{label}</span>
      {children}
    </div>
  );
}

// ── CMDB ──────────────────────────────────────────────────────────────────

function CmdbTab({ cc, segments, reload }) {
  const [filters, setFilters] = useState({ port: "", host: "", ip: "", os: "", status: "" });
  const [editingAsset, setEditingAsset] = useState(null);
  const [tagForm, setTagForm] = useState(null);

  const assets = cc?.cmdb?.cmdb_assets || [];
  const rows = useMemo(() => {
    const out = [];
    for (const a of assets) {
      if (filters.host && !a.hostname?.toLowerCase().includes(filters.host.toLowerCase())) continue;
      if (filters.ip && !a.ip.includes(filters.ip)) continue;
      if (filters.os && !a.os?.toLowerCase().includes(filters.os.toLowerCase())) continue;
      if (filters.status && assetStatus(a).label !== filters.status) continue;
      const services = (a.services || []).length ? a.services : (a.observations || []).map((obs) => ({
        name: obs.source || "observed",
        port: "—",
        protocol: "log",
        application: obs.source || "BAS evidence",
        version: obs.evidence || "",
      }));
      for (const svc of services) {
        if (filters.port && !(String(svc.port).includes(filters.port) || svc.name?.toLowerCase().includes(filters.port.toLowerCase()))) continue;
        out.push({ asset: a, svc });
      }
    }
    return out.sort((a, b) => Number(a.svc.port || 0) - Number(b.svc.port || 0) || a.asset.ip.localeCompare(b.asset.ip));
  }, [assets, filters]);

  const openTagForm = (asset) => {
    setEditingAsset(asset);
    setTagForm({
      match_type: asset.domain ? "domain" : "cidr",
      match_value: asset.domain || `${asset.ip.split(".").slice(0, 3).join(".")}.0/24`,
      business_unit: asset.business_unit || "",
      criticality: asset.criticality || "medium",
      controlsText: (asset.controls || []).map((c) => `${c.name}:${c.vendor}`).join(", "),
    });
  };
  const saveTag = async () => {
    const controls = tagForm.controlsText.split(",").map((s) => s.trim()).filter(Boolean).map((pair) => {
      const [name, vendor] = pair.split(":").map((s) => s.trim());
      return { name: name || pair, vendor: vendor || "" };
    });
    try {
      await client.post("/api/bas/network-segments", {
        match_type: tagForm.match_type, match_value: tagForm.match_value,
        business_unit: tagForm.business_unit, criticality: tagForm.criticality, controls,
      });
      toastSuccess("Segmento de rede classificado.");
      setEditingAsset(null); setTagForm(null);
      await reload();
    } catch (error) { toastError(error?.response?.data?.detail || "Falha ao salvar segmento de rede."); }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card>
        <CardTitle sub={`${new Set(rows.map((row) => row.asset.ip)).size} host(s) · ${rows.length} evidência(s) no filtro atual`}>CMDB · inventário de hosts e portas</CardTitle>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0,1fr)) auto", gap: 8 }}>
          <input className="ops-tv-select" style={fieldStyle} placeholder="Porta ou serviço" value={filters.port} onChange={(e) => setFilters({ ...filters, port: e.target.value })} />
          <input className="ops-tv-select" style={fieldStyle} placeholder="Hostname" value={filters.host} onChange={(e) => setFilters({ ...filters, host: e.target.value })} />
          <input className="ops-tv-select" style={fieldStyle} placeholder="IP" value={filters.ip} onChange={(e) => setFilters({ ...filters, ip: e.target.value })} />
          <select className="ops-tv-select" style={fieldStyle} value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
            <option value="">Todos os status</option>
            <option value="observado">Observado</option>
            <option value="alcançável">Alcançável</option>
            <option value="validado">Validado</option>
            <option value="sem evidência">Sem evidência</option>
          </select>
          <button className="btn" onClick={() => setFilters({ port: "", host: "", ip: "", os: "", status: "" })} style={{ background: "transparent", border: `1px solid ${TV.border}`, color: TV.text }}>Limpar</button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "110px minmax(0,1fr) 96px 90px 110px 110px 100px 80px", gap: 12, padding: "0 12px 8px", borderBottom: `1px solid ${TV.border}` }}>
          {["IP", "Hostname", "Status", "Porta", "Business unit", "Criticidade", "Risco", "Vulns"].map((h) => (
            <span key={h} style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".6px" }}>{h}</span>
          ))}
        </div>
        {rows.length === 0 && <Empty>Nenhum host com essa porta/serviço no CMDB atual.</Empty>}
        <div style={{ maxHeight: 620, overflowY: "auto" }}>
          {rows.map(({ asset, svc }, idx) => (
            <div key={`${asset.ip}:${svc.port}:${idx}`} style={{ display: "grid", gridTemplateColumns: "110px minmax(0,1fr) 96px 90px 110px 110px 100px 80px", gap: 12, alignItems: "center", padding: "10px 12px", borderBottom: `1px solid ${TV.border}` }}>
              <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", fontFamily: "var(--font-mono,monospace)" }}>{asset.ip}</span>
              <span style={{ fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{asset.hostname}</span>
              <Pill color={assetStatus(asset).color}>{assetStatus(asset).label}</Pill>
              <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", fontFamily: "var(--font-mono,monospace)" }}>{svc.port}/{svc.protocol}</span>
              <span style={{ fontWeight: 400, fontSize: 11.5, lineHeight: "16px", color: asset.classified ? TV.text : TV.label }}>{asset.business_unit || "—"}</span>
              <span style={{ fontWeight: 400, fontSize: 11.5, lineHeight: "16px", color: TV.text }}>{asset.criticality || "—"}</span>
              <Pill color={RISK_COLOR[asset.risk_level] || TV.muted}>{asset.risk_level}</Pill>
              <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "flex-end" }}>
                <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "16px", color: TV.muted }}>{asset.vulnerabilities?.length || 0}</span>
                <button className="btn" style={{ padding: "2px 8px", fontSize: 11, background: "transparent", border: `1px solid ${TV.border}`, color: TV.text }} onClick={() => openTagForm(asset)}>
                  {asset.classified ? "editar" : "classificar"}
                </button>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {editingAsset && tagForm && (
        <Card>
          <CardTitle sub={`Aplica-se a todo host que caia neste ${tagForm.match_type === "cidr" ? "CIDR" : "domínio"}, não só a ${editingAsset.ip}`}>
            Classificar segmento — {editingAsset.hostname || editingAsset.ip}
          </CardTitle>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <Field label="Tipo de correspondência">
              <select className="ops-tv-select" style={fieldStyle} value={tagForm.match_type} onChange={(e) => setTagForm({ ...tagForm, match_type: e.target.value })}>
                <option value="cidr">CIDR</option>
                <option value="domain">Domínio (AD)</option>
              </select>
            </Field>
            <Field label={tagForm.match_type === "cidr" ? "CIDR" : "Domínio"}>
              <input className="ops-tv-select" style={fieldStyle} value={tagForm.match_value} onChange={(e) => setTagForm({ ...tagForm, match_value: e.target.value })} />
            </Field>
            <Field label="Business unit">
              <input className="ops-tv-select" style={fieldStyle} value={tagForm.business_unit} onChange={(e) => setTagForm({ ...tagForm, business_unit: e.target.value })} placeholder="ex.: Identity core" />
            </Field>
            <Field label="Criticidade">
              <select className="ops-tv-select" style={fieldStyle} value={tagForm.criticality} onChange={(e) => setTagForm({ ...tagForm, criticality: e.target.value })}>
                <option value="low">Baixa</option><option value="medium">Média</option><option value="high">Alta</option><option value="critical">Crítica</option>
              </select>
            </Field>
            <div style={{ gridColumn: "1 / -1" }}>
              <Field label="Controles (nome:vendor, separados por vírgula)">
                <input className="ops-tv-select" style={fieldStyle} value={tagForm.controlsText} onChange={(e) => setTagForm({ ...tagForm, controlsText: e.target.value })} placeholder="EDR / XDR:CrowdStrike Falcon, WAF:Cloudflare" />
              </Field>
            </div>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <button className="btn btn-primary" onClick={saveTag}>Salvar classificação</button>
            <button className="btn" onClick={() => { setEditingAsset(null); setTagForm(null); }} style={{ background: "transparent", border: `1px solid ${TV.border}`, color: TV.text }}>Cancelar</button>
          </div>
        </Card>
      )}

      <Card>
        <CardTitle sub={`${segments.length} segmento(s) classificado(s)`}>Segmentos de rede classificados</CardTitle>
        {segments.length === 0 && <Empty>Nenhum segmento classificado ainda — use "classificar" numa linha do CMDB acima.</Empty>}
        {segments.map((s) => (
          <div key={s.id} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${TV.border}`, fontSize: 12 }}>
            <span>{s.match_type === "cidr" ? s.match_value : `domínio: ${s.match_value}`} · {s.business_unit || "sem BU"} · {s.criticality}</span>
            <span style={{ color: TV.muted }}>{(s.controls || []).map((c) => c.name).join(", ") || "sem controles"}</span>
          </div>
        ))}
      </Card>
    </div>
  );
}

// ── Vulnerabilidades ──────────────────────────────────────────────────────

function VulnsTab({ cc }) {
  const [sevFilter, setSevFilter] = useState("todas");
  const cmdbAssets = cc?.cmdb?.cmdb_assets || [];
  const findings = useMemo(() => {
    const rawFindings = cc?.findings || [];
    const assets = cmdbAssets.map((asset) => ({
      ip: String(asset.ip || "").trim(),
      hostname: String(asset.hostname || "").trim(),
      domain: String(asset.domain || "").trim(),
    })).filter((asset) => asset.ip || asset.hostname || asset.domain);
    return rawFindings.map((finding) => {
      if ((finding.affected_assets || []).length) return finding;
      const haystack = [
        finding.target,
        finding.title,
        finding.category,
        ...(finding.key_findings || []),
        finding.proof?.evidence,
        finding.proof?.target,
      ].filter(Boolean).join("\n").toLowerCase();
      const affectedAssets = assets.filter((asset) => {
        const keys = [asset.ip, asset.hostname, asset.domain].filter(Boolean).map((value) => value.toLowerCase());
        return keys.some((key) => haystack.includes(key));
      });
      return { ...finding, affected_assets: affectedAssets };
    });
  }, [cc?.findings, cmdbAssets]);
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => { if (sevCounts[f.severity] != null) sevCounts[f.severity]++; });
  const filtered = sevFilter === "todas" ? findings : findings.filter((f) => f.severity === sevFilter);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <section style={{ display: "flex", gap: 10, alignItems: "center" }}>
        {[["todas", "Todas", findings.length, TV.muted], ...Object.entries(sevCounts).map(([k, v]) => [k, k, v, SEVERITY_COLOR[k]])].map(([key, label, count, color]) => (
          <button key={key} onClick={() => setSevFilter(key)} style={{
            cursor: "pointer", display: "flex", alignItems: "center", gap: 7, fontWeight: 600, fontSize: 12, lineHeight: "16px", padding: "8px 14px", borderRadius: 999,
            border: `1px solid ${sevFilter === key ? color : TV.border}`, background: sevFilter === key ? `${color}22` : "transparent", color: sevFilter === key ? color : TV.muted,
          }}>
            <span style={{ width: 8, height: 8, borderRadius: 999, background: color }} />{label} {count}
          </button>
        ))}
        <span style={{ marginLeft: "auto", fontWeight: 400, fontSize: 12, lineHeight: "16px", color: TV.label }}>{filtered.length} achado(s) no filtro atual</span>
      </section>

      <Card>
        <CardTitle sub={`${cmdbAssets.length} ativo(s) derivados de evidência/logs no CMDB BAS`}>Achados · CVE &amp; CVSS</CardTitle>
        <div style={{ display: "grid", gridTemplateColumns: "88px minmax(0,1.3fr) minmax(0,0.9fr) 100px 60px 90px 130px", gap: 12, padding: "0 12px 8px", borderBottom: `1px solid ${TV.border}` }}>
          {["Severidade", "Achado", "Alvo", "CVE", "CVSS", "EPSS", "Exploit"].map((h) => (
            <span key={h} style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".6px" }}>{h}</span>
          ))}
        </div>
        {filtered.length === 0 && <Empty>Nenhum achado BAS neste filtro.</Empty>}
        {filtered.map((f) => (
          <div key={f.id} style={{ display: "grid", gridTemplateColumns: "88px minmax(0,1.3fr) minmax(0,0.9fr) 100px 60px 90px 130px", gap: 12, alignItems: "center", padding: "10px 12px", borderBottom: `1px solid ${TV.border}` }}>
            <Pill color={SEVERITY_COLOR[f.severity] || TV.muted}>{f.severity}</Pill>
            <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
              <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px" }}>{f.title}{f.simulated ? " (simulado)" : ""}</span>
              <span style={{ fontWeight: 400, fontSize: 10.5, lineHeight: "13px", color: TV.label }}>{f.category}</span>
            </div>
            <span style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
              <span style={{ fontWeight: 600, fontSize: 11.5, lineHeight: "16px", color: TV.text, fontFamily: "var(--font-mono,monospace)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.affected_assets?.map((asset) => asset.ip).join(", ") || f.target || "—"}</span>
              <span style={{ fontWeight: 400, fontSize: 10, lineHeight: "13px", color: TV.label, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.target || "sem alvo bruto"}</span>
            </span>
            <span style={{ fontWeight: 400, fontSize: 11.5, lineHeight: "16px", color: TV.text, fontFamily: "var(--font-mono,monospace)" }}>{f.cve || "n/a"}</span>
            <span style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", color: f.cvss >= 9 ? "#d64545" : f.cvss >= 7 ? "#fe7b02" : f.cvss >= 4 ? "#d4a500" : TV.muted }}>{f.cvss ?? "n/a"}</span>
            <span style={{ fontWeight: 400, fontSize: 11, lineHeight: "16px", color: TV.muted }}>{f.epss != null ? `${Math.round(f.epss * 100)}%` : "n/a"}</span>
            <span style={{ fontWeight: 600, fontSize: 10.5, lineHeight: "14px", color: f.exploit_available ? "#d64545" : f.exploit_available === false ? "#1f8a59" : TV.muted }}>
              {f.exploit_available == null ? "n/a" : f.exploit_available ? "público" : "nenhum conhecido"}
            </span>
          </div>
        ))}
      </Card>

      <Card>
        <CardTitle>Detalhes de exploração</CardTitle>
        {filtered.length === 0 && <Empty>Nenhum achado BAS neste filtro.</Empty>}
        {filtered.map((f) => (
          <div key={f.id} style={{ border: `1px solid ${TV.border}`, borderRadius: 10, padding: "12px 14px", display: "grid", gridTemplateColumns: "minmax(0,1.4fr) minmax(0,1fr)", gap: 14 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                <span style={{ fontWeight: 700, fontSize: 13, lineHeight: "16px" }}>{f.title}</span>
                <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: SEVERITY_COLOR[f.severity] }}>{f.severity}</span>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {(f.affected_assets || []).length ? (f.affected_assets || []).map((asset) => (
                  <span key={`${f.id}-${asset.ip}-${asset.hostname}`} style={{ fontWeight: 600, fontSize: 10.5, lineHeight: "14px", color: TV.text, border: `1px solid ${TV.border}`, borderRadius: 999, padding: "2px 7px", fontFamily: "var(--font-mono,monospace)" }}>
                    {asset.hostname && asset.hostname !== asset.ip ? `${asset.hostname} · ${asset.ip}` : asset.ip}
                  </span>
                )) : (
                  <span style={{ fontWeight: 600, fontSize: 10.5, lineHeight: "14px", color: TV.label, border: `1px solid ${TV.border}`, borderRadius: 999, padding: "2px 7px", fontFamily: "var(--font-mono,monospace)" }}>
                    alvo bruto · {f.target || "sem alvo"}
                  </span>
                )}
              </div>
              <div>
                <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".5px" }}>O que foi observado</span>
                {(f.key_findings || []).length > 0 ? (
                  <ul style={{ margin: "4px 0 0", paddingLeft: 16, display: "flex", flexDirection: "column", gap: 2 }}>
                    {f.key_findings.map((line, idx) => (
                      <li key={idx} style={{ fontWeight: 400, fontSize: 11, lineHeight: "15px", color: TV.text, fontFamily: "var(--font-mono,monospace)" }}>{line}</li>
                    ))}
                  </ul>
                ) : (
                  <div style={{ fontWeight: 400, fontSize: 11, lineHeight: "15px", color: TV.muted }}>Sem detalhes de evidência registrados para este achado.</div>
                )}
              </div>
              <div>
                <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".5px" }}>Recomendação</span>
                <div style={{ fontWeight: 400, fontSize: 11, lineHeight: "15px", color: TV.muted }}>{f.recommendation || "Sem recomendação registrada para este achado."}</div>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0,1fr))", gap: 8 }}>
              <MiniStat label="Verificação" value={f.proof_valid ? "Confirmado" : (f.proof_status || "pendente")} />
              <MiniStat label="Exploit público" value={f.exploit_available == null ? "não verificado" : f.exploit_available ? "sim" : "nenhum conhecido"} color={f.exploit_available ? "#d64545" : undefined} />
              <MiniStat label="CVE" value={f.cve || "n/a"} />
              <MiniStat label="EPSS" value={f.epss != null ? `${Math.round(f.epss * 100)}%` : "n/a"} />
            </div>
          </div>
        ))}
      </Card>
    </div>
  );
}

function MiniStat({ label, value, color }) {
  return (
    <div>
      <span style={{ fontWeight: 600, fontSize: 10, lineHeight: "13px", color: TV.label, textTransform: "uppercase", letterSpacing: ".5px" }}>{label}</span>
      <div style={{ fontWeight: 600, fontSize: 12, lineHeight: "16px", color: color || TV.text }}>{value}</div>
    </div>
  );
}
