import { useEffect, useMemo, useState, useCallback } from "react";
import client from "../api/client";

const STATUS_META = {
  executed: { label: "Executada", tone: "var(--sev-low-text)", bg: "var(--sev-low-bg)", border: "var(--sev-low-border)" },
  partial_coverage: { label: "Parcial", tone: "var(--sev-high-text)", bg: "var(--sev-high-bg)", border: "var(--sev-high-border)" },
  attempted_failed: { label: "Falhou", tone: "var(--sev-critical-text)", bg: "var(--sev-critical-bg)", border: "var(--sev-critical-border)" },
  node_completed_tools_skipped: { label: "Tools puladas", tone: "var(--sev-info-text)", bg: "var(--sev-info-bg)", border: "var(--sev-info-border)" },
  no_tools_installed: { label: "Sem tool", tone: "var(--ink-muted)", bg: "var(--surface-soft)", border: "var(--line)" },
  node_completed_no_phase_tools: { label: "Sem tools", tone: "var(--sev-high-text)", bg: "var(--sev-high-bg)", border: "var(--sev-high-border)" },
  node_visited_no_tools: { label: "Visitada", tone: "var(--sev-info-text)", bg: "var(--sev-info-bg)", border: "var(--sev-info-border)" },
  pending: { label: "Pendente", tone: "var(--ink-muted)", bg: "var(--surface-soft)", border: "var(--line)" },
  skipped: { label: "Ignorada", tone: "var(--ink-muted)", bg: "var(--surface-soft)", border: "var(--line)" },
};

const DEFAULT_PHASES = [
  ["P01", "Subdomain enumeration"],
  ["P02", "Port and service discovery"],
  ["P03", "Endpoint discovery"],
  ["P04", "Parameter discovery"],
  ["P05", "Technology fingerprinting"],
  ["P06", "HTTP behavior mapping"],
  ["P07", "OSINT and exposure"],
  ["P08", "TLS and transport checks"],
  ["P09", "Authentication surface"],
  ["P10", "Access control probes"],
  ["P11", "Input validation"],
  ["P12", "Template and injection checks"],
  ["P13", "Header and routing abuse"],
  ["P14", "Known CVE checks"],
  ["P15", "Sensitive path discovery"],
  ["P16", "Cloud and object exposure"],
  ["P17", "API contract checks"],
  ["P18", "JavaScript and client secrets"],
  ["P19", "Method and verb tampering"],
  ["P20", "Business logic probes"],
  ["P21", "Leak and paste intelligence"],
  ["P22", "Evidence, scoring and report"],
].map(([id, title]) => ({ id, title, status: "pending", tools_used: [], tools_missing: [] }));

function statusMeta(status) {
  return STATUS_META[status] || STATUS_META.pending;
}

function pct(value) {
  const n = Number(value || 0);
  return Math.max(0, Math.min(100, n));
}

function compactTitle(title) {
  return String(title || "").replace(/\s+/g, " ").trim() || "-";
}

function PhaseCard({ phase, active }) {
  const meta = statusMeta(phase.status);
  const toolsUsed = [
    ...(phase.tools_success || []),
    ...(phase.tools_failed || []),
    ...(phase.tools_used || []),
  ].filter(Boolean);

  return (
    <div
      title={`${phase.id} · ${compactTitle(phase.title)} · ${meta.label}`}
      style={{
        minHeight: 94,
        border: `1px solid ${active ? "var(--brand-500)" : meta.border}`,
        borderLeft: `4px solid ${meta.tone}`,
        background: active ? "rgba(254,123,2,0.08)" : meta.bg,
        borderRadius: 8,
        padding: "9px 10px",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
        <strong className="mono-sm" style={{ color: meta.tone }}>{phase.id}</strong>
        <span className="mono-sm" style={{ color: meta.tone, fontWeight: 800 }}>{active ? "ativa" : meta.label}</span>
      </div>
      <div style={{ marginTop: 6, color: "var(--ink)", fontSize: 12, fontWeight: 800, lineHeight: 1.25 }}>
        {compactTitle(phase.title || phase.phase)}
      </div>
      <div className="mono-sm muted" style={{ marginTop: 7 }}>
        tools {toolsUsed.length}/{(phase.tools_expected || phase.tools || []).length || phase.tools_used?.length || 0}
      </div>
    </div>
  );
}

function KillChainStrip({ killChain }) {
  const phases = Array.isArray(killChain?.phases) ? killChain.phases : [];
  if (!phases.length) return null;

  return (
    <div style={{ marginTop: 14 }}>
      <div className="mono-sm muted" style={{ marginBottom: 8 }}>evolução ofensiva</div>
      <div style={{ display: "grid", gap: 6 }}>
        {phases.map((phase, idx) => {
          const tone = phase.completed ? "var(--sev-low-text)" : phase.visited ? "var(--brand-700)" : "var(--ink-muted)";
          return (
            <div key={phase.phase || idx} style={{ display: "grid", gridTemplateColumns: "24px 1fr auto", gap: 8, alignItems: "center" }}>
              <span className="mono-sm" style={{ color: tone, fontWeight: 900 }}>{String(idx + 1).padStart(2, "0")}</span>
              <span style={{ color: "var(--ink-soft)", fontSize: 12, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {phase.label || phase.phase}
              </span>
              <span className="mono-sm" style={{ color: tone }}>{phase.completed ? "done" : phase.visited ? "ativa" : "pendente"}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Phase breakdown status config (design system tokens) ─────────────────────
const PHASE_STATUS_CFG = {
  done:    { bar: "var(--sev-low-solid)",      text: "var(--sev-low-text)",      bg: "var(--sev-low-bg)",      border: "var(--sev-low-border)",      label: "Concluída"  },
  running: { bar: "var(--sev-high-solid,#fe7b02)", text: "var(--sev-high-text)", bg: "var(--sev-high-bg)",     border: "var(--sev-high-border)",     label: "Executando" },
  partial: { bar: "var(--sev-medium-solid)",   text: "var(--sev-medium-text)",   bg: "var(--sev-medium-bg)",   border: "var(--sev-medium-border)",   label: "Parcial"    },
  queued:  { bar: "var(--sev-info-solid)",     text: "var(--sev-info-text)",     bg: "var(--sev-info-bg)",     border: "var(--sev-info-border)",     label: "Na fila"    },
  paused:  { bar: "var(--sev-medium-solid)",   text: "var(--sev-medium-text)",   bg: "var(--sev-medium-bg)",   border: "var(--sev-medium-border)",   label: "Pausado"    },
  blocked: { bar: "var(--line-strong)",        text: "var(--ink-muted)",         bg: "var(--surface-soft)",    border: "var(--line)",                label: "Bloqueada"  },
  failed:  { bar: "var(--sev-critical-solid)", text: "var(--sev-critical-text)", bg: "var(--sev-critical-bg)", border: "var(--sev-critical-border)", label: "Falhou"     },
  empty:   { bar: "var(--line)",               text: "var(--ink-muted)",         bg: "var(--surface-soft)",    border: "var(--line-soft)",           label: "—"          },
};

function PhaseRow({ phase }) {
  const cfg = PHASE_STATUS_CFG[phase.status] || PHASE_STATUS_CFG.empty;
  const hasItems = phase.total > 0;
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "38px 1fr 34px 110px",
      alignItems: "center",
      gap: 8,
      padding: "4px 0",
      borderBottom: "1px solid var(--line-soft)",
    }}>
      {/* Phase pill */}
      <span className="mono-sm" style={{
        color: cfg.text, background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        borderRadius: 5, padding: "1px 4px",
        fontWeight: 800, fontSize: 9, textAlign: "center",
      }}>
        {phase.phase_id}
      </span>
      {/* Bar */}
      <div style={{ height: 6, borderRadius: 99, background: "var(--bg-muted)", overflow: "hidden", position: "relative" }}>
        {hasItems && (
          <div style={{
            position: "absolute", left: 0, top: 0, bottom: 0,
            width: `${phase.pct}%`, background: cfg.bar, borderRadius: 99,
            transition: "width 0.5s ease",
          }} />
        )}
      </div>
      {/* Pct */}
      <span className="mono-sm" style={{ color: hasItems ? cfg.text : "var(--ink-muted)", fontWeight: 700, textAlign: "right", fontSize: 10 }}>
        {hasItems ? `${phase.pct}%` : "—"}
      </span>
      {/* Chips */}
      <div style={{ display: "flex", gap: 3, justifyContent: "flex-end", flexWrap: "wrap" }}>
        {hasItems ? (
          <>
            <span className="mono-sm" style={{ color: "var(--sev-low-text)", fontSize: 9 }} title="concluídos com sucesso">{phase.completed}✓</span>
            {phase.skipped > 0 && <span style={{ fontSize: 9, fontWeight: 700, color: "var(--ink-muted)", background: "var(--surface-soft)", border: "1px solid var(--line)", padding: "0 4px", borderRadius: 4 }} title="ferramenta não-aplicável (n/a)">{phase.skipped}∅</span>}
            {phase.running > 0 && <span style={{ fontSize: 9, fontWeight: 700, color: "var(--sev-high-text)", background: "var(--sev-high-bg)", border: "1px solid var(--sev-high-border)", padding: "0 4px", borderRadius: 4 }}>{phase.running}▶</span>}
            {phase.queued  > 0 && <span style={{ fontSize: 9, fontWeight: 700, color: "var(--sev-info-text)", background: "var(--sev-info-bg)", border: "1px solid var(--sev-info-border)", padding: "0 4px", borderRadius: 4 }}>{phase.queued}q</span>}
            {phase.blocked > 0 && <span style={{ fontSize: 9, fontWeight: 700, color: "var(--ink-muted)", background: "var(--surface-soft)", border: "1px solid var(--line)", padding: "0 4px", borderRadius: 4 }}>{phase.blocked}⊘</span>}
            {((phase.failed||0)+(phase.timeout||0)) > 0 && <span style={{ fontSize: 9, fontWeight: 700, color: "var(--sev-critical-text)", background: "var(--sev-critical-bg)", border: "1px solid var(--sev-critical-border)", padding: "0 4px", borderRadius: 4 }} title="falha/timeout">{(phase.failed||0)+(phase.timeout||0)}✕</span>}
          </>
        ) : (
          <span className="mono-sm" style={{ color: "var(--line-strong)", fontSize: 9 }}>aguardando</span>
        )}
      </div>
    </div>
  );
}

export default function MissionProgress({ scan, scanStatus }) {
  const [phaseData, setPhaseData] = useState(null);
  const [breakdown, setBreakdown] = useState(null);
  const [error, setError] = useState("");

  const loadBreakdown = useCallback(async (id) => {
    if (!id) return;
    try {
      const { data } = await client.get(`/api/scans/${id}/phase-breakdown`, { _skipToast: true });
      setBreakdown(data);
    } catch { /* non-critical */ }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (!scan?.id) return;
      setError("");
      try {
        const { data } = await client.get(`/api/scans/${scan.id}/phase-monitor`, { _skipToast: true });
        if (!cancelled) setPhaseData(data);
      } catch {
        if (!cancelled) {
          setPhaseData(null);
          setError("Phase monitor indisponivel; exibindo contrato das 22 fases.");
        }
      }
      if (!cancelled) loadBreakdown(scan?.id);
    };
    load();
    const active = ["queued", "running", "retrying"].includes(String(scan?.status || "").toLowerCase());
    if (!active) return () => { cancelled = true; };
    const timer = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [scan?.id, scan?.status, loadBreakdown]);

  const view = useMemo(() => {
    const phases = Array.isArray(phaseData?.phases) && phaseData.phases.length ? phaseData.phases : DEFAULT_PHASES;
    const currentId = phaseData?.current_pentest_phase_id || phases.find((phase) => phase.status !== "executed")?.id || "";
    const completed = phases.filter((phase) => phase.status === "executed").length;
    const failed = phases.filter((phase) => ["attempted_failed", "partial_coverage"].includes(phase.status)).length;
    const toolsAttempted = phaseData?.metrics?.tools_attempted ?? 0;
    const toolsSuccess = phaseData?.metrics?.tools_success ?? 0;
    return { phases, currentId, completed, failed, toolsAttempted, toolsSuccess };
  }, [phaseData]);

  if (!scan) {
    return (
      <section className="panel p-6">
        <h3 className="text-sm font-semibold mb-4">Mapa operacional do scan</h3>
        <p className="text-xs text-slate-400 text-center py-4">Aguardando seleção de scan.</p>
      </section>
    );
  }

  const progress = pct(phaseData?.mission_progress ?? scanStatus?.mission_progress ?? scan?.mission_progress);
  const status = phaseData?.status || scanStatus?.status || scan.status;
  const isActive = ["queued", "running", "retrying"].includes(String(status).toLowerCase());

  // Elapsed + ETA — recomputed every second while the scan is running
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!isActive) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [isActive]);

  const fmtDuration = (ms) => {
    if (ms < 0) return "-";
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const ss = s % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2,"0")}m`;
    if (m > 0) return `${m}m ${String(ss).padStart(2,"0")}s`;
    return `${ss}s`;
  };

  const startMs = scan?.created_at ? new Date(scan.created_at).getTime() : null;
  const endMs = !isActive && scan?.updated_at ? new Date(scan.updated_at).getTime() : null;
  const elapsedMs = startMs ? (endMs || now) - startMs : null;
  const etaMs = (isActive && progress > 0 && progress < 100 && elapsedMs)
    ? (elapsedMs / progress) * (100 - progress)
    : null;

  return (
    <section className="panel p-6">
      {/* Header row: title + % */}
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start", marginBottom: 6 }}>
        <div>
          <h3 className="text-sm font-semibold">22 fases de evolução do teste</h3>
          <div className="mono-sm muted" style={{ marginTop: 4 }}>
            scan #{scan.id} · {status} · {view.completed}/22 fases executadas
          </div>
        </div>
        <div className="mono-sm" style={{ color: view.failed ? "var(--sev-critical-text)" : "var(--brand-700)", fontWeight: 900, fontSize: 22 }}>
          {progress}%
        </div>
      </div>

      {/* Progress bar */}
      <div style={{ height: 9, borderRadius: 99, overflow: "hidden", background: "var(--bg-muted)", marginBottom: 8 }}>
        <div
          style={{
            width: `${progress}%`,
            height: "100%",
            background: view.failed ? "var(--sev-critical-solid)" : "var(--brand-500)",
            transition: "width 0.4s ease",
          }}
        />
      </div>

      {/* Elapsed + ETA */}
      {elapsedMs !== null && (
        <div style={{ display: "flex", gap: 16, marginBottom: 12, fontSize: 11 }}>
          <span style={{ color: "var(--ink-muted)" }}>
            ⏱ percorrido: <strong style={{ color: "var(--ink)" }}>{fmtDuration(elapsedMs)}</strong>
          </span>
          {etaMs !== null && (
            <span style={{ color: "var(--ink-muted)" }}>
              ⏳ previsto: <strong style={{ color: "var(--brand-600)" }}>{fmtDuration(etaMs)}</strong>
            </span>
          )}
          {!isActive && (
            <span style={{ color: "var(--sev-low-text)", fontWeight: 700 }}>✓ concluído</span>
          )}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8, marginBottom: 14 }}>
        <div style={metricBox}>
          <div className="mono-sm muted">fase atual</div>
          <strong style={{ color: "var(--ink)" }}>{view.currentId || "-"}</strong>
        </div>
        <div style={metricBox}>
          <div className="mono-sm muted">tools</div>
          <strong style={{ color: "var(--ink)" }}>{view.toolsSuccess}/{view.toolsAttempted}</strong>
        </div>
        <div style={metricBox}>
          <div className="mono-sm muted">alertas</div>
          <strong style={{ color: view.failed ? "var(--sev-critical-text)" : "var(--sev-low-text)" }}>{view.failed}</strong>
        </div>
      </div>

      {error && <div className="mono-sm" style={{ color: "var(--sev-high-text)", marginBottom: 10 }}>{error}</div>}

      {/* Phase breakdown rows — P01-P22 com barras de progresso */}
      {breakdown?.phases?.length > 0 ? (
        <>
          <div style={{ borderTop: "1px solid var(--line-soft)", paddingTop: 10 }}>
            {breakdown.phases.map(phase => (
              <PhaseRow key={phase.phase_id} phase={phase} />
            ))}
          </div>

          {/* P21 strip */}
          {breakdown.summary?.p21_total > 0 && (
            <div style={{
              display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
              padding: "6px 10px", borderRadius: 8, marginTop: 10,
              background: "var(--sev-info-bg)", border: "1px solid var(--sev-info-border)",
            }}>
              <span className="mono-sm" style={{ color: "var(--sev-info-text)", fontWeight: 800 }}>🔬 P21 Sandbox</span>
              <span className="mono-sm" style={{ color: "var(--sev-low-text)" }}>✓ {breakdown.summary.p21_confirmed}</span>
              <span className="mono-sm" style={{ color: "var(--sev-critical-text)" }}>✕ {breakdown.summary.p21_refuted}</span>
              {breakdown.summary.p21_pending > 0 && (
                <span className="mono-sm" style={{ color: "var(--sev-high-text)" }}>⏳ {breakdown.summary.p21_pending}</span>
              )}
              <span className="mono-sm muted" style={{ marginLeft: "auto" }}>{breakdown.summary.p21_total} validações</span>
            </div>
          )}

          {/* Legend */}
          <div style={{ display: "flex", gap: 10, marginTop: 8, paddingTop: 8, borderTop: "1px solid var(--line-soft)", flexWrap: "wrap" }}>
            {[["done","Concluída"],["running","Executando"],["queued","Na fila"],["blocked","Bloqueada"],["failed","Falhou"]].map(([k, lbl]) => (
              <span key={k} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: PHASE_STATUS_CFG[k].bar, display: "inline-block" }} />
                <span className="mono-sm muted">{lbl}</span>
              </span>
            ))}
          </div>
        </>
      ) : (
        // Fallback: trabalho ainda não populado
        <div style={{ borderTop: "1px solid var(--line-soft)", paddingTop: 10 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(128px, 1fr))", gap: 8 }}>
            {view.phases.slice(0, 22).map((phase) => (
              <PhaseCard key={phase.id} phase={phase} active={phase.id === view.currentId} />
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

const metricBox = {
  border: "1px solid var(--line)",
  borderRadius: 8,
  padding: "8px 9px",
  background: "var(--surface-soft)",
};
