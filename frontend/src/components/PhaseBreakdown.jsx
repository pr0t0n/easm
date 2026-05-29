import { useEffect, useState, useCallback } from "react";
import client from "../api/client";

// Status → design system tokens
const STATUS_CFG = {
  done:    {
    bar:    "var(--sev-low-solid)",
    text:   "var(--sev-low-text)",
    bg:     "var(--sev-low-bg)",
    border: "var(--sev-low-border)",
    label:  "Concluída",
  },
  running: {
    bar:    "var(--sev-high-solid, #fe7b02)",
    text:   "var(--sev-high-text)",
    bg:     "var(--sev-high-bg)",
    border: "var(--sev-high-border)",
    label:  "Executando",
  },
  partial: {
    bar:    "var(--sev-medium-solid)",
    text:   "var(--sev-medium-text)",
    bg:     "var(--sev-medium-bg)",
    border: "var(--sev-medium-border)",
    label:  "Parcial",
  },
  queued: {
    bar:    "var(--sev-info-solid)",
    text:   "var(--sev-info-text)",
    bg:     "var(--sev-info-bg)",
    border: "var(--sev-info-border)",
    label:  "Na fila",
  },
  blocked: {
    bar:    "var(--line-strong)",
    text:   "var(--ink-muted)",
    bg:     "var(--surface-soft)",
    border: "var(--line)",
    label:  "Bloqueada",
  },
  failed: {
    bar:    "var(--sev-critical-solid)",
    text:   "var(--sev-critical-text)",
    bg:     "var(--sev-critical-bg)",
    border: "var(--sev-critical-border)",
    label:  "Falhou",
  },
  empty: {
    bar:    "var(--line)",
    text:   "var(--ink-muted)",
    bg:     "var(--surface-soft)",
    border: "var(--line-soft)",
    label:  "—",
  },
};

function PhaseRow({ phase }) {
  const cfg = STATUS_CFG[phase.status] || STATUS_CFG.empty;
  const pct = phase.pct || 0;
  const hasItems = phase.total > 0;

  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "36px 1fr 36px 120px",
      alignItems: "center",
      gap: 8,
      padding: "5px 0",
      borderBottom: "1px solid var(--line-soft)",
    }}>

      {/* Phase pill */}
      <span className="mono-sm" style={{
        color: cfg.text,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        borderRadius: 5,
        padding: "1px 4px",
        fontWeight: 800,
        fontSize: 9,
        textAlign: "center",
        letterSpacing: "0.03em",
      }}>
        {phase.phase_id}
      </span>

      {/* Progress bar track */}
      <div style={{
        height: 7,
        borderRadius: 99,
        background: "var(--bg-muted)",
        overflow: "hidden",
        position: "relative",
      }}>
        {hasItems && (
          <div style={{
            position: "absolute",
            left: 0, top: 0, bottom: 0,
            width: `${pct}%`,
            background: cfg.bar,
            borderRadius: 99,
            transition: "width 0.5s ease",
          }} />
        )}
      </div>

      {/* Percentage */}
      <span className="mono-sm" style={{
        color: hasItems ? cfg.text : "var(--ink-muted)",
        fontWeight: 700,
        textAlign: "right",
        fontSize: 10,
      }}>
        {hasItems ? `${pct}%` : "—"}
      </span>

      {/* Count chips */}
      <div style={{ display: "flex", gap: 3, justifyContent: "flex-end", flexWrap: "wrap" }}>
        {hasItems ? (
          <>
            <span className="mono-sm" style={{ color: "var(--ink-muted)", fontSize: 9 }}>
              {phase.completed}/{phase.total}
            </span>
            {phase.running > 0 && (
              <span style={{
                fontSize: 9, fontWeight: 700,
                color: "var(--sev-high-text)",
                background: "var(--sev-high-bg)",
                border: "1px solid var(--sev-high-border)",
                padding: "0 4px", borderRadius: 4,
              }}>{phase.running}▶</span>
            )}
            {phase.queued > 0 && phase.status !== "done" && (
              <span style={{
                fontSize: 9, fontWeight: 700,
                color: "var(--sev-info-text)",
                background: "var(--sev-info-bg)",
                border: "1px solid var(--sev-info-border)",
                padding: "0 4px", borderRadius: 4,
              }}>{phase.queued}q</span>
            )}
            {phase.blocked > 0 && (
              <span style={{
                fontSize: 9, fontWeight: 700,
                color: "var(--ink-muted)",
                background: "var(--surface-soft)",
                border: "1px solid var(--line)",
                padding: "0 4px", borderRadius: 4,
              }}>{phase.blocked}⊘</span>
            )}
            {phase.failed > 0 && (
              <span style={{
                fontSize: 9, fontWeight: 700,
                color: "var(--sev-critical-text)",
                background: "var(--sev-critical-bg)",
                border: "1px solid var(--sev-critical-border)",
                padding: "0 4px", borderRadius: 4,
              }}>{phase.failed}✕</span>
            )}
          </>
        ) : (
          <span className="mono-sm" style={{ color: "var(--line-strong)", fontSize: 9 }}>aguardando</span>
        )}
      </div>
    </div>
  );
}

export default function PhaseBreakdown({ scanId, scanStatus }) {
  const [data, setData]         = useState(null);
  const [collapsed, setCollapsed] = useState(false);

  const load = useCallback(async () => {
    if (!scanId) return;
    try {
      const { data: d } = await client.get(`/api/scans/${scanId}/phase-breakdown`, { _skipToast: true });
      setData(d);
    } catch { /* non-critical */ }
  }, [scanId]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!scanId) return;
    if (!["queued", "running", "retrying"].includes(String(scanStatus || "").toLowerCase())) return;
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, [scanId, scanStatus, load]);

  if (!data) return null;

  const { phases = [], summary = {} } = data;
  const running = phases.filter(p => p.status === "running").length;
  const phasesWithItems = phases.filter(p => p.total > 0);

  return (
    <section className="panel p-6">
      {/* Header */}
      <div
        style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", marginBottom: collapsed ? 0 : 14 }}
        onClick={() => setCollapsed(v => !v)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <h3 className="text-sm font-semibold">Kill Chain — Fases P01-P22</h3>
          {running > 0 && (
            <span style={{
              fontSize: 10, fontWeight: 700,
              color: "var(--sev-high-text)",
              background: "var(--sev-high-bg)",
              border: "1px solid var(--sev-high-border)",
              padding: "1px 7px", borderRadius: 99,
            }}>
              {running} ativa{running > 1 ? "s" : ""}
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="mono-sm" style={{ color: "var(--sev-low-text)" }}>
            ✓ {summary.phases_done || 0}
          </span>
          <span className="mono-sm" style={{ color: "var(--ink-muted)" }}>
            ⊘ {summary.phases_blocked || 0}
          </span>
          <span className="mono-sm muted">
            {summary.total_done || 0}/{summary.total_items || 0}
          </span>
          <span style={{ color: "var(--ink-muted)", fontSize: 12 }}>{collapsed ? "▼" : "▲"}</span>
        </div>
      </div>

      {!collapsed && (
        <>
          {/* P21 PoC strip — only when P21 has been used */}
          {summary.p21_total > 0 && (
            <div style={{
              display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
              padding: "7px 10px", borderRadius: 8, marginBottom: 12,
              background: "var(--sev-info-bg)",
              border: "1px solid var(--sev-info-border)",
            }}>
              <span className="mono-sm" style={{ color: "var(--sev-info-text)", fontWeight: 800 }}>
                🔬 P21 Sandbox PoC
              </span>
              <span className="mono-sm" style={{ color: "var(--sev-low-text)" }}>
                ✓ {summary.p21_confirmed} confirmados
              </span>
              <span className="mono-sm" style={{ color: "var(--sev-critical-text)" }}>
                ✕ {summary.p21_refuted} refutados
              </span>
              {summary.p21_pending > 0 && (
                <span className="mono-sm" style={{ color: "var(--sev-high-text)" }}>
                  ⏳ {summary.p21_pending} pendentes
                </span>
              )}
              <span className="mono-sm muted" style={{ marginLeft: "auto" }}>
                {summary.p21_total} validações
              </span>
            </div>
          )}

          {/* Phase rows — only phases that have work items, plus a preview of next blocked */}
          <div>
            {phasesWithItems.length === 0 ? (
              <p className="mono-sm muted text-center py-3">Work queue ainda não populada para este scan.</p>
            ) : (
              phases.map(phase => (
                <PhaseRow key={phase.phase_id} phase={phase} />
              ))
            )}
          </div>

          {/* Legend */}
          <div style={{
            display: "flex", gap: 12, marginTop: 10,
            paddingTop: 8, borderTop: "1px solid var(--line-soft)",
            flexWrap: "wrap",
          }}>
            {[
              ["done",    "Concluída"],
              ["running", "Executando"],
              ["queued",  "Na fila"],
              ["blocked", "Bloqueada"],
              ["failed",  "Falhou"],
            ].map(([key, label]) => {
              const cfg = STATUS_CFG[key];
              return (
                <span key={key} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <span style={{
                    width: 8, height: 8, borderRadius: 2,
                    background: cfg.bar, display: "inline-block", flexShrink: 0,
                  }} />
                  <span className="mono-sm muted">{label}</span>
                </span>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}
