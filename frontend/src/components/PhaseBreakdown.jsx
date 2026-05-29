import { useEffect, useState, useCallback } from "react";
import client from "../api/client";

const STATUS_COLOR = {
  done:    { bar: "#22c55e", badge: "#16a34a", label: "Concluída" },
  running: { bar: "#f59e0b", badge: "#d97706", label: "Executando" },
  queued:  { bar: "#3b82f6", badge: "#2563eb", label: "Na fila" },
  blocked: { bar: "#475569", badge: "#334155", label: "Bloqueada" },
  failed:  { bar: "#ef4444", badge: "#dc2626", label: "Falhou" },
  partial: { bar: "#a78bfa", badge: "#7c3aed", label: "Parcial" },
  empty:   { bar: "#1e293b", badge: "#0f172a", label: "Não iniciada" },
};

function PhaseRow({ phase }) {
  const cfg = STATUS_COLOR[phase.status] || STATUS_COLOR.empty;
  const pct = phase.pct || 0;

  const flags = [];
  if (phase.running > 0) flags.push({ v: phase.running,  color: "#f59e0b", label: "run" });
  if (phase.queued  > 0) flags.push({ v: phase.queued,   color: "#3b82f6", label: "q" });
  if (phase.blocked > 0) flags.push({ v: phase.blocked,  color: "#475569", label: "blk" });
  if (phase.failed  > 0) flags.push({ v: phase.failed,   color: "#ef4444", label: "fail" });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 0" }}>
      {/* Phase ID pill */}
      <span style={{
        minWidth: 34, textAlign: "center",
        fontSize: 9, fontWeight: 700, letterSpacing: "0.04em",
        padding: "1px 4px", borderRadius: 4,
        background: cfg.badge + "33",
        color: cfg.bar,
        border: `1px solid ${cfg.bar}44`,
        flexShrink: 0,
      }}>
        {phase.phase_id}
      </span>

      {/* Progress bar */}
      <div style={{ flex: 1, position: "relative", height: 6, borderRadius: 3, background: "#1e293b", overflow: "hidden" }}>
        {phase.total > 0 && (
          <div style={{
            position: "absolute", left: 0, top: 0, bottom: 0,
            width: `${pct}%`,
            background: cfg.bar,
            borderRadius: 3,
            transition: "width 0.6s ease",
          }} />
        )}
        {/* Running pulse overlay */}
        {phase.running > 0 && (
          <div style={{
            position: "absolute", right: 0, top: 0, bottom: 0,
            width: `${Math.min(30, 100 - pct)}%`,
            background: `linear-gradient(90deg, transparent, ${cfg.bar}44)`,
            animation: "pulse 1.5s ease-in-out infinite",
          }} />
        )}
      </div>

      {/* Percentage */}
      <span style={{ fontSize: 9, fontWeight: 600, color: phase.total > 0 ? cfg.bar : "#334155", minWidth: 28, textAlign: "right", flexShrink: 0 }}>
        {phase.total > 0 ? `${pct}%` : "—"}
      </span>

      {/* Counts badges */}
      <div style={{ display: "flex", gap: 3, flexShrink: 0, minWidth: 80, justifyContent: "flex-end" }}>
        {phase.total > 0 ? (
          <>
            <span style={{ fontSize: 8, color: "#64748b" }}>{phase.completed}/{phase.total}</span>
            {flags.map(f => (
              <span key={f.label} style={{
                fontSize: 8, fontWeight: 700,
                color: f.color, background: f.color + "22",
                padding: "0 3px", borderRadius: 3,
              }}>{f.v}{f.label}</span>
            ))}
          </>
        ) : (
          <span style={{ fontSize: 8, color: "#334155" }}>não iniciada</span>
        )}
      </div>
    </div>
  );
}

export default function PhaseBreakdown({ scanId, scanStatus }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  const load = useCallback(async () => {
    if (!scanId) return;
    try {
      setLoading(true);
      const { data: d } = await client.get(`/api/scans/${scanId}/phase-breakdown`);
      setData(d);
    } catch {
      // silently ignore — not critical
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    load();
  }, [load]);

  // Auto-refresh while scan is running
  useEffect(() => {
    if (!scanId) return;
    const ACTIVE = ["queued", "running", "retrying"];
    if (!ACTIVE.includes(scanStatus)) return;
    const timer = setInterval(load, 8000);
    return () => clearInterval(timer);
  }, [scanId, scanStatus, load]);

  if (!data) return null;

  const { phases = [], summary = {} } = data;
  const activePhasesCount = phases.filter(p => p.status === "running").length;

  return (
    <section style={{
      background: "#0f172a",
      border: "1px solid #1e293b",
      borderRadius: 10,
      overflow: "hidden",
    }}>
      {/* Header */}
      <div
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "10px 14px", cursor: "pointer",
          borderBottom: collapsed ? "none" : "1px solid #1e293b",
        }}
        onClick={() => setCollapsed(v => !v)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: "#94a3b8", letterSpacing: "0.06em" }}>
            ⛓ KILL CHAIN — FASES P01-P22
          </span>
          {activePhasesCount > 0 && (
            <span style={{
              fontSize: 9, fontWeight: 700, color: "#f59e0b",
              background: "#f59e0b22", padding: "1px 6px", borderRadius: 10,
              animation: "pulse 2s ease-in-out infinite",
            }}>
              {activePhasesCount} ativa{activePhasesCount > 1 ? "s" : ""}
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {/* Mini stats */}
          <span style={{ fontSize: 9, color: "#22c55e" }}>✓ {summary.phases_done || 0}</span>
          <span style={{ fontSize: 9, color: "#475569" }}>⊘ {summary.phases_blocked || 0}</span>
          <span style={{ fontSize: 9, color: "#94a3b8" }}>{summary.total_done || 0}/{summary.total_items || 0} items</span>
          <span style={{ fontSize: 10, color: "#475569" }}>{collapsed ? "▼" : "▲"}</span>
        </div>
      </div>

      {!collapsed && (
        <div style={{ padding: "10px 14px" }}>

          {/* P21 PoC strip — only show when P21 has items */}
          {summary.p21_total > 0 && (
            <div style={{
              display: "flex", gap: 12, alignItems: "center",
              padding: "6px 10px", borderRadius: 6, marginBottom: 10,
              background: "#0d1117", border: "1px solid #1e3a5f",
              flexWrap: "wrap",
            }}>
              <span style={{ fontSize: 9, fontWeight: 700, color: "#58a6ff" }}>🔬 P21 Sandbox</span>
              <span style={{ fontSize: 9, color: "#22c55e" }}>✅ {summary.p21_confirmed} confirmados</span>
              <span style={{ fontSize: 9, color: "#ef4444" }}>❌ {summary.p21_refuted} refutados</span>
              {summary.p21_pending > 0 && (
                <span style={{ fontSize: 9, color: "#f59e0b" }}>⏳ {summary.p21_pending} pendentes</span>
              )}
              <span style={{ fontSize: 8, color: "#334155", marginLeft: "auto" }}>
                {summary.p21_total} validações
              </span>
            </div>
          )}

          {/* Phase rows */}
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            {phases.map(phase => (
              <PhaseRow key={phase.phase_id} phase={phase} />
            ))}
          </div>

          {/* Legend */}
          <div style={{ display: "flex", gap: 10, marginTop: 10, flexWrap: "wrap", borderTop: "1px solid #1e293b", paddingTop: 8 }}>
            {Object.entries(STATUS_COLOR).filter(([k]) => k !== "empty").map(([key, cfg]) => (
              <span key={key} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 8, color: "#64748b" }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: cfg.bar, display: "inline-block" }} />
                {cfg.label}
              </span>
            ))}
          </div>
        </div>
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </section>
  );
}
