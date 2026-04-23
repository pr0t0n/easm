/**
 * AttackEvolutionPage — Evolução Temporal de Ataques
 *
 * Mostra a acumulação de findings ao longo do tempo com:
 * - Gráfico de área acumulativa por severidade
 * - Gráfico de barras de novos findings por dia
 * - Filtros: janela de tempo, severidade, alvo
 * - Tabela de top alvos e top tipos de ataque
 * - Resumo por severidade com badges
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import client from "../api/client";

/* ─── paleta de severidade ──────────────────────────────────────────── */
const SEV = {
  critical: { color: "#dc2626", label: "Critical", bg: "#fee2e2" },
  high:     { color: "#f97316", label: "High",     bg: "#ffedd5" },
  medium:   { color: "#eab308", label: "Medium",   bg: "#fef9c3" },
  low:      { color: "#22c55e", label: "Low",      bg: "#dcfce7" },
  info:     { color: "#6b7280", label: "Info",     bg: "#f3f4f6" },
};
const SEV_KEYS = ["critical", "high", "medium", "low", "info"];

/* ─── utilitários de chart SVG ──────────────────────────────────────── */
const W = 780, H = 200, PAD = { top: 12, right: 16, bottom: 28, left: 44 };
const CW = W - PAD.left - PAD.right;
const CH = H - PAD.top - PAD.bottom;

function scaleX(i, total) {
  if (total <= 1) return PAD.left;
  return PAD.left + (i / (total - 1)) * CW;
}
function scaleY(v, maxV) {
  if (!maxV) return PAD.top + CH;
  return PAD.top + CH - (v / maxV) * CH;
}

/** Área acumulada (stacked) por severidade */
function AreaChart({ data, severities, title }) {
  if (!data || data.length === 0)
    return <EmptyChart title={title} />;

  const maxV = Math.max(...data.map((d) => SEV_KEYS.reduce((s, k) => s + (d[k] || 0), 0)), 1);
  const ticks = computeTicks(maxV);
  const n = data.length;

  // stacked areas — rendered bottom-up so critical is on top
  const stackedPaths = [];
  const baseline = data.map(() => PAD.top + CH);

  for (let si = SEV_KEYS.length - 1; si >= 0; si--) {
    const sev = SEV_KEYS[si];
    if (!severities.includes(sev)) continue;

    const tops = data.map((d, i) => {
      const accumulated = SEV_KEYS.slice(0, si + 1).reduce((s, k) => s + (d[k] || 0), 0);
      return scaleY(accumulated, maxV);
    });

    const pts = tops.map((y, i) => `${scaleX(i, n)},${y}`).join(" ");
    const bpts = [...baseline].reverse().map((y, i) => `${scaleX(n - 1 - i, n)},${y}`).join(" ");

    stackedPaths.push(
      <polygon
        key={sev}
        points={`${pts} ${bpts}`}
        fill={SEV[sev].color}
        fillOpacity={0.7}
      />,
    );

    for (let i = 0; i < n; i++) baseline[i] = tops[i];
  }

  const xLabels = pickEvenly(data.map((d) => d.date), 6);

  return (
    <div>
      <p style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 4 }}>{title}</p>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: H }}>
        {/* grid */}
        {ticks.map((t) => {
          const y = scaleY(t, maxV);
          return (
            <g key={t}>
              <line x1={PAD.left} x2={W - PAD.right} y1={y} y2={y} stroke="#e5e7eb" strokeWidth={1} />
              <text x={PAD.left - 4} y={y + 4} textAnchor="end" fontSize={9} fill="#9ca3af">{t}</text>
            </g>
          );
        })}
        {/* areas */}
        {stackedPaths}
        {/* x labels */}
        {xLabels.map(({ label, idx }) => (
          <text key={label} x={scaleX(idx, n)} y={H - 4} textAnchor="middle" fontSize={9} fill="#9ca3af">
            {label.slice(5)} {/* MM-DD */}
          </text>
        ))}
      </svg>
    </div>
  );
}

/** Barras diárias de novos findings */
function BarChart({ data, severities, title }) {
  if (!data || data.length === 0)
    return <EmptyChart title={title} />;

  const maxV = Math.max(...data.map((d) => SEV_KEYS.reduce((s, k) => s + (d[k] || 0), 0)), 1);
  const n = data.length;
  const barW = Math.max(1, CW / n - 1);
  const ticks = computeTicks(maxV);
  const xLabels = pickEvenly(data.map((d) => d.date), 6);

  return (
    <div>
      <p style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 4 }}>{title}</p>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: H }}>
        {ticks.map((t) => {
          const y = scaleY(t, maxV);
          return (
            <g key={t}>
              <line x1={PAD.left} x2={W - PAD.right} y1={y} y2={y} stroke="#e5e7eb" strokeWidth={1} />
              <text x={PAD.left - 4} y={y + 4} textAnchor="end" fontSize={9} fill="#9ca3af">{t}</text>
            </g>
          );
        })}
        {data.map((d, i) => {
          const x = PAD.left + (i / n) * CW;
          let stackY = PAD.top + CH;
          return (
            <g key={d.date}>
              {SEV_KEYS.slice().reverse().map((sev) => {
                if (!severities.includes(sev)) return null;
                const v = d[sev] || 0;
                if (!v) return null;
                const bh = (v / maxV) * CH;
                stackY -= bh;
                return (
                  <rect
                    key={sev}
                    x={x}
                    y={stackY}
                    width={barW}
                    height={bh}
                    fill={SEV[sev].color}
                    fillOpacity={0.85}
                  />
                );
              })}
            </g>
          );
        })}
        {xLabels.map(({ label, idx }) => (
          <text key={label} x={PAD.left + (idx / n) * CW + barW / 2} y={H - 4} textAnchor="middle" fontSize={9} fill="#9ca3af">
            {label.slice(5)}
          </text>
        ))}
      </svg>
    </div>
  );
}

function EmptyChart({ title }) {
  return (
    <div>
      <p style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 4 }}>{title}</p>
      <div style={{ height: H, display: "flex", alignItems: "center", justifyContent: "center", color: "#9ca3af", fontSize: 13, border: "1px dashed #e5e7eb", borderRadius: 8 }}>
        Sem dados para exibir
      </div>
    </div>
  );
}

function computeTicks(maxV) {
  if (!maxV) return [0];
  const step = Math.ceil(maxV / 4);
  return [0, step, step * 2, step * 3, maxV];
}

function pickEvenly(labels, count) {
  if (!labels.length) return [];
  if (labels.length <= count) return labels.map((l, idx) => ({ label: l, idx }));
  const result = [];
  const step = (labels.length - 1) / (count - 1);
  for (let i = 0; i < count; i++) {
    const idx = Math.round(i * step);
    result.push({ label: labels[idx], idx });
  }
  return result;
}

/* ─── componente principal ───────────────────────────────────────────── */
export default function AttackEvolutionPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  /* filtros */
  const [days, setDays] = useState(90);
  const [severity, setSeverity] = useState(""); // "" = todos
  const [targetInput, setTargetInput] = useState("");
  const [targetFilter, setTargetFilter] = useState(""); // aplicado
  const [activeSeverities, setActiveSeverities] = useState(new Set(SEV_KEYS));

  const fetchTimeline = useCallback(async (d, sev, tgt) => {
    setLoading(true);
    setError("");
    try {
      const params = { days: d };
      if (sev) params.severity = sev;
      if (tgt) params.target = tgt;
      const { data: res } = await client.get("/api/findings/timeline", { params });
      setData(res);
    } catch (err) {
      setError(err?.response?.data?.detail || "Erro ao carregar dados.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTimeline(days, severity, targetFilter);
  }, [days, severity, targetFilter, fetchTimeline]);

  const toggleSev = (sev) => {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) { if (next.size > 1) next.delete(sev); }
      else next.add(sev);
      return next;
    });
  };

  const activeSevList = SEV_KEYS.filter((s) => activeSeverities.has(s));

  const summary = data?.summary || {};
  const cumulative = data?.cumulative || [];
  const dailyNew = data?.daily_new || [];
  const byTarget = data?.by_target || [];
  const byType = data?.by_type || [];

  const maxCount = Math.max(...byTarget.map((t) => t.count), 1);
  const maxTypeCount = Math.max(...byType.map((t) => t.count), 1);

  return (
    <div style={{ padding: 16, display: "grid", gap: 16 }}>

      {/* ── filtros ─────────────────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 8,
          alignItems: "center",
          background: "#fff",
          border: "1px solid #d1d5db",
          borderRadius: 10,
          padding: "10px 14px",
        }}
      >
        <span style={{ fontSize: 13, fontWeight: 600, color: "#374151" }}>Janela:</span>
        {[30, 60, 90, 180, 365].map((d) => (
          <button
            key={d}
            type="button"
            onClick={() => setDays(d)}
            style={{
              padding: "4px 12px",
              borderRadius: 6,
              border: `1px solid ${days === d ? "#2563eb" : "#d1d5db"}`,
              background: days === d ? "#eff6ff" : "#f9fafb",
              color: days === d ? "#1d4ed8" : "#374151",
              fontSize: 12,
              fontWeight: days === d ? 600 : 400,
              cursor: "pointer",
            }}
          >
            {d}d
          </button>
        ))}

        <div style={{ width: 1, height: 20, background: "#e5e7eb" }} />

        <span style={{ fontSize: 13, fontWeight: 600, color: "#374151" }}>Severidade:</span>
        {SEV_KEYS.map((sev) => (
          <button
            key={sev}
            type="button"
            onClick={() => toggleSev(sev)}
            style={{
              padding: "3px 10px",
              borderRadius: 6,
              border: `1px solid ${activeSeverities.has(sev) ? SEV[sev].color : "#d1d5db"}`,
              background: activeSeverities.has(sev) ? SEV[sev].bg : "#f9fafb",
              color: activeSeverities.has(sev) ? SEV[sev].color : "#9ca3af",
              fontSize: 11,
              fontWeight: activeSeverities.has(sev) ? 700 : 400,
              cursor: "pointer",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            {SEV[sev].label}
          </button>
        ))}

        <div style={{ width: 1, height: 20, background: "#e5e7eb" }} />

        <input
          type="text"
          placeholder="Filtrar por alvo…"
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && setTargetFilter(targetInput.trim())}
          style={{ padding: "5px 10px", borderRadius: 6, border: "1px solid #d1d5db", fontSize: 12, minWidth: 180 }}
        />
        <button
          type="button"
          onClick={() => setTargetFilter(targetInput.trim())}
          style={{ padding: "5px 12px", borderRadius: 6, border: "1px solid #d1d5db", background: "#f9fafb", fontSize: 12, cursor: "pointer" }}
        >
          Aplicar
        </button>
        {targetFilter && (
          <button
            type="button"
            onClick={() => { setTargetInput(""); setTargetFilter(""); }}
            style={{ padding: "5px 10px", borderRadius: 6, border: "1px solid #fca5a5", background: "#fff5f5", color: "#dc2626", fontSize: 12, cursor: "pointer" }}
          >
            ✕ {targetFilter}
          </button>
        )}

        <div style={{ flex: 1 }} />
        {loading && <span style={{ fontSize: 12, color: "#6b7280" }}>Carregando…</span>}
        <button
          type="button"
          onClick={() => fetchTimeline(days, severity, targetFilter)}
          disabled={loading}
          style={{ padding: "5px 12px", borderRadius: 6, border: "1px solid #d1d5db", background: "#f9fafb", fontSize: 12, cursor: "pointer" }}
        >
          ↺ Atualizar
        </button>
      </div>

      {error && (
        <div style={{ padding: 12, background: "#fef2f2", border: "1px solid #fca5a5", borderRadius: 8, color: "#b91c1c", fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* ── badges de resumo ─────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {SEV_KEYS.map((sev) => (
          <div
            key={sev}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "8px 16px",
              background: SEV[sev].bg,
              border: `1px solid ${SEV[sev].color}30`,
              borderRadius: 10,
              minWidth: 110,
            }}
          >
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: SEV[sev].color }} />
            <div>
              <div style={{ fontSize: 18, fontWeight: 700, color: SEV[sev].color, lineHeight: 1 }}>
                {summary[sev] ?? 0}
              </div>
              <div style={{ fontSize: 10, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                {SEV[sev].label}
              </div>
            </div>
          </div>
        ))}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "8px 16px",
            background: "#f0f9ff",
            border: "1px solid #bae6fd",
            borderRadius: 10,
            minWidth: 110,
          }}
        >
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#0ea5e9" }} />
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, color: "#0369a1", lineHeight: 1 }}>
              {summary.total ?? 0}
            </div>
            <div style={{ fontSize: 10, color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.06em" }}>
              Total
            </div>
          </div>
        </div>
      </div>

      {/* ── gráficos ─────────────────────────────────────────────── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 16,
        }}
      >
        <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: 16 }}>
          <AreaChart
            data={cumulative}
            severities={activeSevList}
            title="Findings acumulados por severidade"
          />
          <Legend severities={activeSevList} />
        </div>
        <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: 16 }}>
          <BarChart
            data={dailyNew}
            severities={activeSevList}
            title="Novos findings por dia"
          />
          <Legend severities={activeSevList} />
        </div>
      </div>

      {/* ── top alvos + top tipos ────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

        {/* top alvos */}
        <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: 16 }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 10 }}>
            Top Alvos por Volume
          </p>
          {byTarget.length === 0 ? (
            <p style={{ fontSize: 12, color: "#9ca3af" }}>Sem dados.</p>
          ) : (
            <div style={{ display: "grid", gap: 6 }}>
              {byTarget.map(({ target, count }) => (
                <div key={target} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span
                    style={{ flex: 1, fontSize: 12, color: "#374151", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={target}
                  >
                    {target}
                  </span>
                  <div style={{ width: 100, background: "#f3f4f6", borderRadius: 4, height: 8, flexShrink: 0 }}>
                    <div
                      style={{
                        width: `${(count / maxCount) * 100}%`,
                        height: "100%",
                        background: "#2563eb",
                        borderRadius: 4,
                      }}
                    />
                  </div>
                  <span style={{ fontSize: 11, color: "#6b7280", width: 24, textAlign: "right", flexShrink: 0 }}>{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* top tipos */}
        <div style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: 16 }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: "#374151", marginBottom: 10 }}>
            Top Tipos de Ataque
          </p>
          {byType.length === 0 ? (
            <p style={{ fontSize: 12, color: "#9ca3af" }}>Sem dados.</p>
          ) : (
            <div style={{ display: "grid", gap: 6 }}>
              {byType.map(({ title, count }) => (
                <div key={title} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span
                    style={{ flex: 1, fontSize: 12, color: "#374151", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={title}
                  >
                    {title}
                  </span>
                  <div style={{ width: 100, background: "#f3f4f6", borderRadius: 4, height: 8, flexShrink: 0 }}>
                    <div
                      style={{
                        width: `${(count / maxTypeCount) * 100}%`,
                        height: "100%",
                        background: "#7c3aed",
                        borderRadius: 4,
                      }}
                    />
                  </div>
                  <span style={{ fontSize: 11, color: "#6b7280", width: 24, textAlign: "right", flexShrink: 0 }}>{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

    </div>
  );
}

function Legend({ severities }) {
  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 6 }}>
      {severities.map((sev) => (
        <span key={sev} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10, color: "#6b7280" }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: SEV[sev].color, display: "inline-block" }} />
          {SEV[sev].label}
        </span>
      ))}
    </div>
  );
}
