import { useEffect, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

/**
 * Lê os design tokens reais (CSS custom properties em :root) uma única vez.
 * Mantém o tema como fonte única de verdade — nada de hex duplicado em JS.
 */
function useThemeColors() {
  const [colors, setColors] = useState(null);
  useEffect(() => {
    const root = getComputedStyle(document.documentElement);
    const v = (name, fallback) => (root.getPropertyValue(name) || fallback).trim();
    setColors({
      brand300: v("--brand-300", "#f3a6a6"),
      brand500: v("--brand-500", "#e96363"),
      brand700: v("--brand-700", "#a83232"),
      ink: v("--ink", "#1c1c1c"),
      inkSoft: v("--ink-soft", "#3d3d3d"),
      inkMuted: v("--ink-muted", "#6b6b6b"),
      line: v("--line", "#e5dcd5"),
      surface: v("--surface", "#ffffff"),
      critical: v("--sev-critical-solid", "#d64545"),
      high: v("--sev-high-solid", "#fe7b02"),
      medium: v("--sev-medium-solid", "#d4a500"),
      low: v("--sev-low-solid", "#229160"),
      info: v("--sev-info-solid", "#4b73ff"),
      gradeA: v("--grade-a", "#10b981"),
      gradeB: v("--grade-b", "#06b6d4"),
      gradeC: v("--grade-c", "#eab308"),
      gradeD: v("--grade-d", "#f97316"),
      gradeF: v("--grade-f", "#ef4444"),
    });
  }, []);
  return colors;
}

function gradeColor(c, score) {
  const s = Number(score || 0);
  if (s >= 90) return c.gradeA;
  if (s >= 80) return c.gradeB;
  if (s >= 70) return c.gradeC;
  if (s >= 60) return c.gradeD;
  return c.gradeF;
}

function EmptyViz({ title, hint }) {
  return (
    <div className="viz-empty">
      <span className="viz-empty-title">{title}</span>
      {hint && <span className="viz-empty-hint">{hint}</span>}
    </div>
  );
}

function VizHead({ eyebrow, title, value, tone }) {
  return (
    <div className="viz-head">
      <div>
        <div className="viz-eyebrow">{eyebrow}</div>
        <h3 className="viz-title">{title}</h3>
      </div>
      {value != null && <strong className={`viz-value ${tone || ""}`}>{value}</strong>}
    </div>
  );
}

function vizTooltip(colors) {
  return {
    contentStyle: {
      background: colors.surface,
      border: `1px solid ${colors.line}`,
      borderRadius: 10,
      boxShadow: "0 8px 24px rgba(28,28,28,0.10)",
      fontSize: 12,
      color: colors.ink,
      padding: "8px 12px",
    },
    labelStyle: { color: colors.inkMuted, fontSize: 11, marginBottom: 4 },
    itemStyle: { color: colors.ink, fontSize: 12, padding: 0 },
    cursor: { fill: "rgba(233,99,99,0.06)" },
  };
}

/* ──────────────────────────────────────────────────────────────────────────
 * Risk Score Timeline — evolução do rating contínuo ao longo dos scans
 * data: [{ scan_id, created_at, rating_score, open_findings }]
 * ────────────────────────────────────────────────────────────────────────── */
export function RiskTimelineChart({ data }) {
  const colors = useThemeColors();
  const series = useMemo(() => {
    const rows = Array.isArray(data) ? data : [];
    return rows
      .map((d) => ({
        score: Number(d?.rating_score ?? 0),
        open: Number(d?.open_findings ?? 0),
        scan: d?.scan_id != null ? `#${d.scan_id}` : "",
        label: d?.created_at
          ? new Date(d.created_at).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" })
          : (d?.scan_id != null ? `#${d.scan_id}` : ""),
      }))
      .filter((d) => Number.isFinite(d.score));
  }, [data]);

  if (!colors) return null;

  const latest = series.length ? series[series.length - 1].score : null;
  const first = series.length ? series[0].score : null;
  const delta = latest != null && first != null ? latest - first : 0;
  const tone = delta > 1 ? "t-green" : delta < -1 ? "t-red" : "t-amber";
  const deltaLabel = series.length > 1 ? `${delta >= 0 ? "+" : ""}${delta.toFixed(1)} pts` : "—";

  return (
    <div className="viz-card viz-span2">
      <VizHead
        eyebrow="Postura de risco · histórico"
        title="Evolução do rating de segurança"
        value={latest != null ? `${latest.toFixed(1)}` : "—"}
        tone={latest != null ? (latest >= 80 ? "t-green" : latest >= 60 ? "t-amber" : "t-red") : ""}
      />
      {series.length < 2 ? (
        <EmptyViz title="Histórico insuficiente" hint="São necessários ≥2 scans concluídos para traçar a curva." />
      ) : (
        <>
          <div className="viz-chart" style={{ height: 200 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={series} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={colors.brand500} stopOpacity={0.28} />
                    <stop offset="100%" stopColor={colors.brand500} stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 11, fill: colors.inkMuted }}
                  axisLine={{ stroke: colors.line }}
                  tickLine={false}
                />
                <YAxis
                  domain={[0, 100]}
                  ticks={[0, 25, 50, 75, 100]}
                  tick={{ fontSize: 11, fill: colors.inkMuted }}
                  axisLine={false}
                  tickLine={false}
                  width={36}
                />
                <Tooltip
                  {...vizTooltip(colors)}
                  formatter={(val, name) =>
                    name === "score" ? [`${Number(val).toFixed(1)}`, "Rating"] : [val, "Abertos"]
                  }
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke={colors.brand500}
                  strokeWidth={2.4}
                  fill="url(#riskGrad)"
                  dot={{ r: 2.5, fill: colors.brand500, strokeWidth: 0 }}
                  activeDot={{ r: 4.5, fill: colors.brand700 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="viz-foot">
            <span className={`viz-delta ${tone}`}>{deltaLabel}</span>
            <span className="viz-foot-hint">desde o primeiro scan · {series.length} pontos</span>
          </div>
        </>
      )}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 * Severity Donut — distribuição de achados por severidade
 * stats: { critical, high, medium, low } (+ info opcional via findings)
 * ────────────────────────────────────────────────────────────────────────── */
export function SeverityDonut({ stats, infoCount = 0 }) {
  const colors = useThemeColors();
  const slices = useMemo(() => {
    if (!colors) return [];
    return [
      { key: "critical", name: "Crítico", value: Number(stats?.critical || 0), fill: colors.critical },
      { key: "high", name: "Alto", value: Number(stats?.high || 0), fill: colors.high },
      { key: "medium", name: "Médio", value: Number(stats?.medium || 0), fill: colors.medium },
      { key: "low", name: "Baixo", value: Number(stats?.low || 0), fill: colors.low },
      { key: "info", name: "Info", value: Number(infoCount || 0), fill: colors.info },
    ].filter((s) => s.value > 0);
  }, [colors, stats, infoCount]);

  if (!colors) return null;
  const total = slices.reduce((acc, s) => acc + s.value, 0);

  return (
    <div className="viz-card">
      <VizHead eyebrow="Achados · severidade" title="Distribuição de risco" value={total || "0"} />
      {total === 0 ? (
        <EmptyViz title="Sem achados no escopo" hint="Nenhuma vulnerabilidade classificada ainda." />
      ) : (
        <div className="viz-donut-wrap">
          <div className="viz-chart" style={{ height: 168, flex: "0 0 168px" }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={slices}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={52}
                  outerRadius={78}
                  paddingAngle={2}
                  stroke="none"
                >
                  {slices.map((s) => (
                    <Cell key={s.key} fill={s.fill} />
                  ))}
                </Pie>
                <Tooltip {...vizTooltip(colors)} formatter={(val, name) => [val, name]} />
              </PieChart>
            </ResponsiveContainer>
            <div className="viz-donut-center">
              <strong>{total}</strong>
              <span>achados</span>
            </div>
          </div>
          <ul className="viz-legend">
            {slices.map((s) => (
              <li key={s.key}>
                <i style={{ background: s.fill }} />
                <span>{s.name}</span>
                <b>{s.value}</b>
                <em>{((s.value / total) * 100).toFixed(0)}%</em>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 * FAIR Gauge — exposição financeira + rating externo como medidor radial
 * score: 0-100 (rating), grade: A-F, ale: USD
 * ────────────────────────────────────────────────────────────────────────── */
export function FairGauge({ score, grade, ale }) {
  const colors = useThemeColors();
  if (!colors) return null;

  const s = Math.max(0, Math.min(100, Number(score || 0)));
  const fill = gradeColor(colors, s);
  const gaugeData = [{ name: "rating", value: s, fill }];
  const aleNum = Number(ale || 0);
  const aleLabel =
    aleNum >= 1_000_000
      ? `$${(aleNum / 1_000_000).toFixed(2)}M`
      : aleNum >= 1_000
        ? `$${(aleNum / 1_000).toFixed(1)}k`
        : `$${aleNum.toFixed(0)}`;

  return (
    <div className="viz-card">
      <VizHead eyebrow="FAIR · exposição quantificada" title="Rating externo & ALE" />
      <div className="viz-gauge-wrap">
        <div className="viz-chart" style={{ height: 168, flex: "0 0 168px", position: "relative" }}>
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              innerRadius="72%"
              outerRadius="100%"
              data={gaugeData}
              startAngle={220}
              endAngle={-40}
            >
              <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
              <RadialBar background={{ fill: colors.line }} dataKey="value" cornerRadius={10} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div className="viz-gauge-center">
            <strong style={{ color: fill }}>{grade || "—"}</strong>
            <span>{s.toFixed(0)}/100</span>
          </div>
        </div>
        <div className="viz-gauge-meta">
          <div className="viz-gauge-ale">
            <span>Perda anual esperada (ALE)</span>
            <strong>{aleLabel}</strong>
          </div>
          <p className="viz-foot-hint">Estimativa FAIR sobre achados abertos no escopo atual.</p>
        </div>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────────
 * Attack → Detection Funnel — funil ataque×detecção (BAS)
 * data: [{ label, value }]
 * ────────────────────────────────────────────────────────────────────────── */
export function AttackFunnel({ data }) {
  const colors = useThemeColors();
  const rows = useMemo(() => {
    const arr = Array.isArray(data) ? data : [];
    return arr.map((d) => {
      const label = String(d?.label || "");
      const isGap = /gap/i.test(label);
      return { label, value: Number(d?.value || 0), isGap };
    });
  }, [data]);

  if (!colors) return null;
  const hasData = rows.some((r) => r.value > 0);

  return (
    <div className="viz-card viz-span2">
      <VizHead eyebrow="BAS · ataque × detecção" title="Funil ofensivo até a telemetria do Blue Team" />
      {!hasData ? (
        <EmptyViz title="Sem dados de BAS" hint="O funil aparece após execução de técnicas adversárias." />
      ) : (
        <div className="viz-chart" style={{ height: Math.max(160, rows.length * 30) }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 28, left: 4, bottom: 4 }}>
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="label"
                width={150}
                tick={{ fontSize: 11, fill: colors.inkSoft }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip {...vizTooltip(colors)} formatter={(val) => [val, "Itens"]} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]} barSize={16}>
                {rows.map((r, i) => (
                  <Cell key={i} fill={r.isGap ? colors.critical : colors.brand500} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
