import { useCallback, useEffect, useMemo, useState } from "react";
import client from "../api/client";

const SEV = {
  critical: { color: "var(--sev-critical-text)", bg: "var(--sev-critical-bg)", label: "Critical" },
  high: { color: "var(--sev-high-text)", bg: "var(--sev-high-bg)", label: "High" },
  medium: { color: "var(--sev-medium-text)", bg: "var(--sev-medium-bg)", label: "Medium" },
  low: { color: "var(--sev-low-text)", bg: "var(--sev-low-bg)", label: "Low" },
  info: { color: "var(--sev-info-text)", bg: "var(--sev-info-bg)", label: "Info" },
};
const SEV_KEYS = ["critical", "high", "medium", "low", "info"];
const PERSONAS = {
  executive: "Executivo",
  technical: "Técnico",
  compliance: "Compliance",
};

const PRESETS = [
  { id: "all", label: "Escopo Completo", severity: "", periodDays: "all" },
  { id: "critical", label: "Apenas Críticos", severity: "critical", periodDays: "30" },
  { id: "high", label: "Alta+ 30 dias", severity: "high", periodDays: "30" },
  { id: "last7", label: "Últimos 7 dias", severity: "", periodDays: "7" },
];

const colors = {
  ink: "var(--ink)",
  inkSoft: "var(--ink-soft)",
  inkMuted: "var(--ink-muted)",
  line: "var(--line)",
  lineStrong: "var(--line-strong)",
  surface: "var(--surface)",
  surfaceSoft: "var(--surface-soft)",
  bgMuted: "var(--bg-muted)",
  brand: "var(--brand-500)",
  brandDark: "var(--brand-700)",
};

const panelStyle = {
  background: colors.surface,
  border: `1px solid ${colors.line}`,
  borderRadius: 12,
  padding: 12,
  boxShadow: "var(--shadow-card)",
};

const controlStyle = {
  padding: "6px 10px",
  border: `1px solid ${colors.line}`,
  borderRadius: 8,
  fontSize: 12,
  background: colors.surface,
  color: colors.ink,
};

const softButton = {
  padding: "6px 10px",
  border: `1px solid ${colors.line}`,
  borderRadius: 999,
  background: colors.surface,
  color: colors.inkSoft,
  fontSize: 12,
  cursor: "pointer",
};

function fmtNum(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  return new Intl.NumberFormat("pt-BR").format(n);
}

function fmtDate(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "-";
  return dt.toLocaleString("pt-BR");
}

function sevBadge(sev) {
  const key = String(sev || "info").toLowerCase();
  const cfg = SEV[key] || SEV.info;
  return {
    color: cfg.color,
    background: cfg.bg,
    border: `1px solid ${cfg.color}40`,
    padding: "3px 8px",
    borderRadius: 999,
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: "0.03em",
    textTransform: "uppercase",
  };
}

function ScoreCard({ overview }) {
  const score = Number(overview?.score || 0);
  const color = score >= 80 ? "var(--sev-low-solid)" : score >= 60 ? "var(--sev-medium-solid)" : "var(--sev-critical-solid)";
  return (
    <div style={{ ...panelStyle, padding: 16 }}>
      <p style={{ fontSize: 12, color: colors.inkMuted, margin: 0 }}>Score geral de risco</p>
      <div style={{ display: "flex", alignItems: "end", gap: 8, marginTop: 4 }}>
        <span style={{ fontSize: 42, lineHeight: 1, fontWeight: 800, color }}>{fmtNum(score)}</span>
        <span style={{ fontSize: 13, color: colors.inkMuted, marginBottom: 6 }}>/ 100</span>
      </div>
      <div style={{ marginTop: 12, background: colors.bgMuted, height: 10, borderRadius: 99, overflow: "hidden" }}>
        <div style={{ width: `${Math.max(0, Math.min(100, score))}%`, height: "100%", background: color }} />
      </div>
      <div style={{ display: "grid", gap: 4, marginTop: 10, fontSize: 12, color: colors.inkSoft }}>
        <div>Total de vulnerabilidades: <strong>{fmtNum(overview?.total_vulnerabilities)}</strong></div>
        <div>Ocorrencias encontradas: <strong>{fmtNum(overview?.findings_total)}</strong></div>
        <div>Alvos afetados: <strong>{fmtNum(overview?.affected_targets)}</strong></div>
      </div>
    </div>
  );
}

function SeverityCard({ summary }) {
  return (
    <div style={{ ...panelStyle, padding: 16 }}>
      <p style={{ fontSize: 12, color: colors.inkMuted, margin: 0 }}>Vulnerabilidades por criticidade</p>
      <div style={{ display: "grid", gap: 8, marginTop: 12 }}>
        {SEV_KEYS.map((sev) => {
          const total = Number(summary?.[sev] || 0);
          const max = Math.max(...SEV_KEYS.map((k) => Number(summary?.[k] || 0)), 1);
          return (
            <div key={sev} style={{ display: "grid", gridTemplateColumns: "80px 1fr 44px", gap: 8, alignItems: "center" }}>
              <span style={{ fontSize: 11, color: SEV[sev].color, fontWeight: 700 }}>{SEV[sev].label}</span>
              <div style={{ background: colors.bgMuted, height: 8, borderRadius: 99 }}>
                <div style={{ width: `${(total / max) * 100}%`, height: "100%", borderRadius: 99, background: SEV[sev].color }} />
              </div>
              <span style={{ fontSize: 12, color: colors.inkSoft, textAlign: "right" }}>{fmtNum(total)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AgeCard({ age }) {
  return (
    <div style={{ ...panelStyle, padding: 16 }}>
      <p style={{ fontSize: 12, color: colors.inkMuted, margin: 0 }}>Age das vulnerabilidades</p>
      <div style={{ marginTop: 10, display: "grid", gap: 8, fontSize: 12, color: colors.inkSoft }}>
        <div>
          <strong>Conhecida no ambiente</strong>
          <div>Media: {fmtNum(age?.known_in_environment_avg_days)} dias</div>
          <div>Maximo: {fmtNum(age?.known_in_environment_max_days)} dias</div>
        </div>
        <div>
          <strong>Existencia no mercado (publicacao CVE)</strong>
          <div>Media: {fmtNum(age?.known_in_market_avg_days)} dias</div>
          <div>Maximo: {fmtNum(age?.known_in_market_max_days)} dias</div>
        </div>
      </div>
    </div>
  );
}

function RemediationCard({ remediation }) {
  return (
    <div style={{ ...panelStyle, padding: 16 }}>
      <p style={{ fontSize: 12, color: colors.inkMuted, margin: 0 }}>Historico de correcao</p>
      <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
        <MiniMetric label="Abertas" value={remediation?.open} color="var(--sev-critical-text)" />
        <MiniMetric label="Corrigidas" value={remediation?.closed} color="var(--sev-low-text)" />
        <MiniMetric label="Taxa de fechamento" value={`${fmtNum(remediation?.closure_rate_percent)}%`} color="var(--sev-high-text)" />
      </div>
      <p style={{ marginTop: 10, marginBottom: 0, fontSize: 11, color: colors.inkMuted }}>
        Regra aplicada: se uma vulnerabilidade nao reaparece no scan posterior, ela e considerada finalizada.
      </p>
    </div>
  );
}

function MiniMetric({ label, value, color }) {
  return (
    <div style={{ background: colors.surfaceSoft, border: `1px solid ${colors.line}`, borderRadius: 8, padding: 10 }}>
      <div style={{ fontSize: 11, color: colors.inkMuted }}>{label}</div>
      <div style={{ marginTop: 3, fontSize: 20, fontWeight: 800, color }}>{value ?? "-"}</div>
    </div>
  );
}

export default function AttackEvolutionPage() {
  const [wizardStep, setWizardStep] = useState(1);
  const [persona, setPersona] = useState("executive");
  const [sortMode, setSortMode] = useState("risk");
  const [dashboard, setDashboard] = useState(null);
  const [comparisonDashboard, setComparisonDashboard] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [actionMessage, setActionMessage] = useState("");

  const [targetInput, setTargetInput] = useState("");
  const [targetFilter, setTargetFilter] = useState("");
  const [comparisonTarget, setComparisonTarget] = useState("");
  const [severity, setSeverity] = useState("");
  const [periodDays, setPeriodDays] = useState("all");
  const [selectedKey, setSelectedKey] = useState("");

  const fetchDashboard = useCallback(async (tgt, sev, days) => {
    setLoading(true);
    setError("");
    try {
      const params = {};
      if (tgt) params.target = tgt;
      if (sev) params.severity = sev;
      if (days && days !== "all") params.period_days = Number(days);
      const { data } = await client.get("/api/vulnerability-management/dashboard", { params });
      setDashboard(data);
      const rows = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
      if (rows.length > 0 && !rows.find((row) => row.vulnerability_key === selectedKey)) {
        setSelectedKey(rows[0].vulnerability_key);
      }

      if (comparisonTarget.trim()) {
        const compareParams = { ...params, target: comparisonTarget.trim() };
        const { data: compareData } = await client.get("/api/vulnerability-management/dashboard", { params: compareParams });
        setComparisonDashboard(compareData);
      } else {
        setComparisonDashboard(null);
      }
    } catch (err) {
      setError(err?.response?.data?.detail || "Falha ao carregar dashboard de vulnerabilidades.");
    } finally {
      setLoading(false);
    }
  }, [selectedKey, comparisonTarget]);

  useEffect(() => {
    fetchDashboard(targetFilter, severity, periodDays);
  }, [targetFilter, severity, periodDays, fetchDashboard]);

  const vulnerabilities = useMemo(
    () => {
      const rows = Array.isArray(dashboard?.vulnerabilities) ? [...dashboard.vulnerabilities] : [];
      if (sortMode === "occurrences") {
        rows.sort((a, b) => Number(b?.occurrence_count || 0) - Number(a?.occurrence_count || 0));
      } else if (sortMode === "recency") {
        rows.sort((a, b) => new Date(b?.latest_seen_at || 0).getTime() - new Date(a?.latest_seen_at || 0).getTime());
      } else if (sortMode === "name") {
        rows.sort((a, b) => String(a?.title || "").localeCompare(String(b?.title || "")));
      }
      return rows;
    },
    [dashboard, sortMode],
  );

  const selectedVulnerability = useMemo(
    () => vulnerabilities.find((item) => item.vulnerability_key === selectedKey) || vulnerabilities[0] || null,
    [vulnerabilities, selectedKey],
  );

  const comparisonSummary = useMemo(() => {
    if (!comparisonDashboard?.overview || !dashboard?.overview) return null;
    const current = Number(dashboard?.overview?.total_vulnerabilities || 0);
    const baseline = Number(comparisonDashboard?.overview?.total_vulnerabilities || 0);
    const delta = current - baseline;
    return {
      baselineTarget: comparisonTarget,
      baseline,
      current,
      delta,
    };
  }, [dashboard, comparisonDashboard, comparisonTarget]);

  const runQuickAction = useCallback((actionType) => {
    const label =
      actionType === "ticket"
        ? "Ticket criado para time responsável"
        : actionType === "retest"
          ? "Revalidação agendada para esta vulnerabilidade"
          : "Risco marcado para aceite com justificativa";
    setActionMessage(`${label}: ${selectedVulnerability?.title || "-"}`);
    setTimeout(() => setActionMessage(""), 2800);
  }, [selectedVulnerability]);

  const exportCsv = useCallback(() => {
    const rows = vulnerabilities;
    if (!rows.length) return;
    const header = ["title", "severity", "cve", "occurrence_count", "open_count", "closed_count", "affected_targets", "latest_seen_at"];
    const lines = [header.join(",")];
    for (const row of rows) {
      const line = [
        row.title,
        row.severity,
        row.cve || "",
        row.occurrence_count,
        row.open_count,
        row.closed_count,
        (row.affected_targets || []).join("|"),
        row.latest_seen_at || "",
      ].map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",");
      lines.push(line);
    }
    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attack-evolution-${targetFilter || "all"}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [vulnerabilities, targetFilter]);

  const availableTargets = dashboard?.filters?.available_targets || [];
  const selectedTargetUrl = dashboard?.filters?.selected_target_url || "";
  const dataQuality = dashboard?.data_quality || {};

  const scopeSummary = useMemo(() => {
    const sevLabel = severity ? SEV[severity]?.label || severity : "Todas";
    const periodLabel = periodDays === "all" ? "Histórico completo" : `${periodDays} dias`;
    return `${PERSONAS[persona]} | alvo: ${targetFilter || "todos"} | severidade: ${sevLabel} | janela: ${periodLabel}`;
  }, [persona, targetFilter, severity, periodDays]);

  return (
    <div style={{ padding: 16, display: "grid", gap: 16 }}>
      <div style={{ ...panelStyle, display: "grid", gap: 10 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {[1, 2, 3].map((step) => (
            <button
              key={step}
              type="button"
              onClick={() => setWizardStep(step)}
              style={{
                padding: "6px 10px",
                borderRadius: 999,
                border: `1px solid ${wizardStep === step ? colors.brand : colors.line}`,
                background: wizardStep === step ? colors.brand : colors.surface,
                color: wizardStep === step ? "#ffffff" : colors.inkSoft,
                fontSize: 12,
                cursor: "pointer",
              }}
            >
              {step}. {step === 1 ? "Contexto" : step === 2 ? "Análise" : "Ação"}
            </button>
          ))}
          <div style={{ flex: 1 }} />
          <label style={{ fontSize: 12, color: colors.inkMuted, display: "flex", alignItems: "center", gap: 6 }}>
            Persona
            <select value={persona} onChange={(e) => setPersona(e.target.value)} style={controlStyle}>
              {Object.entries(PERSONAS).map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
            </select>
          </label>
        </div>

        <div style={{ position: "sticky", top: 8, zIndex: 4, background: "rgba(255,255,255,0.94)", border: `1px solid ${colors.line}`, borderRadius: 10, padding: "8px 10px", color: colors.inkSoft, fontSize: 12, boxShadow: "var(--shadow-card)" }}>
          <strong style={{ color: colors.ink }}>Escopo ativo:</strong> {scopeSummary}
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => {
                setSeverity(preset.severity);
                setPeriodDays(preset.periodDays);
              }}
              style={softButton}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ ...panelStyle, display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <span style={{ fontSize: 12, color: colors.ink, fontWeight: 700 }}>Filtro por alvo/subdominio</span>
        <select
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          style={{ ...controlStyle, minWidth: 220 }}
        >
          <option value="">Selecionar alvo conhecido</option>
          {availableTargets.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
        <input
          type="text"
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          placeholder="ou digite alvo/subdominio"
          onKeyDown={(e) => e.key === "Enter" && setTargetFilter(targetInput.trim())}
          style={{ ...controlStyle, minWidth: 220 }}
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          style={controlStyle}
        >
          <option value="">Todas severidades</option>
          {SEV_KEYS.map((sev) => (
            <option key={sev} value={sev}>{SEV[sev].label}</option>
          ))}
        </select>
        <select
          value={periodDays}
          onChange={(e) => setPeriodDays(e.target.value)}
          style={controlStyle}
        >
          <option value="all">Janela completa</option>
          <option value="7">Últimos 7 dias</option>
          <option value="30">Últimos 30 dias</option>
          <option value="90">Últimos 90 dias</option>
        </select>
        <select
          value={sortMode}
          onChange={(e) => setSortMode(e.target.value)}
          style={controlStyle}
        >
          <option value="risk">Ordenar por risco</option>
          <option value="occurrences">Ordenar por ocorrências</option>
          <option value="recency">Ordenar por recência</option>
          <option value="name">Ordenar por nome</option>
        </select>
        <select
          value={comparisonTarget}
          onChange={(e) => setComparisonTarget(e.target.value)}
          style={{ ...controlStyle, minWidth: 220 }}
        >
          <option value="">Sem comparação de alvo</option>
          {availableTargets.map((item) => (
            <option key={`cmp-${item}`} value={item}>{item}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setTargetFilter(targetInput.trim())}
          style={{ padding: "6px 12px", border: `1px solid ${colors.brand}`, borderRadius: 8, background: colors.brand, color: "#ffffff", fontSize: 12, cursor: "pointer", boxShadow: "var(--shadow-cta)" }}
        >
          Aplicar
        </button>
        <button
          type="button"
          onClick={() => {
            setTargetInput("");
            setTargetFilter("");
            setSeverity("");
            setPeriodDays("all");
            setComparisonTarget("");
          }}
          style={{ padding: "6px 12px", border: `1px solid ${colors.line}`, borderRadius: 8, background: colors.surface, color: colors.inkSoft, fontSize: 12, cursor: "pointer" }}
        >
          Limpar
        </button>
        <button
          type="button"
          onClick={exportCsv}
          style={{ padding: "6px 12px", border: `1px solid ${colors.line}`, borderRadius: 8, background: colors.surfaceSoft, color: colors.ink, fontSize: 12, cursor: "pointer" }}
        >
          Exportar CSV
        </button>
        <div style={{ flex: 1 }} />
        {loading && <span style={{ fontSize: 12, color: colors.inkMuted }}>Carregando...</span>}
      </div>

      {actionMessage && (
        <div style={{ background: "var(--sev-low-bg)", border: "1px solid var(--sev-low-border)", color: "var(--sev-low-text)", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
          {actionMessage}
        </div>
      )}

      <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
        <div style={panelStyle}>
          <div style={{ color: colors.inkMuted, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Cobertura e confiança</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginTop: 8 }}>
            <MiniMetric label="Findings retornados" value={fmtNum(dataQuality?.returned_findings)} color={colors.brandDark} />
            <MiniMetric label="Candidatos no filtro" value={fmtNum(dataQuality?.total_candidates)} color={colors.ink} />
            <MiniMetric label="Cobertura" value={`${fmtNum(dataQuality?.coverage_percent)}%`} color="var(--sev-high-text)" />
            <MiniMetric label="Truncado pelo limite" value={dataQuality?.truncated ? "Sim" : "Não"} color={dataQuality?.truncated ? "var(--sev-critical-text)" : "var(--sev-low-text)"} />
          </div>
        </div>

        {comparisonSummary && (
          <div style={panelStyle}>
            <div style={{ color: colors.inkMuted, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Comparação entre alvos</div>
            <div style={{ marginTop: 8, color: colors.inkSoft, fontSize: 12 }}>
              Base: <strong>{comparisonSummary.baselineTarget}</strong>
            </div>
            <div style={{ marginTop: 8, display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
              <MiniMetric label="Atual" value={fmtNum(comparisonSummary.current)} color={colors.brandDark} />
              <MiniMetric label="Base" value={fmtNum(comparisonSummary.baseline)} color={colors.ink} />
              <MiniMetric label="Delta" value={`${comparisonSummary.delta > 0 ? "+" : ""}${fmtNum(comparisonSummary.delta)}`} color={comparisonSummary.delta > 0 ? "var(--sev-critical-text)" : "var(--sev-low-text)"} />
            </div>
          </div>
        )}
      </div>

      {selectedTargetUrl && (
        <div style={{ background: "var(--sev-high-bg)", border: "1px solid var(--sev-high-border)", color: "var(--sev-high-text)", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
          URL do alvo selecionado: <strong>{selectedTargetUrl}</strong>
        </div>
      )}

      {error && (
        <div style={{ background: "var(--sev-critical-bg)", border: "1px solid var(--sev-critical-border)", color: "var(--sev-critical-text)", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
          {error}
        </div>
      )}

      <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
        <ScoreCard overview={dashboard?.overview || {}} />
        {persona !== "executive" && <SeverityCard summary={dashboard?.overview?.severity_counts || {}} />}
        <AgeCard age={dashboard?.age || {}} />
        {persona !== "compliance" && <RemediationCard remediation={dashboard?.remediation_history || {}} />}
      </div>

      <div style={{ display: "grid", gap: 12, gridTemplateColumns: "1.2fr 1fr" }}>
        <div style={{ ...panelStyle, padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "10px 12px", borderBottom: `1px solid ${colors.line}`, fontSize: 12, color: colors.ink, fontWeight: 700 }}>
            Vulnerabilidades (clique para detalhar locais e correcao)
          </div>
          <div style={{ maxHeight: 520, overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ background: colors.surfaceSoft, position: "sticky", top: 0 }}>
                  <th style={thStyle}>Vulnerabilidade</th>
                  <th style={thStyle}>Sev</th>
                  <th style={thStyle}>Ocorrencias</th>
                  <th style={thStyle}>Alvos</th>
                  <th style={thStyle}>Status</th>
                </tr>
              </thead>
              <tbody>
                {vulnerabilities.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ padding: 16, textAlign: "center", color: colors.inkMuted }}>Sem vulnerabilidades para os filtros selecionados.</td>
                  </tr>
                )}
                {vulnerabilities.map((row) => {
                  const active = selectedVulnerability?.vulnerability_key === row.vulnerability_key;
                  return (
                    <tr
                      key={row.vulnerability_key}
                      onClick={() => setSelectedKey(row.vulnerability_key)}
                      style={{ background: active ? "rgba(233,99,99,0.08)" : colors.surface, cursor: "pointer", borderBottom: `1px solid ${colors.line}` }}
                    >
                      <td style={tdStyle}>
                        <div style={{ fontWeight: 600, color: colors.ink }}>{row.title}</div>
                        <div style={{ color: colors.inkMuted, fontSize: 11 }}>{row.cve || "sem CVE"}</div>
                      </td>
                      <td style={tdStyle}><span style={sevBadge(row.severity)}>{row.severity}</span></td>
                      <td style={tdStyle}>{fmtNum(row.occurrence_count)}</td>
                      <td style={tdStyle}>{fmtNum((row.affected_targets || []).length)}</td>
                      <td style={tdStyle}>{fmtNum(row.open_count)} abertas / {fmtNum(row.closed_count)} fechadas</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ ...panelStyle, display: "grid", gap: 10, alignContent: "start" }}>
          {!selectedVulnerability ? (
            <div style={{ color: colors.inkMuted, fontSize: 12 }}>Selecione uma vulnerabilidade para ver todos os subdominios, paths, URLs e recomendacoes.</div>
          ) : (
            <>
              <div>
                <div style={{ fontSize: 11, color: colors.inkMuted }}>Vulnerabilidade selecionada</div>
                <div style={{ marginTop: 3, fontWeight: 700, color: colors.ink }}>{selectedVulnerability.title}</div>
                <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <span style={sevBadge(selectedVulnerability.severity)}>{selectedVulnerability.severity}</span>
                  {selectedVulnerability.cve && <span style={chipStyle}>{selectedVulnerability.cve}</span>}
                  {selectedVulnerability.tool && <span style={chipStyle}>{selectedVulnerability.tool}</span>}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: colors.inkMuted }}>Correcao recomendada</div>
                <div style={{ marginTop: 4, fontSize: 12, color: colors.inkSoft, background: colors.surfaceSoft, border: `1px solid ${colors.line}`, borderRadius: 8, padding: 10 }}>
                  {selectedVulnerability.recommendation || "Sem recomendacao registrada para essa vulnerabilidade."}
                </div>
                <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button type="button" onClick={() => runQuickAction("ticket")} style={actionBtn(colors.brand, colors.brandDark)}>Abrir ticket</button>
                  <button type="button" onClick={() => runQuickAction("retest")} style={actionBtn("var(--sev-high-border)", "var(--sev-high-text)")}>Agendar re-scan</button>
                  <button type="button" onClick={() => runQuickAction("accept")} style={actionBtn("var(--sev-low-border)", "var(--sev-low-text)")}>Aceitar risco</button>
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: colors.inkMuted, marginBottom: 4 }}>Todos os subdominios afetados</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(selectedVulnerability.affected_targets || []).length === 0 && <span style={{ color: colors.inkMuted, fontSize: 12 }}>Sem subdominio mapeado.</span>}
                  {(selectedVulnerability.affected_targets || []).map((item) => <span key={item} style={chipStyle}>{item}</span>)}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: colors.inkMuted, marginBottom: 4 }}>Todos os paths afetados</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(selectedVulnerability.affected_paths || []).length === 0 && <span style={{ color: colors.inkMuted, fontSize: 12 }}>Sem path mapeado.</span>}
                  {(selectedVulnerability.affected_paths || []).map((item) => <span key={item} style={chipStyle}>{item}</span>)}
                </div>
              </div>

              <div style={{ borderTop: `1px solid ${colors.line}`, paddingTop: 8 }}>
                <div style={{ fontSize: 11, color: colors.inkMuted, marginBottom: 4 }}>Ocorrencias (alvo + path + URL)</div>
                <div style={{ maxHeight: 220, overflow: "auto", border: `1px solid ${colors.line}`, borderRadius: 8 }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ background: colors.surfaceSoft, position: "sticky", top: 0 }}>
                        <th style={thStyle}>Subdominio</th>
                        <th style={thStyle}>Path</th>
                        <th style={thStyle}>URL</th>
                        <th style={thStyle}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(selectedVulnerability.occurrences || []).map((occ) => (
                        <tr key={`${selectedVulnerability.vulnerability_key}-${occ.finding_id}`} style={{ borderBottom: `1px solid ${colors.line}` }}>
                          <td style={tdStyle}>{occ.subdomain || "-"}</td>
                          <td style={tdStyle}>{occ.path || "-"}</td>
                          <td style={tdStyle} title={occ.url || ""}>{occ.url || "-"}</td>
                          <td style={tdStyle}>{occ.lifecycle_status || "open"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div style={{ marginTop: 6, fontSize: 11, color: colors.inkMuted }}>
                  Ultima deteccao: {fmtDate(selectedVulnerability.latest_seen_at)}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const thStyle = {
  textAlign: "left",
  padding: "8px 10px",
  fontSize: 11,
  color: colors.inkMuted,
  borderBottom: `1px solid ${colors.line}`,
};

const tdStyle = {
  textAlign: "left",
  padding: "8px 10px",
  color: colors.inkSoft,
  verticalAlign: "top",
};

const chipStyle = {
  padding: "2px 8px",
  borderRadius: 999,
  border: `1px solid ${colors.line}`,
  background: colors.surfaceSoft,
  fontSize: 11,
  color: colors.inkSoft,
};

function actionBtn(borderColor, textColor) {
  return {
    padding: "6px 10px",
    border: `1px solid ${borderColor}`,
    borderRadius: 8,
    background: "#ffffff",
    color: textColor,
    fontSize: 11,
    cursor: "pointer",
  };
}
