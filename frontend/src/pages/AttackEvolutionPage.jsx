import { useCallback, useEffect, useMemo, useState } from "react";
import client from "../api/client";

const SEV = {
  critical: { color: "#fca5a5", bg: "rgba(185,28,28,0.18)", label: "Critical" },
  high: { color: "#fdba74", bg: "rgba(194,65,12,0.18)", label: "High" },
  medium: { color: "#fde68a", bg: "rgba(161,98,7,0.18)", label: "Medium" },
  low: { color: "#86efac", bg: "rgba(21,128,61,0.18)", label: "Low" },
  info: { color: "#cbd5e1", bg: "rgba(71,85,105,0.24)", label: "Info" },
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
  const color = score >= 80 ? "#86efac" : score >= 60 ? "#fde68a" : "#fca5a5";
  return (
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Score geral de risco</p>
      <div style={{ display: "flex", alignItems: "end", gap: 8, marginTop: 4 }}>
        <span style={{ fontSize: 42, lineHeight: 1, fontWeight: 800, color }}>{fmtNum(score)}</span>
        <span style={{ fontSize: 13, color: "#94a3b8", marginBottom: 6 }}>/ 100</span>
      </div>
      <div style={{ marginTop: 12, background: "#1e293b", height: 10, borderRadius: 99, overflow: "hidden" }}>
        <div style={{ width: `${Math.max(0, Math.min(100, score))}%`, height: "100%", background: color }} />
      </div>
      <div style={{ display: "grid", gap: 4, marginTop: 10, fontSize: 12, color: "#cbd5e1" }}>
        <div>Total de vulnerabilidades: <strong>{fmtNum(overview?.total_vulnerabilities)}</strong></div>
        <div>Ocorrencias encontradas: <strong>{fmtNum(overview?.findings_total)}</strong></div>
        <div>Alvos afetados: <strong>{fmtNum(overview?.affected_targets)}</strong></div>
      </div>
    </div>
  );
}

function SeverityCard({ summary }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Vulnerabilidades por criticidade</p>
      <div style={{ display: "grid", gap: 8, marginTop: 12 }}>
        {SEV_KEYS.map((sev) => {
          const total = Number(summary?.[sev] || 0);
          const max = Math.max(...SEV_KEYS.map((k) => Number(summary?.[k] || 0)), 1);
          return (
            <div key={sev} style={{ display: "grid", gridTemplateColumns: "80px 1fr 44px", gap: 8, alignItems: "center" }}>
              <span style={{ fontSize: 11, color: SEV[sev].color, fontWeight: 700 }}>{SEV[sev].label}</span>
              <div style={{ background: "#1e293b", height: 8, borderRadius: 99 }}>
                <div style={{ width: `${(total / max) * 100}%`, height: "100%", borderRadius: 99, background: SEV[sev].color }} />
              </div>
              <span style={{ fontSize: 12, color: "#cbd5e1", textAlign: "right" }}>{fmtNum(total)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AgeCard({ age }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Age das vulnerabilidades</p>
      <div style={{ marginTop: 10, display: "grid", gap: 8, fontSize: 12, color: "#cbd5e1" }}>
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
    <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 16 }}>
      <p style={{ fontSize: 12, color: "#94a3b8", margin: 0 }}>Historico de correcao</p>
      <div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
        <MiniMetric label="Abertas" value={remediation?.open} color="#b91c1c" />
        <MiniMetric label="Corrigidas" value={remediation?.closed} color="#166534" />
        <MiniMetric label="Taxa de fechamento" value={`${fmtNum(remediation?.closure_rate_percent)}%`} color="#a16207" />
      </div>
      <p style={{ marginTop: 10, marginBottom: 0, fontSize: 11, color: "#94a3b8" }}>
        Regra aplicada: se uma vulnerabilidade nao reaparece no scan posterior, ela e considerada finalizada.
      </p>
    </div>
  );
}

function MiniMetric({ label, value, color }) {
  return (
    <div style={{ background: "#111827", border: "1px solid #334155", borderRadius: 8, padding: 10 }}>
      <div style={{ fontSize: 11, color: "#94a3b8" }}>{label}</div>
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
      <div style={{ background: "#0b1220", border: "1px solid #334155", borderRadius: 12, padding: 12, display: "grid", gap: 10 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {[1, 2, 3].map((step) => (
            <button
              key={step}
              type="button"
              onClick={() => setWizardStep(step)}
              style={{
                padding: "6px 10px",
                borderRadius: 999,
                border: `1px solid ${wizardStep === step ? "#a16207" : "#475569"}`,
                background: wizardStep === step ? "rgba(245,158,11,0.18)" : "#111827",
                color: wizardStep === step ? "#fcd34d" : "#cbd5e1",
                fontSize: 12,
                cursor: "pointer",
              }}
            >
              {step}. {step === 1 ? "Contexto" : step === 2 ? "Análise" : "Ação"}
            </button>
          ))}
          <div style={{ flex: 1 }} />
          <label style={{ fontSize: 12, color: "#94a3b8", display: "flex", alignItems: "center", gap: 6 }}>
            Persona
            <select value={persona} onChange={(e) => setPersona(e.target.value)} style={{ padding: "5px 8px", border: "1px solid #475569", borderRadius: 8, background: "#111827", color: "#e2e8f0", fontSize: 12 }}>
              {Object.entries(PERSONAS).map(([key, label]) => (
                <option key={key} value={key}>{label}</option>
              ))}
            </select>
          </label>
        </div>

        <div style={{ position: "sticky", top: 8, zIndex: 4, background: "rgba(2,6,23,0.86)", border: "1px solid #334155", borderRadius: 10, padding: "8px 10px", color: "#cbd5e1", fontSize: 12 }}>
          <strong style={{ color: "#e2e8f0" }}>Escopo ativo:</strong> {scopeSummary}
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
              style={{ padding: "6px 10px", border: "1px solid #334155", borderRadius: 999, background: "#111827", color: "#cbd5e1", fontSize: 12, cursor: "pointer" }}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ background: "#0b1220", border: "1px solid #334155", borderRadius: 12, padding: 12, display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 700 }}>Filtro por alvo/subdominio</span>
        <select
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, minWidth: 220, background: "#111827", color: "#e2e8f0" }}
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
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, minWidth: 220, background: "#111827", color: "#e2e8f0" }}
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, background: "#111827", color: "#e2e8f0" }}
        >
          <option value="">Todas severidades</option>
          {SEV_KEYS.map((sev) => (
            <option key={sev} value={sev}>{SEV[sev].label}</option>
          ))}
        </select>
        <select
          value={periodDays}
          onChange={(e) => setPeriodDays(e.target.value)}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, background: "#111827", color: "#e2e8f0" }}
        >
          <option value="all">Janela completa</option>
          <option value="7">Últimos 7 dias</option>
          <option value="30">Últimos 30 dias</option>
          <option value="90">Últimos 90 dias</option>
        </select>
        <select
          value={sortMode}
          onChange={(e) => setSortMode(e.target.value)}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, background: "#111827", color: "#e2e8f0" }}
        >
          <option value="risk">Ordenar por risco</option>
          <option value="occurrences">Ordenar por ocorrências</option>
          <option value="recency">Ordenar por recência</option>
          <option value="name">Ordenar por nome</option>
        </select>
        <select
          value={comparisonTarget}
          onChange={(e) => setComparisonTarget(e.target.value)}
          style={{ padding: "6px 10px", border: "1px solid #475569", borderRadius: 8, fontSize: 12, minWidth: 220, background: "#111827", color: "#e2e8f0" }}
        >
          <option value="">Sem comparação de alvo</option>
          {availableTargets.map((item) => (
            <option key={`cmp-${item}`} value={item}>{item}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setTargetFilter(targetInput.trim())}
          style={{ padding: "6px 12px", border: "1px solid #f59e0b", borderRadius: 8, background: "rgba(245,158,11,0.16)", color: "#fcd34d", fontSize: 12, cursor: "pointer" }}
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
          style={{ padding: "6px 12px", border: "1px solid #7f1d1d", borderRadius: 8, background: "rgba(185,28,28,0.16)", color: "#fca5a5", fontSize: 12, cursor: "pointer" }}
        >
          Limpar
        </button>
        <button
          type="button"
          onClick={exportCsv}
          style={{ padding: "6px 12px", border: "1px solid #0369a1", borderRadius: 8, background: "rgba(14,116,144,0.16)", color: "#7dd3fc", fontSize: 12, cursor: "pointer" }}
        >
          Exportar CSV
        </button>
        <div style={{ flex: 1 }} />
        {loading && <span style={{ fontSize: 12, color: "#94a3b8" }}>Carregando...</span>}
      </div>

      {actionMessage && (
        <div style={{ background: "rgba(21,128,61,0.18)", border: "1px solid #166534", color: "#86efac", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
          {actionMessage}
        </div>
      )}

      <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 12 }}>
          <div style={{ color: "#94a3b8", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Cobertura e confiança</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginTop: 8 }}>
            <MiniMetric label="Findings retornados" value={fmtNum(dataQuality?.returned_findings)} color="#7dd3fc" />
            <MiniMetric label="Candidatos no filtro" value={fmtNum(dataQuality?.total_candidates)} color="#a5b4fc" />
            <MiniMetric label="Cobertura" value={`${fmtNum(dataQuality?.coverage_percent)}%`} color="#fde68a" />
            <MiniMetric label="Truncado pelo limite" value={dataQuality?.truncated ? "Sim" : "Não"} color={dataQuality?.truncated ? "#fca5a5" : "#86efac"} />
          </div>
        </div>

        {comparisonSummary && (
          <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 12 }}>
            <div style={{ color: "#94a3b8", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Comparação entre alvos</div>
            <div style={{ marginTop: 8, color: "#e2e8f0", fontSize: 12 }}>
              Base: <strong>{comparisonSummary.baselineTarget}</strong>
            </div>
            <div style={{ marginTop: 8, display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
              <MiniMetric label="Atual" value={fmtNum(comparisonSummary.current)} color="#7dd3fc" />
              <MiniMetric label="Base" value={fmtNum(comparisonSummary.baseline)} color="#a5b4fc" />
              <MiniMetric label="Delta" value={`${comparisonSummary.delta > 0 ? "+" : ""}${fmtNum(comparisonSummary.delta)}`} color={comparisonSummary.delta > 0 ? "#fca5a5" : "#86efac"} />
            </div>
          </div>
        )}
      </div>

      {selectedTargetUrl && (
        <div style={{ background: "rgba(245,158,11,0.14)", border: "1px solid #a16207", color: "#fcd34d", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
          URL do alvo selecionado: <strong>{selectedTargetUrl}</strong>
        </div>
      )}

      {error && (
        <div style={{ background: "rgba(185,28,28,0.16)", border: "1px solid #7f1d1d", color: "#fca5a5", borderRadius: 10, padding: "8px 12px", fontSize: 12 }}>
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
        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ padding: "10px 12px", borderBottom: "1px solid #334155", fontSize: 12, color: "#e2e8f0", fontWeight: 700 }}>
            Vulnerabilidades (clique para detalhar locais e correcao)
          </div>
          <div style={{ maxHeight: 520, overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ background: "#111827", position: "sticky", top: 0 }}>
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
                    <td colSpan={5} style={{ padding: 16, textAlign: "center", color: "#94a3b8" }}>Sem vulnerabilidades para os filtros selecionados.</td>
                  </tr>
                )}
                {vulnerabilities.map((row) => {
                  const active = selectedVulnerability?.vulnerability_key === row.vulnerability_key;
                  return (
                    <tr
                      key={row.vulnerability_key}
                      onClick={() => setSelectedKey(row.vulnerability_key)}
                      style={{ background: active ? "rgba(245,158,11,0.15)" : "#0f172a", cursor: "pointer", borderBottom: "1px solid #1e293b" }}
                    >
                      <td style={tdStyle}>
                        <div style={{ fontWeight: 600, color: "#e2e8f0" }}>{row.title}</div>
                        <div style={{ color: "#94a3b8", fontSize: 11 }}>{row.cve || "sem CVE"}</div>
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

        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 12, padding: 12, display: "grid", gap: 10, alignContent: "start" }}>
          {!selectedVulnerability ? (
            <div style={{ color: "#94a3b8", fontSize: 12 }}>Selecione uma vulnerabilidade para ver todos os subdominios, paths, URLs e recomendacoes.</div>
          ) : (
            <>
              <div>
                <div style={{ fontSize: 11, color: "#94a3b8" }}>Vulnerabilidade selecionada</div>
                <div style={{ marginTop: 3, fontWeight: 700, color: "#e2e8f0" }}>{selectedVulnerability.title}</div>
                <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <span style={sevBadge(selectedVulnerability.severity)}>{selectedVulnerability.severity}</span>
                  {selectedVulnerability.cve && <span style={chipStyle}>{selectedVulnerability.cve}</span>}
                  {selectedVulnerability.tool && <span style={chipStyle}>{selectedVulnerability.tool}</span>}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: "#94a3b8" }}>Correcao recomendada</div>
                <div style={{ marginTop: 4, fontSize: 12, color: "#e2e8f0", background: "#111827", border: "1px solid #334155", borderRadius: 8, padding: 10 }}>
                  {selectedVulnerability.recommendation || "Sem recomendacao registrada para essa vulnerabilidade."}
                </div>
                <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button type="button" onClick={() => runQuickAction("ticket")} style={actionBtn("#0369a1", "#7dd3fc")}>Abrir ticket</button>
                  <button type="button" onClick={() => runQuickAction("retest")} style={actionBtn("#a16207", "#fde68a")}>Agendar re-scan</button>
                  <button type="button" onClick={() => runQuickAction("accept")} style={actionBtn("#166534", "#86efac")}>Aceitar risco</button>
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>Todos os subdominios afetados</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(selectedVulnerability.affected_targets || []).length === 0 && <span style={{ color: "#94a3b8", fontSize: 12 }}>Sem subdominio mapeado.</span>}
                  {(selectedVulnerability.affected_targets || []).map((item) => <span key={item} style={chipStyle}>{item}</span>)}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>Todos os paths afetados</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(selectedVulnerability.affected_paths || []).length === 0 && <span style={{ color: "#94a3b8", fontSize: 12 }}>Sem path mapeado.</span>}
                  {(selectedVulnerability.affected_paths || []).map((item) => <span key={item} style={chipStyle}>{item}</span>)}
                </div>
              </div>

              <div style={{ borderTop: "1px solid #334155", paddingTop: 8 }}>
                <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 4 }}>Ocorrencias (alvo + path + URL)</div>
                <div style={{ maxHeight: 220, overflow: "auto", border: "1px solid #334155", borderRadius: 8 }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                    <thead>
                      <tr style={{ background: "#111827", position: "sticky", top: 0 }}>
                        <th style={thStyle}>Subdominio</th>
                        <th style={thStyle}>Path</th>
                        <th style={thStyle}>URL</th>
                        <th style={thStyle}>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(selectedVulnerability.occurrences || []).map((occ) => (
                        <tr key={`${selectedVulnerability.vulnerability_key}-${occ.finding_id}`} style={{ borderBottom: "1px solid #1e293b" }}>
                          <td style={tdStyle}>{occ.subdomain || "-"}</td>
                          <td style={tdStyle}>{occ.path || "-"}</td>
                          <td style={tdStyle} title={occ.url || ""}>{occ.url || "-"}</td>
                          <td style={tdStyle}>{occ.lifecycle_status || "open"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div style={{ marginTop: 6, fontSize: 11, color: "#94a3b8" }}>
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
  color: "#94a3b8",
  borderBottom: "1px solid #334155",
};

const tdStyle = {
  textAlign: "left",
  padding: "8px 10px",
  color: "#e2e8f0",
  verticalAlign: "top",
};

const chipStyle = {
  padding: "2px 8px",
  borderRadius: 999,
  border: "1px solid #475569",
  background: "#111827",
  fontSize: 11,
  color: "#e2e8f0",
};

function actionBtn(borderColor, textColor) {
  return {
    padding: "6px 10px",
    border: `1px solid ${borderColor}`,
    borderRadius: 8,
    background: "#0b1220",
    color: textColor,
    fontSize: 11,
    cursor: "pointer",
  };
}
