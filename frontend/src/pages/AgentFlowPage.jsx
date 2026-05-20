import { useEffect, useState } from "react";
import client from "../api/client";

const STATUS_COLORS = {
  pending: "#94a3b8",
  skill_selected: "#60a5fa",
  tool_selected: "#a78bfa",
  executing: "#fb923c",
  reported: "#34d399",
  approved: "#22c55e",
  rejected: "#f87171",
};

const PHASE_LABEL = {
  pending: "Pendente",
  skill_selected: "Skill Encontrada",
  tool_selected: "Ferramenta Selecionada",
  executing: "Executando",
  reported: "Agente Reportou",
  approved: "Aprovado",
  rejected: "Rejeitado",
};

function ScoreBar({ score, max = 10 }) {
  const pct = Math.min(100, Math.round((score / max) * 100));
  const color = pct >= 80 ? "#22c55e" : pct >= 50 ? "#f59e0b" : "#f87171";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div
        style={{
          flex: 1,
          height: 6,
          borderRadius: 3,
          background: "var(--bg-muted, #1e293b)",
          overflow: "hidden",
        }}
      >
        <div
          style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 3 }}
        />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 600, minWidth: 32 }}>
        {score.toFixed(1)}
      </span>
    </div>
  );
}

function FlowStep({ icon, label, color, children, active }) {
  return (
    <div
      style={{
        border: `1px solid ${active ? color : "var(--border, #334155)"}`,
        borderRadius: 10,
        padding: "12px 14px",
        marginBottom: 8,
        background: active ? `${color}10` : "transparent",
        transition: "all 0.2s",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: children ? 8 : 0,
        }}
      >
        <span style={{ fontSize: 16 }}>{icon}</span>
        <span style={{ fontSize: 12, fontWeight: 600, color: active ? color : "var(--text-muted, #94a3b8)" }}>
          {label}
        </span>
      </div>
      {children && (
        <div style={{ fontSize: 12, color: "var(--text, #e2e8f0)", lineHeight: 1.5 }}>
          {children}
        </div>
      )}
    </div>
  );
}

function ActivityCard({ activity, index }) {
  const [open, setOpen] = useState(false);
  const statusColor = STATUS_COLORS[activity.status] || "#94a3b8";
  const demand = activity.supervisor_demand || {};
  const skillLookup = activity.skill_lookup || {};
  const toolSel = activity.tool_selection || {};
  const report = activity.agent_report || {};
  const evaluation = activity.supervisor_evaluation || {};

  const qualityPct = Math.round((report.quality_score || 0) * 100);

  return (
    <div
      style={{
        border: `1px solid var(--border, #334155)`,
        borderRadius: 12,
        marginBottom: 16,
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <button
        onClick={() => setOpen((p) => !p)}
        style={{
          width: "100%",
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "12px 16px",
          background: "var(--bg-card, #1e293b)",
          border: "none",
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span
          style={{
            minWidth: 24,
            height: 24,
            borderRadius: "50%",
            background: statusColor,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 11,
            fontWeight: 700,
            color: "#fff",
          }}
        >
          {index + 1}
        </span>

        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text, #e2e8f0)" }}>
            {demand.activity_type || "—"}
            {demand.kill_chain_phases?.length > 0 && (
              <span
                style={{
                  marginLeft: 8,
                  fontSize: 10,
                  fontWeight: 500,
                  color: "#60a5fa",
                  background: "#1e3a5f",
                  padding: "2px 6px",
                  borderRadius: 4,
                }}
              >
                {demand.kill_chain_phases.join(", ")}
              </span>
            )}
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted, #94a3b8)", marginTop: 2 }}>
            iter #{activity.iteration} · skill: {skillLookup.skill_name || "—"} · tool: {toolSel.tool_name || "—"} · {report.findings_count || 0} findings
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              fontSize: 10,
              fontWeight: 600,
              padding: "3px 8px",
              borderRadius: 6,
              background: `${statusColor}20`,
              color: statusColor,
              border: `1px solid ${statusColor}40`,
            }}
          >
            {PHASE_LABEL[activity.status] || activity.status}
          </span>
          <span style={{ color: "var(--text-muted)", fontSize: 12 }}>{open ? "▲" : "▼"}</span>
        </div>
      </button>

      {/* Expanded body */}
      {open && (
        <div style={{ padding: "16px", background: "var(--bg-main, #0f172a)", borderTop: "1px solid var(--border, #334155)" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

            {/* Left column: flow steps */}
            <div>
              <FlowStep icon="🎯" label="1. Supervisor → Agente (Demanda)" color="#60a5fa" active={!!demand.activity_type}>
                {demand.activity_type && (
                  <>
                    <div><strong>Atividade:</strong> {demand.activity_type}</div>
                    <div><strong>Objetivo:</strong> {demand.objective}</div>
                    <div style={{ marginTop: 4, fontSize: 11, color: "#94a3b8" }}>
                      <strong>Critérios de qualidade:</strong> {demand.quality_criteria}
                    </div>
                  </>
                )}
              </FlowStep>

              <div style={{ textAlign: "center", fontSize: 12, color: "#475569", marginBottom: 8 }}>↓</div>

              <FlowStep icon="📚" label="2. Agente → Biblioteca (Lookup Skill)" color="#a78bfa" active={!!skillLookup.skill_name}>
                {skillLookup.skill_name ? (
                  <>
                    <div><strong>Skill encontrada:</strong> {skillLookup.skill_name}</div>
                    <div><strong>Categoria:</strong> {skillLookup.skill_category}</div>
                    <div style={{ marginTop: 6 }}>
                      <strong>Ferramentas disponíveis ({skillLookup.tools_available}):</strong>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                        {(skillLookup.top_tools || []).map((t) => (
                          <span
                            key={t.tool_name}
                            style={{
                              fontSize: 10,
                              padding: "2px 6px",
                              borderRadius: 4,
                              background: "#312e81",
                              color: "#a5b4fc",
                            }}
                          >
                            {t.tool_name} ({t.score.toFixed(1)})
                          </span>
                        ))}
                      </div>
                    </div>
                    <div style={{ fontSize: 10, color: "#64748b", marginTop: 4 }}>
                      Fonte: {skillLookup.source}
                    </div>
                  </>
                ) : (
                  <span style={{ color: "#64748b" }}>Aguardando lookup...</span>
                )}
              </FlowStep>

              <div style={{ textAlign: "center", fontSize: 12, color: "#475569", marginBottom: 8 }}>↓</div>

              <FlowStep icon="🔧" label="3. Agente → Catálogo (Seleção de Ferramenta com Score)" color="#fb923c" active={!!toolSel.tool_name}>
                {toolSel.tool_name ? (
                  <>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <strong>{toolSel.tool_name}</strong>
                      <span style={{ fontSize: 10, color: "#94a3b8" }}>score:</span>
                      <ScoreBar score={toolSel.score || 0} />
                    </div>
                    {toolSel.usage_guide && (
                      <div
                        style={{
                          marginTop: 6,
                          padding: "6px 8px",
                          borderRadius: 6,
                          background: "#1e1b4b",
                          fontSize: 11,
                          color: "#a5b4fc",
                          lineHeight: 1.5,
                        }}
                      >
                        <strong>Guia de uso:</strong> {toolSel.usage_guide}
                      </div>
                    )}
                  </>
                ) : (
                  <span style={{ color: "#64748b" }}>Ferramenta não selecionada ainda.</span>
                )}
              </FlowStep>
            </div>

            {/* Right column: execution + report + evaluation */}
            <div>
              <FlowStep icon="⚡" label="4. Execução da Ferramenta" color="#f59e0b" active={report.findings_count >= 0}>
                {report.operation_performed ? (
                  <div>{report.operation_performed}</div>
                ) : (
                  <span style={{ color: "#64748b" }}>Aguardando execução...</span>
                )}
              </FlowStep>

              <div style={{ textAlign: "center", fontSize: 12, color: "#475569", marginBottom: 8 }}>↓</div>

              <FlowStep icon="📋" label="5. Agente → Supervisor (Relatório)" color="#34d399" active={!!report.question_to_supervisor}>
                {report.question_to_supervisor ? (
                  <>
                    <div style={{ marginBottom: 6 }}>
                      <strong>Findings coletados:</strong> {report.findings_count}
                    </div>
                    <div style={{ marginBottom: 6 }}>
                      <strong>Qualidade:</strong>
                      <div style={{ marginTop: 4 }}>
                        <ScoreBar score={(report.quality_score || 0) * 10} max={10} />
                      </div>
                      <span style={{ fontSize: 10, color: "#94a3b8" }}>{qualityPct}%</span>
                    </div>
                    <div
                      style={{
                        padding: "8px 10px",
                        borderRadius: 8,
                        background: "#064e3b",
                        color: "#6ee7b7",
                        fontSize: 11,
                        fontStyle: "italic",
                        marginTop: 4,
                      }}
                    >
                      "{report.question_to_supervisor}"
                    </div>
                    {report.data_collected?.length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <strong style={{ fontSize: 11 }}>Dados coletados:</strong>
                        <div style={{ marginTop: 4, display: "flex", flexDirection: "column", gap: 3 }}>
                          {report.data_collected.map((d, i) => (
                            <div
                              key={i}
                              style={{
                                fontSize: 10,
                                padding: "2px 6px",
                                borderRadius: 4,
                                background: "#1e293b",
                                color: "#94a3b8",
                              }}
                            >
                              [{d.severity}] {d.title}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <span style={{ color: "#64748b" }}>Aguardando relatório do agente...</span>
                )}
              </FlowStep>

              <div style={{ textAlign: "center", fontSize: 12, color: "#475569", marginBottom: 8 }}>↓</div>

              <FlowStep
                icon={evaluation.approved === true ? "✅" : evaluation.approved === false ? "❌" : "⏳"}
                label="6. Supervisor (Avaliação e Aprovação)"
                color={evaluation.approved === true ? "#22c55e" : evaluation.approved === false ? "#f87171" : "#94a3b8"}
                active={evaluation.approved !== undefined && evaluation.approved !== null}
              >
                {evaluation.quality_assessment ? (
                  <>
                    <div
                      style={{
                        fontWeight: 600,
                        color: evaluation.approved ? "#22c55e" : "#f87171",
                        marginBottom: 4,
                      }}
                    >
                      {evaluation.approved ? "APROVADO — avançar na Kill Chain" : "REJEITADO — revisar atividade"}
                    </div>
                    <div style={{ color: "var(--text-muted, #94a3b8)" }}>{evaluation.quality_assessment}</div>
                    {evaluation.next_phase && (
                      <div style={{ fontSize: 10, color: "#60a5fa", marginTop: 4 }}>
                        Próxima fase: {evaluation.next_phase}
                      </div>
                    )}
                  </>
                ) : (
                  <span style={{ color: "#64748b" }}>Aguardando avaliação do supervisor...</span>
                )}
              </FlowStep>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SkillLibraryPanel({ skills }) {
  const [search, setSearch] = useState("");
  const filtered = skills.filter(
    (s) =>
      s.skill_name.toLowerCase().includes(search.toLowerCase()) ||
      s.skill_category.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Buscar skill ou categoria..."
        style={{
          width: "100%",
          padding: "8px 12px",
          borderRadius: 8,
          border: "1px solid var(--border, #334155)",
          background: "var(--bg-card, #1e293b)",
          color: "var(--text, #e2e8f0)",
          fontSize: 13,
          marginBottom: 16,
          boxSizing: "border-box",
        }}
      />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12 }}>
        {filtered.map((skill) => (
          <div
            key={skill.id}
            style={{
              border: "1px solid var(--border, #334155)",
              borderRadius: 10,
              padding: "12px 14px",
              background: "var(--bg-card, #1e293b)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
              <strong style={{ fontSize: 13, color: "var(--text, #e2e8f0)" }}>{skill.skill_name}</strong>
              <span
                style={{
                  fontSize: 10,
                  padding: "2px 6px",
                  borderRadius: 4,
                  background: "#1e3a5f",
                  color: "#60a5fa",
                }}
              >
                {skill.skill_category}
              </span>
            </div>
            <div style={{ fontSize: 11, color: "#94a3b8", marginBottom: 8 }}>{skill.objective}</div>
            {skill.kill_chain_phases?.length > 0 && (
              <div style={{ display: "flex", gap: 4, marginBottom: 8, flexWrap: "wrap" }}>
                {skill.kill_chain_phases.map((p) => (
                  <span
                    key={p}
                    style={{ fontSize: 10, padding: "1px 5px", borderRadius: 3, background: "#1e1b4b", color: "#a5b4fc" }}
                  >
                    {p}
                  </span>
                ))}
              </div>
            )}
            <div>
              {(skill.tools || []).slice(0, 4).map((t) => (
                <div
                  key={t.tool_name}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "4px 0",
                    borderBottom: "1px solid var(--border, #1e293b)",
                  }}
                >
                  <span style={{ fontSize: 12, color: "#e2e8f0" }}>{t.tool_name}</span>
                  <div style={{ width: 80 }}>
                    <ScoreBar score={t.score} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AgentFlowPage() {
  const [scanId, setScanId] = useState("");
  const [flow, setFlow] = useState(null);
  const [skills, setSkills] = useState([]);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState("flow");
  const [error, setError] = useState("");

  useEffect(() => {
    client
      .get("/api/agent-flow/skill-library")
      .then((r) => setSkills(r.data.skills || []))
      .catch(() => {});
  }, []);

  const loadFlow = async () => {
    if (!scanId) return;
    setLoading(true);
    setError("");
    try {
      const r = await client.get(`/api/agent-flow/scans/${scanId}`);
      setFlow(r.data);
    } catch (e) {
      setError(e?.response?.data?.detail || "Erro ao carregar fluxo.");
    } finally {
      setLoading(false);
    }
  };

  const approved = (flow?.activities || []).filter((a) => a.status === "approved").length;
  const rejected = (flow?.activities || []).filter((a) => a.status === "rejected").length;

  return (
    <div style={{ padding: "24px 32px", maxWidth: 1400, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: "var(--text, #e2e8f0)", marginBottom: 4 }}>
          Agent Flow
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-muted, #94a3b8)" }}>
          Visualize o fluxo completo: Supervisor demanda atividade → Agente busca skill na biblioteca →
          Seleciona ferramenta por score → Executa → Reporta ao Supervisor → Supervisor aprova/rejeita na Kill Chain.
        </p>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 24 }}>
        {[
          { key: "flow", label: "Fluxo de Execução" },
          { key: "library", label: `Biblioteca de Skills (${skills.length})` },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              padding: "8px 16px",
              borderRadius: 8,
              border: "none",
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 500,
              background: tab === t.key ? "#3b82f6" : "var(--bg-card, #1e293b)",
              color: tab === t.key ? "#fff" : "var(--text-muted, #94a3b8)",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "library" && <SkillLibraryPanel skills={skills} />}

      {tab === "flow" && (
        <>
          {/* Scan selector */}
          <div style={{ display: "flex", gap: 12, marginBottom: 24, alignItems: "center" }}>
            <input
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              placeholder="ID do Scan (ex: 42)"
              style={{
                padding: "8px 12px",
                borderRadius: 8,
                border: "1px solid var(--border, #334155)",
                background: "var(--bg-card, #1e293b)",
                color: "var(--text, #e2e8f0)",
                fontSize: 13,
                width: 200,
              }}
              onKeyDown={(e) => e.key === "Enter" && loadFlow()}
            />
            <button
              onClick={loadFlow}
              disabled={loading || !scanId}
              style={{
                padding: "8px 18px",
                borderRadius: 8,
                border: "none",
                background: "#3b82f6",
                color: "#fff",
                fontSize: 13,
                fontWeight: 600,
                cursor: loading || !scanId ? "not-allowed" : "pointer",
                opacity: loading || !scanId ? 0.6 : 1,
              }}
            >
              {loading ? "Carregando..." : "Carregar Fluxo"}
            </button>
            {flow && (
              <button
                onClick={loadFlow}
                style={{
                  padding: "8px 14px",
                  borderRadius: 8,
                  border: "1px solid var(--border, #334155)",
                  background: "transparent",
                  color: "var(--text-muted, #94a3b8)",
                  fontSize: 12,
                  cursor: "pointer",
                }}
              >
                ↺ Atualizar
              </button>
            )}
          </div>

          {error && (
            <div
              style={{
                padding: "10px 14px",
                borderRadius: 8,
                background: "#450a0a",
                color: "#fca5a5",
                marginBottom: 16,
                fontSize: 13,
              }}
            >
              {error}
            </div>
          )}

          {flow && (
            <>
              {/* Summary */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(4, 1fr)",
                  gap: 12,
                  marginBottom: 24,
                }}
              >
                {[
                  { label: "Alvo", value: flow.target, color: "#60a5fa" },
                  { label: "Atividades", value: flow.total_activities, color: "#a78bfa" },
                  { label: "Aprovadas", value: approved, color: "#22c55e" },
                  { label: "Rejeitadas", value: rejected, color: "#f87171" },
                ].map((card) => (
                  <div
                    key={card.label}
                    style={{
                      border: "1px solid var(--border, #334155)",
                      borderRadius: 10,
                      padding: "14px 16px",
                      background: "var(--bg-card, #1e293b)",
                    }}
                  >
                    <div style={{ fontSize: 11, color: "var(--text-muted, #94a3b8)", marginBottom: 4 }}>
                      {card.label}
                    </div>
                    <div style={{ fontSize: 20, fontWeight: 700, color: card.color }}>
                      {card.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* Flow diagram legend */}
              <div
                style={{
                  display: "flex",
                  gap: 8,
                  flexWrap: "wrap",
                  marginBottom: 16,
                  padding: "10px 14px",
                  borderRadius: 8,
                  background: "var(--bg-card, #1e293b)",
                  border: "1px solid var(--border, #334155)",
                }}
              >
                <span style={{ fontSize: 11, color: "#94a3b8", marginRight: 8 }}>Fluxo:</span>
                {[
                  { label: "🎯 Supervisor → Demanda", color: "#60a5fa" },
                  { label: "📚 Agente → Biblioteca", color: "#a78bfa" },
                  { label: "🔧 Catálogo de Ferramentas", color: "#fb923c" },
                  { label: "⚡ Execução", color: "#f59e0b" },
                  { label: "📋 Agente → Relatório", color: "#34d399" },
                  { label: "✅ Supervisor → Aprovação", color: "#22c55e" },
                ].map((step) => (
                  <span
                    key={step.label}
                    style={{
                      fontSize: 11,
                      padding: "3px 8px",
                      borderRadius: 6,
                      background: `${step.color}15`,
                      color: step.color,
                      border: `1px solid ${step.color}30`,
                    }}
                  >
                    {step.label}
                  </span>
                ))}
              </div>

              {/* Activities */}
              {flow.activities.length === 0 ? (
                <div
                  style={{
                    textAlign: "center",
                    padding: "40px",
                    color: "var(--text-muted, #94a3b8)",
                    fontSize: 14,
                  }}
                >
                  Nenhuma atividade registrada para este scan ainda.
                  <br />
                  <span style={{ fontSize: 12 }}>
                    Execute um scan para ver o fluxo supervisor ↔ agente em tempo real.
                  </span>
                </div>
              ) : (
                flow.activities.map((activity, i) => (
                  <ActivityCard key={activity.id} activity={activity} index={i} />
                ))
              )}
            </>
          )}

          {!flow && !loading && (
            <div
              style={{
                textAlign: "center",
                padding: "60px 20px",
                color: "var(--text-muted, #94a3b8)",
              }}
            >
              <div style={{ fontSize: 40, marginBottom: 16 }}>🔍</div>
              <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
                Digite o ID de um Scan
              </div>
              <div style={{ fontSize: 13 }}>
                Para visualizar o fluxo completo supervisor ↔ agente com skill lookup,
                seleção de ferramenta por score e relatórios de qualidade.
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
