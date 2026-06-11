import { useMemo, useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import ErrorBoundary from "../components/ErrorBoundary";
import AgentFlowPage from "./AgentFlowPage";
import AttackEvolutionPage from "./AttackEvolutionPage";
import JobsRegistryPage from "./JobsRegistryPage";
import PhaseMonitorPage from "./PhaseMonitorPage";
import WorkerLogsPage from "./WorkerLogsPage";
import WorkersPage from "./WorkersPage";
import PlatformHealthPage from "./PlatformHealthPage";
import LearningPage from "./LearningPage";
import client from "../api/client";

function SubTabs({ tabs, activeId, onSelect }) {
  return (
    <div style={{ display: "flex", gap: 6, marginBottom: 16, borderBottom: "1px solid var(--border)", paddingBottom: 10 }}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onSelect(t.id)}
          style={{
            padding: "4px 14px",
            borderRadius: 6,
            border: activeId === t.id ? "1px solid var(--brand-600)" : "1px solid var(--border)",
            background: activeId === t.id ? "var(--brand-600)" : "transparent",
            color: activeId === t.id ? "#fff" : "var(--muted)",
            fontSize: 12,
            fontWeight: 500,
            cursor: "pointer",
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ── Intelligence View (Crown Jewels + LLM Operator + OSINT) ──────────────────
function IntelligenceView() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState("");
  const [crownJewels, setCrownJewels] = useState([]);
  const [osint, setOsint] = useState(null);
  const [narrative, setNarrative] = useState("");
  const [narrativeMethod, setNarrativeMethod] = useState("");
  const [generatingNarrative, setGeneratingNarrative] = useState(false);
  const [narrativeError, setNarrativeError] = useState("");
  const [learning, setLearning] = useState(null);

  useEffect(() => {
    client.get("/api/scans", { params: { limit: 50 } }).then(({ data }) => {
      const list = Array.isArray(data) ? data : [];
      setScans(list);
      if (list.length) setSelectedScan(String(list[0].id));
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedScan) return;
    client.get(`/api/scans/${selectedScan}/crown-jewels`)
      .then(({ data }) => setCrownJewels(Array.isArray(data?.crown_jewels) ? data.crown_jewels : []))
      .catch(() => setCrownJewels([]));
    client.get(`/api/scans/${selectedScan}/osint`, { _skipToast: true })
      .then(({ data }) => setOsint(data?.osint || null))
      .catch(() => setOsint(null));
    client.get(`/api/scans/${selectedScan}/attack-narrative`)
      .then(({ data }) => { setNarrative(data.narrative || ""); setNarrativeMethod(data.method || ""); })
      .catch(() => { setNarrative(""); setNarrativeMethod(""); });
    client.get(`/api/scans/${selectedScan}/learning-usage`)
      .then(({ data }) => setLearning(data || null))
      .catch(() => setLearning(null));
  }, [selectedScan]);

  const generateNarrative = async () => {
    setGeneratingNarrative(true);
    setNarrativeError("");
    try {
      const { data } = await client.post(`/api/scans/${selectedScan}/generate-narrative`);
      setNarrative(data.narrative || "");
      setNarrativeMethod(data.method || "");
    } catch (err) {
      setNarrativeError(err?.response?.data?.detail || "Falha ao gerar narrativa.");
    } finally {
      setGeneratingNarrative(false);
    }
  };

  const CROWN_COLORS = {
    "identity/auth": "#7c3aed", "payment/financial": "#b45309", "admin_panel": "#dc2626",
    "data_store": "#1d4ed8", "cicd": "#0f766e", "secrets_mgmt": "#7c3aed",
  };

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <span style={{ fontWeight: 700 }}>🧠 Inteligência de Ataque</span>
        <select
          value={selectedScan}
          onChange={(e) => setSelectedScan(e.target.value)}
          style={{ padding: "6px 10px", borderRadius: 8, border: "1px solid var(--line)", fontSize: 12.5 }}
        >
          {scans.map((s) => (
            <option key={s.id} value={s.id}>#{s.id} · {String(s.target_query || "").slice(0, 50)}</option>
          ))}
        </select>
      </div>

      {/* ── Aprendizado HackerOne: uso + acertividade (P3a) ── */}
      <div style={{ padding: "16px 20px", background: "var(--canvas-soft)", borderRadius: 10, border: "1px solid var(--line)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <span style={{ fontWeight: 700, fontSize: 14, color: "var(--ink)" }}>🧠 Aprendizado HackerOne — Uso &amp; Acertividade</span>
          {learning && <span style={{ fontSize: 11, color: "var(--ink-muted)" }}>base: {Number(learning.learning_base_size || 0).toLocaleString()} learnings aceitos</span>}
        </div>
        {!learning || (learning.summary?.total_seeded || 0) === 0 ? (
          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
            Nenhuma técnica de aprendizado semeada ainda neste scan (ocorre após detecção de tecnologia em P07).
          </div>
        ) : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(120px,1fr))", gap: 10, marginBottom: 12 }}>
              {[
                ["Técnicas semeadas", learning.summary.total_seeded, "var(--sev-info-text)"],
                ["Completadas", learning.summary.completed, "var(--brand-700)"],
                ["Achados gerados", learning.summary.findings_produced, "var(--sev-low-text)"],
                ["Acertividade", `${learning.summary.accuracy_pct}%`, "var(--sev-medium-text)"],
                ["Taxa confirmação", `${learning.summary.confirm_rate_pct}%`, "var(--sev-high-text)"],
              ].map(([lbl, val, color]) => (
                <div key={lbl} style={{ background: "#fff", borderRadius: 8, padding: "10px 12px", textAlign: "center", border: "1px solid var(--line)" }}>
                  <div style={{ fontSize: 22, fontWeight: 800, color }}>{val}</div>
                  <div style={{ fontSize: 10, color: "var(--ink-muted)", marginTop: 2 }}>{lbl}</div>
                </div>
              ))}
            </div>
            {/* Por que foi usado: tech stacks */}
            {(learning.tech_stacks || []).length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: "var(--ink-muted)", marginBottom: 4 }}>Por que foi usado — stacks detectados que dispararam o aprendizado:</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {learning.tech_stacks.slice(0, 10).map((t) => (
                    <span key={t.tech} style={{ fontSize: 11, background: "var(--sev-info-bg)", color: "var(--sev-info-text)", border: "1px solid var(--sev-info-border)", padding: "2px 8px", borderRadius: 10 }}>{t.tech} ×{t.count}</span>
                  ))}
                </div>
              </div>
            )}
            {/* Por CLASSE de vulnerabilidade (família) — utilização + acertividade */}
            {(learning.by_family || []).length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: "var(--ink-muted)", marginBottom: 6 }}>Por classe de vulnerabilidade (similaridade ao alvo → utilização → acertividade):</div>
                <div style={{ display: "grid", gap: 4 }}>
                  {learning.by_family.map((fam) => {
                    const acc = Number(fam.accuracy_pct || 0);
                    const accColor = acc >= 50 ? "var(--sev-low-text)" : acc > 0 ? "var(--sev-medium-text)" : "var(--ink-muted)";
                    const sim = Number(fam.similarity_pct || 0);
                    const isSemantic = fam.engine === "semantic_match";
                    const reports = fam.matched_reports || [];
                    return (
                      <div key={fam.family} style={{ padding: "5px 8px", background: "#fff", borderRadius: 6, border: "1px solid var(--line)" }}>
                        <div style={{ display: "grid", gridTemplateColumns: "130px 1fr 150px", gap: 8, alignItems: "center", fontSize: 11 }}>
                          <span style={{ fontWeight: 700, color: "var(--ink)", textTransform: "uppercase", letterSpacing: "0.03em" }}>{String(fam.family).replace(/_/g, " ")}</span>
                          <span style={{ color: "var(--ink-muted)", fontFamily: "var(--font-mono)", fontSize: 10 }}>
                            {sim > 0 && <b style={{ color: "var(--sev-info-text)" }}>{sim}% similar</b>}{sim > 0 ? " · " : ""}
                            {Number(fam.learning_count || 0).toLocaleString()} aprend. · {fam.seeded} semeadas · {fam.completed} ok · <b style={{ color: "var(--sev-low-text)" }}>{fam.findings} achados</b>
                          </span>
                          <span style={{ textAlign: "right", fontWeight: 800, color: accColor }}>{acc}% acertividade</span>
                        </div>
                        {(isSemantic && reports.length > 0) && (
                          <div style={{ marginTop: 3, fontSize: 9.5, color: "var(--ink-muted)", fontFamily: "var(--font-mono)" }}>
                            ↳ matched por similaridade aos reports HackerOne #{reports.join(", #")}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            {/* Por técnica/ferramenta (detalhe) */}
            {(learning.by_tool || []).length > 0 && (
              <details style={{ marginBottom: 10 }}>
                <summary style={{ fontSize: 11, color: "var(--ink-muted)", cursor: "pointer" }}>Detalhe por ferramenta…</summary>
                <div style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 6 }}>
                  {learning.by_tool.slice(0, 16).map((t) => (
                    <div key={t.tool} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, fontFamily: "var(--font-mono)" }}>
                      <span style={{ color: "var(--ink-soft)" }}>{t.tool}</span>
                      <span style={{ color: "var(--ink-muted)" }}>{t.seeded} semeadas · {t.completed} ok · <b style={{ color: "var(--sev-low-text)" }}>{t.findings || 0} achados</b></span>
                    </div>
                  ))}
                </div>
              </details>
            )}
            <div style={{ fontSize: 10.5, color: "var(--ink-muted)", borderTop: "1px solid var(--line)", paddingTop: 8, lineHeight: 1.5 }}>
              {learning.rationale}
            </div>
          </>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        {/* Crown Jewels */}
        <div style={{ padding: "14px 18px", background: "var(--canvas-soft)", borderRadius: 10, border: "1px solid var(--line)" }}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 10 }}>⭐ Crown Jewels ({crownJewels.length})</div>
          {crownJewels.length === 0 ? (
            <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>Análise ainda não executada (roda após 3+ items P01/P02)</div>
          ) : (
            <div style={{ display: "grid", gap: 6 }}>
              {crownJewels.slice(0, 8).map((cj) => (
                <div key={cj.target} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 10px", background: "#fff", borderRadius: 6, border: `1px solid ${CROWN_COLORS[cj.label] || "#e5e7eb"}` }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 600 }}>{cj.target}</span>
                  <span style={{ fontSize: 10.5, fontWeight: 700, color: CROWN_COLORS[cj.label] || "#6b7280" }}>{cj.label?.replace(/_/g, " ")}</span>
                </div>
              ))}
              {crownJewels.length > 8 && <div style={{ fontSize: 11, color: "var(--ink-muted)" }}>+{crownJewels.length - 8} mais…</div>}
            </div>
          )}
        </div>

        {/* OSINT Phase Zero */}
        <div style={{ padding: "14px 18px", background: "var(--canvas-soft)", borderRadius: 10, border: "1px solid var(--line)" }}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 10 }}>🔍 OSINT Phase Zero</div>
          {!osint ? (
            <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>Sem dados OSINT para este scan (configure HIBP_API_KEY e/ou GITHUB_TOKEN)</div>
          ) : (
            <div style={{ display: "grid", gap: 8 }}>
              {osint.hibp && !osint.hibp.skipped && (
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <span>🔓 HIBP emails em breach</span>
                  <strong style={{ color: osint.hibp.emails_breached > 0 ? "#dc2626" : "#16a34a" }}>{osint.hibp.emails_breached || 0}</strong>
                </div>
              )}
              {osint.github_dork && !osint.github_dork.skipped && (
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <span>📂 GitHub secrets/env expostos</span>
                  <strong style={{ color: osint.github_dork.results_count > 0 ? "#b45309" : "#16a34a" }}>{osint.github_dork.results_count || 0}</strong>
                </div>
              )}
              {osint.shodan_asn && !osint.shodan_asn.skipped && (
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                  <span>🌐 IPs Shodan ASN {osint.shodan_asn.asn}</span>
                  <strong>{(osint.shodan_asn.total_hosts_in_asn || 0).toLocaleString("pt-BR")}</strong>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Attack Narrative */}
      <div style={{ padding: "14px 18px", background: "var(--canvas-soft)", borderRadius: 10, border: "1px solid var(--line)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <div style={{ fontWeight: 700, fontSize: 13 }}>
            📖 Narrativa de Ataque
            {narrativeMethod && <span style={{ fontWeight: 400, fontSize: 11, color: "var(--ink-muted)", marginLeft: 6 }}>via {narrativeMethod}</span>}
          </div>
          <button
            onClick={generateNarrative}
            disabled={generatingNarrative || !selectedScan}
            style={{ padding: "6px 14px", borderRadius: 8, border: "1px solid var(--brand-500)", background: "var(--brand-500)", color: "#fff", fontSize: 12, fontWeight: 600, cursor: "pointer", opacity: generatingNarrative ? 0.6 : 1 }}
          >
            {generatingNarrative ? "⟳ Gerando…" : "⚡ Gerar Narrativa"}
          </button>
        </div>
        {narrativeError && <div style={{ color: "#dc2626", fontSize: 12, marginBottom: 8 }}>{narrativeError}</div>}
        {narrative ? (
          <div style={{
            fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.7,
            whiteSpace: "pre-wrap", maxHeight: 480, overflowY: "auto",
            background: "#0f172a", color: "#e2e8f0", padding: "14px 16px",
            borderRadius: 8,
          }}>
            {narrative}
          </div>
        ) : (
          <div style={{ fontSize: 12, color: "var(--ink-muted)" }}>
            Narrativa não gerada ainda. Clique em "Gerar Narrativa" para criar um relatório de ataque em linguagem natural (PT-BR) com Ollama.
          </div>
        )}
      </div>
    </div>
  );
}

function PhasesAgentsView() {
  const [sub, setSub] = useState("phases");
  return (
    <div>
      <SubTabs
        tabs={[
          { id: "phases", label: "Phase Monitor" },
          { id: "agents", label: "Fluxo de Agentes" },
        ]}
        activeId={sub}
        onSelect={setSub}
      />
      <ErrorBoundary key={sub}>
        {sub === "phases" ? <PhaseMonitorPage /> : <AgentFlowPage />}
      </ErrorBoundary>
    </div>
  );
}

function EvolutionInfraView() {
  const [sub, setSub] = useState("evolution");
  return (
    <div>
      <SubTabs
        tabs={[
          { id: "evolution", label: "Attack Evolution" },
          { id: "workers", label: "Workers" },
          { id: "jobs", label: "Job Registry" },
        ]}
        activeId={sub}
        onSelect={setSub}
      />
      <ErrorBoundary key={sub}>
        {sub === "evolution" ? <AttackEvolutionPage /> : sub === "workers" ? <WorkersPage /> : <JobsRegistryPage />}
      </ErrorBoundary>
    </div>
  );
}

const modules = [
  { id: "runtime", label: "RedTeam Runtime", hint: "fase, comandos, saidas e comunicacao", component: WorkerLogsPage },
  { id: "phases_agents", label: "Fases & Agentes", hint: "phase monitor + fluxo de agentes", component: PhasesAgentsView },
  { id: "infra", label: "Workers & Jobs", hint: "workers ao vivo, fila, registro de jobs e evolução", component: EvolutionInfraView },
  { id: "aprendizado", label: "Aprendizado HackerOne", hint: "treinar técnicas via URLs HackerOne + aceite humano", component: LearningPage },
  { id: "intel", label: "Inteligência", hint: "crown jewels, OSINT, LLM chains, narrativa", component: IntelligenceView },
  { id: "health", label: "Saúde da Plataforma", hint: "status/health dos containers + alertas + último erro", component: PlatformHealthPage },
];

const MODULE_ALIASES = {
  phases: "phases_agents",
  agents: "phases_agents",
  evolution: "infra",
  workers: "infra",
  jobs: "infra",
  learning: "aprendizado",
};

export default function OperationsCenterPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeModule, setActiveModule] = useState(() => {
    const m = searchParams.get("module");
    const resolved = MODULE_ALIASES[m] || m;
    return modules.some((mod) => mod.id === resolved) ? resolved : "runtime";
  });

  useEffect(() => {
    setSearchParams({ module: activeModule }, { replace: true });
  }, [activeModule, setSearchParams]);

  const ActiveComponent = useMemo(
    () => modules.find((module) => module.id === activeModule)?.component || WorkerLogsPage,
    [activeModule],
  );
  const activeMeta = modules.find((module) => module.id === activeModule) || modules[0];

  return (
    <main className="dpage">
      <div className="page-intro">
        <h2>Centro Operacional.</h2>
        <div className="sub">cabine única para operador RedTeam: runtime, fases &amp; agentes, evolução &amp; infra</div>
      </div>

      {/* ── Banner informativo — apenas precaução, sem bloqueios ── */}
      <div style={{
        display: "flex", alignItems: "flex-start", gap: 12,
        padding: "11px 16px", marginBottom: 16,
        background: "#fefce8", border: "1px solid #fde68a",
        borderRadius: 10, fontSize: 12.5, color: "#92400e",
      }}>
        <span style={{ fontSize: 16, flexShrink: 0 }}>⚠️</span>
        <span>
          <strong>Execute testes apenas em ambientes autorizados.</strong>
          {" "}Certifique-se de ter autorização formal do proprietário do alvo antes de iniciar qualquer scan.
          Testes em sistemas sem autorização são ilegais — o uso desta plataforma implica em responsabilidade do operador.
        </span>
      </div>

      <section className="panel p-4" style={{ marginBottom: 16 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 10 }}>
          <div>
            <div className="mono-sm muted">modulo ativo</div>
            <strong style={{ display: "block", color: "var(--ink)", marginTop: 4 }}>{activeMeta.label}</strong>
            <div className="mono-sm soft" style={{ marginTop: 2 }}>{activeMeta.hint}</div>
          </div>
          <div>
            <div className="mono-sm muted">visao operacional</div>
            <strong style={{ display: "block", color: "var(--ink)", marginTop: 4 }}>Supervisor → Workers → MCP → Kali</strong>
            <div className="mono-sm soft" style={{ marginTop: 2 }}>comandos, respostas, progresso e falhas no mesmo lugar</div>
          </div>
          <div>
            <div className="mono-sm muted">agrupamentos</div>
            <strong style={{ display: "block", color: "var(--ink)", marginTop: 4 }}>4 módulos, 7 sub-views</strong>
            <div className="mono-sm soft" style={{ marginTop: 2 }}>inteligência (crown jewels, OSINT, LLM, narrativa)</div>
          </div>
        </div>
      </section>

      <div className="t-tools" style={{ marginBottom: 18 }}>
        {modules.map((module) => (
          <button
            key={module.id}
            type="button"
            onClick={() => setActiveModule(module.id)}
            className={`filter${activeModule === module.id ? " active" : ""}`}
            title={module.hint}
          >
            {module.label}
          </button>
        ))}
      </div>

      <ErrorBoundary key={activeModule}>
        <ActiveComponent />
      </ErrorBoundary>
    </main>
  );
}
