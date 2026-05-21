import { useMemo, useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import ErrorBoundary from "../components/ErrorBoundary";
import AgentFlowPage from "./AgentFlowPage";
import AttackEvolutionPage from "./AttackEvolutionPage";
import JobsRegistryPage from "./JobsRegistryPage";
import PhaseMonitorPage from "./PhaseMonitorPage";
import WorkerLogsPage from "./WorkerLogsPage";
import WorkersPage from "./WorkersPage";

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
            border: activeId === t.id ? "1px solid var(--accent)" : "1px solid var(--border)",
            background: activeId === t.id ? "var(--accent)" : "transparent",
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
  { id: "infra", label: "Evolução & Infra", hint: "attack evolution, workers e job registry", component: EvolutionInfraView },
];

const MODULE_ALIASES = {
  phases: "phases_agents",
  agents: "phases_agents",
  evolution: "infra",
  workers: "infra",
  jobs: "infra",
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
            <strong style={{ display: "block", color: "var(--ink)", marginTop: 4 }}>3 módulos, 6 sub-views</strong>
            <div className="mono-sm soft" style={{ marginTop: 2 }}>fases+agentes juntos · evolution+workers+jobs juntos</div>
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
