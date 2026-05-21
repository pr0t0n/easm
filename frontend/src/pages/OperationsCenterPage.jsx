import { useMemo, useState } from "react";
import ErrorBoundary from "../components/ErrorBoundary";
import AgentFlowPage from "./AgentFlowPage";
import AttackEvolutionPage from "./AttackEvolutionPage";
import JobsRegistryPage from "./JobsRegistryPage";
import PhaseMonitorPage from "./PhaseMonitorPage";
import WorkerLogsPage from "./WorkerLogsPage";
import WorkersPage from "./WorkersPage";

const modules = [
  { id: "runtime", label: "RedTeam Runtime", hint: "fase, comandos, saidas e comunicacao", component: WorkerLogsPage },
  { id: "phases", label: "Phase Monitor", hint: "22 fases e validadores", component: PhaseMonitorPage },
  { id: "agents", label: "Fluxo de Agentes", hint: "supervisor e grafo", component: AgentFlowPage },
  { id: "evolution", label: "Attack Evolution", hint: "diff historico e postura", component: AttackEvolutionPage },
  { id: "workers", label: "Workers", hint: "saude e capacidade", component: WorkersPage },
  { id: "jobs", label: "Job Registry", hint: "execucoes e auditoria", component: JobsRegistryPage },
];

export default function OperationsCenterPage() {
  const [activeModule, setActiveModule] = useState("runtime");
  const ActiveComponent = useMemo(
    () => modules.find((module) => module.id === activeModule)?.component || WorkerLogsPage,
    [activeModule],
  );
  const activeMeta = modules.find((module) => module.id === activeModule) || modules[0];

  return (
    <main className="dpage">
      <div className="page-intro">
        <h2>Centro Operacional.</h2>
        <div className="sub">cabine única para operador RedTeam: runtime, fases, agentes, evolução, workers e jobs</div>
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
            <div className="mono-sm muted">diff e merge</div>
            <strong style={{ display: "block", color: "var(--ink)", marginTop: 4 }}>Attack Evolution integrado</strong>
            <div className="mono-sm soft" style={{ marginTop: 2 }}>mantem a tela atual como modulo do centro</div>
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
