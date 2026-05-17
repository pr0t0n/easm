import { useMemo, useState } from "react";
import AgentFlowPage from "./AgentFlowPage";
import AttackEvolutionPage from "./AttackEvolutionPage";
import JobsRegistryPage from "./JobsRegistryPage";
import PhaseMonitorPage from "./PhaseMonitorPage";
import WorkerLogsPage from "./WorkerLogsPage";
import WorkersPage from "./WorkersPage";

const modules = [
  { id: "phases", label: "Phase Monitor", component: PhaseMonitorPage },
  { id: "agents", label: "Fluxo de Agentes", component: AgentFlowPage },
  { id: "jobs", label: "Job Registry", component: JobsRegistryPage },
  { id: "workers", label: "Workers", component: WorkersPage },
  { id: "logs", label: "Worker Logs", component: WorkerLogsPage },
  { id: "evolution", label: "Attack Evolution", component: AttackEvolutionPage },
];

export default function OperationsCenterPage() {
  const [activeModule, setActiveModule] = useState("phases");
  const ActiveComponent = useMemo(
    () => modules.find((module) => module.id === activeModule)?.component || PhaseMonitorPage,
    [activeModule],
  );

  return (
    <main className="dpage">
      <div className="page-intro">
        <h2>Centro Operacional.</h2>
        <div className="sub">fases, agentes, jobs, workers, logs e evolução ofensiva em uma única área</div>
      </div>

      <div className="t-tools" style={{ marginBottom: 18 }}>
        {modules.map((module) => (
          <button
            key={module.id}
            type="button"
            onClick={() => setActiveModule(module.id)}
            className={`filter${activeModule === module.id ? " active" : ""}`}
          >
            {module.label}
          </button>
        ))}
      </div>

      <ActiveComponent />
    </main>
  );
}
