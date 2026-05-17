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
    <main className="flex flex-col gap-0">
      <div className="border-b border-slate-800/50 bg-gradient-to-r from-slate-900/20 to-slate-950/40 px-8 py-6">
        <div className="mx-auto max-w-7xl">
          <h1 className="section-title">Centro Operacional</h1>
          <p className="mt-2 text-sm text-slate-400">
            Monitoramento de fases, agentes, jobs, workers, logs e evolução ofensiva em uma única área.
          </p>
        </div>
      </div>

      <div className="flex-1 px-8 py-8">
        <div className="mx-auto max-w-7xl space-y-6">
          <div className="panel flex flex-wrap gap-2 p-2">
            {modules.map((module) => (
              <button
                key={module.id}
                type="button"
                onClick={() => setActiveModule(module.id)}
                className={`rounded-lg px-3 py-2 text-xs font-semibold transition md:text-sm ${
                  activeModule === module.id
                    ? "bg-blue-600 text-white"
                    : "border border-slate-700 bg-slate-900/40 text-slate-300 hover:bg-slate-800"
                }`}
              >
                {module.label}
              </button>
            ))}
          </div>

          <ActiveComponent />
        </div>
      </div>
    </main>
  );
}
