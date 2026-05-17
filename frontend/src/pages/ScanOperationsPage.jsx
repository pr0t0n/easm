import { useState } from "react";
import ScansPage from "./ScansPage";
import SchedulingPage from "./SchedulingPage";

const tabs = [
  { id: "unit", label: "Scan unitário" },
  { id: "schedule", label: "Scan agendado" },
];

export default function ScanOperationsPage() {
  const [activeTab, setActiveTab] = useState("unit");

  return (
    <main className="flex flex-col gap-0">
      <div className="border-b border-slate-800/50 bg-gradient-to-r from-slate-900/20 to-slate-950/40 px-8 py-6">
        <div className="mx-auto max-w-7xl">
          <h1 className="section-title">Scans e Agendamentos</h1>
          <p className="mt-2 text-sm text-slate-400">
            Uma única área para executar scans sob demanda ou configurar recorrência operacional.
          </p>
        </div>
      </div>

      <div className="flex-1 px-8 py-8">
        <div className="mx-auto max-w-7xl space-y-6">
          <div className="panel flex flex-wrap gap-2 p-2">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
                  activeTab === tab.id
                    ? "bg-blue-600 text-white"
                    : "border border-slate-700 bg-slate-900/40 text-slate-300 hover:bg-slate-800"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {activeTab === "unit" ? <ScansPage embedded /> : <SchedulingPage embedded />}
        </div>
      </div>
    </main>
  );
}
