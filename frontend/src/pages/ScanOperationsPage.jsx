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
    <main className="dpage">
      <div className="page-intro">
        <h2>Execuções e agendamentos.</h2>
        <div className="sub">uma única área para executar scans sob demanda ou configurar recorrência operacional</div>
      </div>

      <div className="t-tools" style={{ marginBottom: 18 }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`filter${activeTab === tab.id ? " active" : ""}`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "unit" ? <ScansPage embedded /> : <SchedulingPage embedded />}
    </main>
  );
}
