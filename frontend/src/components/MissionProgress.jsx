import { useMemo } from "react";

const PIPELINE_LABELS = {
  "1. AssetDiscovery": "Reconhecimento",
  "2. ThreatIntel": "OSINT / Threat Intel",
  "3. RiskAssessment": "Análise de Vulnerabilidade",
  "4. Governance": "Governança FAIR+AGE",
  "5. ExecutiveAnalysis": "Análise Executiva",
};

export default function MissionProgress({ scan, scanStatus }) {
  const pipeline = useMemo(() => {
    if (!scan) return null;

    const missionItems = scanStatus?.mission_items?.length
      ? scanStatus.mission_items
      : ["1. AssetDiscovery", "2. ThreatIntel", "3. RiskAssessment", "4. Governance", "5. ExecutiveAnalysis"];

    const missionIndex = scanStatus?.mission_index ?? 0;
    const scanDone = scan.status === "completed" || scan.status === "failed" || scan.status === "stopped";
    const scanRunning = scan.status === "running" || scan.status === "retrying";
    const burpStatus = scanStatus?.burp_status || "none";

    const steps = missionItems.map((item, idx) => {
      const label = PIPELINE_LABELS[item] || item.replace(/^\d+\.\s*/, "");
      let status = "pending";
      if (scanDone) {
        status = "completed";
      } else if (scanRunning) {
        if (idx < missionIndex) status = "completed";
        else if (idx === missionIndex) status = "running";
        else status = "pending";
      }
      return { id: idx, key: item, label, status };
    });

    // Enriquece step de RiskAssessment com info Engine vs Burp
    const riskStep = steps.find((s) => s.key === "3. RiskAssessment");
    let engineStatus = "pending";
    let burpDisplay = "pending";

    if (riskStep) {
      if (riskStep.status === "completed" || riskStep.status === "running") {
        // Engine (nmap, nikto) roda síncrono — se risk_assessment está completo, engine terminou
        engineStatus = riskStep.status === "completed" ? "completed" : "running";
      }
      // Burp é assíncrono
      if (burpStatus === "completed") burpDisplay = "completed";
      else if (burpStatus === "pending" || burpStatus === "scheduled") burpDisplay = "running";
      else if (riskStep.status === "completed" && burpStatus === "none") burpDisplay = "skipped";
      else burpDisplay = "pending";

      if (burpStatus === "error") burpDisplay = "error";
    }

    return { steps, engineStatus, burpDisplay, burpStatus, scanDone, scanRunning };
  }, [scan, scanStatus]);

  if (!pipeline) {
    return (
      <section className="panel p-6">
        <h3 className="text-sm font-semibold mb-4">📊 Progresso do Pipeline</h3>
        <p className="text-xs text-slate-400 text-center py-4">Aguardando inicialização...</p>
      </section>
    );
  }

  const colorMap = {
    completed: "bg-green-900/30 border-green-700/50 text-green-300",
    running: "bg-blue-900/30 border-blue-700/50 text-blue-300 animate-pulse",
    pending: "bg-slate-800/30 border-slate-700/50 text-slate-400",
    skipped: "bg-slate-800/20 border-slate-700/30 text-slate-500",
    error: "bg-red-900/30 border-red-700/50 text-red-300",
  };
  const iconMap = {
    completed: "✅",
    running: "▶️",
    pending: "⏳",
    skipped: "⊘",
    error: "❌",
  };
  const labelMap = {
    completed: "Concluída",
    running: "Em execução",
    pending: "Pendente",
    skipped: "N/A",
    error: "Erro",
  };

  const barWidth = {
    completed: "w-full",
    running: "w-2/3",
    pending: "w-0",
    skipped: "w-0",
    error: "w-1/3",
  };
  const barColor = {
    completed: "bg-green-500",
    running: "bg-blue-500",
    pending: "bg-slate-500",
    skipped: "bg-slate-600",
    error: "bg-red-500",
  };

  return (
    <section className="panel p-6">
      <h3 className="text-sm font-semibold mb-4">📊 Progresso do Pipeline</h3>

      <div className="space-y-3">
        {pipeline.steps.map((step) => {
          const isRisk = step.key === "3. RiskAssessment";

          return (
            <div key={step.id}>
              <div className={`rounded-lg border p-3 transition-all ${colorMap[step.status]}`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{iconMap[step.status]}</span>
                    <span className="text-sm font-medium">{step.label}</span>
                  </div>
                  <span className="text-xs font-mono px-2 py-1 rounded bg-black/30">
                    {labelMap[step.status]}
                  </span>
                </div>
                <div className="mt-2 h-1 bg-black/20 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all ${barWidth[step.status]} ${barColor[step.status]}`}
                    style={{
                      animation: step.status === "running" ? "pulse 2s ease-in-out infinite" : "none",
                    }}
                  />
                </div>
              </div>

              {/* Sub-itens Engine vs Burp no step de RiskAssessment */}
              {isRisk && (step.status === "running" || step.status === "completed") && (
                <div className="ml-6 mt-2 space-y-2">
                  {/* Engine (nmap-vulscan, nikto) */}
                  <div className={`rounded border p-2 text-xs ${colorMap[pipeline.engineStatus]}`}>
                    <div className="flex items-center justify-between">
                      <span>
                        {iconMap[pipeline.engineStatus]} <b>A</b> — Engine (nmap-vulscan, nikto)
                      </span>
                      <span className="font-mono px-1.5 py-0.5 rounded bg-black/30">
                        {labelMap[pipeline.engineStatus]}
                      </span>
                    </div>
                  </div>

                  {/* Burp Suite */}
                  <div className={`rounded border p-2 text-xs ${colorMap[pipeline.burpDisplay]}`}>
                    <div className="flex items-center justify-between">
                      <span>
                        {iconMap[pipeline.burpDisplay]} <b>B</b> — Burp Suite (async)
                      </span>
                      <span className="font-mono px-1.5 py-0.5 rounded bg-black/30">
                        {pipeline.burpDisplay === "running"
                          ? "Em execução (async)"
                          : pipeline.burpDisplay === "skipped"
                          ? "Não habilitado"
                          : labelMap[pipeline.burpDisplay]}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Progresso global */}
      <div className="mt-4 pt-4 border-t border-slate-700/50 flex items-center justify-between text-xs text-slate-400">
        <span>Progresso global: {scan.mission_progress || 0}%</span>
        {pipeline.burpStatus === "pending" && (
          <span className="text-amber-400">⏳ Burp executando em paralelo</span>
        )}
        {pipeline.burpStatus === "completed" && (
          <span className="text-green-400">✅ Burp concluído — rating recalculado</span>
        )}
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
      `}</style>
    </section>
  );
}
