import { useMemo } from "react";

export default function MissionProgress({ scan, logs }) {
  // Extrai informações de progresso dos logs
  const missionStatus = useMemo(() => {
    if (!logs || logs.length === 0 || !scan) return null;

    // Procura pelos logs de resumo de missões
    const progressLogs = logs.filter(
      (log) => log.source === "worker.progress_detail" || log.source === "worker.summary"
    );

    if (progressLogs.length === 0) return null;

    // Extrai o último log de progresso
    const lastProgressLog = progressLogs[progressLogs.length - 1];
    const message = lastProgressLog.message || "";

    // Define as missões padrão
    const missions = [
      { id: 1, name: "Reconhecimento", emoji: "1️⃣" },
      { id: 2, name: "Análise de Vulnerabilidade", emoji: "2️⃣" },
      { id: 3, name: "OSINT", emoji: "3️⃣" },
    ];

    // Tenta extrair informações do message
    // Se tem ✅ na missão 1, está completa
    // Se tem ▶️ na missão 2, está em execução
    // Se tem ⏳ na missão 3, está pendente
    
    const parseStatus = () => {
      const result = {};
      missions.forEach((mission) => {
        if (message.includes(`✅ ${mission.id}`)) {
          result[mission.id] = "completed";
        } else if (message.includes(`▶️ ${mission.id}`)) {
          result[mission.id] = "running";
        } else if (message.includes(`⏳ ${mission.id}`)) {
          result[mission.id] = "pending";
        } else {
          // Fallback: baseado em mission_progress
          if (scan.mission_progress >= 90) result[mission.id] = "completed";
          else if (scan.mission_progress >= 40) result[mission.id] = "running";
          else result[mission.id] = "pending";
        }
      });
      return result;
    };

    return {
      missions,
      status: parseStatus(),
      lastLog: lastProgressLog,
      message,
    };
  }, [logs, scan]);

  if (!missionStatus) {
    return (
      <section className="panel p-6">
        <h3 className="text-sm font-semibold mb-4">📊 Progresso das Missões</h3>
        <p className="text-xs text-slate-400 text-center py-4">Aguardando atualização...</p>
      </section>
    );
  }

  const getMissionColor = (status) => {
    switch (status) {
      case "completed":
        return "bg-green-900/30 border-green-700/50 text-green-300";
      case "running":
        return "bg-blue-900/30 border-blue-700/50 text-blue-300 animate-pulse";
      case "pending":
        return "bg-slate-800/30 border-slate-700/50 text-slate-400";
      default:
        return "bg-slate-800/30 border-slate-700/50 text-slate-400";
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "completed":
        return "✅";
      case "running":
        return "▶️";
      case "pending":
        return "⏳";
      default:
        return "○";
    }
  };

  return (
    <section className="panel p-6">
      <h3 className="text-sm font-semibold mb-4">📊 Progresso das Missões</h3>
      
      <div className="space-y-3">
        {missionStatus.missions.map((mission) => {
          const status = missionStatus.status[mission.id];
          const color = getMissionColor(status);
          const icon = getStatusIcon(status);

          return (
            <div
              key={mission.id}
              className={`rounded-lg border p-3 transition-all ${color}`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-lg">{icon}</span>
                  <span className="text-sm font-medium">{mission.name}</span>
                </div>
                <span className="text-xs font-mono px-2 py-1 rounded bg-black/30">
                  {status === "completed"
                    ? "Concluída"
                    : status === "running"
                    ? "Em execução"
                    : "Pendente"}
                </span>
              </div>

              {/* Barra de progresso simplificada */}
              <div className="mt-2 h-1 bg-black/20 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all ${
                    status === "completed"
                      ? "w-full bg-green-500"
                      : status === "running"
                      ? "w-2/3 bg-blue-500"
                      : "w-0 bg-slate-500"
                  }`}
                  style={{
                    animation: status === "running" ? "pulse 2s ease-in-out infinite" : "none",
                  }}
                ></div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Informação adicional */}
      {missionStatus.lastLog && (
        <div className="mt-4 pt-4 border-t border-slate-700/50 text-xs text-slate-400">
          <p>
            <span className="text-slate-500">Atualizado:</span>{" "}
            {new Date(missionStatus.lastLog.created_at).toLocaleTimeString("pt-BR")}
          </p>
        </div>
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
      `}</style>
    </section>
  );
}
