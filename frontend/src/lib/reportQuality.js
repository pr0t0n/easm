export function remediationPriority(finding = {}) {
  const severity = String(finding.severity || "").toLowerCase();
  if (severity === "critical" || (finding.isJewel && finding.status === "confirmed")) return "P0";
  if (severity === "high") return "P1";
  if (severity === "medium") return "P2";
  return null;
}

export function remediationSla(priority) {
  return ({
    P0: { due: "24–72h", effort: "Imediato", owner: "SecOps + sistema" },
    P1: { due: "7 dias", effort: "Sprint atual", owner: "Time do sistema" },
    P2: { due: "30 dias", effort: "Próxima sprint", owner: "Backlog priorizado" },
  })[priority] || { due: "Definir", effort: "Triar", owner: "Atribuir" };
}

export function isTerminalScanStatus(status) {
  return ["completed", "completed_with_gaps", "failed", "cancelled", "stopped"].includes(String(status || "").toLowerCase());
}
