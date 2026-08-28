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

export function completedWithGapsSummary(scan = {}, qualityOverride = null) {
  const status = String(scan?.status || "").toLowerCase();
  const state = scan?.state_data || {};
  const quality = qualityOverride || state.quality_snapshot || state.scan_quality || state.quality || {};
  const gate = quality.quality_gate || state.quality_gate || {};
  const gaps = Array.isArray(quality.gaps) ? quality.gaps : [];
  const blockers = Array.isArray(gate.blockers) ? gate.blockers : [];
  const gapCount = Number(gate.gap_count ?? gaps.length ?? 0);
  const highCount = gaps.filter((gap) => ["critical", "high"].includes(String(gap?.severity || "").toLowerCase())).length;
  const score = quality.score == null ? null : Math.max(0, Math.min(100, Number(quality.score || 0)));
  const visible = status === "completed_with_gaps" || String(gate.completion_status || "").toLowerCase() === "completed_with_gaps";
  const detailParts = [];
  if (Number.isFinite(score)) detailParts.push(`${score.toFixed(1)}% qualidade`);
  if (gapCount > 0) detailParts.push(`${gapCount} gap(s)`);
  if (highCount > 0) detailParts.push(`${highCount} crítico(s)/alto(s)`);
  if (blockers.length > 0) detailParts.push(`${blockers.length} bloqueador(es) preservado(s)`);
  return {
    visible,
    label: "Concluído com gaps",
    detail: detailParts.join(" · ") || "Finalizado com cobertura incompleta visível",
    gapCount,
    highCount,
    blockersCount: blockers.length,
    score,
  };
}
