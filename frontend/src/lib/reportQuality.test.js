import test from "node:test";
import assert from "node:assert/strict";

import {
  completedWithGapsSummary,
  isTerminalScanStatus,
  remediationPriority,
  remediationSla,
  verificationStatusDescriptor,
  verificationStatusSummary,
} from "./reportQuality.js";

test("quality completion with gaps remains terminal and visible", () => {
  assert.equal(isTerminalScanStatus("completed_with_gaps"), true);
  const summary = completedWithGapsSummary({
    status: "completed_with_gaps",
    state_data: {
      quality_snapshot: {
        score: 64.25,
        gaps: [
          { severity: "high", title: "Auth incompleto" },
          { severity: "medium", title: "JS parcial" },
        ],
        quality_gate: { gap_count: 2, blockers: [{ area: "auth" }] },
      },
    },
  });
  assert.equal(summary.visible, true);
  assert.equal(summary.label, "Concluído com gaps");
  assert.equal(summary.gapCount, 2);
  assert.equal(summary.highCount, 1);
  assert.match(summary.detail, /64\.3% qualidade/);
});

test("remediation priority and SLA are deterministic", () => {
  assert.equal(remediationPriority({ severity: "critical" }), "P0");
  assert.equal(remediationPriority({ severity: "medium" }), "P2");
  assert.deepEqual(remediationSla("P1"), {
    due: "7 dias",
    effort: "Sprint atual",
    owner: "Time do sistema",
  });
});

test("verification status aliases collapse into report states", () => {
  assert.equal(verificationStatusDescriptor("confirmed").status, "confirmed");
  assert.equal(verificationStatusDescriptor("needs_human_review").status, "blocked");
  assert.equal(verificationStatusDescriptor("invalid_evidence").status, "refuted");
  assert.equal(verificationStatusDescriptor("candidate").status, "candidate");
});

test("verification status summary groups by severity", () => {
  const summary = verificationStatusSummary([
    { severity: "high", verification_status: "confirmed" },
    { severity: "high", verification_status: "needs_human_review" },
    { severity: "medium", adjudication: { final_verdict: "false_positive" } },
    { severity: "low", verification_status: "hypothesis" },
  ]);

  assert.equal(summary.matrix_by_severity.high.confirmed, 1);
  assert.equal(summary.matrix_by_severity.high.blocked, 1);
  assert.equal(summary.matrix_by_severity.medium.refuted, 1);
  assert.equal(summary.matrix_by_severity.low.candidate, 1);
  assert.deepEqual(summary.totals_by_state, {
    confirmed: 1,
    candidate: 1,
    blocked: 1,
    refuted: 1,
  });
});
