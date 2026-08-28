import test from "node:test";
import assert from "node:assert/strict";

import { completedWithGapsSummary, isTerminalScanStatus, remediationPriority, remediationSla } from "./reportQuality.js";

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
