import test from "node:test";
import assert from "node:assert/strict";

import { isTerminalScanStatus, remediationPriority, remediationSla } from "./reportQuality.js";

test("quality completion with gaps remains terminal and visible", () => {
  assert.equal(isTerminalScanStatus("completed_with_gaps"), true);
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
