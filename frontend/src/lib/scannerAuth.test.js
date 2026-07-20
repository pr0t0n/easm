import test from "node:test";
import assert from "node:assert/strict";

import { buildScannerAuthConfig } from "./scannerAuth.js";

test("builds two auditable bearer identities", () => {
  const result = buildScannerAuthConfig(true, {
    type: "bearer",
    multiIdentity: true,
    token: "token-a",
    tokenB: "token-b",
  });
  assert.equal(result.required, true);
  assert.deepEqual(result.identities.map((identity) => identity.id), ["user_a", "user_b"]);
});

test("rejects incomplete identity matrix", () => {
  assert.equal(buildScannerAuthConfig(true, { type: "bearer", multiIdentity: true, token: "a", tokenB: "" }), null);
});
