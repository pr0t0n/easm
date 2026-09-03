import test from "node:test";
import assert from "node:assert/strict";

import { apiCredentialPlan, buildApiScanConfig } from "./apiScan.js";

test("api credential plan follows zero one two credential rule", () => {
  assert.deepEqual(apiCredentialPlan(null).contexts, ["anonymous"]);
  assert.deepEqual(apiCredentialPlan({ type: "bearer", token: "a" }).contexts, ["anonymous", "authenticated:user_a"]);
  assert.deepEqual(apiCredentialPlan({ identities: [{ id: "a" }, { id: "b" }] }).contexts, ["anonymous", "authenticated:user_a", "authenticated:user_b"]);
});

test("api scan config parses inline json and carries auth strategy expectation", () => {
  const config = buildApiScanConfig(
    true,
    { specUrl: "https://api.example.test/openapi.json", specJson: "{\"openapi\":\"3.0.0\",\"paths\":{}}" },
    { type: "bearer", token: "a" },
  );

  assert.equal(config.spec_url, "https://api.example.test/openapi.json");
  assert.equal(config.expected_auth_strategy, "anonymous_authenticated");
  assert.deepEqual(config.spec_payload, { openapi: "3.0.0", paths: {} });
});

test("disabled api scan does not emit config", () => {
  assert.equal(buildApiScanConfig(false, { specUrl: "https://api.example.test/openapi.json" }), null);
});
