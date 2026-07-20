import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("dashboard uses the consolidated control-plane BFF", () => {
  const source = readFileSync(new URL("../pages/DashboardPage.jsx", import.meta.url), "utf8");
  assert.match(source, /\/api\/dashboard\/control-plane/);
  assert.doesNotMatch(source, /\/api\/findings\/verification-stats/);
  assert.doesNotMatch(source, /\/api\/scans\/\$\{selectedSubdomainScanId\}\/crown-jewels/);
  assert.doesNotMatch(source, /\/api\/scans\/\$\{selectedSubdomainScanId\}\/osint/);
});
