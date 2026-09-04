import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const scansPage = readFileSync(new URL("../pages/ScansPage.jsx", import.meta.url), "utf8");
const reportJs = readFileSync(new URL("../../public/custom-report/js/report.js", import.meta.url), "utf8");

test("scan drawer renders API ZAP observability", () => {
  assert.match(scansPage, /api_scan_observability/);
  assert.ok(scansPage.includes("API / ZAP"));
  assert.ok(scansPage.includes("URLs importadas"));
  assert.ok(scansPage.includes("Alertas ZAP"));
  assert.ok(scansPage.includes("Findings brutos"));
});

test("custom report renders API ZAP observability", () => {
  assert.match(reportJs, /api_scan_observability/);
  assert.ok(reportJs.includes("API / OWASP ZAP"));
  assert.ok(reportJs.includes("URLs importadas"));
  assert.ok(reportJs.includes("Alertas ZAP"));
  assert.ok(reportJs.includes("Findings brutos"));
});
