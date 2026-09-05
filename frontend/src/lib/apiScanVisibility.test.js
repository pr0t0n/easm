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

test("scan drawer renders BAC 200 visibility", () => {
  assert.match(scansPage, /business_access_control/);
  assert.ok(scansPage.includes("BAC / 200"));
  assert.ok(scansPage.includes("retornando 200"));
});

test("custom report renders BAC 200 visibility", () => {
  assert.match(reportJs, /business_access_control/);
  assert.ok(reportJs.includes("Broken Access Control / HTTP 200"));
  assert.ok(reportJs.includes("Retornando 200"));
});
