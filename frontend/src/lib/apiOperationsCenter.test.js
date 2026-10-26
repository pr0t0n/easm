import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const app = readFileSync(new URL("../App.jsx", import.meta.url), "utf8");
const page = readFileSync(new URL("../pages/ApiOperationsCenterPage.jsx", import.meta.url), "utf8");
const styles = readFileSync(new URL("../index.css", import.meta.url), "utf8");

test("API operations center uses a non-proxy route", () => {
  assert.match(app, /path=\"\/operacional-api\"/);
  assert.doesNotMatch(app, /path=\"\/api\/operacional\"/);
});

test("API operations center owns a black canvas at every shell level", () => {
  assert.match(page, /<main style=\{\{ background: \"#000\"/);
  assert.match(styles, /html\.api-ops-active[\s\S]*background: #000 !important/);
  assert.match(styles, /\.api-ops-shell[\s\S]*background: #000 !important/);
});
