import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("runtime rows keep unique React keys when labels repeat", () => {
  const source = readFileSync(new URL("../pages/CapabilityBlueprintPage.jsx", import.meta.url), "utf8");
  assert.match(source, /lines\.map\(\(line, index\) =>/);
  assert.match(source, /key=\{`\$\{index\}-\$\{line\}`\}/);
  assert.doesNotMatch(source, /<div key=\{line\}/);
});

test("MITRE heatmap keeps unique React keys when techniques repeat", () => {
  const source = readFileSync(new URL("../pages/BasControlCenterPage.jsx", import.meta.url), "utf8");
  assert.match(source, /cells\.map\(\(c, index\) =>/);
  assert.match(source, /key=\{`\$\{category\}-\$\{c\.mitre_id\}-\$\{index\}`\}/);
  assert.doesNotMatch(source, /<div key=\{c\.mitre_id\}/);
});
