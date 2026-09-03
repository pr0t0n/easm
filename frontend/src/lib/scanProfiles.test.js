import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../pages/ScansPage.jsx", import.meta.url), "utf8");

test("pentest composer keeps three pentest profiles", () => {
  assert.match(source, /Superficial: "asm"/);
  assert.match(source, /Normal: "full"/);
  assert.match(source, /Agressivo: "aggressive"/);
  assert.match(source, /Perfil Pentest/);
  assert.doesNotMatch(source, /scanLevel:\s*"full"/);
  assert.match(source, /scanLevel:\s*LEVEL_REVERSE\[perfil\]/);
});
