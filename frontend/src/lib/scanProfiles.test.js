import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../pages/ScansPage.jsx", import.meta.url), "utf8");

test("pentest composer keeps the two platform profiles", () => {
  // Superficial = ASM; Normal = completo (aggressive). Decisão do sponsor
  // 2026-11-04: o perfil profundo é o padrão e se chama Normal.
  assert.match(source, /Superficial: "asm"/);
  assert.match(source, /Normal: "aggressive"/);
  assert.match(source, /Perfil Pentest/);
  assert.doesNotMatch(source, /LEVEL_REVERSE = \{[^}]*full/);
  assert.doesNotMatch(source, /scanLevel:\s*"full"/);
  assert.match(source, /scanLevel:\s*LEVEL_REVERSE\[perfil\]/);
});

test("Normal (completo) is the default profile", () => {
  assert.match(source, /useState\("Normal"\)/);
  assert.match(source, /\|\|\s*"aggressive"/);
  assert.match(source, /\["Normal","Superficial"\]/);
  assert.match(source, /<option value="aggressive">Normal \(padrão\)<\/option>/);
  assert.match(source, /<option value="asm">Superficial \(ASM\)<\/option>/);
});
