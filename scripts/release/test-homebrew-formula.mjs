// Tests for gen-homebrew-formula.mjs. Run: node scripts/release/test-homebrew-formula.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderFormula, TARGETS } from "./gen-homebrew-formula.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const sums = {};
const manifest = {
  version: "0.4.2",
  source_commit: "0".repeat(40),
  built_at: "2026-01-01T00:00:00Z",
  dashboard: "d".repeat(64),
  binaries: TARGETS.map(([os, arch], i) => {
    const sha256 = String(i + 1).repeat(64);
    sums[`${os}-${arch}`] = sha256;
    return { os, arch, asset: `ozbox-${os}-${arch}`, sha256 };
  }),
};

let n = 0;
const t = (name, fn) => {
  fn();
  n++;
  console.log(`ok   ${name}`);
};

t("renders every program's url and sha256", () => {
  const f = renderFormula(manifest);
  for (const [os, arch] of TARGETS) {
    assert.ok(f.includes(`https://github.com/OzboxHQ/ozbox/releases/download/v0.4.2/ozbox-${os}-${arch}"`));
    assert.ok(f.includes(`sha256 "${sums[`${os}-${arch}`]}"`));
  }
});
t("names the licence, version and a test that runs --version", () => {
  const f = renderFormula(manifest);
  assert.match(f, /license "Apache-2\.0"/);
  assert.match(f, /version "0\.4\.2"/);
  assert.match(f, /class Ozbox < Formula/);
  assert.match(f, /shell_output\("#\{bin\}\/ozbox --version"\)/);
  assert.match(f, /bin\.install Dir\["ozbox-\*"\]\.first => "ozbox"/);
});
t("macOS and Linux blocks each carry arm and intel", () => {
  const f = renderFormula(manifest);
  assert.match(f, /on_macos do[\s\S]*on_arm do[\s\S]*on_intel do[\s\S]*end\n {2}end/);
  assert.match(f, /on_linux do[\s\S]*on_arm do[\s\S]*on_intel do/);
});
t("a different repository is used in every url and the homepage", () => {
  const f = renderFormula(manifest, "example-org/example-repo");
  assert.ok(!f.includes("OzboxHQ"));
  assert.ok(f.includes("https://github.com/example-org/example-repo"));
});
t("a pre-release is refused", () => {
  assert.throws(() => renderFormula({ ...manifest, version: "0.5.0-rc.1" }), /stable release/);
});
t("a missing program is refused", () => {
  const m = { ...manifest, binaries: manifest.binaries.filter((b) => b.asset !== "ozbox-darwin-x86_64") };
  assert.throws(() => renderFormula(m), /darwin\/x86_64/);
});
t("a bad sha256 is refused", () => {
  const m = { ...manifest, binaries: manifest.binaries.map((b, i) => (i === 0 ? { ...b, sha256: "xyz" } : b)) };
  assert.throws(() => renderFormula(m), /not valid/);
});
t("a malformed repository is refused", () => {
  assert.throws(() => renderFormula(manifest, 'a/b"; system "id'), /owner\/name/);
});
t("the command line writes the same text", () => {
  const dir = mkdtempSync(join(tmpdir(), "ozbox-brew-"));
  writeFileSync(join(dir, "m.json"), JSON.stringify(manifest));
  execFileSync("node", [join(here, "gen-homebrew-formula.mjs"), join(dir, "m.json"), "--out", join(dir, "ozbox.rb")]);
  assert.equal(readFileSync(join(dir, "ozbox.rb"), "utf8"), renderFormula(manifest));
});
console.log(`\n${n} passed`);
