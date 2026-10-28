import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";

const base = mkdtempSync(join(tmpdir(), "rea-extras-"));
const allowed = join(base, "allowed"),
  denied = join(base, "denied");
mkdirSync(allowed);
mkdirSync(denied);
const sample = join(allowed, "sample 1.elf");
writeFileSync(sample, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
const secret = join(denied, "secret.elf");
writeFileSync(secret, Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
symlinkSync(secret, join(allowed, "escape.elf"));
const mock = join(base, "fake-ablation");
writeFileSync(
  mock,
  '#!/usr/bin/env node\nif(process.argv[2]==="--help") console.log("help");else console.log(JSON.stringify(process.argv.slice(2)));\n',
  { mode: 0o755 },
);
const entry = resolve(
  "skills/reverse-engineer-anything/scripts/rea-extras.mjs",
);
const env = {
  ...process.env,
  REA_ABLATION_BIN: mock,
  REA_INVESTIGATION_INPUT_ROOTS_JSON: JSON.stringify([allowed]),
};
const go = (...args) =>
  spawnSync(process.execPath, [entry, ...args], {
    env,
    encoding: "utf8",
    timeout: 10_000,
  });

test("detects external CLI", () => {
  const r = go("doctor", "--json");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).ablation.available, true);
});
test("triages magic bytes without executing target", () => {
  const r = go("triage", sample, "--json");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).format, "ELF");
});
test("passes arguments as data, never a shell", () => {
  const r = go("ablation", "search", sample, "a; echo NO", "--json");
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(JSON.parse(r.stdout).stdout), [
    "search",
    sample,
    "a; echo NO",
  ]);
});
test("rejects traversal and symlink escapes", () => {
  for (const p of [secret, join(allowed, "escape.elf")]) {
    const r = go("ablation", "analyze", p);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /outside approved input roots/);
  }
});
test("requires explicit approved roots", () => {
  const r = spawnSync(process.execPath, [entry, "triage", sample], {
    env: { ...env, REA_INVESTIGATION_INPUT_ROOTS_JSON: "[]" },
    encoding: "utf8",
  });
  assert.notEqual(r.status, 0);
});
test("rejects arbitrary subcommands and invalid offsets", () => {
  assert.notEqual(go("ablation", "other", sample).status, 0);
  assert.notEqual(go("ablation", "cfg", sample, "; rm -rf /").status, 0);
});
