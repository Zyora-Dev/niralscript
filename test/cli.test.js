// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { assert } from "./helpers.js";

const cli = fileURLToPath(new URL("../cli.js", import.meta.url));

function nrs(args, cwd) {
  return spawnSync(process.execPath, [cli, ...args], { cwd, encoding: "utf8" });
}

function workspace(files) {
  const dir = mkdtempSync(join(tmpdir(), "nrs-cli-"));
  for (const [name, source] of Object.entries(files)) writeFileSync(join(dir, name), source);
  return dir;
}

test("check exits 0 on valid source", () => {
  const dir = workspace({ "a.nrs": "export const value = 1 + 2" });
  try {
    const result = nrs(["check", "--root", dir, "a.nrs"], dir);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("check exits 1 and reports a diagnostic on invalid source", () => {
  const dir = workspace({ "a.nrs": "const x: number = \"nope\"" });
  try {
    const result = nrs(["check", "--root", dir, "a.nrs"], dir);
    assert.equal(result.status, 1);
    assert.match(result.stdout + result.stderr, /NRS\d+/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("invalid arguments exit 2", () => {
  const dir = workspace({ "a.nrs": "export const value = 1" });
  try {
    const result = nrs(["frobnicate", "a.nrs"], dir);
    assert.equal(result.status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("compile emits an .mjs and a source map", () => {
  const dir = workspace({ "a.nrs": "export const value = 1 + 2" });
  try {
    const result = nrs(["compile", "--root", dir, "a.nrs", "--out", "a.mjs"], dir);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.ok(existsSync(join(dir, "a.mjs")), "emits the .mjs output");
    assert.ok(existsSync(join(dir, "a.mjs.map")), "emits the source map");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
