// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
import { test } from "node:test";
import { SourceMap } from "node:module";
import { assert, run } from "./helpers.js";
import { compileNiralScript } from "../compile.js";

test("emits an ESM instance factory with a source map", () => {
  const output = compileNiralScript("const value = 1 + 2\nexport const doubled = value * 2", "entry.nrs", {});
  assert.ok(output.code.includes("createInstance"), "exports a createInstance factory");
  assert.ok(output.map && output.map.version === 3, "emits a v3 source map");
  assert.deepEqual(output.map.sources?.length >= 1, true, "source map references at least one source");
});

test("generated source map maps back to the .nrs source", () => {
  const source = "const first = 17\nconst second = first + 23";
  const output = compileNiralScript(source, "entry.nrs", {});
  assert.deepEqual(output.map.sources, ["entry.nrs"]);
  assert.deepEqual(output.map.sourcesContent, [source]);
  const map = new SourceMap(output.map);
  const generated = output.code.split("\n");
  for (const [originalLine, literal] of ["(17)", "(23)"].entries()) {
    const generatedLine = generated.findIndex(line => line.startsWith("const ") && line.includes(literal));
    assert.ok(generatedLine >= 0, `missing emitted declaration for source line ${originalLine + 1}`);
    const entry = map.findEntry(generatedLine, 0);
    assert.equal(entry.originalSource, "entry.nrs");
    assert.equal(entry.originalLine, originalLine);
    assert.equal(entry.originalColumn, 0);
  }
});

test("executes emitted code and exposes reactive values", async () => {
  const { instance } = await run("const value = 1 + 2\nexport const doubled = value * 2");
  assert.equal(instance.values.value, 3);
  assert.equal(instance.values.doubled, 6);
});

test("derive recomputes when state changes", async () => {
  const { instance } = await run("state count: number = 1\nderive doubled: number = count * 2");
  assert.equal(instance.values.doubled, 2);
  instance.values.count = 10;
  assert.equal(instance.values.doubled, 20);
});

test("updateInputs updates inputs without resetting state", async () => {
  const source = "input initial: number\nstate count: number = initial\nderive doubled: number = count * 2\nderive total: number = doubled + initial";
  const { instance } = await run(source, { inputs: { initial: 4 } });
  assert.equal(instance.values.initial, 4);
  assert.equal(instance.values.count, 4);
  assert.equal(instance.values.doubled, 8);
  assert.equal(instance.values.total, 12);
  instance.values.count = 10;
  assert.equal(instance.values.total, 24);
  instance.updateInputs({ initial: 8 });
  assert.equal(instance.values.initial, 8);
  assert.equal(instance.values.count, 10, "existing state is preserved");
  assert.equal(instance.values.doubled, 20);
  assert.equal(instance.values.total, 28);
  instance.updateInputs({ initial: 0 });
  assert.equal(instance.values.initial, 0);
  assert.equal(instance.values.count, 10);
  assert.equal(instance.values.total, 20);
});

test("instances are isolated from one another", async () => {
  const output = compileNiralScript("state count: number = 0", "entry.nrs", {});
  const module = await import("data:text/javascript;base64," + Buffer.from(output.code).toString("base64"));
  const a = module.createInstance();
  const b = module.createInstance();
  a.values.count = 99;
  assert.equal(b.values.count, 0, "a separate instance keeps its own state");
});
