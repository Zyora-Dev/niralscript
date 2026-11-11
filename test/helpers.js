// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
// Shared helpers for the standalone NiralScript compiler test suite.
// Imports only from the published package surface so the suite runs from a clean checkout.
import assert from "node:assert/strict";
import { parseNiralScript, analyzeNiralScript } from "../parser.js";
import { checkNiralScript } from "../check.js";
import { compileNiralScript } from "../compile.js";

export { assert };

// Parse + analyze a source string, returning the analysis. Throws on any error.
export function analyze(source, options = {}) {
  const program = parseNiralScript(source, options.filename ?? "test.nrs");
  return analyzeNiralScript(program, { topLevelAwait: true, ...options });
}

// Assert that checking a source succeeds (no diagnostics thrown).
export function checksOk(source, options = {}) {
  assert.doesNotThrow(() => checkNiralScript(source, options.filename ?? "test.nrs", options), `expected source to check cleanly:\n${source}`);
}

// Assert that checking a source fails with a diagnostic matching `expected`
// (a RegExp for the message, or an object of NiralScriptError fields).
export function checksFail(source, expected, options = {}) {
  assert.throws(() => checkNiralScript(source, options.filename ?? "test.nrs", options), expected, `expected source to fail checking:\n${source}`);
}

// Compile a source to an ESM instance factory and execute it, returning the
// instance's reactive values. Throws on compile or runtime error.
export async function run(source, { inputs, ...options } = {}) {
  const output = compileNiralScript(source, options.filename ?? "entry.nrs", options);
  const module = await import("data:text/javascript;base64," + Buffer.from(output.code).toString("base64"));
  return { module, output, instance: module.createInstance(inputs) };
}
