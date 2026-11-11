// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
import { test } from "node:test";
import { assert } from "./helpers.js";
import { parseNiralScript } from "../parser.js";
import { linkNiralScript } from "../modules.js";

// A minimal in-memory module resolver: maps specifier -> source string.
function resolver(graph) {
  return (specifier) => (specifier in graph ? { filename: specifier, source: graph[specifier] } : null);
}

test("links a named import across modules", () => {
  const entry = parseNiralScript('import { answer } from "./lib.nrs"\nexport const value = answer', "entry.nrs");
  const program = linkNiralScript(entry, resolver({ "./lib.nrs": "export const answer = 42" }));
  assert.equal(program.type, "Program");
  assert.ok(Array.isArray(program.sources), "linked program carries its combined sources");
  assert.ok(program.sources.some(s => s.filename === "./lib.nrs"), "dependency source is included");
});

test("reports a missing module", () => {
  const entry = parseNiralScript('import { answer } from "./missing.nrs"\nexport const value = answer', "entry.nrs");
  assert.throws(() => linkNiralScript(entry, resolver({})), error => error.name === "NiralScriptError");
});

test("rejects a module dependency cycle", () => {
  const entry = parseNiralScript('import { b } from "./b.nrs"\nexport const value = b', "entry.nrs");
  const graph = {
    "entry.nrs": 'import { b } from "./b.nrs"\nexport const value = b',
    "./b.nrs": 'import { c } from "./c.nrs"\nexport const b = c',
    "./c.nrs": 'import { entry } from "entry.nrs"\nexport const c = entry',
  };
  assert.throws(() => linkNiralScript(entry, resolver(graph)), error => error.name === "NiralScriptError" && /cycle/i.test(error.message));
});

test("library modules may only contain declarations", () => {
  const entry = parseNiralScript('import { answer } from "./lib.nrs"\nexport const value = answer', "entry.nrs");
  assert.throws(
    () => linkNiralScript(entry, resolver({ "./lib.nrs": "export const answer = 42\nconsole.log(answer)" })),
    error => error.name === "NiralScriptError",
  );
});
