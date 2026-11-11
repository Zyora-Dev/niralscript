// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
import { test } from "node:test";
import { assert } from "./helpers.js";
import { parseNiralScript } from "../parser.js";
import { RESERVED_WORDS } from "../scanner.js";

test("scanner reserves NiralScript keywords", () => {
  for (const word of ["state", "derive", "input", "class", "return", "await"]) {
    assert.ok(RESERVED_WORDS.has(word), `${word} must be reserved`);
  }
  assert.ok(!RESERVED_WORDS.has("count"), "ordinary identifiers are not reserved");
});

test("reserved words cannot be used as binding names", () => {
  assert.throws(() => parseNiralScript("const state = 1", "bad.nrs"), error => error.name === "NiralScriptError");
});

test("malformed source reports a located NiralScriptError", () => {
  assert.throws(
    () => parseNiralScript("const valid = 1\nconst x = @", "bad.nrs"),
    { name: "NiralScriptError", code: "NRS071", filename: "bad.nrs", line: 2, col: 11, start: 26, end: 27 },
  );
});
