// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
import { test } from "node:test";
import { assert } from "./helpers.js";
import { parseNiralScript } from "../parser.js";

function statements(source) {
  return parseNiralScript(source, "test.nrs").body;
}

test("parses a program into a typed AST", () => {
  const program = parseNiralScript("const value = 1 + 2", "test.nrs");
  assert.equal(program.type, "Program");
  assert.equal(program.filename, "test.nrs");
  assert.ok(Array.isArray(program.body));
  assert.equal(program.body.length, 1);
});

test("parses reactive declarations", () => {
  const body = statements("input initial: number\nstate count: number = initial\nderive doubled: number = count * 2");
  assert.equal(body.length, 3);
  assert.deepEqual(body.map(node => [node.type, node.id.name, node.id.typeAnnotation.value.kind]), [
    ["InputDeclaration", "initial", "number"],
    ["StateDeclaration", "count", "number"],
    ["DerivedDeclaration", "doubled", "number"],
  ]);
  assert.equal(body[1].init.type, "Identifier");
  assert.equal(body[1].init.name, "initial");
  assert.equal(body[2].init.type, "BinaryExpression");
  assert.equal(body[2].init.operator, "*");
  assert.equal(body[2].init.left.name, "count");
  assert.equal(body[2].init.right.value, 2);
});

test("preserves operator precedence and left associativity in the AST", () => {
  const expression = statements("const result = 10 - 3 - 2 * 4")[0].init;
  assert.equal(expression.type, "BinaryExpression");
  assert.equal(expression.operator, "-");
  assert.equal(expression.left.operator, "-");
  assert.equal(expression.left.left.value, 10);
  assert.equal(expression.left.right.value, 3);
  assert.equal(expression.right.operator, "*");
  assert.equal(expression.right.left.value, 2);
  assert.equal(expression.right.right.value, 4);
});

test("detects presence of type annotations", () => {
  assert.equal(parseNiralScript("const x: number = 1", "t.nrs").typed, true);
  assert.equal(parseNiralScript("const x = 1", "t.nrs").typed, false);
});

test("rejects an unterminated block", () => {
  assert.throws(() => parseNiralScript("function f() {", "t.nrs"), error => error.name === "NiralScriptError");
});

test("rejects a dangling operator", () => {
  assert.throws(() => parseNiralScript("const x = 1 +", "t.nrs"), error => error.name === "NiralScriptError");
});
