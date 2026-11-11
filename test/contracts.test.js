// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
import { test } from "node:test";
import { assert, run } from "./helpers.js";
import { compileNiralScript } from "../compile.js";

test("runtime contracts validate structural shapes", async () => {
  const source = [
    "type Item = { quantity: number, tags?: string[] }",
    "function read(candidate: unknown): Item { return contract<Item>(candidate) }",
    "export const result = read({ quantity: 4 })",
  ].join("\n");
  const { instance } = await run(source, { strictTypes: true });
  assert.deepEqual(instance.values.result, { quantity: 4 });
});

test("runtime contracts reject invalid data with located errors", async () => {
  const source = [
    "type Item = { quantity: number, tags?: string[] }",
    "export function read(candidate: unknown): Item { return contract<Item>(candidate) }",
  ].join("\n");
  const { instance } = await run(source, { strictTypes: true });
  assert.throws(() => instance.values.read({ quantity: "4" }), { code: "NRS081", path: "$.quantity" });
  assert.throws(() => instance.values.read({ quantity: 4, tags: [2] }), { path: "$.tags[0]" });
  assert.throws(() => instance.values.read({ quantity: 4, extra: true }), { path: "$.extra" });
});

test("unsupported contract target types are rejected at compile time", () => {
  assert.throws(
    () => compileNiralScript("function read(c: unknown) { return contract<Promise<number>>(c) }"),
    /Unsupported runtime contract/,
  );
});
