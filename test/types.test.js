// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
import { test } from "node:test";
import { checksOk, checksFail } from "./helpers.js";

test("accepts matching primitive annotations", () => {
  checksOk("const count: number = 1");
  checksOk('const name: string = "niral"');
  checksOk("const flag: boolean = true");
});

test("rejects mismatched primitive annotations", () => {
  checksFail("const count: number = \"one\"", { code: "NRS080" });
});

test("checks object type members", () => {
  checksOk("type Point = { x: number, y: number }\nconst p: Point = { x: 1, y: 2 }");
  checksFail("type Point = { x: number, y: number }\nconst p: Point = { x: 1 }", /Expected|received/);
});

test("checks generic Promise return annotations", () => {
  checksOk("export async function run(): Promise<number> { return 1 }");
  checksFail("export async function run(): Promise<number> { return \"x\" }", /Expected|received/);
});

test("async functions require a Promise return annotation", () => {
  checksFail("export async function run(): number { return 1 }", /Promise/);
});

test("strict mode rejects implicit any from host globals in typed positions", () => {
  // Documents the current strict-mode behavior: a global's result does not satisfy
  // a concrete type without an explicit annotation. Guards against silent regressions.
  const source = "export async function run(): Promise<number> {\n  const value = await Promise.resolve(41)\n  return value + 1\n}";
  checksFail(source, { code: "NRS080" }, { strictTypes: true, globals: ["Promise"] });
  // Annotating the awaited value restores a clean check.
  const annotated = "export async function run(): Promise<number> {\n  const value: number = await Promise.resolve(41)\n  return value + 1\n}";
  checksOk(annotated, { strictTypes: true, globals: ["Promise"] });
});

test("non-strict mode allows host-global results to flow", () => {
  const source = "export async function run(): Promise<number> {\n  const value = await Promise.resolve(41)\n  return value + 1\n}";
  checksOk(source, { globals: ["Promise"] });
});
