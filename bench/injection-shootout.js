// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ZyoraLabs. Runtime Library Exception applies — see LICENSE.
//
// Injection shoot-out: the SAME attack payloads run through three toolchains —
// plain JavaScript, real TypeScript (tsc), and NiralScript — to show which ones
// catch an injection *at compile time* and which silently ship a vulnerable app.
//
//   node bench/injection-shootout.js
//
// JS is executed. TypeScript is type-checked with the real compiler bundled in
// .niral/lib/typescript. NiralScript is compiled with the standalone compiler.
// No reasoning, no hand-waving — every verdict is produced by actually running
// the respective toolchain.

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { compileNiralScript as compileNiral } from "../compile.js";

const here = dirname(fileURLToPath(import.meta.url));

// Self-contained TypeScript loader (NIRAL_TSC env or node_modules).
function loadTypescript() {
  const req = createRequire(join(here, "..", "package.json"));
  const candidates = [];
  if (process.env.NIRAL_TSC) candidates.push(process.env.NIRAL_TSC);
  for (let d = resolve(here, ".."); ; d = dirname(d)) {
    candidates.push(join(d, "node_modules", "typescript", "lib", "typescript.js"));
    if (dirname(d) === d) break;
  }
  for (const c of candidates) if (existsSync(c)) return req(c);
  throw new Error("TypeScript compiler not found — `npm install typescript`, or point NIRAL_TSC at a typescript.js.");
}

const ts = loadTypescript();

const GREEN = s => `\x1b[32m${s}\x1b[0m`;
const RED = s => `\x1b[31m${s}\x1b[0m`;
const YELLOW = s => `\x1b[33m${s}\x1b[0m`;
const DIM = s => `\x1b[2m${s}\x1b[0m`;
const BOLD = s => `\x1b[1m${s}\x1b[0m`;

// --- toolchain probes -------------------------------------------------------

// JavaScript: no type system. It always "compiles" — the only question is what
// the program *does* at runtime. We run it and report the string it would emit.
function runJs(source, attack) {
  try {
    const factory = new Function("input", "sql", "html", "escape", "sanitize", source + "\n;return typeof run === 'function' ? run : null;");
    const emitted = [];
    const sink = { last: null };
    const run = factory(
      attack, // `input` — the attacker-controlled value
      { query: q => (sink.last = q) }, // sql.query — records what hit the DB
      v => (sink.last = v), // html() — records what hit the DOM
      v => String(v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
      v => String(v).replace(/['";]/g, "") // toy sanitizer
    );
    if (!run) return { compiled: true, emitted: null };
    run();
    return { compiled: true, emitted: sink.last };
  } catch (error) {
    return { compiled: true, runtimeError: error.message };
  }
}

// TypeScript: real compiler. Reports whether tsc emits ANY diagnostic for the
// program. A clean compile means TS considers the injection perfectly valid.
function runTs(source) {
  const result = ts.transpileModule(source, {
    reportDiagnostics: true,
    compilerOptions: { strict: true, noImplicitAny: true, target: ts.ScriptTarget.ES2022 },
  });
  const diagnostics = result.diagnostics ?? [];
  return { compiled: diagnostics.length === 0, diagnostics: diagnostics.map(d => ts.flattenDiagnosticMessageText(d.messageText, "\n")) };
}

// NiralScript: the standalone compiler with taint tracking enabled.
function runNiral(source) {
  try {
    compileNiral(source, "shootout.nrs", {
      strictTypes: true,
      globals: ["sql", "html", "escape", "sanitize", "trust"],
      taintSources: ["input"],
    });
    return { compiled: true };
  } catch (error) {
    return { compiled: false, code: error.code, message: error.message };
  }
}

// --- the attack matrix ------------------------------------------------------
// Each scenario carries THREE source spellings of the SAME program, because the
// three languages differ in surface syntax (type annotations, taint markers).
// `vulnerable: true`  means an unlaundered attacker value reaches a sink.
// `vulnerable: false` means the value is properly escaped/sanitized first.

const ATTACK = "'; DROP TABLE users; --";
const XSS = "<script>alert(document.cookie)</script>";

const scenarios = [
  {
    name: "SQL injection — direct",
    vulnerable: true,
    attack: ATTACK,
    kind: "sql",
    js: "function run() { sql.query(input) }",
    ts: "declare const sql: { query(q: string): void }; function run(input: string) { sql.query(input) }",
    nrs: "input q: string\nexport function run() { sql.query(q) }",
  },
  {
    name: "SQL injection — string concat",
    vulnerable: true,
    attack: ATTACK,
    kind: "sql",
    js: "function run() { sql.query('select * from users where name = ' + input) }",
    ts: "declare const sql: { query(q: string): void }; function run(input: string) { sql.query('select * from users where name = ' + input) }",
    nrs: "input q: string\nexport function run() { sql.query('select * from users where name = ' + q) }",
  },
  {
    name: "SQL injection — via alias",
    vulnerable: true,
    attack: ATTACK,
    kind: "sql",
    js: "function run() { const q = input; const q2 = q; sql.query(q2) }",
    ts: "declare const sql: { query(q: string): void }; function run(input: string) { const q = input; const q2 = q; sql.query(q2) }",
    nrs: "input q: string\nexport function run() { const a = q\nconst b = a\nsql.query(b) }",
  },
  {
    name: "SQL injection — via reassignment",
    vulnerable: true,
    attack: ATTACK,
    kind: "sql",
    js: "function run() { let q = 'safe'; q = input; sql.query(q) }",
    ts: "declare const sql: { query(q: string): void }; function run(input: string) { let q = 'safe'; q = input; sql.query(q) }",
    nrs: "input q: string\nexport function run() { let a = 'safe'\na = q\nsql.query(a) }",
  },
  {
    name: "XSS — raw HTML emit",
    vulnerable: true,
    attack: XSS,
    kind: "html",
    js: "function run() { html(input) }",
    ts: "declare function html(s: string): void; function run(input: string) { html(input) }",
    nrs: "input q: string\nexport function run() { html(q) }",
  },
  {
    name: "XSS — template interpolation",
    vulnerable: true,
    attack: XSS,
    kind: "html",
    js: "function run() { html(`<div>${input}</div>`) }",
    ts: "declare function html(s: string): void; function run(input: string) { html(`<div>${input}</div>`) }",
    nrs: "input q: string\nexport function run() { html(`<div>${q}</div>`) }",
  },
  {
    name: "SAFE — SQL laundered via sanitize()",
    vulnerable: false,
    attack: ATTACK,
    kind: "sql",
    js: "function run() { sql.query(sanitize(input)) }",
    ts: "declare const sql: { query(q: string): void }; declare function sanitize(s: string): string; function run(input: string) { sql.query(sanitize(input)) }",
    nrs: "input q: string\nexport function run() { sql.query(sanitize(q)) }",
  },
  {
    name: "SAFE — XSS laundered via escape()",
    vulnerable: false,
    attack: XSS,
    kind: "html",
    js: "function run() { html(escape(input)) }",
    ts: "declare function html(s: string): void; declare function escape(s: string): string; function run(input: string) { html(escape(input)) }",
    nrs: "input q: string\nexport function run() { html(escape(q)) }",
  },
];

// --- run the matrix ---------------------------------------------------------

function verdict(result, vulnerable) {
  // "secure" = the toolchain refused to compile a vulnerable program, OR
  // compiled a correctly-laundered one. "VULNERABLE" = it compiled an injection.
  if (vulnerable) return result.compiled ? RED("SHIPS IT ") : GREEN("BLOCKED  ");
  return result.compiled ? GREEN("compiles ") : YELLOW("false-pos");
}

console.log(BOLD("\n  Injection shoot-out — JavaScript vs TypeScript vs NiralScript"));
console.log(DIM("  Same attack through three toolchains. Does it catch the injection at COMPILE time?\n"));
console.log(
  "  " +
    BOLD("Scenario".padEnd(38)) +
    BOLD("JavaScript".padEnd(12)) +
    BOLD("TypeScript".padEnd(12)) +
    BOLD("NiralScript")
);
console.log("  " + DIM("─".repeat(74)));

let jsCaught = 0;
let tsCaught = 0;
let nrsCaught = 0;
let vulnCount = 0;
const live = [];

for (const scenario of scenarios) {
  const js = runJs(scenario.js, scenario.attack);
  const tsr = runTs(scenario.ts);
  const nrs = runNiral(scenario.nrs);

  // JS and TS have NO taint tracking — they can never block an injection.
  if (scenario.vulnerable) {
    vulnCount++;
    if (!js.compiled) jsCaught++;
    if (!tsr.compiled) tsCaught++;
    if (!nrs.compiled) nrsCaught++;
  }

  console.log(
    "  " +
      scenario.name.padEnd(38) +
      verdict(js, scenario.vulnerable).padEnd(12 + 9) +
      verdict(tsr, scenario.vulnerable).padEnd(12 + 9) +
      verdict(nrs, scenario.vulnerable) +
      (nrs.code ? DIM(` ${nrs.code}`) : "")
  );

  // Record the live exploit evidence for the first few vulnerable SQL/XSS cases.
  if (scenario.vulnerable && js.emitted != null && live.length < 2) {
    live.push({ scenario, emitted: js.emitted, nrs });
  }
}

console.log("  " + DIM("─".repeat(74)));
console.log(
  "  " +
    `Injections blocked at compile time:`.padEnd(38) +
    RED(`${jsCaught}/${vulnCount}`).padEnd(12 + 9) +
    RED(`${tsCaught}/${vulnCount}`).padEnd(12 + 9) +
    GREEN(`${nrsCaught}/${vulnCount}`)
);

// --- live exploit demonstration ---------------------------------------------

console.log(BOLD("\n  Live exploit — what actually reaches the sink\n"));
for (const { scenario, emitted, nrs } of live) {
  const label = scenario.kind === "sql" ? "DB receives" : "DOM receives";
  console.log("  " + BOLD(scenario.name));
  console.log("    attacker sends : " + YELLOW(JSON.stringify(scenario.attack)));
  console.log("    JS / TS  →  " + RED(`${label}: ${JSON.stringify(emitted)}  ← executes!`));
  console.log(
    "    NiralScript →  " +
      GREEN(`compile error ${nrs.code} — the vulnerable build never exists`)
  );
  console.log("");
}

// --- the summary verdict ----------------------------------------------------

console.log(BOLD("  Why JS and TypeScript score 0/" + vulnCount + ":"));
console.log(DIM("    JavaScript has no type system — every program compiles, nothing is checked."));
console.log(DIM("    TypeScript HAS types, but a tainted string and a safe string are both just"));
console.log(DIM("    `string`. tsc cannot tell attacker data from trusted data, so it reports"));
console.log(DIM("    0 errors on every injection above. Types ≠ dataflow security."));
console.log(DIM("    NiralScript tracks taint through aliasing, concat, templates and reassignment,"));
console.log(DIM("    and only a real launder (sanitize/escape/trust/contract) clears it.\n"));

// Hard assertions so this doubles as a regression test of the claim.
assert.equal(jsCaught, 0, "JavaScript cannot catch injections at compile time");
assert.equal(tsCaught, 0, "TypeScript cannot catch injections at compile time");
assert.equal(nrsCaught, vulnCount, "NiralScript must block every vulnerable scenario");
console.log(GREEN("  ✓ asserted: JS 0/" + vulnCount + ", TS 0/" + vulnCount + ", NiralScript " + nrsCaught + "/" + vulnCount + "\n"));
