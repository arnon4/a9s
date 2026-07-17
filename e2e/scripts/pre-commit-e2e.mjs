#!/usr/bin/env node
// Pre-commit gate:
//   1. Every staged view/client module must have a matching e2e test file
//      (tests/<module>*.test.js) — blocks the commit otherwise.
//   2. Builds the project and runs the e2e tests for modules touched by the
//      commit (or the full suite if shared/core files changed).
//
// Installed by .git/hooks/pre-commit. Bypass with `git commit --no-verify`.

import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { MODULE_MAP, isGlobalChange, moduleFor } from "./module-map.mjs";

const REPO_ROOT = path.resolve(import.meta.dirname, "..", "..");
const E2E_DIR = path.resolve(import.meta.dirname, "..");

function stagedFiles() {
  return execSync("git diff --cached --name-only --diff-filter=ACMR", { cwd: REPO_ROOT })
    .toString()
    .split("\n")
    .filter(Boolean)
    .map((f) => f.replaceAll("\\", "/"));
}

const files = stagedFiles();
if (files.length === 0) {
  process.exit(0);
}

// ── 1. every touched module must have a matching e2e test file ──────────────

const touchedModules = new Set();
for (const f of files) {
  const m = moduleFor(f);
  if (m) touchedModules.add(m);
}

const missing = [];
for (const m of touchedModules) {
  const prefixes = MODULE_MAP[m] ?? [m];
  const hasTest = prefixes.some((p) => existsSync(path.join(E2E_DIR, "tests", `${p}.test.js`)));
  if (!hasTest) missing.push(m);
}

if (missing.length > 0) {
  console.error("\n✘ Missing e2e test file for module(s): " + missing.join(", "));
  console.error("  Add e2e/tests/<module>.test.js (see e2e/README.md for the required");
  console.error("  sections: navigation, column headers, error state, keyboard nav, quit");
  console.error("  confirm) and register the module in e2e/scripts/module-map.mjs.");
  console.error("  Bypass with: git commit --no-verify\n");
  process.exit(1);
}

// ── 2. build + run e2e tests scoped to touched modules ───────────────────────

if (touchedModules.size === 0 && !isGlobalChange(files)) {
  // No view/client/shared code touched — nothing relevant to run.
  process.exit(0);
}

console.log("Building project...");
try {
  execSync("zig build", { cwd: REPO_ROOT, stdio: "inherit" });
} catch {
  console.error("\n✘ zig build failed — fix build errors before committing.\n");
  process.exit(1);
}

let testCmd;
if (isGlobalChange(files)) {
  console.log("Shared/core files changed — running full e2e suite.");
  testCmd = "npx @microsoft/tui-test";
} else {
  const prefixes = [...touchedModules].flatMap((m) => MODULE_MAP[m]);
  const regexArgs = prefixes.map((p) => `"tests.${p}"`);
  console.log(`Modules affected: ${[...touchedModules].join(", ")}`);
  testCmd = `npx @microsoft/tui-test ${regexArgs.join(" ")}`;
}

console.log(`Running: ${testCmd}`);
try {
  execSync(testCmd, { cwd: E2E_DIR, stdio: "inherit" });
} catch {
  console.error("\n✘ e2e tests failed — fix them or bypass with git commit --no-verify\n");
  process.exit(1);
}
