#!/usr/bin/env node
// Runs only the e2e test files relevant to modules touched by the current diff.
//
// Usage:
//   node scripts/run-affected.mjs [--base <ref>] [-- <extra tui-test args>]
//
// Maps changed files under src/app/views/<module>/, src/sdk/clients/<module>/
// to test files tests/<module>*.test.js via MODULE_MAP below. Falls back to
// running the full suite if the diff touches shared/core files (app.zig,
// ui/, terminal/, main.zig, helpers.js) since those can affect every view.

import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { MODULE_MAP, isGlobalChange, moduleFor } from "./module-map.mjs";

const REPO_ROOT = path.resolve(import.meta.dirname, "..", "..");
const E2E_DIR = path.resolve(import.meta.dirname, "..");

function parseArgs(argv) {
  let base = "main";
  const extra = [];
  let i = 0;
  while (i < argv.length) {
    if (argv[i] === "--base") {
      base = argv[i + 1];
      i += 2;
    } else if (argv[i] === "--") {
      extra.push(...argv.slice(i + 1));
      break;
    } else {
      extra.push(argv[i]);
      i += 1;
    }
  }
  return { base, extra };
}

function changedFiles(base) {
  let diffFiles = [];
  try {
    const merge = execSync(`git merge-base ${base} HEAD`, { cwd: REPO_ROOT }).toString().trim();
    diffFiles = execSync(`git diff --name-only ${merge}`, { cwd: REPO_ROOT })
      .toString()
      .split("\n")
      .filter(Boolean);
  } catch {
    // base ref doesn't exist (e.g. no remote configured) — fall back to
    // working-tree status only.
  }
  const statusOut = execSync("git status --porcelain", { cwd: REPO_ROOT }).toString();
  const statusFiles = statusOut
    .split("\n")
    .map((l) => l.slice(3).trim())
    .filter(Boolean);
  return [...new Set([...diffFiles, ...statusFiles])].map((f) => f.replaceAll("\\", "/"));
}

function modulesFor(files) {
  const modules = new Set();
  for (const f of files) {
    const m = moduleFor(f);
    if (m && MODULE_MAP[m]) modules.add(m);
  }
  return modules;
}

const { base, extra } = parseArgs(process.argv.slice(2));
const files = changedFiles(base);

if (files.length === 0) {
  console.log("No changes detected — nothing to run.");
  process.exit(0);
}

if (isGlobalChange(files)) {
  console.log("Shared/core files changed — running full e2e suite.");
  execSync(`npx @microsoft/tui-test ${extra.join(" ")}`, { cwd: E2E_DIR, stdio: "inherit" });
  process.exit(0);
}

const modules = modulesFor(files);
if (modules.size === 0) {
  console.log("No view/client modules touched — nothing to run.");
  process.exit(0);
}

const prefixes = [...modules].flatMap((m) => MODULE_MAP[m]);
const regexArgs = prefixes.map((p) => `tests.${p}`);

console.log(`Modules affected: ${[...modules].join(", ")}`);
console.log(`Running: npx @microsoft/tui-test ${regexArgs.join(" ")}`);

const testFilesExist = prefixes.some((p) =>
  existsSync(path.join(E2E_DIR, "tests", `${p}.test.js`))
);
if (!testFilesExist) {
  console.log("No matching test files found for affected modules.");
  process.exit(0);
}

execSync(`npx @microsoft/tui-test ${regexArgs.map((r) => `"${r}"`).join(" ")} ${extra.join(" ")}`, {
  cwd: E2E_DIR,
  stdio: "inherit",
});
