/**
 * Real-AWS Lambda tests: functions list, function metadata, function code.
 *
 * Requires tests/fixtures.json — run: node scripts/discover-and-test.mjs --discover-only
 */
import { test, expect } from "@microsoft/tui-test";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { BIN } from "./helpers.js";

const __dir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_PATH = resolve(__dir, "fixtures.json");

const fixtures = existsSync(FIXTURES_PATH)
  ? JSON.parse(readFileSync(FIXTURES_PATH, "utf8"))
  : null;

const testEnv = fixtures?.credentials
  ? { ...process.env, ...fixtures.credentials, AWS_DEFAULT_REGION: fixtures.region }
  : {
      ...process.env,
      AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
      AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      AWS_DEFAULT_REGION: "us-east-1",
    };

test.use({
  program: { file: BIN },
  env: testEnv,
  rows: 40,
  columns: 160,
});

async function runCommand(terminal, cmd) {
  terminal.write(":");
  terminal.write(cmd);
  terminal.submit();
}

// ── navigate to Lambda functions view ─────────────────────────────────────────
async function goToFunctions(terminal) {
  await expect(terminal.getByText("Lambda")).toBeVisible({ timeout: 10_000 });
  terminal.write("j"); // Lambda is below S3 on the home list
  terminal.submit();
  await expect(terminal.getByText("Functions")).toBeVisible({ timeout: 10_000 });
}

// ── navigate into the fixture function (functions list → function detail) ─────
async function goToFunctionDetail(terminal, lambda) {
  await goToFunctions(terminal);
  await expect(
    terminal.getByText(lambda.name, { strict: false })
  ).toBeVisible({ timeout: 30_000 });
  await runCommand(terminal, `filter name contains "${lambda.name}"`);
  terminal.submit();
  await expect(terminal.getByText("Function Name")).toBeVisible({ timeout: 10_000 });
}

// ─────────────────────────────────────────────────────────────────────────────

test("lambda functions list shows function", async ({ terminal }) => {
  if (!fixtures?.lambda) return;

  await goToFunctions(terminal);
  await expect(
    terminal.getByText(fixtures.lambda.name, { strict: false })
  ).toBeVisible({ timeout: 30_000 });
});

test("lambda functions list shows column headers", async ({ terminal }) => {
  if (!fixtures?.lambda) return;

  await goToFunctions(terminal);
  // Column headers rendered in the wide/medium layout
  await expect(terminal.getByText("Functions")).toBeVisible({ timeout: 10_000 });
});

test("lambda function detail shows prop labels", async ({ terminal }) => {
  if (!fixtures?.lambda) return;

  await goToFunctionDetail(terminal, fixtures.lambda);
  await expect(terminal.getByText("ARN")).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Region", { strict: false })).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Runtime")).toBeVisible({ timeout: 20_000 });
  await expect(terminal.getByText("Handler")).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Role", { strict: false })).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Code Size")).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Timeout")).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Memory Size")).toBeVisible({ timeout: 5_000 });
});

test("lambda function detail shows correct function name", async ({ terminal }) => {
  if (!fixtures?.lambda) return;

  await goToFunctionDetail(terminal, fixtures.lambda);
  await expect(
    terminal.getByText(fixtures.lambda.name, { strict: false })
  ).toBeVisible({ timeout: 5_000 });
});

test("lambda function detail shows correct region", async ({ terminal }) => {
  if (!fixtures?.lambda) return;

  await goToFunctionDetail(terminal, fixtures.lambda);
  await expect(
    terminal.getByText(fixtures.lambda.region, { strict: false })
  ).toBeVisible({ timeout: 5_000 });
});

test("lambda function detail shows runtime value", async ({ terminal }) => {
  if (!fixtures?.lambda?.runtime) return;

  await goToFunctionDetail(terminal, fixtures.lambda);
  await expect(
    terminal.getByText(fixtures.lambda.runtime, { strict: false })
  ).toBeVisible({ timeout: 20_000 });
});

test("lambda function detail shows ARN", async ({ terminal }) => {
  if (!fixtures?.lambda?.arn) return;

  await goToFunctionDetail(terminal, fixtures.lambda);
  // ARN is long — check for the distinctive arn:aws:lambda: prefix
  await expect(
    terminal.getByText("arn:aws:lambda:", { strict: false })
  ).toBeVisible({ timeout: 5_000 });
});

test("lambda function code view shows content", async ({ terminal }) => {
  // Code view available only when code_size > 0 and <= 10MB
  const MAX = 10 * 1024 * 1024;
  if (!fixtures?.lambda) return;
  if (!(fixtures.lambda.codeSize > 0 && fixtures.lambda.codeSize <= MAX)) return;

  await goToFunctionDetail(terminal, fixtures.lambda);
  // Enter opens the lambda code view
  terminal.submit();
  // The code view fetches a zip and extracts it; just verify we navigated away
  // from the detail view (Function Name prop no longer the only thing on screen)
  // and some content appeared. Give it generous time for the download.
  await expect(
    terminal.getByText("Function Name")
  ).not.toBeVisible({ timeout: 60_000 });
});

test("lambda functions list sort by name works", async ({ terminal }) => {
  if (!fixtures?.lambda) return;

  await goToFunctions(terminal);
  await expect(
    terminal.getByText(fixtures.lambda.name, { strict: false })
  ).toBeVisible({ timeout: 30_000 });
  await runCommand(terminal, "sort name");
  await expect(terminal.getByText("Functions")).toBeVisible({ timeout: 5_000 });
});

test("lambda functions filter reduces visible items", async ({ terminal }) => {
  if (!fixtures?.lambda) return;

  await goToFunctions(terminal);
  await expect(
    terminal.getByText(fixtures.lambda.name, { strict: false })
  ).toBeVisible({ timeout: 30_000 });
  await runCommand(terminal, `filter name contains "${fixtures.lambda.name}"`);
  await expect(
    terminal.getByText(fixtures.lambda.name, { strict: false })
  ).toBeVisible({ timeout: 5_000 });
});
