/**
 * S3 view e2e tests — fake credentials, no real AWS needed.
 *
 * Covers:
 *  - Navigation home → Buckets list → back
 *  - Column headers visible in wide layout
 *  - Loading then error state with fake creds
 *  - j/k and arrow-key navigation (no-ops when list empty, no crash)
 *  - Quit confirm from Buckets view
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

// Wide layout: NAME | REGION | ACCOUNT | CREATED | SIZE
test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 140,
});

async function goToBuckets(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.submit();
  await expect(terminal.getByText("Buckets")).toBeVisible();
}

// ── navigation ────────────────────────────────────────────────────────────────

test("navigate home → S3 opens Buckets view", async ({ terminal }) => {
  await goToBuckets(terminal);
});

test("Esc from Buckets returns to home", async ({ terminal }) => {
  await goToBuckets(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("Lambda")).toBeVisible();
});

// ── column headers ─────────────────────────────────────────────────────────────

test("Buckets list shows NAME column header", async ({ terminal }) => {
  await goToBuckets(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
});

test("Buckets list shows REGION column header", async ({ terminal }) => {
  await goToBuckets(terminal);
  await expect(terminal.getByText("REGION")).toBeVisible();
});

test("Buckets list shows ACCOUNT column header (wide layout)", async ({ terminal }) => {
  await goToBuckets(terminal);
  await expect(terminal.getByText("ACCOUNT")).toBeVisible();
});

test("Buckets list shows CREATED column header (wide layout)", async ({ terminal }) => {
  await goToBuckets(terminal);
  await expect(terminal.getByText("CREATED")).toBeVisible();
});

test("Buckets list shows SIZE column header (wide layout)", async ({ terminal }) => {
  await goToBuckets(terminal);
  await expect(terminal.getByText("SIZE")).toBeVisible();
});

// ── error state ───────────────────────────────────────────────────────────────

test("Buckets list shows error with fake credentials", async ({ terminal }) => {
  await goToBuckets(terminal);
  // Fake creds → HTTP request fails; view transitions to failed state
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

// ── keyboard navigation (no crash when list is empty/loading) ─────────────────

test("j key in Buckets view does not crash", async ({ terminal }) => {
  await goToBuckets(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  await expect(terminal.getByText("Buckets")).toBeVisible();
});

test("arrow keys in Buckets view do not crash", async ({ terminal }) => {
  await goToBuckets(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("Buckets")).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from Buckets view shows quit confirm", async ({ terminal }) => {
  await goToBuckets(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in Buckets view", async ({ terminal }) => {
  await goToBuckets(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("Buckets")).toBeVisible();
});
