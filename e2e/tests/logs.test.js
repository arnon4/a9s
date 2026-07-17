/**
 * Logs views e2e tests — fake credentials, no real AWS needed.
 *
 * Covers LogGroupsView only (LogStreams/Events require a real log group).
 *  - Navigation home → Log Groups → back
 *  - Column headers visible in wide layout
 *  - Error state with fake creds
 *  - j/k and arrow-key navigation (no crash when empty)
 *  - Quit confirm from Log Groups view
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

// Wide layout: NAME | RETENTION | CLASS | REGION | STORED (width >= 100)
test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 140,
});

async function goToLogGroups(terminal) {
  await expect(terminal.getByText("CloudWatch Logs")).toBeVisible();
  terminal.write("j");
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("Log Groups")).toBeVisible();
}

// ── navigation ────────────────────────────────────────────────────────────────

test("navigate home → CloudWatch Logs opens Log Groups view", async ({ terminal }) => {
  await goToLogGroups(terminal);
});

test("Esc from Log Groups returns to home", async ({ terminal }) => {
  await goToLogGroups(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("CloudWatch Logs")).toBeVisible();
});

// ── column headers ────────────────────────────────────────────────────────────

test("Log Groups list shows NAME column header", async ({ terminal }) => {
  await goToLogGroups(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
});

test("Log Groups list shows RETENTION column header", async ({ terminal }) => {
  await goToLogGroups(terminal);
  await expect(terminal.getByText("RETENTION")).toBeVisible();
});

test("Log Groups list shows CLASS column header (wide layout)", async ({ terminal }) => {
  await goToLogGroups(terminal);
  await expect(terminal.getByText("CLASS")).toBeVisible();
});

test("Log Groups list shows REGION column header (wide layout)", async ({ terminal }) => {
  await goToLogGroups(terminal);
  await expect(terminal.getByText("REGION")).toBeVisible();
});

test("Log Groups list shows STORED column header (wide layout)", async ({ terminal }) => {
  await goToLogGroups(terminal);
  await expect(terminal.getByText("STORED")).toBeVisible();
});

// ── error state ───────────────────────────────────────────────────────────────

test("Log Groups shows error with fake credentials", async ({ terminal }) => {
  await goToLogGroups(terminal);
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

// ── keyboard navigation (no crash when list empty/loading) ────────────────────

test("j key in Log Groups view does not crash", async ({ terminal }) => {
  await goToLogGroups(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  await expect(terminal.getByText("Log Groups")).toBeVisible();
});

test("arrow keys in Log Groups view do not crash", async ({ terminal }) => {
  await goToLogGroups(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("Log Groups")).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from Log Groups view shows quit confirm", async ({ terminal }) => {
  await goToLogGroups(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in Log Groups view", async ({ terminal }) => {
  await goToLogGroups(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("Log Groups")).toBeVisible();
});
