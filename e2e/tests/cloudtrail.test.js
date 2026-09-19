/**
 * CloudTrail view e2e tests — fake credentials, no real AWS needed.
 *
 * Covers TrailsView only (Events/Event detail require a real trail).
 *  - Navigation home → CloudTrail → back
 *  - Column headers visible in wide layout
 *  - Error state with fake creds
 *  - j/k and arrow-key navigation (no crash when empty)
 *  - Quit confirm from Trails view
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

// Wide layout: NAME | ACCOUNT | REGION | STATUS (width >= 110)
test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 140,
});

async function goToTrails(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("j");
  terminal.write("j");
  terminal.write("j");
  terminal.write("j");
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("Trails")).toBeVisible();
}

// ── navigation ────────────────────────────────────────────────────────────────

test("navigate home → CloudTrail opens Trails view", async ({ terminal }) => {
  await goToTrails(terminal);
});

test("Esc from Trails returns to home", async ({ terminal }) => {
  await goToTrails(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("CloudTrail")).toBeVisible();
});

// ── column headers ────────────────────────────────────────────────────────────

test("Trails list shows NAME column header", async ({ terminal }) => {
  await goToTrails(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
});

test("Trails list shows ACCOUNT column header (wide layout)", async ({ terminal }) => {
  await goToTrails(terminal);
  await expect(terminal.getByText("ACCOUNT")).toBeVisible();
});

test("Trails list shows REGION column header (wide layout)", async ({ terminal }) => {
  await goToTrails(terminal);
  await expect(terminal.getByText("REGION")).toBeVisible();
});

test("Trails list shows STATUS column header", async ({ terminal }) => {
  await goToTrails(terminal);
  await expect(terminal.getByText("STATUS")).toBeVisible();
});

// ── error state ───────────────────────────────────────────────────────────────

test("Trails list shows error with fake credentials", async ({ terminal }) => {
  await goToTrails(terminal);
  // Fake creds → HTTP request fails; view transitions to failed state
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

// ── keyboard navigation (no crash when list is empty/loading) ─────────────────

test("j key in Trails view does not crash", async ({ terminal }) => {
  await goToTrails(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  await expect(terminal.getByText("Trails")).toBeVisible();
});

test("arrow keys in Trails view do not crash", async ({ terminal }) => {
  await goToTrails(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("Trails")).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from Trails view shows quit confirm", async ({ terminal }) => {
  await goToTrails(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in Trails view", async ({ terminal }) => {
  await goToTrails(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("Trails")).toBeVisible();
});
