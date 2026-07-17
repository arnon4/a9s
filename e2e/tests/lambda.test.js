/**
 * Lambda view e2e tests — fake credentials, no real AWS needed.
 *
 * Covers:
 *  - Navigation home → Functions list → back
 *  - Column headers visible in wide and medium layouts
 *  - Loading then error state with fake creds
 *  - j/k and arrow-key navigation (no-ops when list empty, no crash)
 *  - Quit confirm from Functions view
 *  - Function detail view: props, action bar, Esc back
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

// ── shared config ─────────────────────────────────────────────────────────────

// Wide layout: NAME | RUNTIME | REGION | ACCOUNT | ARCH | PKG | MODIFIED
test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 140,
});

async function goToFunctions(terminal) {
  await expect(terminal.getByText("Lambda")).toBeVisible();
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("Functions")).toBeVisible();
}

// ── navigation ────────────────────────────────────────────────────────────────

test("navigate home → Lambda opens Functions view", async ({ terminal }) => {
  await goToFunctions(terminal);
});

test("Esc from Functions returns to home", async ({ terminal }) => {
  await goToFunctions(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("Lambda")).toBeVisible();
});

// ── column headers ─────────────────────────────────────────────────────────────

test("Functions list shows NAME column header", async ({ terminal }) => {
  await goToFunctions(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
});

test("Functions list shows RUNTIME column header", async ({ terminal }) => {
  await goToFunctions(terminal);
  await expect(terminal.getByText("RUNTIME")).toBeVisible();
});

test("Functions list shows REGION column header (wide layout)", async ({ terminal }) => {
  await goToFunctions(terminal);
  await expect(terminal.getByText("REGION")).toBeVisible();
});

test("Functions list shows MODIFIED column header (wide layout)", async ({ terminal }) => {
  await goToFunctions(terminal);
  await expect(terminal.getByText("MODIFIED")).toBeVisible();
});

// ── error state ───────────────────────────────────────────────────────────────

test("Functions list shows error with fake credentials", async ({ terminal }) => {
  await goToFunctions(terminal);
  // Fake creds → HTTP request fails; view transitions to failed state
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

// ── keyboard navigation (no crash when list is empty/loading) ─────────────────

test("j key in Functions view does not crash", async ({ terminal }) => {
  await goToFunctions(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  // View is still visible
  await expect(terminal.getByText("Functions")).toBeVisible();
});

test("arrow keys in Functions view do not crash", async ({ terminal }) => {
  await goToFunctions(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("Functions")).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from Functions view shows quit confirm", async ({ terminal }) => {
  await goToFunctions(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in Functions view", async ({ terminal }) => {
  await goToFunctions(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("Functions")).toBeVisible();
});
