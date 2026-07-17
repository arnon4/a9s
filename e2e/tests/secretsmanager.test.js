/**
 * Secrets Manager view e2e tests — fake credentials, no real AWS needed.
 *
 * Covers:
 *  - Navigation home → Secrets Manager → back
 *  - Column headers visible in wide layout
 *  - Loading then error state with fake creds
 *  - j/k and arrow-key navigation (no-ops when list empty, no crash)
 *  - Quit confirm from Secrets view
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

// Wide layout: NAME | ACCOUNT | REGION | CREATED | LAST ACCESSED (width >= 120)
test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 140,
});

async function goToSecrets(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("j");
  terminal.write("j");
  terminal.write("j");
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("Secrets")).toBeVisible();
}

// ── navigation ────────────────────────────────────────────────────────────────

test("navigate home → Secrets Manager opens Secrets view", async ({ terminal }) => {
  await goToSecrets(terminal);
});

test("Esc from Secrets returns to home", async ({ terminal }) => {
  await goToSecrets(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("Secrets Manager")).toBeVisible();
});

// ── column headers ─────────────────────────────────────────────────────────────

test("Secrets list shows NAME column header", async ({ terminal }) => {
  await goToSecrets(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
});

test("Secrets list shows ACCOUNT column header (wide layout)", async ({ terminal }) => {
  await goToSecrets(terminal);
  await expect(terminal.getByText("ACCOUNT")).toBeVisible();
});

test("Secrets list shows REGION column header", async ({ terminal }) => {
  await goToSecrets(terminal);
  await expect(terminal.getByText("REGION")).toBeVisible();
});

test("Secrets list shows CREATED column header", async ({ terminal }) => {
  await goToSecrets(terminal);
  await expect(terminal.getByText("CREATED")).toBeVisible();
});

test("Secrets list shows LAST ACCESSED column header (wide layout)", async ({ terminal }) => {
  await goToSecrets(terminal);
  await expect(terminal.getByText("LAST ACCESSED")).toBeVisible();
});

// ── error state ───────────────────────────────────────────────────────────────

test("Secrets list shows error with fake credentials", async ({ terminal }) => {
  await goToSecrets(terminal);
  // Fake creds → HTTP request fails; view transitions to failed state
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

// ── keyboard navigation (no crash when list is empty/loading) ─────────────────

test("j key in Secrets view does not crash", async ({ terminal }) => {
  await goToSecrets(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  await expect(terminal.getByText("Secrets")).toBeVisible();
});

test("arrow keys in Secrets view do not crash", async ({ terminal }) => {
  await goToSecrets(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("Secrets")).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from Secrets view shows quit confirm", async ({ terminal }) => {
  await goToSecrets(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in Secrets view", async ({ terminal }) => {
  await goToSecrets(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("Secrets")).toBeVisible();
});
