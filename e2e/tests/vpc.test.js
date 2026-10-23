/**
 * VPC view e2e tests — fake credentials, no real AWS needed.
 *
 * Covers the VPCs list only.
 *  - Navigation home → VPC → back
 *  - Column headers visible in wide layout
 *  - Error state with fake creds
 *  - j/k and arrow-key navigation (no crash when empty)
 *  - Quit confirm from VPCs view
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

// Wide layout: NAME | VPC ID | CIDR | REGION | STATE | ACCOUNT (width >= 110)
test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 140,
});

async function goToVpcs(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible();
  for (let i = 0; i < 6; i++) terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("VPCs")).toBeVisible();
}

// ── navigation ────────────────────────────────────────────────────────────────

test("navigate home → VPC opens VPCs view", async ({ terminal }) => {
  await goToVpcs(terminal);
});

test("Esc from VPCs returns to home", async ({ terminal }) => {
  await goToVpcs(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("CloudTrail")).toBeVisible();
});

// ── column headers ────────────────────────────────────────────────────────────

test("VPCs list shows NAME column header", async ({ terminal }) => {
  await goToVpcs(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
});

test("VPCs list shows VPC ID column header", async ({ terminal }) => {
  await goToVpcs(terminal);
  await expect(terminal.getByText("VPC ID")).toBeVisible();
});

test("VPCs list shows CIDR column header", async ({ terminal }) => {
  await goToVpcs(terminal);
  await expect(terminal.getByText("CIDR")).toBeVisible();
});

test("VPCs list shows REGION column header (wide layout)", async ({ terminal }) => {
  await goToVpcs(terminal);
  await expect(terminal.getByText("REGION")).toBeVisible();
});

test("VPCs list shows STATE column header (wide layout)", async ({ terminal }) => {
  await goToVpcs(terminal);
  await expect(terminal.getByText("STATE")).toBeVisible();
});

test("VPCs list shows ACCOUNT column header (wide layout)", async ({ terminal }) => {
  await goToVpcs(terminal);
  await expect(terminal.getByText("ACCOUNT")).toBeVisible();
});

// ── error state ───────────────────────────────────────────────────────────────

test("VPCs list shows error with fake credentials", async ({ terminal }) => {
  await goToVpcs(terminal);
  // Fake creds → AuthFailure; view transitions to failed state
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

// ── keyboard navigation (no crash when list is empty/loading) ─────────────────

test("j key in VPCs view does not crash", async ({ terminal }) => {
  await goToVpcs(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  await expect(terminal.getByText("VPCs")).toBeVisible();
});

test("arrow keys in VPCs view do not crash", async ({ terminal }) => {
  await goToVpcs(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("VPCs")).toBeVisible();
});

test("Enter on empty VPCs list does not crash", async ({ terminal }) => {
  await goToVpcs(terminal);
  terminal.submit();
  await expect(terminal.getByText("VPCs")).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from VPCs view shows quit confirm", async ({ terminal }) => {
  await goToVpcs(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in VPCs view", async ({ terminal }) => {
  await goToVpcs(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("VPCs")).toBeVisible();
});
