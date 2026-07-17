/**
 * Help view e2e tests — fake credentials, no real AWS needed.
 *
 * Covers:
 *  - Opening help from home with ?
 *  - General topic content (Keybinds, Commands sections)
 *  - j/k scroll does not crash
 *  - Esc / ? / Enter all close the help view
 *  - q from Help shows quit confirm
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 100,
});

async function openHelp(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("?");
  await expect(terminal.getByText("Keybinds")).toBeVisible();
}

// ── open / close ──────────────────────────────────────────────────────────────

test("? opens help view with Keybinds section", async ({ terminal }) => {
  await openHelp(terminal);
});

test("help view shows Commands section", async ({ terminal }) => {
  await openHelp(terminal);
  await expect(terminal.getByText("Commands")).toBeVisible();
});

test("Esc closes help view and returns home", async ({ terminal }) => {
  await openHelp(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("S3")).toBeVisible();
});

test("Enter closes help view", async ({ terminal }) => {
  await openHelp(terminal);
  terminal.submit();
  await expect(terminal.getByText("S3")).toBeVisible();
});

// ── scrolling (no crash) ───────────────────────────────────────────────────────

test("j/k scroll in help view does not crash", async ({ terminal }) => {
  await openHelp(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  await expect(terminal.getByText("Keybinds", { strict: false })).toBeVisible();
});

test("arrow keys scroll in help view do not crash", async ({ terminal }) => {
  await openHelp(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("Keybinds", { strict: false })).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from Help view shows quit confirm", async ({ terminal }) => {
  await openHelp(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in Help view", async ({ terminal }) => {
  await openHelp(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("Keybinds", { strict: false })).toBeVisible();
});
