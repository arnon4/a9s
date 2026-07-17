/**
 * IAM view e2e tests — fake credentials, no real AWS needed.
 *
 * Medium-layout terminal (140 cols): Users list shows
 * NAME | GROUPS | LAST ACTIVITY | MFA | ACCESS KEY LAST USED.
 *
 * Covers:
 *  - Navigation home → IAM → Users/Roles/Policies → back
 *  - Users column headers in medium layout
 *  - Table border reaches the full terminal width (regression: previously the
 *    table stopped short and left a blank gap before the outer frame)
 *  - Loading then error state with fake creds
 *  - j/k and arrow-key navigation (no-ops when list empty, no crash)
 *  - Quit confirm from Users view
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 140,
});

// Box-drawing glyphs a table row's first/last cell should be, if the table
// border spans the full terminal width.
const LEFT_BORDER_CHARS = ["│", "├", "└"];
const RIGHT_BORDER_CHARS = ["│", "┤", "┘"];

async function goToIamHome(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("j");
  terminal.write("j");
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("IAM")).toBeVisible();
}

async function goToUsers(terminal) {
  await goToIamHome(terminal);
  terminal.submit(); // Users is the first menu item
  await expect(terminal.getByText("Users")).toBeVisible();
}

async function goToRoles(terminal) {
  await goToIamHome(terminal);
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("Roles")).toBeVisible();
}

async function goToPolicies(terminal) {
  await goToIamHome(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("Policies")).toBeVisible();
}

// Finds the row index (in the viewable buffer) whose joined text contains `needle`.
function findRow(buffer, needle) {
  return buffer.findIndex((row) => row.join("").includes(needle));
}

// Finds the last row containing `needle` (e.g. the bottom border, which may
// not be the terminal's last line if there's a command bar area below it).
function findLastRow(buffer, needle) {
  for (let i = buffer.length - 1; i >= 0; i--) {
    if (buffer[i].join("").includes(needle)) return i;
  }
  return -1;
}

// ── navigation ────────────────────────────────────────────────────────────────

test("navigate home → IAM opens IAM home view", async ({ terminal }) => {
  await goToIamHome(terminal);
  await expect(terminal.getByText("Users")).toBeVisible();
  await expect(terminal.getByText("Roles")).toBeVisible();
  await expect(terminal.getByText("Policies")).toBeVisible();
});

test("navigate home → IAM → Users opens Users view", async ({ terminal }) => {
  await goToUsers(terminal);
});

test("Esc from Users returns to IAM home", async ({ terminal }) => {
  await goToUsers(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("Roles")).toBeVisible();
  await expect(terminal.getByText("Policies")).toBeVisible();
});

test("navigate home → IAM → Roles opens Roles view", async ({ terminal }) => {
  await goToRoles(terminal);
});

test("Esc from Roles returns to IAM home", async ({ terminal }) => {
  await goToRoles(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("Users")).toBeVisible();
});

test("navigate home → IAM → Policies opens Policies view", async ({ terminal }) => {
  await goToPolicies(terminal);
});

test("Esc from Policies returns to IAM home", async ({ terminal }) => {
  await goToPolicies(terminal);
  terminal.keyEscape();
  await expect(terminal.getByText("Users")).toBeVisible();
});

// ── column headers (medium layout) ─────────────────────────────────────────────

test("Users list shows NAME column header", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
});

test("Users list shows GROUPS column header (medium layout)", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("GROUPS")).toBeVisible();
});

test("Users list shows LAST ACTIVITY column header", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("LAST ACTIVITY")).toBeVisible();
});

test("Users list shows MFA column header (medium layout)", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("MFA")).toBeVisible();
});

test("Users list shows ACCESS KEY LAST USED column header (medium layout)", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("ACCESS KEY LAST USED")).toBeVisible();
});

// Medium layout should not show wide-only columns.
test("Users list hides PATH column in medium layout", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("PATH")).not.toBeVisible();
});

// ── border integrity (regression) ──────────────────────────────────────────────

test("Users table border reaches the full terminal width", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();

  const buffer = terminal.getViewableBuffer();
  const cols = buffer[0].length;

  const headerRow = findRow(buffer, "NAME");
  expect(headerRow).toBeGreaterThanOrEqual(0);

  // Header row, the separator below it, and the very last (bottom border) row
  // must all start/end with a box-drawing border glyph — not blank space —
  // confirming the table spans the full width with no trailing gap.
  const bottomRow = findLastRow(buffer, "┘");
  expect(bottomRow).toBeGreaterThanOrEqual(0);
  const rowsToCheck = [headerRow, headerRow + 1, bottomRow];
  for (const r of rowsToCheck) {
    const row = buffer[r];
    expect(LEFT_BORDER_CHARS).toContain(row[0]);
    expect(RIGHT_BORDER_CHARS).toContain(row[cols - 1]);
  }
});

// ── error state ───────────────────────────────────────────────────────────────

test("Users list shows error with fake credentials", async ({ terminal }) => {
  await goToUsers(terminal);
  // Fake creds → HTTP request fails; view transitions to failed state
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

test("Roles list shows error with fake credentials", async ({ terminal }) => {
  await goToRoles(terminal);
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

test("Policies list shows error with fake credentials", async ({ terminal }) => {
  await goToPolicies(terminal);
  await expect(terminal.getByText("Error", { strict: false })).toBeVisible({
    timeout: 15_000,
  });
});

// ── keyboard navigation (no crash when list is empty/loading) ─────────────────

test("j key in Users view does not crash", async ({ terminal }) => {
  await goToUsers(terminal);
  terminal.write("j");
  terminal.write("j");
  terminal.write("k");
  await expect(terminal.getByText("Users")).toBeVisible();
});

test("arrow keys in Users view do not crash", async ({ terminal }) => {
  await goToUsers(terminal);
  terminal.keyDown();
  terminal.keyDown();
  terminal.keyUp();
  await expect(terminal.getByText("Users")).toBeVisible();
});

// ── quit confirm ──────────────────────────────────────────────────────────────

test("q from Users view shows quit confirm", async ({ terminal }) => {
  await goToUsers(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses and stays in Users view", async ({ terminal }) => {
  await goToUsers(terminal);
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("Users")).toBeVisible();
});
