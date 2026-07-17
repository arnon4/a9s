/**
 * IAM Users view e2e tests — wide layout (220 cols), fake credentials.
 *
 * At >=200 cols the Users list shows the full column set:
 * NAME | PATH | GROUPS | LAST ACTIVITY | MFA | PASSWORD AGE |
 * CONSOLE SIGN-IN | ACCOUNT ID | ACTIVE KEY AGE | ACCESS KEY LAST USED.
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 220,
});

const LEFT_BORDER_CHARS = ["│", "├", "└"];
const RIGHT_BORDER_CHARS = ["│", "┤", "┘"];

async function goToUsers(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("j");
  terminal.write("j");
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("IAM")).toBeVisible();
  terminal.submit(); // Users is the first menu item
  await expect(terminal.getByText("Users")).toBeVisible();
}

function findRow(buffer, needle) {
  return buffer.findIndex((row) => row.join("").includes(needle));
}

function findLastRow(buffer, needle) {
  for (let i = buffer.length - 1; i >= 0; i--) {
    if (buffer[i].join("").includes(needle)) return i;
  }
  return -1;
}

test("Users list shows all wide-layout column headers", async ({ terminal }) => {
  await goToUsers(terminal);
  for (const header of [
    "NAME",
    "PATH",
    "GROUPS",
    "LAST ACTIVITY",
    "MFA",
    "PASSWORD AGE",
    "CONSOLE SIGN-IN",
    "ACCOUNT ID",
    "ACTIVE KEY AGE",
    "ACCESS KEY LAST USED",
  ]) {
    await expect(terminal.getByText(header)).toBeVisible();
  }
});

test("Users table border reaches the full terminal width in wide layout", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("ACCOUNT ID")).toBeVisible();

  const buffer = terminal.getViewableBuffer();
  const cols = buffer[0].length;
  const headerRow = findRow(buffer, "NAME");
  expect(headerRow).toBeGreaterThanOrEqual(0);

  const bottomRow = findLastRow(buffer, "┘");
  expect(bottomRow).toBeGreaterThanOrEqual(0);
  const rowsToCheck = [headerRow, headerRow + 1, bottomRow];
  for (const r of rowsToCheck) {
    const row = buffer[r];
    expect(LEFT_BORDER_CHARS).toContain(row[0]);
    expect(RIGHT_BORDER_CHARS).toContain(row[cols - 1]);
  }
});
