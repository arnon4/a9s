/**
 * IAM Users view e2e tests — compact layout (80 cols), fake credentials.
 *
 * Below 110 cols the Users list drops down to NAME | LAST ACTIVITY only.
 * This is the exact width class where the original border-fill bug was
 * reported: the table stopped short of the terminal edge, leaving a blank
 * gap before the outer frame.
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 80,
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

test("Users list shows only NAME and LAST ACTIVITY in compact layout", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();
  await expect(terminal.getByText("LAST ACTIVITY")).toBeVisible();
  await expect(terminal.getByText("GROUPS")).not.toBeVisible();
  await expect(terminal.getByText("MFA")).not.toBeVisible();
  await expect(terminal.getByText("PATH")).not.toBeVisible();
});

test("Users table border reaches the full terminal width in compact layout", async ({ terminal }) => {
  await goToUsers(terminal);
  await expect(terminal.getByText("NAME")).toBeVisible();

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
