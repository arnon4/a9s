import { test, expect } from "@microsoft/tui-test";
import { BIN, envNoCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envNoCreds,
  rows: 30,
  columns: 100,
});

test("shows auth options when no credentials configured", async ({ terminal }) => {
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
  await expect(terminal.getByText("Inline Credentials")).toBeVisible();
});

test("shows Not authenticated in header", async ({ terminal }) => {
  await expect(terminal.getByText("Not authenticated")).toBeVisible();
});

test("navigate auth options with j/k", async ({ terminal }) => {
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
  terminal.write("j");
  await expect(terminal.getByText("Inline Credentials")).toBeVisible();
  terminal.write("k");
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
});

test("navigate auth options with arrow keys", async ({ terminal }) => {
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
  terminal.keyDown();
  await expect(terminal.getByText("Inline Credentials")).toBeVisible();
  terminal.keyUp();
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
});

test("enter on Inline Credentials opens credentials input", async ({ terminal }) => {
  await expect(terminal.getByText("Inline Credentials")).toBeVisible();
  terminal.write("j");
  terminal.submit();
  await expect(terminal.getByText("Access Key ID")).toBeVisible();
  await expect(terminal.getByText("Secret Access Key")).toBeVisible();
});

test("enter on SSO Profile opens SSO profile view", async ({ terminal }) => {
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
  terminal.submit();
  await expect(terminal.getByText("Profile")).toBeVisible();
});

test("q from auth prompt shows quit confirm", async ({ terminal }) => {
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("escape from auth prompt returns to home or closes", async ({ terminal }) => {
  await expect(terminal.getByText("SSO Profile")).toBeVisible();
  terminal.keyEscape();
  // After esc from auth prompt it pops — app either exits or shows base if base is beneath
  // Just verify the terminal is still active (no crash)
  await expect(terminal.getByText("SSO Profile")).not.toBeVisible();
});
