import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 100,
});

test("shows home view items S3 and Lambda", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("Lambda")).toBeVisible();
});

test("header shows region", async ({ terminal }) => {
  await expect(terminal.getByText("Region")).toBeVisible();
  await expect(terminal.getByText("us-east-1")).toBeVisible();
});

test("header shows credentials source", async ({ terminal }) => {
  await expect(terminal.getByText("Environment")).toBeVisible();
});

test("header shows help hint", async ({ terminal }) => {
  await expect(terminal.getByText("? help")).toBeVisible();
});

test("navigate home items with j/k", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("j");
  await expect(terminal.getByText("Lambda")).toBeVisible();
  terminal.write("k");
  await expect(terminal.getByText("S3")).toBeVisible();
});

test("navigate home items with arrow keys", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.keyDown();
  await expect(terminal.getByText("Lambda")).toBeVisible();
  terminal.keyUp();
  await expect(terminal.getByText("S3")).toBeVisible();
});

test("press colon activates command bar", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write(":");
  // command bar renders ":" prefix — may match multiple on screen so use strict:false
  await expect(terminal.getByText(":", { strict: false })).toBeVisible();
});

test("press ? opens help view", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("?");
  // Help view shows "Keybinds" as first section heading
  await expect(terminal.getByText("Keybinds")).toBeVisible();
});

test("press q shows quit confirm", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  await expect(terminal.getByText("[ No ]")).toBeVisible();
  await expect(terminal.getByText("[ Yes ]")).toBeVisible();
});

test("quit confirm No dismisses dialog", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write("q");
  await expect(terminal.getByText("Quit the application?")).toBeVisible();
  terminal.write("n");
  await expect(terminal.getByText("Quit the application?")).not.toBeVisible();
  await expect(terminal.getByText("S3")).toBeVisible();
});

test("enter on S3 opens S3 buckets view", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.submit();
  // S3 view breadcrumb is "Buckets"
  await expect(terminal.getByText("Buckets")).toBeVisible();
});

test("enter on Lambda opens Lambda functions view", async ({ terminal }) => {
  await expect(terminal.getByText("Lambda")).toBeVisible();
  terminal.write("j");
  terminal.submit();
  // Lambda view breadcrumb is "Functions"
  await expect(terminal.getByText("Functions")).toBeVisible();
});
