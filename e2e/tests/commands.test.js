import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envWithCreds,
  rows: 30,
  columns: 100,
});

// Activate command bar, type cmd, submit. No intermediate assertion on ":"
// because the header also contains ":" (e.g. "Region: us-east-1").
async function runCommand(terminal, cmd) {
  terminal.write(":");
  terminal.write(cmd);
  terminal.submit();
}

test("unknown command shows error", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await runCommand(terminal, "xyzunknown");
  await expect(terminal.getByText("unknown command")).toBeVisible();
});

test(":goto s3 navigates to S3 view", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await runCommand(terminal, "goto s3");
  await expect(terminal.getByText("Buckets")).toBeVisible();
});

test(":goto lambda navigates to Lambda functions view", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await runCommand(terminal, "goto lambda");
  await expect(terminal.getByText("Functions")).toBeVisible();
});

test(":goto unknown shows error", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await runCommand(terminal, "goto nonexistentview");
  await expect(terminal.getByText("unknown view")).toBeVisible();
});

test(":help opens general help view", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await runCommand(terminal, "help");
  await expect(terminal.getByText("Keybinds")).toBeVisible();
});

test(":region show displays current region", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await runCommand(terminal, "region show");
  await expect(terminal.getByText("us-east-1")).toBeVisible();
});

test(":region use changes the active region", async ({ terminal }) => {
  await expect(terminal.getByText("us-east-1")).toBeVisible();
  await runCommand(terminal, "region use eu-west-1");
  await expect(terminal.getByText("eu-west-1")).toBeVisible();
});

test(":region add adds a region alongside existing ones", async ({ terminal }) => {
  await expect(terminal.getByText("us-east-1")).toBeVisible();
  await runCommand(terminal, "region add eu-west-1");
  await expect(terminal.getByText("eu-west-1")).toBeVisible();
  await expect(terminal.getByText("us-east-1")).toBeVisible();
});

test(":sort not allowed on home view shows error", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  await runCommand(terminal, "sort name");
  await expect(terminal.getByText("not allowed in this view")).toBeVisible();
});

test("escape dismisses command bar without executing", async ({ terminal }) => {
  await expect(terminal.getByText("S3")).toBeVisible();
  terminal.write(":");
  terminal.write("goto s3");
  terminal.keyEscape();
  // command bar dismissed; still on home view, Buckets should NOT appear
  await expect(terminal.getByText("S3")).toBeVisible();
  await expect(terminal.getByText("Buckets")).not.toBeVisible();
});
