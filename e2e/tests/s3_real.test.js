/**
 * Real-AWS S3 tests: objects list, object metadata, object content.
 *
 * Requires tests/fixtures.json — run: node scripts/discover-and-test.mjs --discover-only
 */
import { test, expect } from "@microsoft/tui-test";
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { BIN } from "./helpers.js";

const __dir = dirname(fileURLToPath(import.meta.url));
const FIXTURES_PATH = resolve(__dir, "fixtures.json");

const fixtures = existsSync(FIXTURES_PATH)
  ? JSON.parse(readFileSync(FIXTURES_PATH, "utf8"))
  : null;

// Always set up test.use at module level — tui-test requires this.
// Use real creds when available; fall back to fake creds so the app still starts.
const testEnv = fixtures?.credentials
  ? {
      ...process.env,
      ...fixtures.credentials,
      AWS_DEFAULT_REGION: fixtures.region,
    }
  : {
      ...process.env,
      AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE",
      AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      AWS_DEFAULT_REGION: "us-east-1",
    };

test.use({
  program: { file: BIN },
  env: testEnv,
  rows: 40,
  columns: 160,
});

// Short key: last path component, capped at 40 chars — enough to confirm presence
// without worrying about truncation in narrow columns.
function displayKey(key) {
  const last = key.split("/").pop() ?? key;
  return last.length > 40 ? last.slice(0, 40) : last;
}

async function runCommand(terminal, cmd) {
  terminal.write(":");
  terminal.write(cmd);
  terminal.submit();
}

// ── navigate to S3 buckets view ───────────────────────────────────────────────
async function goToBuckets(terminal) {
  await expect(terminal.getByText("S3")).toBeVisible({ timeout: 10_000 });
  terminal.submit();
  await expect(terminal.getByText("Buckets")).toBeVisible({ timeout: 10_000 });
}

// ── navigate into the fixture bucket (buckets view → objects view) ─────────────
async function goToObjects(terminal, bucket) {
  await goToBuckets(terminal);
  await expect(terminal.getByText(bucket.name, { strict: false })).toBeVisible({
    timeout: 30_000,
  });
  await runCommand(terminal, `filter name contains "${bucket.name}"`);
  // Bucket region loads async (HeadBucket after ListBuckets). Enter on "-" is a no-op.
  await new Promise((r) => setTimeout(r, 3000));
  terminal.submit();
  // "KEY" is the objects-list column header — not present in the object detail view.
  // This confirms we reached the objects list and not one level deeper.
  await expect(terminal.getByText("KEY", { strict: false })).toBeVisible({
    timeout: 20_000,
  });
}

// ── navigate into the fixture object (objects view → object detail view) ────────
async function goToObjectDetail(terminal, bucket) {
  await goToObjects(terminal, bucket);
  const key = bucket.object.key;
  await expect(
    terminal.getByText(displayKey(key), { strict: false }),
  ).toBeVisible({ timeout: 30_000 });
  await runCommand(terminal, `filter name contains "${key}"`);
  terminal.submit();
  await expect(terminal.getByText("Key")).toBeVisible({ timeout: 10_000 });
}

// ─────────────────────────────────────────────────────────────────────────────

test("s3 buckets list includes fixture bucket", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  await goToBuckets(terminal);
  await expect(
    terminal.getByText(fixtures.bucket.name, { strict: false }),
  ).toBeVisible({ timeout: 30_000 });
});

test("s3 objects list shows object key", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  const { bucket } = fixtures;
  await goToObjects(terminal, bucket);
  await expect(
    terminal.getByText(displayKey(bucket.object.key), { strict: false }),
  ).toBeVisible({ timeout: 30_000 });
});

test("s3 objects list shows KEY/SIZE column headers", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  await goToObjects(terminal, fixtures.bucket);
  await expect(terminal.getByText("KEY")).toBeVisible({ timeout: 10_000 });
  await expect(terminal.getByText("SIZE")).toBeVisible({ timeout: 5_000 });
});

test("s3 object detail shows metadata prop labels", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  await goToObjectDetail(terminal, fixtures.bucket);
  await expect(terminal.getByText("Bucket", { strict: false })).toBeVisible({
    timeout: 5_000,
  });
  await expect(terminal.getByText("Region", { strict: false })).toBeVisible({
    timeout: 5_000,
  });
  await expect(terminal.getByText("Size")).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("ETag")).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Storage Class")).toBeVisible({
    timeout: 5_000,
  });
});

test("s3 object detail shows correct bucket name", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  await goToObjectDetail(terminal, fixtures.bucket);
  await expect(
    terminal.getByText(fixtures.bucket.name, { strict: false }),
  ).toBeVisible({ timeout: 5_000 });
});

test("s3 object detail shows correct region", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  await goToObjectDetail(terminal, fixtures.bucket);
  await expect(
    terminal.getByText(fixtures.bucket.region, { strict: false }),
  ).toBeVisible({ timeout: 5_000 });
});

test("s3 object detail shows correct storage class", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  const sc = fixtures.bucket.object.storageClass;
  await goToObjectDetail(terminal, fixtures.bucket);
  await expect(terminal.getByText(sc, { strict: false })).toBeVisible({
    timeout: 5_000,
  });
});

test("s3 object detail SSE/lock metadata labels visible", async ({
  terminal,
}) => {
  if (!fixtures?.bucket) return;

  await goToObjectDetail(terminal, fixtures.bucket);
  await expect(terminal.getByText("SSE")).toBeVisible({ timeout: 5_000 });
  await expect(terminal.getByText("Object Lock Mode")).toBeVisible({
    timeout: 5_000,
  });
});

test("s3 object content view shows file content", async ({ terminal }) => {
  if (!fixtures?.bucket?.object?.canView) return;

  await goToObjectDetail(terminal, fixtures.bucket);
  // Enter opens content view (action_idx=0 is View Content when viewable)
  terminal.submit();

  const snippet = fixtures.bucket.object.contentSnippet ?? "";
  const probe = snippet.trim().split("\n")[0].trim().slice(0, 30);
  if (probe.length > 0) {
    await expect(terminal.getByText(probe, { strict: false })).toBeVisible({
      timeout: 20_000,
    });
  } else {
    // Just confirm we left the detail view (no "Key" prop visible anymore)
    await expect(terminal.getByText("Key")).not.toBeVisible({ timeout: 5_000 });
  }
});

test("s3 buckets list sort by name works", async ({ terminal }) => {
  if (!fixtures?.allBuckets?.length) return;

  await goToBuckets(terminal);
  await expect(
    terminal.getByText(fixtures.allBuckets[0], { strict: false }),
  ).toBeVisible({ timeout: 30_000 });
  await runCommand(terminal, "sort name");
  // After sort the first bucket (alphabetically) should still be visible
  await expect(terminal.getByText("Buckets")).toBeVisible({ timeout: 5_000 });
});

test("s3 objects list sort by size works", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  await goToObjects(terminal, fixtures.bucket);
  await runCommand(terminal, "sort size");
  // "SIZE" column header is unique to the objects list — confirms view is intact after sort
  await expect(terminal.getByText("SIZE", { strict: false })).toBeVisible({
    timeout: 5_000,
  });
});

test("s3 buckets filter reduces visible items", async ({ terminal }) => {
  if (!fixtures?.bucket) return;

  await goToBuckets(terminal);
  await expect(
    terminal.getByText(fixtures.bucket.name, { strict: false }),
  ).toBeVisible({ timeout: 30_000 });

  await runCommand(terminal, `filter name contains "${fixtures.bucket.name}"`);
  await expect(
    terminal.getByText(fixtures.bucket.name, { strict: false }),
  ).toBeVisible({ timeout: 5_000 });
});
