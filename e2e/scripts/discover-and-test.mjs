#!/usr/bin/env node
/**
 * Discover real AWS resources, write tests/fixtures.json, then run real-AWS E2E tests.
 *
 * Usage:
 *   node scripts/discover-and-test.mjs
 *   node scripts/discover-and-test.mjs --profile myprofile [--region us-west-2]
 *   node scripts/discover-and-test.mjs --discover-only
 */

import { execSync, spawnSync } from "node:child_process";
import { writeFileSync, readFileSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const __dir = dirname(fileURLToPath(import.meta.url));
const E2E_DIR = resolve(__dir, "..");
const FIXTURES_PATH = resolve(E2E_DIR, "tests", "fixtures.json");

// ── CLI args ─────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const idx = (flag) => argv.indexOf(flag);
const profileArg = idx("--profile") >= 0 ? argv[idx("--profile") + 1] : null;
const regionArg = idx("--region") >= 0 ? argv[idx("--region") + 1] : null;
const discoverOnly = argv.includes("--discover-only");

// ── Helpers ───────────────────────────────────────────────────────────────────
const TEXT_EXTS = new Set([
  ".txt",
  ".log",
  ".csv",
  ".md",
  ".html",
  ".xml",
  ".json",
  ".jsonl",
  ".ndjson",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
  ".js",
  ".ts",
  ".py",
  ".sh",
  ".rb",
  ".go",
  ".java",
  ".c",
  ".cpp",
  ".h",
  ".cs",
  ".tf",
  ".hcl",
]);

function hasTextExt(key) {
  const dot = key.lastIndexOf(".");
  return dot >= 0 && TEXT_EXTS.has(key.slice(dot).toLowerCase());
}

function isTextMime(ct) {
  if (!ct) return false;
  const base = ct.split(";")[0].trim().toLowerCase();
  return (
    base.startsWith("text/") ||
    [
      "application/json",
      "application/xml",
      "application/javascript",
      "application/yaml",
      "application/toml",
      "application/x-ndjson",
      "application/x-yaml",
    ].includes(base)
  );
}

function run(cmd) {
  try {
    return execSync(cmd, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

function awsJson(cmd) {
  const out = run(`aws ${cmd} --output json`);
  if (!out) return null;
  try {
    return JSON.parse(out);
  } catch {
    return null;
  }
}

// ── AWS helpers ───────────────────────────────────────────────────────────────
function getProfiles() {
  if (profileArg) return [profileArg];
  const out = run("aws configure list-profiles");
  return out
    ? out
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];
}

function getCredentials(profile) {
  const v2 = run(`aws configure export-credentials --profile "${profile}"`);
  if (v2) {
    try {
      const c = JSON.parse(v2);
      if (c.AccessKeyId)
        return {
          AWS_ACCESS_KEY_ID: c.AccessKeyId,
          AWS_SECRET_ACCESS_KEY: c.SecretAccessKey,
          ...(c.SessionToken ? { AWS_SESSION_TOKEN: c.SessionToken } : {}),
        };
    } catch {}
  }
  // Fallback: static key from config (works for IAM users, not SSO)
  const keyId = run(
    `aws configure get aws_access_key_id     --profile "${profile}"`,
  );
  const secret = run(
    `aws configure get aws_secret_access_key --profile "${profile}"`,
  );
  if (keyId && secret)
    return { AWS_ACCESS_KEY_ID: keyId, AWS_SECRET_ACCESS_KEY: secret };
  return null;
}

function getRegion(profile) {
  if (regionArg) return regionArg;
  const out = run(`aws configure get region --profile "${profile}"`);
  return out || "us-east-1";
}

function getBucketRegion(profile, homeRegion, bucket) {
  const r = awsJson(
    `s3api get-bucket-location --profile "${profile}" --region "${homeRegion}" --bucket "${bucket}"`,
  );
  const loc = r?.LocationConstraint;
  return loc && loc !== "null" ? loc : "us-east-1";
}

function listBuckets(profile, region) {
  return (
    awsJson(`s3api list-buckets --profile "${profile}" --region "${region}"`)
      ?.Buckets ?? []
  );
}

function listObjects(profile, region, bucket) {
  const k = `"${bucket.replace(/"/g, '\\"')}"`;
  return (
    awsJson(
      `s3api list-objects-v2 --profile "${profile}" --region "${region}" --bucket ${k} --max-items 200`,
    )?.Contents ?? []
  );
}

function headObject(profile, region, bucket, key) {
  const b = `"${bucket.replace(/"/g, '\\"')}"`;
  const k = `"${key.replace(/"/g, '\\"')}"`;
  return awsJson(
    `s3api head-object --profile "${profile}" --region "${region}" --bucket ${b} --key ${k}`,
  );
}

function fetchObjectContent(profile, region, bucket, key) {
  const tmp = join(tmpdir(), `a9s-e2e-${Date.now()}.bin`);
  const b = `"${bucket.replace(/"/g, '\\"')}"`;
  const k = `"${key.replace(/"/g, '\\"')}"`;
  const ok = run(
    `aws s3api get-object --profile "${profile}" --region "${region}" --bucket ${b} --key ${k} "${tmp}"`,
  );
  if (!ok) return null;
  try {
    return readFileSync(tmp, "utf8").slice(0, 1000);
  } catch {
    return null;
  }
}

function listLambdas(profile, region) {
  return (
    awsJson(`lambda list-functions --profile "${profile}" --region "${region}"`)
      ?.Functions ?? []
  );
}

// ── Discovery ─────────────────────────────────────────────────────────────────
const profiles = getProfiles();
if (!profiles.length) {
  console.error(
    "No AWS profiles found. Run `aws configure` or pass --profile <name>.",
  );
  process.exit(1);
}

console.log(`Profiles to try: ${profiles.join(", ")}\n`);

let fixture = null;

for (const profile of profiles) {
  console.log(`── ${profile} ──────────────────────`);

  const creds = getCredentials(profile);
  if (!creds) {
    console.log(
      "  ✗ No credentials (for SSO: aws sso login --profile " + profile + ")",
    );
    continue;
  }

  const region = getRegion(profile);
  console.log(`  Region: ${region}`);

  process.stdout.write("  S3 buckets... ");
  const buckets = listBuckets(profile, region);
  console.log(`${buckets.length} found`);

  process.stdout.write("  Lambda functions... ");
  const lambdas = listLambdas(profile, region);
  console.log(`${lambdas.length} found`);

  // ── S3: find a bucket with objects ────────────────────────────────────────
  let bucketFixture = null;

  const MAX_VIEWABLE = 5 * 1024 * 1024;

  for (const b of buckets) {
    const bname = b.Name;
    let bregion = region;
    try {
      bregion = getBucketRegion(profile, region, bname) || region;
    } catch {}

    process.stdout.write(`  Bucket ${bname} (${bregion})... `);
    const objects = listObjects(profile, bregion, bname);

    if (!objects.length) {
      console.log("empty");
      continue;
    }

    // Prefer small text objects; fall back to anything under 5 MB
    const pick =
      objects.find(
        (o) =>
          hasTextExt(o.Key ?? "") &&
          (o.Size ?? 0) > 0 &&
          (o.Size ?? 0) < MAX_VIEWABLE,
      ) ??
      objects.find((o) => (o.Size ?? 0) > 0 && (o.Size ?? 0) < MAX_VIEWABLE) ??
      objects[0];

    console.log(`${objects.length} objects → "${pick.Key}"`);

    const head = headObject(profile, bregion, bname, pick.Key);
    const contentType = head?.ContentType ?? "";
    const canView = hasTextExt(pick.Key ?? "") || isTextMime(contentType);

    let contentSnippet = null;
    if (canView) {
      process.stdout.write("    Fetching content... ");
      contentSnippet = fetchObjectContent(profile, bregion, bname, pick.Key);
      console.log(contentSnippet != null ? "ok" : "binary/error - skipped");
    }

    bucketFixture = {
      name: bname,
      region: bregion,
      object: {
        key: pick.Key,
        size: pick.Size ?? 0,
        lastModified: pick.LastModified ?? "",
        storageClass: pick.StorageClass ?? "STANDARD",
        etag: (pick.ETag ?? "").replace(/"/g, ""),
        contentType,
        canView: canView && contentSnippet != null,
        contentSnippet: contentSnippet ? contentSnippet.slice(0, 400) : null,
      },
    };
    break;
  }

  // ── Lambda: pick the first function ──────────────────────────────────────
  let lambdaFixture = null;
  if (lambdas.length) {
    const fn = lambdas[0];
    console.log(`  Lambda target: ${fn.FunctionName}`);
    lambdaFixture = {
      name: fn.FunctionName,
      arn: fn.FunctionArn ?? "",
      runtime: fn.Runtime ?? "",
      handler: fn.Handler ?? "",
      role: fn.Role ?? "",
      codeSize: fn.CodeSize ?? 0,
      region,
    };
  }

  if (!bucketFixture && !lambdaFixture) {
    console.log("  No testable resources — trying next profile.\n");
    continue;
  }

  fixture = {
    profile,
    region,
    credentials: creds,
    allBuckets: buckets.map((b) => b.Name),
    allLambdas: lambdas.map((f) => f.FunctionName),
    ...(bucketFixture && { bucket: bucketFixture }),
    ...(lambdaFixture && { lambda: lambdaFixture }),
  };
  break;
}

if (!fixture) {
  console.error(
    "\n✗ No usable profile. Check credentials and that S3/Lambda resources exist.",
  );
  process.exit(1);
}

console.log(`\nWriting ${FIXTURES_PATH}`);
writeFileSync(FIXTURES_PATH, JSON.stringify(fixture, null, 2));
console.log("Fixtures written.\n");

if (discoverOnly) {
  console.log("--discover-only: skipping test run.");
  process.exit(0);
}

// ── Run E2E tests ─────────────────────────────────────────────────────────────
console.log("Running real-AWS E2E tests...\n");
const result = spawnSync(
  "npx",
  ["@microsoft/tui-test", "s3_real", "lambda_real"],
  { cwd: E2E_DIR, stdio: "inherit", shell: true },
);
process.exit(result.status ?? 0);
