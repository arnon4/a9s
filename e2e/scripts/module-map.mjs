// Shared module → test-file mapping, used by run-affected.mjs and the
// pre-commit hook (scripts/pre-commit-e2e.mjs).
//
// Register a new module here when you add a new top-level view
// (src/app/views/<name>/) or SDK client (src/sdk/clients/<name>/).

// module name (matches src/app/views/<name> and src/sdk/clients/<name>) -> test file prefixes
export const MODULE_MAP = {
  s3: ["s3"],
  lambda: ["lambda"],
  logs: ["logs"],
  iam: ["iam"],
  secretsmanager: ["secretsmanager"],
  auth: ["auth"],
  help: ["help"],
};

// Changes under these paths can affect every view — run the full suite
// instead of trying to scope to specific modules.
export const GLOBAL_PATTERNS = [
  /^src\/app\/app\.zig$/,
  /^src\/app\/views\/base\.zig$/,
  /^src\/ui\//,
  /^src\/terminal\//,
  /^src\/main\.zig$/,
  /^e2e\/tests\/helpers\.js$/,
  /^e2e\/package\.json$/,
];

// Matches src/app/views/<module>/... or src/sdk/clients/<module>/...
export function moduleFor(file) {
  const m = file.match(/^src\/(?:app\/views|sdk\/clients)\/([^/]+)\//);
  return m ? m[1] : null;
}

export function isGlobalChange(files) {
  return files.some((f) => GLOBAL_PATTERNS.some((re) => re.test(f)));
}
