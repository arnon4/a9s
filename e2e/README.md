# E2E tests

Framework: [`@microsoft/tui-test`](https://github.com/microsoft/tui-test).

## Layout

One test file per top-level module (matches `src/app/views/<module>/`):

- `tests/auth.test.js` — auth/credential prompt view
- `tests/home.test.js` — home/base view, global keys (`:`, `?`, `q`)
- `tests/help.test.js` — help view
- `tests/commands.test.js` — vim-style `:command` bar
- `tests/s3.test.js`, `tests/lambda.test.js`, `tests/logs.test.js`,
  `tests/iam.test.js`, `tests/secretsmanager.test.js` — fake-credential
  coverage per module (navigation, columns, error state, keys, quit confirm)
- `tests/<module>_<variant>.test.js` — extra layout/regression variants
  (e.g. `iam_users_compact.test.js`, `iam_users_wide.test.js`)

**When adding a new view/module**, add a `tests/<module>.test.js` following
the template below — don't fold it into an unrelated file.

### Required sections in a fake-credential module test file

```js
/**
 * <Module> view e2e tests — fake credentials, no real AWS needed.
 */
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({ program: { file: BIN }, env: envWithCreds, rows: 30, columns: 140 });

async function goTo<Module>(terminal) { /* navigate from home, assert breadcrumb */ }

// ── navigation ──────────────────────────────────────────────────────────────
// enter view, Esc back to home/parent

// ── column headers ──────────────────────────────────────────────────────────
// one assertion per header, tagged (wide layout) / (medium layout) where relevant

// ── error state ──────────────────────────────────────────────────────────────
// fake creds → HTTP fails → expect "Error" text within 15s

// ── keyboard navigation ──────────────────────────────────────────────────────
// j/k and arrow keys don't crash on empty/loading list

// ── quit confirm ─────────────────────────────────────────────────────────────
// q shows confirm, n dismisses and stays in view
```

Keep each section's tests independent (no shared mutable state across
`test()` blocks — tui-test spawns a fresh terminal per test).

## Running

- Full suite: `cd e2e && npx @microsoft/tui-test` (or `npm test`)
- Single file / pattern: `npx @microsoft/tui-test tests/lambda.test.js` (args
  are regexes matched against absolute file paths)
- **Only tests for modules touched by your changes**:
  `npm run test:affected` (or `node scripts/run-affected.mjs [--base <ref>]`)
  - Maps changed files under `src/app/views/<module>/` or
    `src/sdk/clients/<module>/` to `tests/<module>*.test.js`
  - Falls back to the full suite if shared/core files changed
    (`app.zig`, `views/base.zig`, `ui/`, `terminal/`, `main.zig`,
    `e2e/tests/helpers.js`)
  - Considers both the working tree (`git status`) and commits since
    `--base` (default `main`)

Module → test-file mapping lives in `scripts/module-map.mjs` (`MODULE_MAP`) —
register a new module there.

## Pre-commit hook

`.git/hooks/pre-commit` runs `scripts/pre-commit-e2e.mjs` on every commit:

1. For every staged file under `src/app/views/<module>/` or
   `src/sdk/clients/<module>/`, checks a matching `tests/<module>*.test.js`
   exists — blocks the commit if not (this is what catches "new module, no
   e2e test").
2. Runs `zig build`, then the e2e tests for touched modules (or the full
   suite if shared/core files changed), against the built binary.

Bypass with `git commit --no-verify`. The hook file lives under `.git/hooks/`
(not tracked by git) — if you clone this repo fresh, reinstall it:

```sh
cp e2e/scripts/pre-commit.sh .git/hooks/pre-commit
```

(on a filesystem where `core.filemode` matters, also `chmod +x` it.)
