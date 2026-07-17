---
description: Reference for the a9s codebase — keyboard-driven AWS TUI in Zig 0.16. Use when doing anything in this repo.
---

## Repo Structure

```
a9s/
├── build.zig
├── src/
│   ├── app/
│   │   ├── app.zig             # Main event loop, view stack, command bar
│   │   ├── profile_set.zig     # Multi-profile credential management
│   │   └── views/
│   │       ├── auth/           # SSO + manual credentials views
│   │       ├── s3/             # S3 buckets → objects → content
│   │       ├── lambda/         # Lambda functions list + detail
│   │       └── logs/           # CloudWatch log groups → streams → events
│   ├── sdk/
│   │   ├── clients/            # One subdir per service; each has client.zig + get/, describe/, or similar - for exmaple the Lambda `getFunction` function will be under `./sdk/clients/lambda/get/function.zig`
│   │   ├── credentials/fetcher.zig
│   │   └── sig/sigv4.zig
│   ├── ui/view.zig             # View union + ViewContext + Action — register new views here
│   ├── terminal/input.zig      # Raw-mode reader; input.notify() wakes event loop
│   └── event.zig               # Event tagged union
└── e2e/tests/                  # @microsoft/tui-test JS tests; helpers.js has BIN + envWithCreds
```

## Build

Use the zig-builder agent to build and run the project.

Debug output → `a9s.log`.

## Adding a View

Three steps:

**1. Create** `src/app/views/<service>/<view>.zig` — file IS the struct (`pub const MyView = @This()`).

Required methods:

| Method | Signature |
|--------|-----------|
| `init` | `(allocator, ...) !MyView` — allocator always first |
| `deinit` | `(*MyView) void` |
| `breadcrumb` | `(*MyView) []const u8` — shown in header |
| `handleEvent` | `(*MyView, Event, ViewContext) !Action` |
| `render` | `(*MyView, *std.Io.Writer, Coord) !void` — full redraw each frame |

Actions: `.none` (stay), `.pop` (back), `.quit`, `.{ .push = View }` (drill in).

Copy an existing view for the full boilerplate — `src/app/views/logs/` is a good reference.

**2. Register** in `src/ui/view.zig`: add import and a variant to the `View` union. The `inline else` dispatch in `handleEvent`/`render` picks it up automatically.

**3. Push** from a parent's `handleEvent`:
```zig
.enter => return .{ .push = .{ .my_view = try MyView.init(ctx.allocator, ctx.color_support) } },
```

### Async data (background fetch)

Heap-allocate a `FetchCtx` struct holding params, result fields, and a `std.atomic.Value(bool)` done flag. Spawn a thread in `init` or on first `handleEvent`. Thread must call `input.notify()` in its `defer` block to wake the event loop. In `render`, check `ctx.done.load(.acquire)` and show a spinner or results.

## SDK Client Pattern

Layout: `src/sdk/clients/<service>/client.zig` + `get/<op>.zig` (or `describe/`).

See `src/sdk/clients/logs/` as the canonical reference. Key rules:
- Every request requires SigV4 signing via `src/sdk/sig/sigv4.zig`
- JSON built manually with `std.ArrayList(u8)` — no `std.json.stringify`
- JSON parsed with `std.json.parseFromSlice` → walk `Value` tree manually
- `Result` owns all its memory; `deinit` must free everything
- Non-200 response → log the body, then return a descriptive `error` (e.g. `error.AccessDenied`)

## Key Invariants

- `input.notify()` must be called after any background thread write — wakes the event loop
- Views own their allocations; `deinit` is called when the view is popped
- `Action.push` takes a fully initialized `View`; init errors propagate via `try`
- `ViewContext.credentials` is the default profile store; for non-default profiles, create a `fetcher.CredentialsStore` with `profile_name` set explicitly
- `zig build` always cross-compiles both targets; `zig build test` is native only

---

## E2E Tests

Framework: @microsoft/tui-test v0.0.4. Tests are JavaScript in e2e/tests/.

### Setup

```bash
cd e2e && npm install
zig build                  # binary must exist at zig-out/bin/a9s.exe
npm test
```

### Writing a test

```js
// e2e/tests/my_feature.test.js
import { test, expect } from "@microsoft/tui-test";
import { BIN, envWithCreds } from "./helpers.js";

test.use({
  program: { file: BIN },
  env: envWithCreds,   // fake AWS_ACCESS_KEY_ID etc. — no real AWS needed for basic nav
  rows: 30,
  columns: 100,
});

test("navigates to my view", async ({ terminal }) => {
  // wait for home screen
  await expect(terminal.getByText("S3")).toBeVisible();

  // navigate: j/k move selection, Enter opens, Esc goes back
  terminal.write("j");           // move down
  terminal.submit();             // press Enter
  await expect(terminal.getByText("My breadcrumb")).toBeVisible();

  terminal.keyEscape();          // go back
  await expect(terminal.getByText("S3")).toBeVisible();
});
```

### Terminal API

| Call | Effect |
|------|--------|
| terminal.write("j") | send keypress |
| terminal.submit() | press Enter |
| terminal.keyEscape() | press Esc |
| terminal.keyDown() | arrow down |
| terminal.keyUp() | arrow up |
| expect(terminal.getByText("foo")).toBeVisible() | assert text on screen |
| expect(...).not.toBeVisible() | assert text absent |

`getByText` is fuzzy by default; pass `{ strict: false }` to allow partial matches. Default expect timeout: 8s.

For tests that need real AWS (e.g. s3_real.test.js, lambda_real.test.js), use `envWithCreds` and skip if credentials are absent.

### helpers.js exports

```js
export const BIN = "../zig-out/bin/a9s.exe";
export const envWithCreds;   // AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_REGION set to fake values
export const envNoCreds;     // no AWS_ vars — triggers auth prompt
```
