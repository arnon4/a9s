# a9s

A keyboard-driven AWS TUI explorer built with Zig.

## Supported services

**S3** — browse buckets, drill into objects, view or download object content inline.

**Lambda** — list functions across regions, open function detail and view code.

**CloudWatch Logs** — browse log groups and log streams; open a live log events viewer that auto-refreshes every 5 seconds.

## Getting started

**Build**

```
zig build
```

Binary is written to `zig-out/bin/a9s` (`zig-out/bin/a9s.exe` on Windows).

**Run**

```
./zig-out/bin/a9s
```

**Authentication**

a9s uses the standard AWS credential chain: environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), `~/.aws/credentials`, and SSO profiles in `~/.aws/config`. On first launch you will be prompted if no credentials are found. Use `:profile` to add or switch profiles without restarting.

## Basic navigation

Arrow keys or `j`/`k` move up and down. `Enter` opens the selected item; `Esc` goes back. Press `?` for a full keybind reference or `:help` for command reference.

## Multi-profile and multi-region

`:profile` commands manage which credential profiles are active (multiple profiles can be active simultaneously — Lambda and CloudWatch Logs query all of them in parallel).

`:region` commands manage the active region list. Default is `us-east-1`; S3 always uses the global endpoint.

## Log file

Debug and error output is written to `a9s.log` in the working directory.
