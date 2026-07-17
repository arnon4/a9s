# a9s

A keyboard-driven AWS TUI explorer, inspired by k9s. Linux and Windows (x86_64) supported currently.

## Overview

- Terminal-based workflow - access supported AWS services directly from your terminal.
- Multi-region, multi-account - view multiple profiles across multiple different AWS regions at once.
- Read-only permissions - inspect resources and logs without fear of destroying your environments.

## Getting started

**Download**

The [releases](https://github.com/arnon4/a9s/releases) page contains prebuilt binaries. Download it, add to your path, and run.

**Build**

```bash
zig build
```

Binary is written to `zig-out/bin/a9s` on Linux, `zig-out\bin\a9s.exe` on Windows.

**Run**

```bash
./zig-out/bin/a9s       # Linux
.\zig-out\bin\a9s.exe   # Windows
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
