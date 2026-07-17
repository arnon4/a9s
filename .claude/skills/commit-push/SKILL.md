---
name: commit-push
description: Branch naming, branch protection rules, and commit/push workflow for the a9s repo. Use whenever creating a branch, committing, or pushing in this repo.
---

# Commit & push workflow — a9s

## Branch naming (required)

Every branch must start with one of:

- `fix/...` — bug fixes → **patch** version bump
- `feat/...` — new features → **minor** version bump
- `release/...` — release branches → **major** version bump

Enforced by the `branch-name` job in `.github/workflows/sanity.yaml` (runs on
every push to a non-main branch), which is wired up as a **required status
check** on the `Protect main` ruleset. A branch with any other prefix can't
be merged into `main`.

`branch_name_pattern` (GitHub's native ruleset rule for this) requires GitHub
Enterprise and 422s on free/pro plans — that's why enforcement is a CI job +
required status check instead of a native rule.

## `main` branch protection (ruleset "Protect main", id 19094706)

- **No direct pushes** — `pull_request` rule requires a PR to merge (0
  required approvals currently).
- **No force-push** — `non_fast_forward` rule.
- **No deletion** — `deletion` rule.
- **Required status check**: `branch-name` (from `sanity.yaml`) must pass
  before merge.
- E2E is **not** a required check (by design — sanity's `branch-name` is the
  only merge gate; e2e/sanity zig-test overlap is avoided by gating sanity's
  test job off when a PR is already open for the branch).

To inspect/modify: `gh api repos/arnon4/a9s/rulesets/19094706`.

## Creating a new branch

```sh
git fetch origin
git checkout main
git pull origin main
git checkout -b fix/whatever-it-is   # or feat/..., release/...
git push -u origin fix/whatever-it-is
```

Always branch from an up-to-date `main` — stale bases cause unrelated-history
or conflict pain (e.g. the LICENSE-file incident where local `main` had
diverged from a freshly-initialized GitHub repo).

## Pre-commit hook

`.git/hooks/pre-commit` (local only, not tracked — reinstall via
`cp e2e/scripts/pre-commit.sh .git/hooks/pre-commit` after a fresh clone)
runs the full e2e suite on any commit touching shared/core files
(`app.zig`, `views/base.zig`, `ui/`, `terminal/`, `main.zig`, `helpers.js`)
or a view/client module lacking a matching e2e test file.

This repo currently has a **known pre-existing flake**: `auth.test.js`'s SSO
Profile flow times out (~8 failures) unrelated to most changes. When a commit
is blocked by this and the diff doesn't touch auth/SSO code, bypass with
`git commit --no-verify` rather than waiting on/fixing an unrelated flake —
confirmed acceptable pattern in this repo. Always check *why* the hook
failed first; only bypass for this known, unrelated flake, not for real
regressions.

## Squash-merge gotcha

PR merges here squash to a single commit. If you push more commits to a
branch *after* a PR against it was already reviewed/queued for merge, the
merge may capture an earlier state and silently drop your later commits —
happened once with `paths-ignore` + unit-test-removal changes to `ci.yaml`.
After any merge, diff the merged branch against `origin/main` to confirm
nothing got left behind:

```sh
git diff origin/main origin/<branch> --stat
```

## Commit message convention

Short, imperative, prefixed by type when useful (`ci:`, `fix:`, `docs:`).
Don't add a co-author trailer unless asked. Never `git push --force` to
`main` (it's blocked anyway) or use `--no-verify` to skip a *real* failure.
