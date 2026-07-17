#!/bin/sh
# Validates e2e test coverage for touched modules and runs relevant e2e
# tests. See e2e/scripts/pre-commit-e2e.mjs. Bypass with --no-verify.
#
# Install: cp e2e/scripts/pre-commit.sh .git/hooks/pre-commit

exec node "$(git rev-parse --show-toplevel)/e2e/scripts/pre-commit-e2e.mjs"
