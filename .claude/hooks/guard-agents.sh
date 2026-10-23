#!/bin/bash
# Enforce: git add/commit/push only via the committer agent; zig build/test/run only via the zig-builder agent.
# Not airtight (e.g. wrapped shells) but good enough.
check_type="$1"   # "commit" | "add" | "push" | "zig"
input=$(cat)
command=$(jq -r '.tool_input.command // empty' <<<"$input")
agent_type=$(jq -r '.agent_type // empty' <<<"$input")

deny() {
  jq -n --arg reason "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

case "$check_type" in
  commit)
    if grep -qE -- '--no-verify' <<<"$command"; then
      deny "git commit --no-verify is never allowed from here. If the pre-commit hook fails, fix or report it."
    fi
    [ "$agent_type" != "committer" ] && deny "Direct commits aren't allowed. Delegate to the committer subagent."
    ;;
  add)
    if grep -qE -- '(-A\b|--all\b)' <<<"$command" || grep -qE 'git add[[:space:]]+\.([[:space:]]|$)' <<<"$command"; then
      deny "Broad staging (-A/--all/.) isn't allowed. Stage the specific files that belong in the commit."
    fi
    [ "$agent_type" != "committer" ] && deny "Direct staging isn't allowed. Delegate to the committer subagent."
    ;;
  push)
    if grep -qE -- '(--force\b|-f\b|--force-with-lease)' <<<"$command"; then
      deny "Force-push is never allowed."
    fi
    [ "$agent_type" != "committer" ] && deny "Direct pushes aren't allowed. Delegate to the committer subagent."
    ;;
  zig)
    [ "$agent_type" != "zig-builder" ] && deny "Direct zig build/test/run isn't allowed. Delegate to the zig-builder subagent."
    ;;
esac

exit 0
