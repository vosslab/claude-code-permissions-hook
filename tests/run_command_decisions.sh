#!/usr/bin/env bash
# Run tests/command_decisions.tsv against the LIVE user config and the
# release binary. Each TSV row: <expected>\t<command>.
# expected in {allow, deny, passthrough}.
#
# Usage:
#   tests/run_command_decisions.sh                   # run all
#   tests/run_command_decisions.sh ffprobe           # only rows whose
#                                                    # command matches grep
#
# Exits 0 if all match, 1 if any FAIL.

set -u

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK="$REPO_ROOT/target/release/claude-code-permissions-hook"
CFG="$HOME/.config/claude-code-permissions-hook.toml"
TSV="$REPO_ROOT/tests/command_decisions.tsv"
FILTER="${1:-}"

if [ ! -x "$HOOK" ]; then
	echo "FAIL: hook binary missing; run 'cargo build --release' first: $HOOK" >&2
	exit 2
fi
if [ ! -f "$CFG" ]; then
	echo "FAIL: config not found: $CFG" >&2
	exit 2
fi
if [ ! -f "$TSV" ]; then
	echo "FAIL: fixture not found: $TSV" >&2
	exit 2
fi

pass=0
fail=0
total=0

# Decide() pipes one HookInput JSON through the binary and echoes
# allow|deny|passthrough based on the JSON output.
decide() {
	local cmd="$1" out got
	# JSON-escape backslash and double-quote.
	local esc=${cmd//\\/\\\\}
	esc=${esc//\"/\\\"}
	out=$(printf '{"session_id":"s","transcript_path":"/tmp/t","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"},"cwd":"/tmp"}' "$esc" \
		| "$HOOK" run --config "$CFG" 2>&1)
	if   echo "$out" | grep -q '"permissionDecision":"allow"'; then got="allow"
	elif echo "$out" | grep -q '"permissionDecision":"deny"';  then got="deny"
	else                                                            got="passthrough"
	fi
	echo "$got"
}

while IFS= read -r line || [ -n "$line" ]; do
	# Skip blanks and comments.
	case "$line" in
		''|\#*) continue ;;
	esac
	# Split on first tab.
	expected=${line%%	*}
	cmd=${line#*	}
	if [ "$expected" = "$line" ]; then
		echo "SKIP malformed (no tab): $line" >&2
		continue
	fi
	if [ -n "$FILTER" ] && ! echo "$cmd" | grep -q -- "$FILTER"; then
		continue
	fi
	total=$((total + 1))
	got=$(decide "$cmd")
	if [ "$got" = "$expected" ]; then
		printf 'OK   expect=%-11s got=%-11s :: %s\n' "$expected" "$got" "$cmd"
		pass=$((pass + 1))
	else
		printf 'FAIL expect=%-11s got=%-11s :: %s\n' "$expected" "$got" "$cmd"
		fail=$((fail + 1))
	fi
done < "$TSV"

printf '\n%d passed, %d failed, %d total\n' "$pass" "$fail" "$total"
[ "$fail" -eq 0 ]
