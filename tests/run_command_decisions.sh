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
LIVE_CFG="$HOME/.config/claude-code-permissions-hook.toml"
EXAMPLE_CFG="$REPO_ROOT/example.toml"
TSV="$REPO_ROOT/tests/command_decisions.tsv"
FILTER="${1:-}"

if [ ! -x "$HOOK" ]; then
	echo "FAIL: hook binary missing; run 'cargo build --release' first: $HOOK" >&2
	exit 2
fi
if [ ! -f "$LIVE_CFG" ]; then
	echo "FAIL: live config not found: $LIVE_CFG" >&2
	exit 2
fi
if [ ! -f "$EXAMPLE_CFG" ]; then
	echo "FAIL: example config not found: $EXAMPLE_CFG" >&2
	exit 2
fi
if [ ! -f "$TSV" ]; then
	echo "FAIL: fixture not found: $TSV" >&2
	exit 2
fi

# decide_with(cfg, cmd) -> echoes allow|deny|passthrough for a Bash command.
decide_with() {
	local cfg="$1" cmd="$2" out got
	local esc=${cmd//\\/\\\\}
	esc=${esc//\"/\\\"}
	out=$(printf '{"session_id":"s","transcript_path":"/tmp/t","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"},"cwd":"/tmp"}' "$esc" \
		| "$HOOK" run --config "$cfg" 2>&1)
	if   echo "$out" | grep -q '"permissionDecision":"allow"'; then got="allow"
	elif echo "$out" | grep -q '"permissionDecision":"deny"';  then got="deny"
	else                                                            got="passthrough"
	fi
	echo "$got"
}

run_against_config() {
	local cfg="$1" label="$2"
	local pass=0 fail=0 total=0
	echo "=== $label :: $cfg ==="
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			''|\#*) continue ;;
		esac
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
		got=$(decide_with "$cfg" "$cmd")
		if [ "$got" = "$expected" ]; then
			printf 'OK   [%s] expect=%-11s got=%-11s :: %s\n' "$label" "$expected" "$got" "$cmd"
			pass=$((pass + 1))
		else
			printf 'FAIL [%s] expect=%-11s got=%-11s :: %s\n' "$label" "$expected" "$got" "$cmd"
			fail=$((fail + 1))
		fi
	done < "$TSV"
	printf '%s: %d passed, %d failed, %d total\n\n' "$label" "$pass" "$fail" "$total"
	return "$fail"
}

run_against_config "$LIVE_CFG"     "live"
live_fail=$?
run_against_config "$EXAMPLE_CFG"  "example"
example_fail=$?

total_fail=$((live_fail + example_fail))
printf 'OVERALL: %d failures (live=%d, example=%d)\n' "$total_fail" "$live_fail" "$example_fail"
[ "$total_fail" -eq 0 ]
