#!/usr/bin/env python3
"""
Run tests/command_decisions.tsv against the release hook binary.

Replaces the older tests/run_command_decisions.sh and the pytest-based
tests/test_hook.py. This runner is intentionally OUTSIDE pytest -- pytest
in this repo is reserved for Python source quality (pyflakes, ascii,
shebangs, imports, etc.).

TSV row formats accepted:
  expected<TAB>command                       -- Bash (default configs)
  expected<TAB>tool<TAB>json_input           -- non-Bash (default configs)
  expected<TAB>tool<TAB>config<TAB>json_in   -- explicit config path

  expected = allow | deny | passthrough
  tool     = Bash | Read | Write | Edit | Glob | Grep | WebFetch |
             WebSearch | Task | <any other tool name>
  config   = path relative to repo root (e.g. tests/test_config.toml).
             Use "default" to mean: run against both live config and
             example.toml (the original 2-column behavior).

Lines starting with # and blank lines are skipped.

Exit code: 0 if all match, 1 if any FAIL, 2 on missing prerequisites.

Usage:
    python3 tests/run_command_decisions.py            # run all
    python3 tests/run_command_decisions.py ffprobe    # only rows whose
                                                      # command matches substring
"""

# Standard Library
import os
import sys
import json
import subprocess

# local repo modules
# git_file_utils lives under tests/ alongside the other helpers; add that
# directory to sys.path so this script can be invoked from the repo root.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "tests"))
import git_file_utils

REPO_ROOT = git_file_utils.get_repo_root()
HOOK = os.path.join(REPO_ROOT, "target", "release", "claude-code-permissions-hook")
LIVE_CFG = os.path.expanduser("~/.config/claude-code-permissions-hook.toml")
EXAMPLE_CFG = os.path.join(REPO_ROOT, "example.toml")
TSV = os.path.join(REPO_ROOT, "tests", "command_decisions.tsv")

# ANSI color helpers (only when stdout is a tty).
if sys.stdout.isatty():
	RED = "\033[1;31m"
	GREEN = "\033[1;32m"
	BG_RED = "\033[1;37;41m"
	RESET = "\033[0m"
else:
	RED = GREEN = BG_RED = RESET = ""


#============================================
def decide_with(cfg_path: str, tool_name: str, tool_input: dict) -> tuple:
	"""Send one HookInput to the binary and return (decision, reason).

	Returns:
		(decision, reason) where decision is allow|deny|passthrough.
	"""
	hook_input = {
		"session_id": "decision-runner",
		"transcript_path": "/tmp/transcript.jsonl",  # nosec B108
		"hook_event_name": "PreToolUse",
		"tool_name": tool_name,
		"tool_input": tool_input,
		"cwd": "/Users/korny/Dropbox/prj/test",
	}
	json_input = json.dumps(hook_input)
	result = subprocess.run(
		[HOOK, "run", "--config", cfg_path],
		input=json_input,
		capture_output=True,
		text=True,
		timeout=10,
	)
	stdout = result.stdout.strip()
	# Empty stdout = passthrough.
	if not stdout:
		return ("passthrough", "")
	parsed = json.loads(stdout)
	hook_out = parsed.get("hookSpecificOutput", {})
	decision = hook_out.get("permissionDecision", "passthrough")
	reason = hook_out.get("permissionDecisionReason", "")
	return (decision, reason)


#============================================
def parse_row(raw_line: str) -> dict:
	"""Parse one TSV row.

	Returns dict with keys: expected, tool, configs (list), tool_input.
	Returns None for comments/blanks.
	"""
	line = raw_line.rstrip("\n")
	if not line.strip() or line.lstrip().startswith("#"):
		return None
	fields = line.split("\t")
	if len(fields) < 2:
		raise ValueError(f"malformed (need at least expected<TAB>command): {raw_line!r}")
	expected = fields[0]
	# 2-column legacy: expected, command (Bash, default configs)
	if len(fields) == 2:
		row = {
			"expected": expected,
			"tool": "Bash",
			"configs": [LIVE_CFG, EXAMPLE_CFG],
			"tool_input": {"command": fields[1]},
		}
		return row
	# 3-column: expected, tool, json_input  (default configs)
	if len(fields) == 3:
		tool = fields[1]
		row = {
			"expected": expected,
			"tool": tool,
			"configs": [LIVE_CFG, EXAMPLE_CFG],
			"tool_input": _parse_input(tool, fields[2]),
		}
		return row
	# 4-column: expected, tool, config, json_input
	tool = fields[1]
	cfg = fields[2]
	if cfg == "default":
		configs = [LIVE_CFG, EXAMPLE_CFG]
	else:
		configs = [os.path.join(REPO_ROOT, cfg)]
	row = {
		"expected": expected,
		"tool": tool,
		"configs": configs,
		"tool_input": _parse_input(tool, fields[3]),
	}
	return row


#============================================
def _parse_input(tool: str, raw: str) -> dict:
	"""Parse the input field. Bash with bare command -> {command: raw}.
	Anything else (or Bash starting with '{') -> JSON.
	"""
	stripped = raw.strip()
	if tool == "Bash" and not stripped.startswith("{"):
		# Bash shorthand: bare command string.
		out = {"command": raw}
		return out
	# Otherwise interpret as JSON dict.
	parsed = json.loads(raw)
	return parsed


#============================================
def run_row(row: dict, filter_str: str) -> tuple:
	"""Run a single parsed TSV row against all of its configs.

	Returns (passes, fails, skipped). Each config counts independently.
	"""
	# Filter: substring match against the JSON-rendered tool_input.
	display = row["tool"] + " " + json.dumps(row["tool_input"])
	if filter_str and filter_str not in display:
		return (0, 0, 1)
	passes = 0
	fails = 0
	for cfg in row["configs"]:
		got, _reason = decide_with(cfg, row["tool"], row["tool_input"])
		label = os.path.basename(cfg)
		expected = row["expected"]
		if got == expected:
			print(f"OK   [{label:32s}] expect={expected:11s} got={got:11s} :: "
				f"{row['tool']} {json.dumps(row['tool_input'])[:80]}")
			passes += 1
		else:
			print(f"{RED}FAIL [{label:32s}] expect={expected:11s} got={got:11s} :: "
				f"{row['tool']} {json.dumps(row['tool_input'])[:80]}{RESET}")
			fails += 1
	return (passes, fails, 0)


#============================================
def main() -> int:
	"""Entry point."""
	# Preflight checks.
	if not os.access(HOOK, os.X_OK):
		print(f"FAIL: hook binary missing or not executable; "
			f"run 'cargo build --release' first: {HOOK}", file=sys.stderr)
		return 2
	if not os.path.isfile(LIVE_CFG):
		print(f"FAIL: live config not found: {LIVE_CFG}", file=sys.stderr)
		return 2
	if not os.path.isfile(EXAMPLE_CFG):
		print(f"FAIL: example config not found: {EXAMPLE_CFG}", file=sys.stderr)
		return 2
	if not os.path.isfile(TSV):
		print(f"FAIL: fixture not found: {TSV}", file=sys.stderr)
		return 2

	filter_str = sys.argv[1] if len(sys.argv) > 1 else ""

	total_pass = 0
	total_fail = 0
	total_skip = 0
	with open(TSV, "r", encoding="utf-8") as handle:
		for raw in handle:
			row = parse_row(raw)
			if row is None:
				continue
			p, f, s = run_row(row, filter_str)
			total_pass += p
			total_fail += f
			total_skip += s

	print()
	if total_fail == 0:
		print(f"{GREEN}OVERALL: ALL TESTS PASSED "
			f"(passed={total_pass}, skipped={total_skip}){RESET}")
		return 0
	print(f"{BG_RED} ============================================================ {RESET}")
	print(f"{BG_RED}   FAILURE: {total_fail} mismatches "
		f"(passed={total_pass}, skipped={total_skip})  {RESET}")
	print(f"{BG_RED} ============================================================ {RESET}")
	return 1


if __name__ == "__main__":
	sys.exit(main())
