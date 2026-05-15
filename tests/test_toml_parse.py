"""Parse and reason-text invariants for every repo-root TOML config.

Globs all `*.toml` files at the repo root rather than hard-coding a list,
because `claude-code-permissions-hook.toml` is a local symlink and is not
guaranteed to exist in every checkout (e.g., a fresh clone). `example.toml`
and `Cargo.toml` are always present; the local hook config is checked when
it happens to be there.

Distinct from `tools/run_command_decisions.py`, which exercises the compiled
Rust binary against the TSV fixture corpus. This pytest catches plain TOML
syntax errors (mismatched quotes, broken multi-line strings, malformed regex
escapes) and missing deny `reason` fields without needing a build, so a
parse regression is not blurred with a decision-logic regression.

Also enforces deny `reason` parity between `example.toml` and
`claude-code-permissions-hook.toml` when both are present, tolerating the
`~/projects/` <-> `~/nsh/` path-personalization swap on Write/Edit system-dir
denies (the only intentional divergence between the two files).
"""

import os
import glob
import tomllib

import pytest

import git_file_utils

REPO_ROOT = git_file_utils.get_repo_root()


def _root_toml_paths() -> list[str]:
	# Sort for deterministic parametrize IDs.
	return sorted(glob.glob(os.path.join(REPO_ROOT, "*.toml")))


def _load_toml(path: str) -> dict:
	with open(path, "rb") as f:
		data = tomllib.load(f)
	return data


def _normalize_reason(text: str) -> str:
	# example.toml uses `~/projects/`; the personal config uses `~/nsh/`.
	# These are the same logical path, just personalized. Collapse them so
	# parity compares reason wording, not path tokens.
	return text.replace("~/nsh/", "~/projects/")


@pytest.mark.parametrize("path", _root_toml_paths())
def test_toml_parses(path: str) -> None:
	# A parse failure here is unambiguous: the file is syntactically broken.
	_load_toml(path)


@pytest.mark.parametrize("path", _root_toml_paths())
def test_deny_reasons_present(path: str) -> None:
	# Every deny rule must carry a non-empty reason so the hook can steer
	# the agent. Files without a `[[deny]]` array (e.g., Cargo.toml) are
	# skipped naturally because the loop body never runs.
	data = _load_toml(path)
	for i, rule in enumerate(data.get("deny", [])):
		assert "reason" in rule, f"{path}: deny[{i}] missing reason field"
		assert rule["reason"].strip(), f"{path}: deny[{i}] reason is empty"


def test_example_and_live_config_reason_parity() -> None:
	# Long-term invariant: example.toml is the path/script-stripped public
	# mirror of claude-code-permissions-hook.toml. Their deny rules must
	# stay in lockstep on `reason` wording, modulo path personalization.
	example_path = os.path.join(REPO_ROOT, "example.toml")
	live_path = os.path.join(REPO_ROOT, "claude-code-permissions-hook.toml")
	if not os.path.exists(live_path):
		pytest.skip("local claude-code-permissions-hook.toml symlink not present")
	example_rules = _load_toml(example_path).get("deny", [])
	live_rules = _load_toml(live_path).get("deny", [])
	assert len(example_rules) == len(live_rules), (
		f"deny rule count mismatch: example.toml={len(example_rules)}, "
		f"live={len(live_rules)}"
	)
	for i, (ex_rule, live_rule) in enumerate(zip(example_rules, live_rules)):
		ex_reason = _normalize_reason(ex_rule["reason"])
		live_reason = _normalize_reason(live_rule["reason"])
		assert ex_reason == live_reason, (
			f"deny[{i}] reason mismatch between example.toml and live config:\n"
			f"  example: {ex_rule['reason']!r}\n"
			f"  live:    {live_rule['reason']!r}"
		)
