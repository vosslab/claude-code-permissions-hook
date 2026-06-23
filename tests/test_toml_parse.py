"""Parse invariants for every repo-root TOML config.

Globs all `*.toml` files at the repo root rather than hard-coding a list,
because `claude-code-permissions-hook.toml` is a local symlink and is not
guaranteed to exist in every checkout (e.g., a fresh clone). `example.toml`
and `Cargo.toml` are always present; the local hook config is checked when
it happens to be there.

Distinct from `tools/run_command_decisions.py`, which exercises the compiled
Rust binary against the TSV fixture corpus. This pytest catches plain TOML
syntax errors (mismatched quotes, broken multi-line strings, malformed regex
escapes) without needing a build, so a parse regression is not blurred with a
decision-logic regression. Config-content invariants (decision parity between
example.toml and the live config, reason presence) are verified behaviorally
by config_test.sh, not reimplemented here.
"""

import os
import glob
import tomllib

import pytest

import file_utils

REPO_ROOT = file_utils.get_repo_root()


def _root_toml_paths() -> list[str]:
	# Sort for deterministic parametrize IDs.
	return sorted(glob.glob(os.path.join(REPO_ROOT, "*.toml")))


def _load_toml(path: str) -> dict:
	with open(path, "rb") as f:
		data = tomllib.load(f)
	return data


@pytest.mark.parametrize("path", _root_toml_paths())
def test_toml_parses(path: str) -> None:
	# A parse failure here is unambiguous: the file is syntactically broken.
	_load_toml(path)
