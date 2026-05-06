# File structure

Top-level layout for the claude-code-permissions-hook repository.

## Top-level layout

```text
claude-code-permissions-hook/
+- src/                         Rust source for the binary and library
+- tests/                       Rust + Python tests, JSON fixtures, decision TSV
+- tools/                       Operational scripts that drive the built binary
+- docs/                        All non-root documentation
+- devel/                       Developer-only utility scripts
+- target/                      Cargo build output (gitignored)
+- Cargo.toml                   Rust crate manifest (name, deps, edition)
+- Cargo.lock                   Pinned dependency versions (committed)
+- VERSION                      Version string mirroring Cargo.toml
+- example.toml                 Starter config with deny/allow rules + variables
+- claude-code-permissions-hook.toml  Symlink to the user's live config
+- pip_requirements-dev.txt     Python dev dependencies (pytest, pyflakes, etc.)
+- README.md                    Short overview, quick start, doc map
+- AGENTS.md                    Agent-specific instructions and constraints
+- CLAUDE.md                    Project-specific Claude Code instructions
+- LICENSE.LGPL_v3              License text (note: README mentions GPLv3)
+- source_me.sh                 Bash environment bootstrap (set PYTHON* vars)
+- config_test.sh               Build + cargo test + decision-regression wrapper
+- rotate_logs.sh               Audit/passthrough log rotation helper
`- update_rust.sh               Convenience helper for `rustup update`
```

## Key subtrees

### [src/](../src/)

Rust source. Each module is documented in
[docs/CODE_ARCHITECTURE.md](CODE_ARCHITECTURE.md).

```text
src/
+- main.rs                      CLI entry (clap), subcommand dispatch
+- lib.rs                       Public library API + orchestration
+- config.rs                    TOML schema, ${VAR} expansion, rule compilation
+- decomposer.rs                Bash AST walker (leaf sub-command extraction)
+- matcher.rs                   Rule evaluation, protected-branch logic
+- auditing.rs                  JSON-lines audit + passthrough writers
`- hook_io.rs                   HookInput / HookOutput / Decision schemas
```

### [tests/](../tests/)

```text
tests/
+- integration_test.rs          Rust integration tests using JSON fixtures
+- test_protected_branch.rs     Rust tests for protected-branch behavior
+- command_decisions.tsv        Decision-table regression corpus (~440 rows)
+- test_config.toml             Synthetic config used by the Rust integration
|                               tests + a small subset of TSV rows
+- test_protected_branch_config.toml  Config for the protected-branch tests
+- *.json                       HookInput fixtures referenced by integration_test.rs
+- conftest.py                  pytest setup (REPO_ROOT discovery)
+- git_file_utils.py            Shared helper for repo-root resolution
+- check_ascii_compliance.py    Single-file ASCII linter
+- fix_ascii_compliance.py      Single-file ASCII fixer
+- fix_whitespace.py            Single-file whitespace fixer
+- test_ascii_compliance.py     Repo-wide ASCII gate
+- test_bandit_security.py      Bandit security gate
+- test_import_dot.py           Forbid relative imports
+- test_import_requirements.py  Every import must be stdlib / repo-local / declared
+- test_import_star.py          Forbid `from x import *`
+- test_indentation.py          Tabs-only enforcement for Python
+- test_init_files.py           Enforce empty/minimal __init__.py
+- test_pyflakes_code_lint.py   Repo-wide pyflakes gate
+- test_shebangs.py             Shebang/executable-bit alignment
+- test_whitespace.py           Trailing/mixed whitespace gate
`- README.md                    Test layout overview
```

### [tools/](../tools/)

```text
tools/
`- run_command_decisions.py     Drives tests/command_decisions.tsv against
                                the live config + example.toml; lives here
                                because it is operational tooling, not a
                                pytest file
```

### [docs/](../docs/)

```text
docs/
+- INSTALL.md                   Setup, build, hook registration
+- USAGE.md                     CLI reference, examples, I/O formats
+- CONFIGURATION_GUIDE.md       TOML rule syntax for each tool
+- TOOL_INPUT_SCHEMAS.md        Claude Code tool input JSON reference
+- CLAUDE_HOOK_USAGE_GUIDE.md   Allowed/denied patterns for AI agents
+- WORKTREE_POLICY.md           Protected-branch workflow
+- CODE_ARCHITECTURE.md         This repo's component map and data flow
+- FILE_STRUCTURE.md            This file
+- CHANGELOG.md                 Chronological record of changes
+- AUTHORS.md                   Contributor list (centrally maintained)
+- MARKDOWN_STYLE.md            Markdown rules (centrally maintained)
+- PYTHON_STYLE.md              Python rules (centrally maintained)
+- PYTEST_STYLE.md              Pytest rules (centrally maintained)
+- REPO_STYLE.md                Repo-wide layout rules (centrally maintained)
+- TYPESCRIPT_STYLE.md          TypeScript rules (centrally maintained)
`- PLAYWRIGHT_USAGE.md          Playwright rules (centrally maintained)
```

## Generated artifacts

- [target/](../target/) -- Cargo build output. Gitignored. Cleanable via
  `cargo clean` or selectively trimmed by [config_test.sh](../config_test.sh).
- `/tmp/claude-tool-use.json` -- audit log written by the running hook
  (path configurable via `audit_file` in the TOML).
- `/tmp/claude-passthrough.json` -- passthrough log (path configurable).

## Documentation map

- Root docs: [README.md](../README.md), [AGENTS.md](../AGENTS.md),
  [CLAUDE.md](../CLAUDE.md), [LICENSE.LGPL_v3](../LICENSE.LGPL_v3),
  [VERSION](../VERSION).
- All other documentation lives under [docs/](../docs/) using
  SCREAMING_SNAKE_CASE filenames per
  [docs/REPO_STYLE.md](REPO_STYLE.md).

## Where to add new work

- **Rust source**: [src/](../src/). Add a new module by creating
  `src/<name>.rs` and declaring `mod <name>;` in
  [src/lib.rs](../src/lib.rs).
- **Rust tests**: [tests/](../tests/) for integration tests; inline
  `#[cfg(test)] mod tests` blocks within [src/](../src/) for unit tests.
- **Decision-table cases**: append rows to
  [tests/command_decisions.tsv](../tests/command_decisions.tsv) and run
  [tools/run_command_decisions.py](../tools/run_command_decisions.py).
- **Python lint gates**: [tests/](../tests/) with `test_*.py` naming.
- **Operational scripts**: [tools/](../tools/) -- not under [tests/](../tests/).
- **Documentation**: [docs/](../docs/) with SCREAMING_SNAKE_CASE
  filenames; link from [README.md](../README.md) when user-facing.

## Known gaps

- [ ] Reconcile license: [LICENSE.LGPL_v3](../LICENSE.LGPL_v3) is
  present at root but [README.md](../README.md) advertises GPLv3.
  Either rename the file to match the actual license or correct the
  README claim.
- [ ] [improve_prompt.txt](../improve_prompt.txt) at root -- purpose
  unclear; consider moving into [devel/](../devel/) or removing.
