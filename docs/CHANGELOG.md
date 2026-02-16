# Changelog

## 2026-02-16

- Created [docs/INSTALL.md](INSTALL.md) with requirements, build steps, Claude Code
  hook setup, and verify command
- Created [docs/USAGE.md](USAGE.md) with CLI reference, input/output format,
  examples, audit file descriptions, and test commands
- Added passthrough logging to `src/auditing.rs`
  - New `audit_passthrough()` function writes JSON-lines entries to a dedicated file
  - Entry format: `{ timestamp, session_id, tool_name, tool_input, cwd }` (no decision/reason)
  - Reuses existing `truncate_json_strings()` and file-locking patterns
  - Independent of `audit_level`; logs when `passthrough_log_file` is configured
  - Added unit test `test_audit_passthrough_writes_entry`
- Implemented `passthrough_log_file` config field in `src/main.rs`
  - Already defined in config struct but was completely unimplemented
  - After audit, checks if decision is Passthrough and config has `passthrough_log_file`
  - Calls `audit_passthrough()` to write the entry
- Updated `example.toml` and `tests/test_config.toml` with `passthrough_log_file` setting
- Added shell command decomposer in new `src/decomposer.rs`
  - Uses `brush-parser` (v0.3) to parse Bash commands into AST
  - `decompose_command()` walks the AST to extract leaf SimpleCommand strings
  - Handles: `&&`, `||`, `;`, pipes, for/while/until loops, if/case clauses,
    brace groups, subshells
  - Graceful fallback: if parsing fails, returns original command as-is
  - 14 unit tests covering simple commands, compound operators, loops,
    if clauses, redirections, malformed input, and empty strings
- Updated `src/lib.rs` with decomposition-aware rule checking
  - `process_hook_input_with_rules()` now decomposes Bash commands into sub-commands
  - Deny check: if ANY sub-command matches ANY deny rule, deny the whole command
  - Allow check: ALL sub-commands must match some allow rule to allow the whole command
  - Otherwise passthrough
  - Added `with_command()` method to `HookInput` for creating synthetic inputs
- Added `brush-parser = "0.3"` to `Cargo.toml` dependencies
- Added `tempfile = "3"` to dev-dependencies for passthrough audit test
- Added 5 decomposer integration tests to `tests/integration_test.rs`
  - Safe compound allowed, dangerous sub-command denied, mixed passthrough,
    for loop safe body, for loop dangerous body
- Updated `tests/test_hook.py` with 15 new tests (529 total, up from 515)
  - 3 passthrough logging tests: log written, not written for allow, not written for deny
  - 5 tests for dangerous commands inside control flow (for/while/if/brace group)
  - 4 tests for safe control flow decomposition
  - 1 test for mixed safe/unknown passthrough
  - 1 test for deny overriding safe in pipeline
  - Behavioral test updates: `if/case/[[` with safe bodies now expect allow
    (decomposer extracts safe leaf commands); for loop with `$()` in values
    now expects allow (body command `echo $i` is safe, `$()` is in values not body)
- Fixed `src/matcher.rs`: tool-only rule matching and Glob/Grep field extraction
  - Added `is_tool_only_rule()` helper so rules like `[[allow]] tool = "WebFetch"` (no regex) now match
  - Split Glob/Grep into separate match arm using `path` field instead of `file_path`
  - Added unit tests for tool-only rules and Glob/Grep path extraction
- Fixed `src/lib.rs`: added `process_hook_input_with_rules()` to accept pre-compiled rules
  - Eliminates double rule compilation when using `load_config()` + `process_hook_input_with_config()`
- Fixed `src/main.rs`: `run_hook()` now uses pre-compiled rules from `load_config()`
  - Removed `let _ = (deny_rules, allow_rules)` suppression
- Cleaned up `Cargo.toml`: removed unused dependencies (itertools, derive_builder, lazy_static)
- Fixed `claude-code-permissions-hook.toml` user config
  - Fixed empty regex alternative (`||`) in source+python/pytest allow rule
  - Added `command_exclude_regex` to broad shell utilities rule to block command substitution
  - Added Edit tool allow rules mirroring existing Read/Write rules
  - Added `bash <script>.sh` allow rule for running shell scripts directly
  - Added Read allow rule for macOS temp paths (`/var/folders/`)
  - Synced utilities list with settings.json: added chmod, colordiff, comm, diff, done, for, rg, test
  - Added `git -C <path>` variant to git allowlist
  - Added `bash -lc "<utility>"` rule for non-source bash wrapper commands
- Rewrote `tests/test_config.toml` with targeted deny rules
  - Replaced broad `.*(&|;|\\||...).*` deny pattern with targeted `\brm\b` deny rule
  - Added Write, Edit, Glob, and Grep allow rules for the Dropbox project path
  - Added common shell utilities allow rule with narrow exclude (backtick/`$(` only)
  - Added tool-only allow rules for WebFetch and WebSearch
- Added 10 new JSON test fixtures for compound commands, tool-only, Glob/Grep, Edit
- Added 10 new Rust integration tests in `tests/integration_test.rs`
- Created `tests/test_hook.py` pytest harness with 47 parameterized tests
  - Simple allowed commands, safe compound commands, dangerous compound denial
  - Loop passthrough, tool-only rules, path-based rules, deny rules, edge cases
- Added `[variables]` support to TOML config for reusable regex fragments
  - Define variables in `[variables]` section, reference as `${VAR_NAME}` in regex fields
  - Errors on undefined variable references
  - Added `expand_variables()`, `expand_opt()`, and `compile_rule_with_vars()` to `src/config.rs`
  - Added unit tests for variable expansion
- Added `$HOME`/`$USER`/`$TMPDIR` environment variable expansion in `[variables]` values
  - `$VARNAME` (no braces) expands standard OS env vars during config load
  - `${TOML_VAR}` (with braces) expands TOML-defined variables in regex fields
  - Added `expand_env_vars()` to `src/config.rs`
- Updated `example.toml` to demonstrate `[variables]` feature
- Updated user's production TOML config to use variables (`SAFE_CMDS`, `NO_CMD_SUB`, `HOME_PATH`, `NO_TRAVERSAL`)
- Expanded `tests/test_hook.py` from 47 to 346 parameterized torture tests
  - Cargo: allowed subcommands (15) and disallowed subcommands passthrough (11)
  - Utilities: comprehensive coverage of all SAFE_CMDS with flag variations (60+)
  - Compound commands: pipes, &&, ||, semicolons, redirections, complex pipelines (30+)
  - rm denial: standalone (8), hidden in compounds (13), substring false-positive avoidance (8)
  - Command substitution: $() and backtick blocking, ${VAR} vs $() distinction (20+)
  - Control flow: for/while loops, if/case/until passthrough (7)
  - Path traversal: various ../  patterns across Read/Write/Edit (15+)
  - Sensitive files: .env/.secret denial and near-miss patterns not denied (18+)
  - Tool-only rules: WebFetch/WebSearch with varied inputs (12)
  - Glob/Grep: allowed paths, outside paths, no-path, deep nesting (12+)
  - Task/subagent: matching and non-matching types, missing fields (8)
  - Deny-over-allow priority: rm vs echo, sensitive vs allowed path (3)
  - Unknown tools: 11 tool names including NotebookEdit, Skill, etc.
  - Edge cases: empty/whitespace/null/numeric/bool/array inputs, long strings (15+)
  - Special characters and newline injection (15+)
  - Regex boundary testing: misspelled utilities, almost-cargo commands (12)
  - Dangerous non-rm commands passthrough (7)
  - Non-utility programs passthrough (11)
  - JSON edge cases: extra fields, wrong types (5)
  - Stress test: 60 rapid sequential calls (1)
  - Config validation: test and example configs (2)
  - Regression tests: command sub in loops/cargo, pipe/semicolon chains (5)
- Added adversarial evasion tests (126 tests) to `tests/test_hook.py`
  - git commit: 21 evasion attempts including flag insertion (`git -C /tmp commit`),
    chaining, env prefixes, full paths, pipes - all denied
  - git stash: 18 evasion attempts with same bypass techniques - all denied
  - git rm: 12 evasion attempts - all denied
  - rm: 30 evasion attempts including flag variations, full paths, chaining,
    backslash-escaped rm, newline injection, comment prefixes - all denied
  - Path traversal: 14 evasion patterns including deep traversal, targeting
    .ssh/id_rsa, .aws/credentials, .gnupg, proc/self/environ - all denied
  - Sensitive files: 12 patterns including deny-beats-allow priority tests
  - False positive checks: commands with "rm" as substring (alarm, formatting),
    safe git commands (status, diff, log), .env.local/.envrc not denied
  - Deny-beats-allow priority: 10 tests proving deny rules win over allow
  - Newline injection: 7 tests hiding dangerous commands after \\n
  - Write/Edit traversal: 4 tests verifying traversal not allowed
- Added git deny rules to `tests/test_config.toml`
  - `\\bgit\\b.*\\bcommit\\b` - catches git with any flags before commit
  - `\\bgit\\b.*\\bstash\\b` - catches git stash with any flags
  - `\\bgit\\b.*\\brm\\b` - catches git rm with any flags
- **SECURITY FIX**: Fixed production config deny rules
  - Old `.*git\\s+commit.*` was bypassable with `git --no-pager commit`,
    `git -C /tmp commit`, `git -c user.name=evil commit`, etc.
  - Old `.*git\\s+stash.*` had same bypass vulnerability
  - Old rm rules (`^rm .*-rf` and complex -rf flag pattern) missed `rm file.txt`,
    `rm -r dir/`, `rm -f file` (only caught combined -rf flags)
  - New patterns use `\\b` word boundaries: `\\bgit\\b.*\\bcommit\\b`,
    `\\bgit\\b.*\\bstash\\b`, `\\brm\\b`
