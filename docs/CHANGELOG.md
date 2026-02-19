# Changelog

## 2026-02-18

- Added optional `reason` field to TOML deny/allow rules
  - When a rule matches and has a `reason` set, that custom message is shown
    to Claude instead of the auto-generated match description
  - Added `reason: Option<String>` to `RuleConfig` and `Rule` in `src/config.rs`
  - Updated `check_rules()` in `src/matcher.rs` to prefer custom reason
  - Added unit tests: `test_custom_reason_overrides_auto`,
    `test_no_custom_reason_uses_auto`
  - Example TOML usage:
    ```toml
    [[deny]]
    tool = "Bash"
    command_regex = "\\$PYTHON\\b"
    reason = "Use 'python3' directly instead of $PYTHON variable"
    ```
- Added `$(...)` command substitution extraction to the decomposer
  - Commands inside `$(...)` are now extracted and checked against rules
  - Works in SimpleCommand leaves (e.g. `VAR=$(cmd)`) and ForClause
    values (e.g. `for i in $(cmd); do ...`)
  - Recursive: inner `$(...)` in nested contexts are also extracted
  - Added `extract_command_substitutions()` with paren-depth tracking
  - Added ForClause value scanning in `extract_from_compound_command()`
  - 7 new unit tests: for-loop `$()`, assignment `$()`, nested, no
    false positive on `${}`, multiple, basename in loop body, plain values
- Custom reason now includes the matched command: format is
  `"<custom reason> (Matched rule for Bash with command: <actual cmd>)"`
  instead of completely replacing the auto-generated reason
- Added four new deny rules with custom reasons to production config
  - `PYTHONDONTWRITEBYTECODE`/`PYTHONUNBUFFERED` usage: tells Claude to use
    `source source_me.sh && python3` instead of setting env vars manually
  - `VAR=$(...)` assignments: tells Claude to use `source source_me.sh` or
    inline the command directly
  - `$PYTHON` variable usage: denies `$PYTHON` and `${PYTHON}`, tells Claude
    to use `python3` directly
  - Bare env-var assignment: denies `^[A-Z_]+=[^\s]+$` (decomposed leaves
    like `REPO_ROOT=x` with no command), tells Claude to use space-separated
    env prefixes on one line
- Added `[limits]` config section with `max_chain_length` setting
  - Denies Bash commands with more chained sub-commands than the limit
  - Set to 0 to disable (default). Production config set to 5
  - Checked in `process_hook_input_with_rules()` after decomposition,
    before deny/allow rule matching
  - Added `LimitsConfig` struct to `src/config.rs` with `Default` impl
  - Deny message: "Command has N chained sub-commands (limit: M).
    Break into smaller commands."
- Updated env-var-prefix Bash rule to support multiple prefixes and
  `python3`/`pytest`/`pyflakes` commands (was only single prefix + SAFE_CMDS).
  Fixes passthrough for `REPO_ROOT=x PYTHONPATH=y python3 -m pytest ...`
- Added `[Cc]ache` to rm deny exclude pattern (cache files are safe to delete)
- Added Write and Edit allow rules for `$HOME/nsh/` (project files)
- Added Write and Edit allow rules for `$HOME/.claude/` (plan files, settings)
- Added `ls-files` to git subcommand allowlist in [example.toml](../example.toml)
- Added commented `reason` example to [example.toml](../example.toml)
- Added inter-variable expansion: `${VAR}` references in variable values are
  now resolved, allowing variables to reference other variables. Iterates until
  stable; detects circular references. Added unit test
  `test_inter_variable_expansion`
- Split `SAFE_CMDS` into grouped sub-variables (`FILE_CMDS`, `FS_CMDS`,
  `SYS_CMDS`) merged via `SAFE_CMDS = "${FILE_CMDS}|${FS_CMDS}|${SYS_CMDS}"`.
  Applied to production config, example config, and test config
- Fixed `test_while_loop_passthrough` -> `test_while_loop_allowed` in Python
  tests (true and sleep are now in SAFE_CMDS)

## 2026-02-16

- Bumped version to 26.02 (26.2.0 in Cargo.toml due to SemVer constraints),
  added `VERSION` file
- **Bug fix**: `subagent_type_regex` field in TOML was silently ignored by serde
  because the field did not exist in `RuleConfig`. The Task allow rule in
  `example.toml` was acting as a tool-only rule (allowing ALL subagent types)
  instead of restricting to Explore/general-purpose.
  - Added `subagent_type_regex: Option<String>` to `RuleConfig` and
    `subagent_type_regex: Option<Regex>` to `Rule`
  - Updated `check_subagent_type()` in `src/matcher.rs` to check regex match
    as an alternative to exact `subagent_type` match
  - Updated `is_tool_only_rule()` to include `subagent_type_regex`
- **Bug fix**: Added `#[serde(deny_unknown_fields)]` to `RuleConfig` so that
  typos or non-existent fields in TOML rules cause a parse error at startup
  instead of being silently ignored
  - Also fixed `path_regex`/`path_exclude_regex` in Glob/Grep rules (these
    were unknown fields silently ignored) to `file_path_regex`/
    `file_path_exclude_regex`
- Added `tool_regex` field to `RuleConfig` and `Rule` for regex-based tool
  name matching. Allows collapsing many tool-only rules into a single rule
  with a pattern (e.g. `tool_regex = "^mcp__plugin_playwright_"`)
- Added `tree` and `lsof` to SAFE_CMDS in `example.toml`
- Added env-var-prefix Bash rule (`LC_ALL=C grep ...` pattern)
- Fixed macOS `/private/tmp/` path matching: `/tmp/` rules now use
  `^(/private)?/tmp/` to handle macOS symlink resolution
- Added Claude internal tool rules via `tool_regex` (TaskOutput, TaskCreate,
  TaskList, TaskGet, TaskUpdate, TaskStop, Skill, AskUserQuestion,
  ExitPlanMode, EnterPlanMode, SendMessage, TeamCreate, TeamDelete,
  NotebookEdit)
- Added Playwright MCP browser tool rules via `tool_regex`
  (`^mcp__plugin_playwright_playwright__browser_`)
- Expanded Task `subagent_type_regex` to include all standard subagent types
  (Explore, general-purpose, Plan, Bash, haiku, sonnet, opus,
  statusline-setup, claude-code-guide, superpowers:code-reviewer)
- Added `bash -c` unwrapping to `src/decomposer.rs`
  - `try_unwrap_bash_c()` detects `bash -c "inner command"` patterns (including
    `-lc`, `-cl`, and other combined flags) and recursively decomposes the inner
    command string
  - `strip_outer_quotes()` helper removes a single layer of matching quotes
  - Handles both single and double quotes: `bash -lc "..."` and `bash -lc '...'`
  - Only unwraps `bash` (not `zsh`, `sh`, etc.) and only when `-c` flag is present
  - Inner commands are checked against normal allow/deny rules, eliminating the
    need for special `bash -lc` wrapper regex rules in the config
  - Added 8 unit tests: double/single quotes, compound inner commands, `-cl` flag
    order, dangerous inner commands, `-n` without `-c`, non-bash commands
- Added `touch`, `cd`, `file` to SAFE_CMDS in production config
- Fixed production config `bash -lc` rules to accept single quotes (`[\"']`
  instead of `\"` only)
- Removed 5 redundant allow rules from production config (24 -> 19 rules)
  - `bash -lc "source && python/pytest"` wrapper rule (decomposer unwraps bash -c)
  - `source && python/pytest` compound rule (decomposer splits &&)
  - Comment blocks rule (parser ignores comments, leaf commands match SAFE_CMDS)
  - `sleep && safe` compound rule (decomposer splits &&)
  - `bash -[lcn]+ "safe_cmd"` wrapper rule (decomposer unwraps bash -c)
- Simplified python rule exclude regex (removed `&&`/`;`/`|` exclusions since
  the decomposer splits compound operators before rules see them)
- Fixed git allowlist regex: `\s` -> `(\s|$)` so bare `git status`, `git diff`,
  `git log` (without args) now match
- Updated [example.toml](../example.toml) to match production config patterns
  - 5 deny rules (rm, .env/.secret, git commit/stash/rm)
  - 17 allow rules (python, cargo, git, bash scripts, SAFE_CMDS, Glob/Grep,
    Read/Write/Edit, /tmp, web tools, Task)
  - Variables (SAFE_CMDS, NO_CMD_SUB, PROJECT_PATH, NO_TRAVERSAL)
  - Decomposer explanation comment, fixed git regex
- Rewrote [README.md](../README.md) to be concise with links to docs/
- Created [docs/INSTALL.md](INSTALL.md) with requirements, build steps, Claude Code
  hook setup, and verify command
- Created [docs/USAGE.md](USAGE.md) with CLI reference, input/output format,
  examples, audit file descriptions, and test commands
- Removed shebang from `tests/test_hook.py` (pytest-only file, not executable)
- Added `# nosec B108` security annotations to 10 test data lines in
  `tests/test_hook.py` with hardcoded `/tmp` paths (false positives, not actual temp usage)
- Created [pip_requirements-dev.txt](../pip_requirements-dev.txt) with dev dependencies
  (bandit, packaging, pyflakes, pytest, rich)
- Updated `tests/test_shebangs.py` to allowlist `tests/test_hook.py` as a
  non-executable pytest module
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
- Copied shared repo docs and test infrastructure from central repo
  - Added [AGENTS.md](../AGENTS.md), [CLAUDE.md](../CLAUDE.md), [source_me.sh](../source_me.sh)
  - Added [docs/REPO_STYLE.md](REPO_STYLE.md), [docs/PYTHON_STYLE.md](PYTHON_STYLE.md),
    [docs/MARKDOWN_STYLE.md](MARKDOWN_STYLE.md), [docs/AUTHORS.md](AUTHORS.md)
  - Added shared test harnesses: `tests/test_shebangs.py`, `tests/test_bandit_security.py`,
    `tests/test_pyflakes_code_lint.py`, `tests/test_ascii_compliance.py`,
    `tests/test_whitespace.py`, `tests/test_indentation.py`,
    `tests/test_import_requirements.py`, `tests/test_import_star.py`
  - Added `tests/git_file_utils.py` and `.gitignore`

## 2025-12-06

- Created [docs/configuration-guide.md](configuration-guide.md) with rule syntax
  for each supported tool (Read, Write, Edit, Bash, Task, Glob, Grep, WebFetch, WebSearch)
- Created [docs/tool-input-schemas.md](tool-input-schemas.md) with Claude Code
  tool input JSON reference
- Cleaned up [README.md](../README.md), moved detailed docs to `docs/`
- Truncated audit log string fields at 256 characters to keep JSON-lines manageable

## 2025-12-05

- Renamed logging module from `src/logging.rs` to `src/auditing.rs` to avoid
  conflict with `log` crate naming
- Added audit level support: `off`, `matched` (default), `all`
- Added integration test suite in `tests/integration_test.rs` with sample JSON fixtures
- Created `tests/test_config.toml` for integration testing
- Truncated long tool input strings in audit entries
- Cleaned up spurious `Decision` type duplication

## 2025-10-10

- Initial project release
- Core permission hook: reads JSON from stdin, evaluates deny/allow rules, outputs
  decision to stdout
- TOML config with `[[deny]]` and `[[allow]]` rule sections
- Regex pattern matching for Bash `command`, file path tools (`file_path`), and
  Task `subagent_type`
- Exclude regex support (`command_exclude_regex`, `file_path_exclude_regex`)
- JSON-lines audit logging with file locking
- CLI with `run` and `validate` subcommands via `clap`
- [example.toml](../example.toml) with starter rules
- [README.md](../README.md) with setup instructions and flowchart
