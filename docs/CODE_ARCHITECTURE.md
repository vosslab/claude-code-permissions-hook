# Code architecture

A Rust CLI binary that runs as a Claude Code `PreToolUse` hook. Reads one
hook-input JSON object from stdin, evaluates it against deny/allow rules in
a TOML config, and writes a permission decision to stdout. Empty stdout is
"passthrough" -- Claude Code falls back to its normal permission flow.

## Overview

The binary has two subcommands:

- `run --config <path>` -- read hook JSON from stdin, decide, exit.
- `validate --config <path>` -- parse the config and report rule counts.

For each `Bash` tool call, a shell decomposer splits the command into leaf
sub-commands (around `&&`, `||`, `;`, `|`, and inside `bash -c "..."` and
`$(...)` substitutions). Each leaf is evaluated independently:

- ANY leaf matches a deny rule -> deny.
- ALL leaves match an allow rule -> allow.
- Otherwise -> passthrough.

Non-Bash tools (Read, Write, Edit, Glob, Grep, WebFetch, etc.) are matched
against tool-specific field regexes (e.g. `file_path_regex`, `url_regex`).

## Major components

- [main.rs](../src/main.rs) -- CLI entry point. Parses args with `clap`,
  dispatches to `run_hook` or `run_validate_config`, configures logging.
- [lib.rs](../src/lib.rs) -- top-level library API:
  `process_hook_input`, `process_hook_input_with_config`,
  `validate_config`, `load_config`. Wires the config loader, decomposer,
  matcher, and audit emitter together.
- [config.rs](../src/config.rs) -- TOML schema (`Config`,
  `LimitsConfig`, `GitProtectionConfig`, `AuditConfig`, `RuleConfig`,
  compiled `Rule`). Handles `${VAR}` expansion from `[variables]` and
  rule compilation (`compile_rule_with_vars`).
- [decomposer.rs](../src/decomposer.rs) -- Bash AST walker built on
  the `brush-parser` crate. Public entry: `decompose_command(&str) ->
  Vec<String>`. Returns the list of leaf sub-commands (with env-var
  prefixes structurally stripped, `bash -c` unwrapped, and `$(...)`
  substitutions extracted).
- [matcher.rs](../src/matcher.rs) -- rule evaluation. Public entry:
  `check_rules` and `check_rules_with_protected_branches`. Includes the
  protected-branch logic (`get_current_branch`, `is_on_protected_branch`)
  and per-tool field dispatch.
- [auditing.rs](../src/auditing.rs) -- two JSON-lines log writers:
  `audit_tool_use` (allow/deny decisions, controlled by `audit_level`)
  and `audit_passthrough` (commands that matched no rule, useful for
  identifying rule gaps).
- [hook_io.rs](../src/hook_io.rs) -- input/output schemas
  (`HookInput`, `HookOutput`, `HookSpecificOutput`, `Decision` enum).
- [path_check.rs](../src/path_check.rs) -- hardcoded path-existence
  pre-check applied before TOML rule matching for `Read`, `Edit`,
  `MultiEdit`, `Glob`, and `Grep`. See "Path-existence pre-check" below.

## Path-existence pre-check

The pre-check in [path_check.rs](../src/path_check.rs) runs in
[lib.rs](../src/lib.rs) before the TOML allow/deny rule loop, only for
non-Bash inputs whose tool is one of `Read`, `Edit`, `MultiEdit`, `Glob`,
`Grep`. Returning `Some(reason)` short-circuits to a deny; returning
`None` lets the regular rule evaluation continue.

### Why hardcoded and not a TOML field

A `path_must_exist = true` flag on each rule was rejected because:

- Every realistic config wants this behavior. A flag adds a way to disable
  it without adding a use case for disabling it.
- Regex cannot express filesystem state. A TOML expression of the same
  rule would be a stub that still needs Rust I/O underneath.
- The deny reason must be tool-specific (Read != Edit != Glob != Grep);
  the deny-reason field on a TOML rule is one string, which would force
  either a generic reason for every tool or duplicate rules per tool.

### Why per-tool semantics, not one uniform "file or parent" rule

Passthrough-log review during the PR (see the Milestone 0 scan output)
showed that a uniform "file or parent" rule would still leak hundreds of
Read-on-missing-file cases to "allow then fail at execution". Read needs
the file itself, not just its parent dir. Edit accepts a missing file with
an existing parent so legitimate new-file edits inside an existing
directory keep working. Glob needs a directory specifically (a file
passed where a directory is expected is a separate failure mode worth
reporting). Grep accepts file or directory because the underlying tool
does. Write is exempt because it creates files by design.

### Why `fs::metadata` instead of `Path::try_exists`

`try_exists` returns `Result<bool, io::Error>` -- enough to distinguish
present/absent/error, but no type information about the target. Using
`fs::metadata` directly is one syscall and lets the Read branch emit a
precise "is a directory" message when `metadata.is_dir() == true`, which
is more actionable than a generic existence reason.

### Why distinguish `Ok(false)` from `Err(_)`

`Ok(false)` is a confirmed-missing result; the path verifiably does not
exist on the filesystem. Any other `io::Error` (permission denied on a
parent traversal, malformed path, filesystem unmounted) is something the
hook cannot confirm. Conflating the two would print "does not exist" for
paths that actually do exist but the hook could not read. The pre-check
emits "does not exist" only for `Ok(false)` and "could not confirm" for
every other `Err(_)`.

### What the pre-check does not do

- Path canonicalization. Symlink resolution stops at `metadata()`
  following the link once; symlink loops are not detected.
- Permission analysis. The pre-check does not check whether the agent
  has read permission on the target; only that the path resolves.
- Security boundary. Path-traversal protection stays with the existing
  `file_path_exclude_regex = "${NO_TRAVERSAL}"` rules in TOML. The
  pre-check is a usability check, not a sandbox.

### Observed adoption (log scan, 2026-05-16)

A scan of 32,699 logged tool events from `/tmp/claude-tool-use.json`
informed the implementation. The pre-check's measurable benefit is
concentrated on `Read` and `Edit`:

- Read: 365 events that would have allowed-then-failed or stalled as
  passthrough now deny immediately (344 missing files + 21 directories).
- Edit: 14 both-missing events now deny immediately.
- MultiEdit / Glob / Grep: 0 / 0 / 1 events in the same window.

Glob and Grep coverage is defensive: those tools are barely exercised by
real agent traffic in this dataset. A separate finding emerged during the
scan -- denies that steer Bash `grep`/`find` toward the Grep/Glob tools
almost never convert into actual Grep/Glob tool calls (534 file-grep
denies produced 0 Grep tool calls; 222 find denies produced 0 Glob tool
calls). Agents either retry the same Bash form on a different path,
switch to `ls`, or fall back to Read of the whole file. That is an
agent-side behavior issue, separate from this PR, and worth a follow-up:
test shorter, copyable deny messages of the form
`Use the Grep tool now: Grep(pattern="<re>", path="<file>"). Do not retry
grep in Bash.`

## Data flow

End-to-end for one Bash tool call:

1. Claude Code spawns the binary with `run --config <path>`, pipes the
   `HookInput` JSON to stdin.
2. `main::run_hook` reads stdin and calls `lib::process_hook_input`.
3. `lib::load_config` reads the TOML, expands `${VAR}` references, and
   compiles every `[[deny]]` / `[[allow]]` block into a `Rule` with
   pre-compiled regexes.
4. For Bash inputs, `decomposer::decompose_command` walks the parsed AST
   and produces leaf sub-commands. For other tools, the raw `tool_input`
   field values are used directly.
5. `matcher::check_rules` evaluates deny rules first (any-leaf-matches),
   then allow rules (all-leaves-match). Tool-only rules (no field
   regexes) bypass the per-leaf logic.
6. `lib` packages the result into a `HookOutput`; if the decision is
   allow or deny the JSON is written to stdout. Passthrough yields
   empty stdout.
7. `auditing::audit_tool_use` appends a JSON-lines record (when
   `audit_level` permits); passthroughs go to a separate log when
   `passthrough_log_file` is set.

## Testing and verification

- Rust unit + integration tests live alongside the source and in
  [integration_test.rs](../tests/integration_test.rs) +
  [test_protected_branch.rs](../tests/test_protected_branch.rs):
  `cargo test`.
- The decision-table regression corpus is
  [command_decisions.tsv](../tests/command_decisions.tsv), driven
  by [run_command_decisions.py](../tools/run_command_decisions.py)
  (intentionally outside pytest). Each row asserts allow/deny/passthrough
  for one tool input against the live config and `example.toml` (or an
  explicit per-row config override).
- Repo-wide Python lint gates (pyflakes, ascii, shebangs, imports) live
  under `tests/` and are run with `pytest tests/`.

## Extension points

- **New rule field for an existing tool**: add the field to `RuleConfig`
  and the compiled `Rule` in [config.rs](../src/config.rs), then
  handle it in [matcher.rs](../src/matcher.rs).
- **New supported tool**: add a dispatch arm to the per-tool branch in
  [matcher.rs](../src/matcher.rs); document the new field set in
  [TOOL_INPUT_SCHEMAS.md](TOOL_INPUT_SCHEMAS.md).
- **New audit format**: extend [auditing.rs](../src/auditing.rs).
- **New decomposer behavior**: extend the AST walker in
  [decomposer.rs](../src/decomposer.rs); add fixtures to
  [command_decisions.tsv](../tests/command_decisions.tsv).
- **New rule deny/allow**: edit [example.toml](../example.toml) and the
  live config, add TSV rows, run the regression.

## Known gaps

- [ ] Confirm minimum supported Rust version (MSRV); currently uses
  `edition = "2024"`.
- [ ] Document the `[variables]` evaluation order (lexical vs
  topological) for chained variable references.
