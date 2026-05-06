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

- [src/main.rs](../src/main.rs) -- CLI entry point. Parses args with `clap`,
  dispatches to `run_hook` or `run_validate_config`, configures logging.
- [src/lib.rs](../src/lib.rs) -- top-level library API:
  `process_hook_input`, `process_hook_input_with_config`,
  `validate_config`, `load_config`. Wires the config loader, decomposer,
  matcher, and audit emitter together.
- [src/config.rs](../src/config.rs) -- TOML schema (`Config`,
  `LimitsConfig`, `GitProtectionConfig`, `AuditConfig`, `RuleConfig`,
  compiled `Rule`). Handles `${VAR}` expansion from `[variables]` and
  rule compilation (`compile_rule_with_vars`).
- [src/decomposer.rs](../src/decomposer.rs) -- Bash AST walker built on
  the `brush-parser` crate. Public entry: `decompose_command(&str) ->
  Vec<String>`. Returns the list of leaf sub-commands (with env-var
  prefixes structurally stripped, `bash -c` unwrapped, and `$(...)`
  substitutions extracted).
- [src/matcher.rs](../src/matcher.rs) -- rule evaluation. Public entry:
  `check_rules` and `check_rules_with_protected_branches`. Includes the
  protected-branch logic (`get_current_branch`, `is_on_protected_branch`)
  and per-tool field dispatch.
- [src/auditing.rs](../src/auditing.rs) -- two JSON-lines log writers:
  `audit_tool_use` (allow/deny decisions, controlled by `audit_level`)
  and `audit_passthrough` (commands that matched no rule, useful for
  identifying rule gaps).
- [src/hook_io.rs](../src/hook_io.rs) -- input/output schemas
  (`HookInput`, `HookOutput`, `HookSpecificOutput`, `Decision` enum).

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
  [tests/integration_test.rs](../tests/integration_test.rs) +
  [tests/test_protected_branch.rs](../tests/test_protected_branch.rs):
  `cargo test`.
- The decision-table regression corpus is
  [tests/command_decisions.tsv](../tests/command_decisions.tsv), driven
  by [tools/run_command_decisions.py](../tools/run_command_decisions.py)
  (intentionally outside pytest). Each row asserts allow/deny/passthrough
  for one tool input against the live config and `example.toml` (or an
  explicit per-row config override).
- Repo-wide Python lint gates (pyflakes, ascii, shebangs, imports) live
  under [tests/](../tests/) and are run with `pytest tests/`.

## Extension points

- **New rule field for an existing tool**: add the field to `RuleConfig`
  and the compiled `Rule` in [src/config.rs](../src/config.rs), then
  handle it in [src/matcher.rs](../src/matcher.rs).
- **New supported tool**: add a dispatch arm to the per-tool branch in
  [src/matcher.rs](../src/matcher.rs); document the new field set in
  [docs/TOOL_INPUT_SCHEMAS.md](TOOL_INPUT_SCHEMAS.md).
- **New audit format**: extend [src/auditing.rs](../src/auditing.rs).
- **New decomposer behavior**: extend the AST walker in
  [src/decomposer.rs](../src/decomposer.rs); add fixtures to
  [tests/command_decisions.tsv](../tests/command_decisions.tsv).
- **New rule deny/allow**: edit [example.toml](../example.toml) and the
  live config, add TSV rows, run the regression.

## Known gaps

- [ ] Confirm minimum supported Rust version (MSRV); currently uses
  `edition = "2024"`.
- [ ] Document the `[variables]` evaluation order (lexical vs
  topological) for chained variable references.
