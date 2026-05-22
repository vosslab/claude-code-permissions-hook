# Usage

The permissions hook intercepts Claude Code tool calls, evaluates them
against allow/deny rules in a TOML config, and returns allow, deny,
or passthrough decisions.

## Quick start

Validate your config:

```bash
./target/release/claude-code-permissions-hook validate --config my-config.toml
```

Test a tool call manually by piping JSON to stdin:

```bash
echo '{"session_id":"test","transcript_path":"/tmp/t","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | ./target/release/claude-code-permissions-hook run --config my-config.toml
```

## CLI

The binary has two subcommands:

| Subcommand | Description |
| --- | --- |
| `run --config <path>` | Read hook JSON from stdin, evaluate rules, output decision to stdout |
| `validate --config <path>` | Parse and compile the config, report rule counts or errors |

### Environment variables

| Variable | Effect |
| --- | --- |
| `RUST_LOG` | Diagnostic log level on stderr (`debug`, `info`, `warn`, `error`) |

## Examples

Each example shows the stdin payload as compact JSON; output is described
in plain terms (full schema in the [Output (stdout)](#output-stdout)
section below).

### Allow a cargo command

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"cargo test"},"session_id":"s1","transcript_path":"/tmp/t","cwd":"/home/user","hook_event_name":"PreToolUse"}' \
  | ./target/release/claude-code-permissions-hook run --config example.toml
```

Result: `permissionDecision` is `allow`; `permissionDecisionReason` names the matched rule and the command.

### Deny a dangerous command

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"session_id":"s1","transcript_path":"/tmp/t","cwd":"/home/user","hook_event_name":"PreToolUse"}' \
  | ./target/release/claude-code-permissions-hook run --config example.toml
```

Result: `permissionDecision` is `deny`; `permissionDecisionReason` carries the steer text from the matching deny rule.

### Passthrough (no output)

When a call matches no rule, the hook writes nothing to stdout and Claude
Code falls back to its default permission flow.

## Inputs and outputs

### Input (stdin)

JSON object with these fields:

| Field | Type | Description |
| --- | --- | --- |
| `session_id` | string | Claude Code session identifier |
| `transcript_path` | string | Path to session transcript |
| `cwd` | string | Working directory |
| `hook_event_name` | string | Always `PreToolUse` for this hook |
| `tool_name` | string | Tool being invoked (Bash, Read, Write, Edit, etc.) |
| `tool_input` | object | Tool-specific parameters |

See [TOOL_INPUT_SCHEMAS.md](TOOL_INPUT_SCHEMAS.md) for per-tool input fields.

### Output (stdout)

JSON object when a rule matches, wrapped in Claude Code's hook output schema:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "..."
  },
  "suppressOutput": true
}
```

`permissionDecision` is one of `allow` or `deny`. No stdout output on
passthrough -- Claude Code then falls back to its normal permission flow.

### Audit files

- **Audit log** (`audit_file` in config) - JSON-lines file recording
  allow/deny decisions (controlled by `audit_level`).
- **Passthrough log** (`passthrough_log_file` in config) - JSON-lines file
  recording commands that matched no rules, for identifying rule gaps.

## Tests

Run the full developer test suite via [config_test.sh](../config_test.sh):

```bash
bash config_test.sh
```

It runs `cargo build --release`, `cargo test`, the `validate` check, and the `tools/run_command_decisions.py` decision-table regression. For pytest style and test layout, see [PYTEST_STYLE.md](PYTEST_STYLE.md).

## Maintenance

Refresh the Rust toolchain with [update_rust.sh](../update_rust.sh):

```bash
./update_rust.sh
```

Upgrades `rustup` via Homebrew, runs `rustup update`, prints `rustc`/`cargo`/`rustup` versions.

## Known gaps

- [ ] Document supported `tool_name` values exhaustively (currently
  inferred from [TOOL_INPUT_SCHEMAS.md](TOOL_INPUT_SCHEMAS.md)).
- [ ] Document a `--dry-run` flag once available; none currently exists
  in `src/main.rs`.
