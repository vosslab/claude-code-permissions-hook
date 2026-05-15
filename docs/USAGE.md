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

### Allow a cargo command

```bash
echo '{"session_id":"s1","transcript_path":"/tmp/t","cwd":"/home/user","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cargo test"}}' \
  | ./target/release/claude-code-permissions-hook run --config example.toml
```

Output (allowed):

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Matched rule for Bash with command: cargo test"},"suppressOutput":true}
```

### Deny a dangerous command

```bash
echo '{"session_id":"s1","transcript_path":"/tmp/t","cwd":"/home/user","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | ./target/release/claude-code-permissions-hook run --config example.toml
```

Output (denied):

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."},"suppressOutput":true}
```

### Passthrough (no output)

When a tool call matches neither allow nor deny rules, the hook produces
no stdout output. Claude Code then falls back to its normal permission flow.

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

## Running tests

Rust unit and integration tests:

```bash
cargo test
```

Decision-table regression (runs every row in
[command_decisions.tsv](../tests/command_decisions.tsv) against the
live config and `example.toml`; intentionally outside pytest):

```bash
source source_me.sh && python3 tools/run_command_decisions.py
source source_me.sh && python3 tools/run_command_decisions.py ffprobe  # filter
```

## Known gaps

- [ ] Document supported tool names exhaustively (currently inferred from
  [TOOL_INPUT_SCHEMAS.md](TOOL_INPUT_SCHEMAS.md)).
