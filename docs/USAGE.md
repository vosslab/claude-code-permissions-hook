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
{"decision":"allow","reason":"Bash rule: command matches ^cargo (build|test|check|clippy|fmt|run)"}
```

### Deny a dangerous command

```bash
echo '{"session_id":"s1","transcript_path":"/tmp/t","cwd":"/home/user","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | ./target/release/claude-code-permissions-hook run --config example.toml
```

Output (denied):

```json
{"decision":"deny","reason":"Bash rule: command matches ^rm .*-rf"}
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

See [docs/tool-input-schemas.md](tool-input-schemas.md) for per-tool input fields.

### Output (stdout)

JSON object when a rule matches:

```json
{"decision": "allow", "reason": "..."}
```

or

```json
{"decision": "deny", "reason": "..."}
```

No output on passthrough.

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

Python integration tests (requires pytest):

```bash
source source_me.sh && python3 -m pytest tests/test_hook.py -v
```

## Known gaps

- [ ] Document supported tool names exhaustively (currently inferred from
  [docs/tool-input-schemas.md](tool-input-schemas.md)).
