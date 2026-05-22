# claude-code-permissions-hook

Rust permission hook for Claude Code that intercepts every tool call, decomposes compound shell commands, and decides allow, deny, or passthrough against TOML rules to bound blast radius while keeping routine local work unblocked.

## Quick start

1. Build the binary: `cargo build --release`. The hook reads JSON on stdin and writes a JSON decision on stdout, ready to wire into Claude Code's PreToolUse hook.
2. Copy `example.toml` to a personal config location and tailor it to your workspace; the example file is the canonical rule set.
3. Validate any config edit before use: `./target/release/claude-code-permissions-hook validate --config /path/to/your.toml` prints rule counts and audit settings.
4. Register the hook in `.claude/settings.json` (full steps in [docs/INSTALL.md](docs/INSTALL.md)).

## Documentation

### Getting started

- [docs/INSTALL.md](docs/INSTALL.md) - build steps, requirements, and hook registration in `.claude/settings.json`.
- [docs/USAGE.md](docs/USAGE.md) - CLI reference, examples, and I/O formats.
- [docs/CLAUDE_HOOK_USAGE_GUIDE.md](docs/CLAUDE_HOOK_USAGE_GUIDE.md) - what the hook allows, denies, and steers; preferred recovery paths for denied patterns.

### Reference

- [docs/CONFIGURATION_GUIDE.md](docs/CONFIGURATION_GUIDE.md) - TOML rule syntax, variables, and decision-table conventions.
- [docs/CODE_ARCHITECTURE.md](docs/CODE_ARCHITECTURE.md) - high-level design, modules, and data flow.
- [docs/FILE_STRUCTURE.md](docs/FILE_STRUCTURE.md) - directory map and what belongs where.
- [docs/TOOL_INPUT_SCHEMAS.md](docs/TOOL_INPUT_SCHEMAS.md) - per-tool stdin field schemas.
- [docs/CHANGELOG.md](docs/CHANGELOG.md) - dated record of rule changes, decisions, and failures.

### Repo standards

- [AGENTS.md](AGENTS.md) - agent workflow guardrails.
- [docs/REPO_STYLE.md](docs/REPO_STYLE.md) - repo-wide conventions including changelog rotation.
- [docs/PYTHON_STYLE.md](docs/PYTHON_STYLE.md) - Python style rules for the tooling under `tools/` and `tests/`.
- [docs/PYTEST_STYLE.md](docs/PYTEST_STYLE.md) - pytest test-writing rules and failure triage.
- [docs/MARKDOWN_STYLE.md](docs/MARKDOWN_STYLE.md) - Markdown rules for this repo.

## Testing

Run the full check sequence via [config_test.sh](config_test.sh): `cargo build --release`, `cargo test`, the `validate` check on `example.toml` and the live config, and the `tools/run_command_decisions.py` decision-table regression over `tests/command_decisions.tsv`.

## License

LGPLv3. See [LICENSE.LGPL_v3](LICENSE.LGPL_v3).
