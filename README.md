# claude-code-permissions-hook

Rust permission hook for Claude Code that intercepts every tool call, decomposes compound shell commands, and decides allow, deny, or passthrough against TOML rules to bound blast radius while keeping routine local work unblocked.

## Quick start

1. Build the binary: `cargo build --release`. The hook reads JSON input on stdin and writes a JSON decision on stdout, suitable for wiring into Claude Code's PreToolUse hook.
2. Copy `example.toml` to a personal config location and tailor it to your workspace; the example file is the canonical rule set.
3. Validate any config edit before use: `cargo run --release --bin claude-code-permissions-hook -- validate --config /path/to/your.toml` prints the loaded rule count.
4. Exercise the rule corpus: `python3 tools/run_command_decisions.py` runs `tests/command_decisions.tsv` against both the example and live configs.

## Documentation

- [docs/CLAUDE_HOOK_USAGE_GUIDE.md](docs/CLAUDE_HOOK_USAGE_GUIDE.md) - what the hook allows, denies, and steers; preferred recovery paths for denied patterns.
- [docs/CHANGELOG.md](docs/CHANGELOG.md) - dated record of rule changes, decisions, and failures.
- [docs/REPO_STYLE.md](docs/REPO_STYLE.md) - repo-wide conventions including changelog rotation and `README.md` rules.
- [docs/PYTHON_STYLE.md](docs/PYTHON_STYLE.md) - Python style rules for the tooling under `tools/` and `tests/`.
- [AGENTS.md](AGENTS.md) - agent workflow guardrails.

## License

LGPLv3. See [LICENSE.LGPL_v3](LICENSE.LGPL_v3).
