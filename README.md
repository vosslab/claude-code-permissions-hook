# Claude Code permissions hook

A PreToolUse hook for [Claude Code](https://docs.claude.com/en/docs/claude-code)
that provides granular allow/deny control over tool use. Configure rules in a
single TOML file with regex pattern matching, reusable variables, and audit
logging. A built-in shell command decomposer splits compound Bash commands and
unwraps `bash -c "..."` wrappers so each leaf sub-command is checked independently.

Deny rules are checked first, then allow rules. No match falls through to the
normal Claude Code permission prompt. See [docs/INSTALL.md](docs/INSTALL.md) for
build steps and hook registration.

## Quick start

Build the binary and validate your config:

    cargo build --release
    ./target/release/claude-code-permissions-hook validate --config example.toml

Register the hook by pointing a `PreToolUse` entry in `.claude/settings.json` at
the binary with `--config /path/to/config.toml`. See [docs/INSTALL.md](docs/INSTALL.md)
for the full settings block.

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md): requirements, build steps, hook registration
- [docs/USAGE.md](docs/USAGE.md): CLI reference, input/output format, examples
- [docs/configuration-guide.md](docs/configuration-guide.md): rule syntax for each tool
- [docs/tool-input-schemas.md](docs/tool-input-schemas.md): Claude Code tool input JSON reference
- [docs/CLAUDE_HOOK_USAGE_GUIDE.md](docs/CLAUDE_HOOK_USAGE_GUIDE.md): allowed/denied patterns for AI agents
- [docs/CHANGELOG.md](docs/CHANGELOG.md): chronological record of changes
- [example.toml](example.toml): starter config with deny/allow rules and variables

## Testing

    cargo test
    source source_me.sh && python3 -m pytest tests/test_hook.py -v

## License

GPLv3. See LICENSE file for details.

## Maintainer

Neil Voss, https://bsky.app/profile/neilvosslab.bsky.social
