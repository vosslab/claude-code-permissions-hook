# Claude Code permissions hook

A PreToolUse hook for [Claude Code](https://docs.claude.com/en/docs/claude-code)
that provides granular allow/deny control over tool use. Configure rules in a
single TOML file with regex pattern matching, reusable variables, and audit
logging. A built-in shell command decomposer (via `brush-parser`) splits
compound Bash commands and unwraps `bash -c "..."` wrappers so each leaf
sub-command is checked independently against the rules.

## Quick start

```bash
cargo build --release
./target/release/claude-code-permissions-hook validate --config example.toml
```

Register the hook in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/claude-code-permissions-hook run --config /path/to/config.toml"
          }
        ]
      }
    ]
  }
}
```

See [docs/INSTALL.md](docs/INSTALL.md) for full setup steps.

## How it works

Deny rules are checked first (block), then allow rules (permit). No match
means passthrough to the normal Claude Code permission flow. For Bash
commands, compound operators (`&&`, `||`, `;`, pipes, loops) and
`bash -c "..."` wrappers are decomposed so each sub-command is checked
individually.

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md): requirements, build steps, hook registration
- [docs/USAGE.md](docs/USAGE.md): CLI reference, input/output format, examples
- [docs/configuration-guide.md](docs/configuration-guide.md): rule syntax for each tool
- [docs/tool-input-schemas.md](docs/tool-input-schemas.md): Claude Code tool input JSON reference
- [docs/CHANGELOG.md](docs/CHANGELOG.md): chronological record of changes
- [example.toml](example.toml): starter config with deny/allow rules and variables

## Testing

```bash
cargo test
source source_me.sh && python3 -m pytest tests/test_hook.py -v
```

## License

GPLv3. See LICENSE file for details.

## Maintainer

Neil Voss, https://bsky.app/profile/neilvosslab.bsky.social
