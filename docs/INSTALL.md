# Install

A Rust CLI binary that runs as a Claude Code PreToolUse hook.
"Installed" means the compiled binary is available on your system and
Claude Code is configured to invoke it.

## Requirements

- **Rust toolchain** (stable) - install via [rustup](https://rustup.rs/)
- **Claude Code** - the Anthropic CLI tool that fires PreToolUse hooks
- **macOS or Linux** - uses `nix` crate for file locking (`flock`)

### Development requirements (optional)

- **Python 3.12** - for the pytest integration test suite
- **pip packages** listed in [pip_requirements-dev.txt](../pip_requirements-dev.txt):
  bandit, packaging, pyflakes, pytest, rich

## Install steps

1. Clone the repository:

```bash
git clone <repo-url>
cd claude-code-permissions-hook
```

2. Build the release binary:

```bash
cargo build --release
```

The binary is at `target/release/claude-code-permissions-hook`.

3. Create a TOML config file.
   Copy [example.toml](../example.toml) as a starting point and edit
   paths and rules to match your environment.
   See [docs/configuration-guide.md](configuration-guide.md) for rule syntax.

4. Register the hook in `.claude/settings.json`:

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

Replace `/path/to/` with the actual paths to the binary and config file.

## Verify install

Validate the config file compiles without errors:

```bash
./target/release/claude-code-permissions-hook validate --config example.toml
```

Expected output (with `RUST_LOG=info`):

```
[INFO] Configuration is valid!
[INFO]   Deny rules: 3
[INFO]   Allow rules: 7
[INFO]   Audit file: /tmp/claude-tool-use.json
[INFO]   Audit level: Matched
```

## Known gaps

- [ ] Verify whether the `nix` crate `flock` works on all Linux distributions.
- [ ] Confirm minimum supported Rust version (MSRV); currently uses `edition = "2024"`.
