# Install

Rust CLI binary that runs as a Claude Code PreToolUse hook. "Installed" means the compiled binary lives on your system and Claude Code is configured to invoke it on every tool call.

This guide walks novice terminal users through every step. Copy each command block as-is.

## Requirements

- **macOS or Linux** - uses `nix` crate for file locking (`flock`).
- **Rust toolchain** (stable) - provides `cargo` and `rustc`.
- **Git** - to clone this repository.
- **Claude Code** - Anthropic CLI tool that fires the hook ([install instructions](https://docs.claude.com/en/docs/claude-code)).

### Development requirements (optional)

Only needed if you plan to run the test suite or contribute changes:

- **Python 3.12** - for the decision-table runner ([tools/run_command_decisions.py](../tools/run_command_decisions.py)) and the pytest lint gates (pyflakes, ascii, shebangs, imports).
- **pip packages** in [pip_requirements-dev.txt](../pip_requirements-dev.txt): `bandit`, `packaging`, `pyflakes`, `pytest`, `rich`.

## Step 1: clone the repository

Open Terminal and run:

```bash
git clone https://github.com/vosslab/claude-code-permissions-hook.git
cd claude-code-permissions-hook
```

Every command below assumes you are in the `claude-code-permissions-hook` folder.

## Step 2: install dependencies

### macOS (recommended path, uses Homebrew)

Install [Homebrew](https://brew.sh/) first if you do not have it, then run:

```bash
brew bundle
```

This reads the repo [Brewfile](../Brewfile) and installs `rustup` plus `python@3.12`.

Initialize the Rust toolchain (one-time):

```bash
rustup-init -y
source "$HOME/.cargo/env"
```

The `source` line puts `cargo` on your PATH for the current shell. New terminals pick it up automatically.

### Linux (or macOS without Homebrew)

Install Rust via the official one-liner from [rustup.rs](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Install Python 3.12 from your distro package manager if you want the dev test suite (`apt install python3.12`, `dnf install python3.12`, etc.).

### Confirm Rust is ready

```bash
cargo --version
rustc --version
```

Both commands should print a version number. If either says "command not found", reopen the terminal and try again.

## Step 3: build the binary

```bash
cargo build --release
```

First build downloads dependencies and takes a few minutes. The compiled binary lands at:

```
target/release/claude-code-permissions-hook
```

Print its absolute path (you will need it in step 5):

```bash
echo "$(pwd)/target/release/claude-code-permissions-hook"
```

Copy the printed path.

## Step 4: create a config file

Copy the bundled [example.toml](../example.toml) and edit to taste:

```bash
cp example.toml my-config.toml
```

`my-config.toml` is the file the hook will read. See [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) for rule syntax. The example is safe to use unchanged for a first run.

Print its absolute path (also needed in step 5):

```bash
echo "$(pwd)/my-config.toml"
```

## Step 5: register the hook with Claude Code

Claude Code reads hooks from `~/.claude/settings.json` (global) or `<project>/.claude/settings.json` (per-project). Global is easiest for novice users.

Open the file in your editor (creates it if missing):

```bash
mkdir -p ~/.claude
open ~/.claude/settings.json    # macOS
# or: nano ~/.claude/settings.json
```

Paste this block, replacing the two `/ABSOLUTE/PATH/TO/...` lines with the paths you printed in steps 3 and 4:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/ABSOLUTE/PATH/TO/claude-code-permissions-hook run --config /ABSOLUTE/PATH/TO/my-config.toml"
          }
        ]
      }
    ]
  }
}
```

Save and close. Restart Claude Code so it picks up the new hook.

## Step 6: verify install

Confirm the config compiles:

```bash
./target/release/claude-code-permissions-hook validate --config my-config.toml
```

Expected output (rule counts depend on which config you used):

```
Valid: loaded <total> rules (<deny> deny, <allow> allow)
  Audit file:  /tmp/claude-tool-use.json
  Audit level: Matched
```

If you see `Valid:` on the first line, the hook is ready. Open Claude Code and try a command -- the hook now intercepts every tool call.

## Updating later

Refresh the Rust toolchain with [update_rust.sh](../update_rust.sh):

```bash
./update_rust.sh
```

Upgrades `rustup` via Homebrew, runs `rustup update`, prints versions. After a `git pull` of new repo changes, rerun `cargo build --release` to rebuild the binary.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `cargo: command not found` | Run `source "$HOME/.cargo/env"` or open a new terminal. |
| `brew: command not found` (macOS) | Install Homebrew first ([brew.sh](https://brew.sh/)). |
| `validate` reports parse errors | Check the line number it prints; edit `my-config.toml`. |
| Claude Code does not run the hook | Confirm absolute paths in `settings.json`; restart Claude Code. |
| Linux build fails on `nix` crate | Make sure `build-essential` (or distro equivalent) is installed. |

## Known gaps

- [ ] Verify whether the `nix` crate `flock` works on all Linux distributions.
- [ ] Confirm minimum supported Rust version (MSRV); currently uses `edition = "2024"`.
- [ ] Confirm exact macOS and Linux versions tested (only "macOS or Linux" stated above).
