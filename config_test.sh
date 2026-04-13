#!/bin/sh
set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
BIN="$REPO_ROOT/target/release/claude-code-permissions-hook"

cargo build --release
cargo test

"$BIN" validate --config ~/.config/claude-code-permissions-hook.toml

echo ""
readlink "$HOME/.config/claude-code-permissions-hook.toml"
echo ""

# Keep only the release binary; drop ~662M of build scratch.
rm -rf \
  "$REPO_ROOT/target/debug" \
  "$REPO_ROOT/target/release/deps" \
  "$REPO_ROOT/target/release/build" \
  "$REPO_ROOT/target/release/incremental" \
  "$REPO_ROOT/target/release/examples" \
  "$REPO_ROOT/target/release/libclaude_code_permissions_hook.rlib" \
  "$REPO_ROOT/target/release/libclaude_code_permissions_hook.d" \
  "$REPO_ROOT/target/release/claude-code-permissions-hook.d" \
  "$REPO_ROOT/target/tmp"

du -sh "$REPO_ROOT/target"
