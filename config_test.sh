#!/bin/sh


cargo build --release && cargo test

$HOME/nsh/claude-code-permissions-hook/target/release/claude-code-permissions-hook \
  validate \
  --config ~/.config/claude-code-permissions-hook.toml

echo ""
readlink $HOME/.config/claude-code-permissions-hook.toml
echo ""
