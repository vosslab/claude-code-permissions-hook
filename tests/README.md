# Test Directory

This directory contains the integration tests and decision-table corpus for the
command permissions hook.

## Structure

- `integration_test.rs` - Rust integration tests for the library's public API:
  config validation, decomposer compound/loop behavior, and `HookResult`
  constructors
- `test_config.toml` - Synthetic configuration used by the Rust integration
  tests and by the path-zone-specific rows in `command_decisions.tsv`. Its
  Read/Write/Edit/Glob/Grep allow zone is the `/tmp/cck-test/` tree, which the
  decision-table runner materializes before evaluating.
- `command_decisions.tsv` - Decision-table regression corpus (allow / deny /
  passthrough per tool input) covering Bash and non-Bash tools. This corpus is
  the authoritative allow/deny/passthrough coverage and supersedes the older
  per-case JSON hook-input fixtures.
- `command_decisions.tsv` is run by [run_command_decisions.py](../tools/run_command_decisions.py); the runner lives in `tools/` since it is operational tooling, not a pytest file

## Running Tests

```bash
cargo test                                                # Rust tests
source source_me.sh && python3 tools/run_command_decisions.py
                                                          # decision-table
                                                          # regression
source source_me.sh && python3 -m pytest tests/           # Python lint +
                                                          # TOML invariants
```

To run only the Rust integration tests:

```bash
cargo test --test integration_test
```

## Test Configuration

`test_config.toml` is a stripped-down synthetic config with rules that match the
path-zone-specific rows in `command_decisions.tsv`. It is separate from
`example.toml` in the project root, which demonstrates a real-world
configuration.
