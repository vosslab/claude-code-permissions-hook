# Test Directory

This directory contains integration tests and test fixtures for the command permissions hook.

## Structure

- `integration_test.rs` - Rust integration tests that test the library's public API
- `test_config.toml` - Synthetic configuration used by the Rust integration tests
  and by a small subset of `command_decisions.tsv` rows that need its
  `/Users/korny/Dropbox/prj/` path-zone setup
- `command_decisions.tsv` - Decision-table regression corpus (allow / deny /
  passthrough per tool input) covering Bash and non-Bash tools
- `command_decisions.tsv` is run by [tools/run_command_decisions.py](../tools/run_command_decisions.py); the runner lives in `tools/` since it is operational tooling, not a pytest file
- `*.json` - Test fixture files used by `integration_test.rs`

## Running Tests

```bash
cargo test                                                # Rust tests
source source_me.sh && python3 tools/run_command_decisions.py
                                                          # decision-table
                                                          # regression
source source_me.sh && python3 -m pytest tests/           # Python lint gates
```

To run only the Rust integration tests:

```bash
cargo test --test integration_test
```

## Test Fixtures

The JSON files are sample hook inputs used by `integration_test.rs`:

| File | Description | Expected Result |
|------|-------------|-----------------|
| `read_allowed.json` | Read within allowed path | Allow |
| `read_path_traversal.json` | Read with `../` in path | Deny |
| `bash_allowed.json` | Safe `cargo test` command | Allow |
| `bash_injection.json` | Command with `&&` injection | Deny |
| `unknown_tool.json` | Unrecognized tool name | Passthrough |

## Test Configuration

`test_config.toml` is a stripped-down synthetic config with rules that match
the JSON fixtures and the path-zone-specific rows in
`command_decisions.tsv`. It is separate from `example.toml` in the project
root, which demonstrates a real-world configuration.
