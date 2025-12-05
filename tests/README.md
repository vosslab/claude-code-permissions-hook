# Test Directory

This directory contains integration tests and test fixtures for the command permissions hook.

## Structure

- `integration_test.rs` - Rust integration tests that test the library's public API
- `test_config.toml` - Configuration file designed for the test fixtures
- `*.json` - Test fixture files with sample hook inputs

## Running Tests

```bash
cargo test
```

To run only the integration tests:

```bash
cargo test --test integration_test
```

## Test Fixtures

The JSON files are sample hook inputs used by the integration tests:

| File | Description | Expected Result |
|------|-------------|-----------------|
| `read_allowed.json` | Read within allowed path | Allow |
| `read_path_traversal.json` | Read with `../` in path | Deny |
| `bash_allowed.json` | Safe `cargo test` command | Allow |
| `bash_injection.json` | Command with `&&` injection | Deny |
| `unknown_tool.json` | Unrecognized tool name | Passthrough |

## Test Configuration

The tests use `test_config.toml` which has rules matching the test fixtures. This is separate from `example.toml` in the project root, which demonstrates a real-world configuration.
