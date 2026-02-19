//! Integration tests for the claude-code-permissions-hook library.
//!
//! These tests use the library's public API directly to test rule matching
//! logic without spawning a subprocess.

use std::path::PathBuf;

use claude_code_permissions_hook::{
    Decision, HookInput, HookResult, process_hook_input, validate_config,
};

/// Helper to get the path to the test config
fn config_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("test_config.toml");
    path
}

/// Helper to get the path to the example config
fn example_config_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("example.toml");
    path
}

/// Helper to get path to a test JSON file
fn test_json_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push(name);
    path
}

/// Load a test JSON file and parse it as HookInput
fn load_test_input(filename: &str) -> HookInput {
    let json = std::fs::read_to_string(test_json_path(filename))
        .unwrap_or_else(|_| panic!("Failed to read test file: {}", filename));
    serde_json::from_str(&json)
        .unwrap_or_else(|_| panic!("Failed to parse test file: {}", filename))
}

#[test]
fn test_read_allowed() {
    let input = load_test_input("read_allowed.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Read within allowed path should be allowed"
    );
    assert!(
        result.reason.is_some(),
        "Allow decision should have a reason"
    );
}

#[test]
fn test_read_path_traversal_denied() {
    let input = load_test_input("read_path_traversal.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Deny,
        "Path traversal should be denied"
    );
    assert!(
        result.reason.is_some(),
        "Deny decision should have a reason"
    );
}

#[test]
fn test_bash_injection_denied() {
    let input = load_test_input("bash_injection.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Deny,
        "Shell injection attempt should be denied"
    );
    assert!(
        result.reason.is_some(),
        "Deny decision should have a reason"
    );
}

#[test]
fn test_bash_allowed() {
    let input = load_test_input("bash_allowed.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "cargo test should be allowed"
    );
    assert!(
        result.reason.is_some(),
        "Allow decision should have a reason"
    );
}

#[test]
fn test_unknown_tool_passthrough() {
    let input = load_test_input("unknown_tool.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Passthrough,
        "Unknown tool should passthrough"
    );
    assert!(
        result.reason.is_none(),
        "Passthrough should not have a reason"
    );
}

#[test]
fn test_validate_example_config() {
    let result = validate_config(&example_config_path());
    assert!(result.is_ok(), "Example config should be valid");

    let (deny_count, allow_count) = result.unwrap();
    assert!(deny_count > 0, "Example config should have deny rules");
    assert!(allow_count > 0, "Example config should have allow rules");
}

#[test]
fn test_validate_test_config() {
    let result = validate_config(&config_path());
    assert!(result.is_ok(), "Test config should be valid");

    let (deny_count, allow_count) = result.unwrap();
    assert!(deny_count > 0, "Test config should have deny rules");
    assert!(allow_count > 0, "Test config should have allow rules");
}

// --- Decomposer integration tests ---

#[test]
fn test_decomposer_safe_compound_allowed() {
    // echo hi && echo bye: both sub-commands are safe utilities
    let input = HookInput {
        session_id: "test".to_string(),
        transcript_path: "/tmp/test".to_string(),
        cwd: "/home/user".to_string(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({"command": "echo hi && echo bye"}),
    };
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow, "Safe compound should be allowed");
}

#[test]
fn test_decomposer_dangerous_sub_command_denied() {
    // echo ok && rm file: rm sub-command triggers deny
    let input = HookInput {
        session_id: "test".to_string(),
        transcript_path: "/tmp/test".to_string(),
        cwd: "/home/user".to_string(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({"command": "echo ok && rm -rf /tmp"}),
    };
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny, "rm in compound should be denied");
}

#[test]
fn test_decomposer_mixed_passthrough() {
    // echo ok && python3 script: python3 is not in allow rules
    let input = HookInput {
        session_id: "test".to_string(),
        transcript_path: "/tmp/test".to_string(),
        cwd: "/home/user".to_string(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({"command": "echo ok && python3 script.py"}),
    };
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(
        result.decision,
        Decision::Passthrough,
        "Mixed safe + unknown should passthrough"
    );
}

#[test]
fn test_decomposer_for_loop_safe_body() {
    // for loop with safe body commands
    let input = HookInput {
        session_id: "test".to_string(),
        transcript_path: "/tmp/test".to_string(),
        cwd: "/home/user".to_string(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({"command": "for f in *.py; do echo $f; done"}),
    };
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(
        result.decision,
        Decision::Allow,
        "For loop with safe body should be allowed"
    );
}

#[test]
fn test_decomposer_for_loop_dangerous_body() {
    // for loop with rm in body
    let input = HookInput {
        session_id: "test".to_string(),
        transcript_path: "/tmp/test".to_string(),
        cwd: "/home/user".to_string(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({"command": "for f in *.tmp; do rm $f; done"}),
    };
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(
        result.decision,
        Decision::Deny,
        "For loop with rm in body should be denied"
    );
}

// --- New fixture tests for compound commands, tool-only, Glob/Grep, Edit ---

#[test]
fn test_bash_echo_simple_allowed() {
    let input = load_test_input("bash_echo_simple.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Simple echo should be allowed by utilities rule"
    );
}

#[test]
fn test_bash_compound_and_allowed() {
    let input = load_test_input("bash_compound_and.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Safe compound command (echo && echo) should be allowed"
    );
}

#[test]
fn test_bash_compound_or_allowed() {
    let input = load_test_input("bash_compound_or.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Safe compound command (echo || echo) should be allowed"
    );
}

#[test]
fn test_bash_rm_chained_denied() {
    let input = load_test_input("bash_rm_chained.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Deny,
        "Chained rm command should be denied by \\brm\\b deny rule"
    );
}

#[test]
fn test_bash_for_loop_allowed() {
    let input = load_test_input("bash_for_loop.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "For loop should be allowed (for is in utilities list)"
    );
}

#[test]
fn test_bash_while_loop_allowed() {
    let input = load_test_input("bash_while_loop.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    // Both 'true' and 'sleep' are in SAFE_CMDS, so decomposed leaves are all allowed
    assert_eq!(
        result.decision,
        Decision::Allow,
        "While loop with safe body should be allowed"
    );
}

#[test]
fn test_webfetch_tool_only_allowed() {
    let input = load_test_input("webfetch_allowed.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "WebFetch should be allowed by tool-only rule"
    );
    assert!(
        result
            .reason
            .as_ref()
            .unwrap()
            .contains("tool-only"),
        "Reason should mention tool-only: {:?}",
        result.reason
    );
}

#[test]
fn test_glob_allowed_path() {
    let input = load_test_input("glob_allowed.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Glob within allowed path should be allowed"
    );
    assert!(
        result
            .reason
            .as_ref()
            .unwrap()
            .contains("path:"),
        "Reason should mention path field: {:?}",
        result.reason
    );
}

#[test]
fn test_grep_allowed_path() {
    let input = load_test_input("grep_allowed.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Grep within allowed path should be allowed"
    );
    assert!(
        result
            .reason
            .as_ref()
            .unwrap()
            .contains("path:"),
        "Reason should mention path field: {:?}",
        result.reason
    );
}

#[test]
fn test_edit_allowed_path() {
    let input = load_test_input("edit_allowed.json");
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");

    assert_eq!(
        result.decision,
        Decision::Allow,
        "Edit within allowed path should be allowed"
    );
}

#[test]
fn test_hook_result_constructors() {
    let allow = HookResult::allow("test reason".to_string());
    assert_eq!(allow.decision, Decision::Allow);
    assert_eq!(allow.reason, Some("test reason".to_string()));

    let deny = HookResult::deny("denied".to_string());
    assert_eq!(deny.decision, Decision::Deny);
    assert_eq!(deny.reason, Some("denied".to_string()));

    let passthrough = HookResult::passthrough();
    assert_eq!(passthrough.decision, Decision::Passthrough);
    assert_eq!(passthrough.reason, None);
}
