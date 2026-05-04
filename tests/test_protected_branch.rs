//! Integration tests for protected branch functionality.
//!
//! These tests create temporary git repositories and verify that the hook
//! correctly allows/denies git commands based on the current branch.

use std::path::{Path, PathBuf};
use std::process::Command;

use claude_code_permissions_hook::{
    Decision, HookInput, process_hook_input,
};
use tempfile::TempDir;

/// Helper to get the path to the protected branch test config
fn config_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("test_protected_branch_config.toml");
    path
}

/// Helper to get the path to the canonical example.toml config.
fn config_path_example() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("example.toml");
    path
}

/// Helper to write a custom TOML config to a temp file and return the path-owning TempDir.
fn write_temp_config(toml: &str) -> (TempDir, PathBuf) {
    let tmpdir = TempDir::new().expect("Failed to create temp dir");
    let cfg_path = tmpdir.path().join("config.toml");
    std::fs::write(&cfg_path, toml).expect("Failed to write temp config");
    (tmpdir, cfg_path)
}

/// Helper to create a temporary git repo with a given branch.
fn setup_git_repo(branch: &str) -> TempDir {
    let tmpdir = TempDir::new().expect("Failed to create temp dir");
    let repo_path = tmpdir.path();

    // Initialize git repo
    Command::new("git")
        .arg("init")
        .current_dir(repo_path)
        .output()
        .expect("Failed to init git repo");

    // Set git user config (required for commits)
    Command::new("git")
        .args(&["config", "user.email", "test@example.com"])
        .current_dir(repo_path)
        .output()
        .expect("Failed to set git email");

    Command::new("git")
        .args(&["config", "user.name", "Test User"])
        .current_dir(repo_path)
        .output()
        .expect("Failed to set git name");

    // Create initial commit on main
    let test_file = repo_path.join("test.txt");
    std::fs::write(&test_file, "initial").expect("Failed to write test file");

    Command::new("git")
        .args(&["add", "test.txt"])
        .current_dir(repo_path)
        .output()
        .expect("Failed to git add");

    Command::new("git")
        .args(&["commit", "-m", "initial"])
        .current_dir(repo_path)
        .output()
        .expect("Failed to create initial commit");

    // Switch to requested branch if not main
    if branch != "main" {
        Command::new("git")
            .args(&["checkout", "-b", branch])
            .current_dir(repo_path)
            .output()
            .expect("Failed to create branch");
    }

    tmpdir
}

/// Helper to create a test HookInput for a Bash command
fn create_input(command: &str, cwd: &Path) -> HookInput {
    HookInput {
        session_id: "test-session".to_string(),
        transcript_path: "/tmp/test-transcript".to_string(),
        cwd: cwd.to_string_lossy().to_string(),
        hook_event_name: "PreToolUse".to_string(),
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({"command": command}),
    }
}

#[test]
fn test_commit_denied_on_main() {
    let repo = setup_git_repo("main");
    let input = create_input("git commit -m x", repo.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_commit_allowed_on_agent_branch() {
    let repo = setup_git_repo("agent/foo");
    let input = create_input("git commit -m x", repo.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_commit_allowed_on_detached_head() {
    let repo = setup_git_repo("main");

    // Create detached HEAD
    Command::new("git")
        .args(&["checkout", "HEAD~0"])
        .current_dir(repo.path())
        .output()
        .expect("Failed to detach HEAD");

    let input = create_input("git commit -m x", repo.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_reset_hard_denied_on_main() {
    let repo = setup_git_repo("main");
    let input = create_input("git reset --hard HEAD~1", repo.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_reset_hard_allowed_on_agent_branch() {
    let repo = setup_git_repo("agent/foo");
    let input = create_input("git reset --hard HEAD~1", repo.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_merge_no_commit_allowed_on_protected() {
    let repo = setup_git_repo("main");
    let input = create_input("git merge --no-commit --no-ff agent/foo", repo.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow);
}

// --- Priority section-2 cases: branch-state and tightened merge-prepare allow ---

#[test]
fn test_config_override_to_trunk() {
    // Override defaults to protect "trunk" only. main should be allowed.
    let toml = r#"
[audit]
audit_file = "/tmp/test-audit.json"

[git_protection]
protected_branches = ["trunk"]

[[deny]]
tool = "Bash"
command_regex = ".*\\bgit\\b.*\\bcommit\\b"
reason = "Commits denied on protected branches"
protected_branch_check = true

[[allow]]
tool = "Bash"
command_regex = ".*\\bgit\\b.*\\bcommit\\b"
"#;
    let (_keep, cfg) = write_temp_config(toml);

    let main_repo = setup_git_repo("main");
    let input = create_input("git commit -m x", main_repo.path());
    let result = process_hook_input(&cfg, &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow, "main not protected when override is trunk");

    let trunk_repo = setup_git_repo("trunk");
    let input = create_input("git commit -m x", trunk_repo.path());
    let result = process_hook_input(&cfg, &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny, "trunk is protected by override");
}

#[test]
fn test_rev_parse_fails_fail_closes() {
    // cwd is not a git repo; branch lookup fails; protected_branch_check rule must fire (deny).
    let tmpdir = TempDir::new().expect("Failed to create temp dir");
    let input = create_input("git commit -m x", tmpdir.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny, "fail-closed when not a git repo");
}

#[test]
fn test_dash_c_other_repo_on_main_denies() {
    // Hook cwd is on agent/foo, but `git -C <main-repo> commit` should deny based on the -C target.
    let agent_repo = setup_git_repo("agent/foo");
    let main_repo = setup_git_repo("main");
    let cmd = format!("git -C {} commit -m x", main_repo.path().display());
    let input = create_input(&cmd, agent_repo.path());
    let result = process_hook_input(&config_path(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny, "-C target's branch is what the rule checks");
}

#[test]
fn test_raw_merge_on_main_denies() {
    // Raw `git merge agent/foo` (no --no-commit) on main must deny.
    let repo = setup_git_repo("main");
    let input = create_input("git merge agent/foo", repo.path());
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_merge_no_commit_no_ff_protected_source_denies() {
    // Source branch is itself protected (`main`); allow rule must reject it.
    let repo = setup_git_repo("main");
    let input = create_input("git merge --no-commit --no-ff main", repo.path());
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_merge_no_commit_no_ff_with_dash_m_denies() {
    // -m on the merge-prepare command is rejected even with --no-commit --no-ff.
    let repo = setup_git_repo("main");
    let input = create_input(
        r#"git merge --no-commit --no-ff -m "msg" agent/foo"#,
        repo.path(),
    );
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_merge_continue_on_main_denies() {
    let repo = setup_git_repo("main");
    let input = create_input("git merge --continue", repo.path());
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_merge_abort_on_main_allows() {
    let repo = setup_git_repo("main");
    let input = create_input("git merge --abort", repo.path());
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow);
}

// --- Boundary tests for the merge-prepare allow rule ---

#[test]
fn test_merge_no_ff_alone_denies() {
    // Missing --no-commit; falls through to raw-merge deny on protected.
    let repo = setup_git_repo("main");
    let input = create_input("git merge --no-ff agent/foo", repo.path());
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_merge_no_commit_alone_denies() {
    // Missing --no-ff; falls through to raw-merge deny on protected.
    let repo = setup_git_repo("main");
    let input = create_input("git merge --no-commit agent/foo", repo.path());
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Deny);
}

#[test]
fn test_merge_prepare_allowed_on_feature_branch() {
    // On a feature branch the prepare command is also fine -- no protected check fires.
    let repo = setup_git_repo("agent/foo");
    let input = create_input("git merge --no-commit --no-ff agent/bar", repo.path());
    let result = process_hook_input(&config_path_example(), &input).expect("Processing should succeed");
    assert_eq!(result.decision, Decision::Allow);
}

