#![forbid(unsafe_code)]
#![warn(clippy::all)]

//! Hardcoded path-existence pre-check for read-side tools.
//!
//! Runs before TOML allow/deny rules. Converts "hallucinated path"
//! events from passthrough stalls into immediate denies with
//! tool-specific reason strings.
//!
//! Semantics:
//! - Read: file_path must resolve to an existing non-directory target
//!   (symlinks-to-files OK; directories and broken symlinks denied).
//! - Edit / MultiEdit: file_path exists, OR its parent directory exists.
//! - Glob: resolved path must exist as a directory.
//! - Grep: resolved path must exist; if absent the cwd fallback is trusted.
//! - All other tools (including Write): skipped.
//!
//! Distinguishes `Err(NotFound)` (path confirmed missing) from other
//! `Err(_)` variants (could not stat -- emits a "could not confirm"
//! message instead of "does not exist").

use crate::hook_io::HookInput;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Apply tool-specific existence checks. Returns Some(deny_reason) when
/// the call should be denied at the pre-check stage; returns None when
/// the regular TOML allow/deny rules should continue to evaluate.
pub fn check_path_exists(input: &HookInput) -> Option<String> {
    match input.tool_name.as_str() {
        "Read" => check_read(input),
        "Edit" | "MultiEdit" => check_edit(input),
        "Glob" => check_glob(input),
        "Grep" => check_grep(input),
        // All other tools (Write, Bash, Task, WebFetch, etc.) skip the pre-check.
        _ => None,
    }
}

/// Absolutize a path against the hook's cwd if relative.
fn absolutize(raw: &str, cwd: &str) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(cwd).join(raw)
    }
}

/// Read: file_path must exist and not be a directory.
fn check_read(input: &HookInput) -> Option<String> {
    // Read without file_path is malformed; let the regular matcher handle it.
    let raw = input.extract_field("file_path")?;
    let abs = absolutize(&raw, &input.cwd);
    match fs::metadata(&abs) {
        Ok(meta) => {
            if meta.is_dir() {
                // Directory passed to Read -- deny with a helpful steer.
                Some(format!(
                    "Read targets a file, not a directory. Use `ls <dir>` or \
                     `git ls-files <pathspec>` to list directory contents. \
                     Path is a directory: {}.",
                    abs.display()
                ))
            } else {
                // Regular file, symlink-to-file, FIFO, etc. -- allow through.
                None
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Some(format!(
            "Verify the file path before retrying. Read target does not exist: {}.",
            abs.display()
        )),
        Err(_) => Some(format!(
            "Verify the path before retrying. The hook could not confirm that this path exists: {}.",
            abs.display()
        )),
    }
}

/// Edit / MultiEdit: file exists OR parent directory exists.
fn check_edit(input: &HookInput) -> Option<String> {
    let raw = input.extract_field("file_path")?;
    let abs = absolutize(&raw, &input.cwd);
    match fs::metadata(&abs) {
        // File exists -- allow new content into existing file.
        Ok(_) => None,
        // File missing -- check parent to support new-file edits.
        Err(e) if e.kind() == ErrorKind::NotFound => check_edit_parent(&abs),
        // Stat failed for other reasons (permissions, etc.) -- be precise.
        Err(_) => Some(format!(
            "Verify the path before retrying. The hook could not confirm that this path exists: {}.",
            abs.display()
        )),
    }
}

/// Helper: when the Edit target is missing, decide based on the parent dir.
fn check_edit_parent(abs: &Path) -> Option<String> {
    // No parent component (root path or similar) -- treat as both-missing.
    let Some(parent) = abs.parent() else {
        return Some(format!(
            "Create the parent directory first or choose an existing path. \
             Edit target has no parent directory: {}.",
            abs.display()
        ));
    };
    match fs::metadata(parent) {
        // Parent exists -- legitimate new-file edit, allow through.
        Ok(_) => None,
        Err(e) if e.kind() == ErrorKind::NotFound => Some(format!(
            "Create the parent directory first or choose an existing path. \
             Edit target and parent directory are both missing: {}; parent: {}.",
            abs.display(),
            parent.display()
        )),
        Err(_) => Some(format!(
            "Verify the parent directory before retrying. \
             The hook could not confirm that this path's parent exists: {}; parent: {}.",
            abs.display(),
            parent.display()
        )),
    }
}

/// Glob: resolved path must exist as a directory.
fn check_glob(input: &HookInput) -> Option<String> {
    // Glob's path is optional; absent means "use cwd" (always a dir in practice).
    let raw = input.extract_field("path")?;
    let abs = absolutize(&raw, &input.cwd);
    match fs::metadata(&abs) {
        Ok(meta) if meta.is_dir() => None,
        Ok(_) => Some(format!(
            "Choose an existing search directory before retrying. \
             Glob path does not exist as a directory: {}.",
            abs.display()
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => Some(format!(
            "Choose an existing search directory before retrying. \
             Glob path does not exist as a directory: {}.",
            abs.display()
        )),
        Err(_) => Some(format!(
            "Verify the path before retrying. \
             The hook could not confirm that this directory exists: {}.",
            abs.display()
        )),
    }
}

/// Grep: resolved path must exist (as file or directory). Skipped when no
/// path field is present (cwd fallback).
fn check_grep(input: &HookInput) -> Option<String> {
    let raw = input.extract_field("path")?;
    let abs = absolutize(&raw, &input.cwd);
    match fs::metadata(&abs) {
        Ok(_) => None,
        Err(e) if e.kind() == ErrorKind::NotFound => Some(format!(
            "Choose an existing file or directory before retrying. \
             Grep path does not exist: {}.",
            abs.display()
        )),
        Err(_) => Some(format!(
            "Verify the path before retrying. \
             The hook could not confirm that this path exists: {}.",
            abs.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs as stdfs;
    use tempfile::TempDir;

    fn make_input(tool: &str, field: &str, path: &str, cwd: &str) -> HookInput {
        HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/transcript".to_string(),
            cwd: cwd.to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: tool.to_string(),
            tool_input: json!({ field: path }),
        }
    }

    fn make_input_no_field(tool: &str, cwd: &str) -> HookInput {
        HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/transcript".to_string(),
            cwd: cwd.to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: tool.to_string(),
            tool_input: json!({}),
        }
    }

    // ---------------- Read ----------------

    #[test]
    fn read_existing_file_allows() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("real.txt");
        stdfs::write(&f, b"hi").unwrap();
        let input = make_input("Read", "file_path", f.to_str().unwrap(), "/");
        assert_eq!(check_path_exists(&input), None);
    }

    #[test]
    fn read_missing_file_denies() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("ghost.txt");
        let input = make_input("Read", "file_path", f.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("should deny");
        assert!(reason.contains("does not exist"), "reason: {}", reason);
    }

    #[test]
    fn read_directory_denies() {
        let tmp = TempDir::new().unwrap();
        let input = make_input("Read", "file_path", tmp.path().to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("should deny");
        assert!(reason.contains("is a directory"), "reason: {}", reason);
    }

    #[test]
    fn read_missing_with_existing_parent_still_denies() {
        let tmp = TempDir::new().unwrap();
        // parent exists (tmp), file does not
        let f = tmp.path().join("nope.txt");
        let input = make_input("Read", "file_path", f.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("Read requires file, parent does not save it");
        assert!(reason.contains("does not exist"));
    }

    #[test]
    fn read_symlink_to_existing_file_allows() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target.txt");
        stdfs::write(&target, b"x").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let input = make_input("Read", "file_path", link.to_str().unwrap(), "/");
        assert_eq!(check_path_exists(&input), None);
    }

    #[test]
    fn read_symlink_to_missing_denies() {
        let tmp = TempDir::new().unwrap();
        let link = tmp.path().join("dangling");
        std::os::unix::fs::symlink(tmp.path().join("never"), &link).unwrap();
        let input = make_input("Read", "file_path", link.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("broken symlink should deny");
        assert!(reason.contains("does not exist"));
    }

    #[test]
    fn read_relative_path_absolutized_against_cwd() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("rel.txt");
        stdfs::write(&f, b"x").unwrap();
        let input = make_input("Read", "file_path", "rel.txt", tmp.path().to_str().unwrap());
        assert_eq!(check_path_exists(&input), None);
    }

    // ---------------- Edit ----------------

    #[test]
    fn edit_existing_file_allows() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("e.txt");
        stdfs::write(&f, b"x").unwrap();
        let input = make_input("Edit", "file_path", f.to_str().unwrap(), "/");
        assert_eq!(check_path_exists(&input), None);
    }

    #[test]
    fn edit_missing_file_existing_parent_allows() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("new.txt");
        let input = make_input("Edit", "file_path", f.to_str().unwrap(), "/");
        assert_eq!(
            check_path_exists(&input),
            None,
            "Edit should allow new files in existing dirs"
        );
    }

    #[test]
    fn edit_both_missing_denies() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("missing_dir").join("file.txt");
        let input = make_input("Edit", "file_path", f.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("both-missing should deny");
        assert!(reason.contains("both missing"), "reason: {}", reason);
    }

    #[test]
    fn multiedit_both_missing_denies() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("missing_dir").join("file.txt");
        let input = make_input("MultiEdit", "file_path", f.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("MultiEdit follows Edit semantics");
        assert!(reason.contains("both missing"));
    }

    // ---------------- Glob ----------------

    #[test]
    fn glob_existing_dir_allows() {
        let tmp = TempDir::new().unwrap();
        let input = make_input("Glob", "path", tmp.path().to_str().unwrap(), "/");
        assert_eq!(check_path_exists(&input), None);
    }

    #[test]
    fn glob_file_path_denies() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("not_a_dir.txt");
        stdfs::write(&f, b"x").unwrap();
        let input = make_input("Glob", "path", f.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("file passed where dir expected");
        assert!(reason.contains("does not exist as a directory"));
    }

    #[test]
    fn glob_missing_path_denies() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("nope");
        let input = make_input("Glob", "path", p.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("missing dir should deny");
        assert!(reason.contains("does not exist as a directory"));
    }

    #[test]
    fn glob_no_path_field_skips() {
        let tmp = TempDir::new().unwrap();
        let input = make_input_no_field("Glob", tmp.path().to_str().unwrap());
        assert_eq!(check_path_exists(&input), None);
    }

    // ---------------- Grep ----------------

    #[test]
    fn grep_existing_file_allows() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("g.txt");
        stdfs::write(&f, b"x").unwrap();
        let input = make_input("Grep", "path", f.to_str().unwrap(), "/");
        assert_eq!(check_path_exists(&input), None);
    }

    #[test]
    fn grep_existing_dir_allows() {
        let tmp = TempDir::new().unwrap();
        let input = make_input("Grep", "path", tmp.path().to_str().unwrap(), "/");
        assert_eq!(check_path_exists(&input), None);
    }

    #[test]
    fn grep_missing_path_denies() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("nope");
        let input = make_input("Grep", "path", p.to_str().unwrap(), "/");
        let reason = check_path_exists(&input).expect("missing grep target");
        assert!(reason.contains("does not exist"));
    }

    #[test]
    fn grep_no_path_field_skips() {
        let tmp = TempDir::new().unwrap();
        let input = make_input_no_field("Grep", tmp.path().to_str().unwrap());
        assert_eq!(check_path_exists(&input), None);
    }

    // ---------------- Write / other tools ----------------

    #[test]
    fn write_missing_skips() {
        let tmp = TempDir::new().unwrap();
        let f = tmp.path().join("ghost_dir").join("file.txt");
        let input = make_input("Write", "file_path", f.to_str().unwrap(), "/");
        assert_eq!(
            check_path_exists(&input),
            None,
            "Write is exempt -- creates new files"
        );
    }

    #[test]
    fn bash_skips() {
        let input = make_input("Bash", "command", "echo hi", "/");
        assert_eq!(check_path_exists(&input), None);
    }
}
