#![forbid(unsafe_code)]
#![warn(clippy::all)]

use crate::config::AuditLevel;
use crate::hook_io::HookInput;
use chrono::{DateTime, Utc};
use log::warn;
use nix::fcntl::{Flock, FlockArg};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// The outcome of permission checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    Passthrough,
}

/// Maximum length for tool_input in audit entries (in characters when serialized).
const MAX_TOOL_INPUT_LEN: usize = 1024;

#[derive(Debug, Serialize)]
struct AuditEntry {
    timestamp: DateTime<Utc>,
    session_id: String,
    tool_name: String,
    tool_input: serde_json::Value,
    decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    cwd: String,
}

/// Truncate tool_input if its serialized form exceeds `MAX_TOOL_INPUT_LEN` characters.
fn truncate_tool_input(input: &serde_json::Value) -> serde_json::Value {
    let serialized = serde_json::to_string(input).unwrap_or_default();
    if serialized.len() <= MAX_TOOL_INPUT_LEN {
        input.clone()
    } else {
        let truncated: String = serialized.chars().take(MAX_TOOL_INPUT_LEN).collect();
        serde_json::Value::String(truncated + "…")
    }
}

/// Write tool use to the audit file, respecting the configured audit level.
pub fn audit_tool_use(
    audit_path: &Path,
    audit_level: AuditLevel,
    input: &HookInput,
    decision: Decision,
    reason: Option<&str>,
) {
    let should_audit = match audit_level {
        AuditLevel::Off => false,
        AuditLevel::Matched => decision != Decision::Passthrough,
        AuditLevel::All => true,
    };

    if !should_audit {
        return;
    }

    if let Err(e) = try_audit_tool_use(audit_path, input, decision, reason) {
        warn!("Failed to write audit entry: {}", e);
    }
}

fn try_audit_tool_use(
    audit_path: &Path,
    input: &HookInput,
    decision: Decision,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let entry = AuditEntry {
        timestamp: Utc::now(),
        session_id: input.session_id.clone(),
        tool_name: input.tool_name.clone(),
        tool_input: truncate_tool_input(&input.tool_input),
        decision,
        reason: reason.map(String::from),
        cwd: input.cwd.clone(),
    };

    let json_line = serde_json::to_string(&entry)?;

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)?;

    let mut flock = Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, e)| e)?;

    writeln!(flock, "{}", json_line)?;

    flock.unlock().map_err(|(_, e)| e)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_truncate_tool_input_short() {
        let input = json!({"file_path": "/some/short/path.rs"});
        let result = truncate_tool_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_truncate_tool_input_long() {
        let long_content = "x".repeat(2000);
        let input = json!({"content": long_content});
        let result = truncate_tool_input(&input);

        let truncated = result.as_str().unwrap();
        assert!(truncated.ends_with('…'));
        // 1024 chars + ellipsis
        assert_eq!(truncated.chars().count(), MAX_TOOL_INPUT_LEN + 1);
    }
}
