#![forbid(unsafe_code)]
#![warn(clippy::all)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Debug, Deserialize)]
pub struct HookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
    #[serde(rename = "suppressOutput")]
    pub suppress_output: bool,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl HookInput {
    pub fn read_from_stdin() -> Result<Self> {
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("Failed to read from stdin")?;

        let input: HookInput =
            serde_json::from_str(&buffer).context("Failed to parse JSON from stdin")?;

        Ok(input)
    }

    pub fn extract_field(&self, field_name: &str) -> Option<String> {
        self.tool_input
            .get(field_name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Create a copy of this input with only the "command" field replaced.
    ///
    /// Used by the decomposer to create synthetic inputs for each
    /// sub-command extracted from a compound Bash command.
    pub fn with_command(&self, command: &str) -> Self {
        let mut tool_input = serde_json::Map::new();
        tool_input.insert(
            "command".to_string(),
            serde_json::Value::String(command.to_string()),
        );
        HookInput {
            session_id: self.session_id.clone(),
            transcript_path: self.transcript_path.clone(),
            cwd: self.cwd.clone(),
            hook_event_name: self.hook_event_name.clone(),
            tool_name: self.tool_name.clone(),
            tool_input: serde_json::Value::Object(tool_input),
        }
    }
}

impl HookOutput {
    pub fn allow(reason: String) -> Self {
        HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: reason,
            },
            suppress_output: true,
        }
    }

    pub fn deny(reason: String) -> Self {
        HookOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: reason,
            },
            suppress_output: true,
        }
    }

    pub fn write_to_stdout(&self) -> Result<()> {
        let json = serde_json::to_string(self).context("Failed to serialize output to JSON")?;
        io::stdout()
            .write_all(json.as_bytes())
            .context("Failed to write to stdout")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_extract_field() {
        let input = HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/test".to_string(),
            cwd: "/home/user".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: "Read".to_string(),
            tool_input: serde_json::json!({
                "file_path": "/home/user/test.txt"
            }),
        };

        assert_eq!(
            input.extract_field("file_path"),
            Some("/home/user/test.txt".to_string())
        );
        assert_eq!(input.extract_field("nonexistent"), None);
    }

    #[test]
    fn test_hook_output_serialization() -> Result<()> {
        let output = HookOutput::allow("Test reason".to_string());
        let json = serde_json::to_value(&output)?;

        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "Test reason"
        );
        assert_eq!(json["suppressOutput"], true);

        Ok(())
    }
}
