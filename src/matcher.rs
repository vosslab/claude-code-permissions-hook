#![forbid(unsafe_code)]
#![warn(clippy::all)]

use crate::config::Rule;
use crate::hook_io::HookInput;
use log::{debug, trace};

/// Checks rules against input, returning the reason if a rule matches.
pub fn check_rules(rules: &[Rule], input: &HookInput) -> Option<String> {
    trace!(
        "Checking {} rules for tool: {}",
        rules.len(),
        input.tool_name
    );

    for (idx, rule) in rules.iter().enumerate() {
        // Match tool name: use tool_regex if present, otherwise exact match
        let tool_matches = if let Some(ref regex) = rule.tool_regex {
            regex.is_match(&input.tool_name)
        } else {
            rule.tool == input.tool_name
        };
        if !tool_matches {
            trace!("Rule {} skipped - tool mismatch", idx);
            continue;
        }

        trace!("Evaluating rule {} for tool: {}", idx, input.tool_name);
        if let Some(auto_reason) = check_rule(rule, input) {
            // Custom reason is prepended; auto-generated reason with the
            // actual command/path is always appended for specificity.
            let reason = match &rule.reason {
                Some(custom) => format!("{} ({})", custom, auto_reason),
                None => auto_reason,
            };
            debug!("Rule {} matched: {:?}", idx, reason);
            return Some(reason);
        }
    }
    trace!("No rules matched for tool: {}", input.tool_name);
    None
}

/// Check if a rule is tool-only (no regex or subagent fields set).
/// Such rules match any input for the given tool name.
fn is_tool_only_rule(rule: &Rule) -> bool {
    rule.file_path_regex.is_none()
        && rule.file_path_exclude_regex.is_none()
        && rule.command_regex.is_none()
        && rule.command_exclude_regex.is_none()
        && rule.subagent_type.is_none()
        && rule.subagent_type_regex.is_none()
        && rule.subagent_type_exclude_regex.is_none()
        && rule.prompt_regex.is_none()
        && rule.prompt_exclude_regex.is_none()
}

fn check_rule(rule: &Rule, input: &HookInput) -> Option<String> {
    // Tool-only rules (e.g. [[allow]] tool = "WebFetch") match any input for that tool
    if is_tool_only_rule(rule) {
        return Some(format!("Matched tool-only rule for {}", input.tool_name));
    }

    match input.tool_name.as_str() {
        "Read" | "Write" | "Edit" => {
            if let Some(file_path) = input.extract_field("file_path")
                && check_field_with_exclude(
                    &file_path,
                    &rule.file_path_regex,
                    &rule.file_path_exclude_regex,
                )
            {
                return Some(format!(
                    "Matched rule for {} with file_path: {}",
                    input.tool_name, file_path
                ));
            }
        }
        "Glob" | "Grep" => {
            // Glob and Grep use "path" field, not "file_path"
            if let Some(path) = input.extract_field("path")
                && check_field_with_exclude(
                    &path,
                    &rule.file_path_regex,
                    &rule.file_path_exclude_regex,
                )
            {
                return Some(format!(
                    "Matched rule for {} with path: {}",
                    input.tool_name, path
                ));
            }
        }
        "Bash" => {
            if let Some(command) = input.extract_field("command")
                && check_field_with_exclude(
                    &command,
                    &rule.command_regex,
                    &rule.command_exclude_regex,
                )
            {
                return Some(format!("Matched rule for Bash with command: {}", command));
            }
        }
        "Task" => {
            if let Some(subagent_type) = input.extract_field("subagent_type")
                && check_subagent_type(rule, &subagent_type)
            {
                return Some(format!(
                    "Matched rule for Task with subagent_type: {}",
                    subagent_type
                ));
            }
            if let Some(prompt) = input.extract_field("prompt")
                && check_field_with_exclude(&prompt, &rule.prompt_regex, &rule.prompt_exclude_regex)
            {
                return Some("Matched rule for Task with prompt pattern".to_string());
            }
        }
        _ => {}
    }

    None
}

fn check_field_with_exclude(
    value: &str,
    main_regex: &Option<regex::Regex>,
    exclude_regex: &Option<regex::Regex>,
) -> bool {
    if let Some(regex) = main_regex {
        if !regex.is_match(value) {
            trace!("Main regex didn't match value: {}", value);
            return false;
        }
        if let Some(exclude) = exclude_regex
            && exclude.is_match(value)
        {
            debug!(
                "Rule matched but EXCLUDED by exclude pattern. Value: {}",
                value
            );
            return false;
        }
        trace!("Field matched: {}", value);
        return true;
    }
    false
}

fn check_subagent_type(rule: &Rule, subagent_type: &str) -> bool {
    // Check exact match via subagent_type field
    if let Some(ref expected_type) = rule.subagent_type {
        if expected_type != subagent_type {
            trace!(
                "Subagent type didn't match. Expected: {}, got: {}",
                expected_type, subagent_type
            );
            return false;
        }
    // Check regex match via subagent_type_regex field
    } else if let Some(ref regex) = rule.subagent_type_regex {
        if !regex.is_match(subagent_type) {
            trace!(
                "Subagent type didn't match regex. Got: {}",
                subagent_type
            );
            return false;
        }
    } else {
        // No subagent_type or subagent_type_regex set
        return false;
    }

    // Check exclude pattern
    if let Some(ref exclude) = rule.subagent_type_exclude_regex
        && exclude.is_match(subagent_type)
    {
        debug!(
            "Subagent type matched but EXCLUDED by exclude pattern: {}",
            subagent_type
        );
        return false;
    }
    trace!("Subagent type matched: {}", subagent_type);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn test_check_field_with_exclude() {
        let main_regex = Some(Regex::new(r"^/home/.*").unwrap());
        let exclude_regex = Some(Regex::new(r"\.\.").unwrap());

        assert!(check_field_with_exclude(
            "/home/user/file.txt",
            &main_regex,
            &exclude_regex
        ));
        assert!(!check_field_with_exclude(
            "/home/user/../etc/passwd",
            &main_regex,
            &exclude_regex
        ));
        assert!(!check_field_with_exclude(
            "/etc/passwd",
            &main_regex,
            &exclude_regex
        ));
    }

    #[test]
    fn test_is_tool_only_rule() {
        let tool_only = Rule {
            tool: "WebFetch".to_string(),
            tool_regex: None,
            file_path_regex: None,
            file_path_exclude_regex: None,
            command_regex: None,
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: None,
        };
        assert!(is_tool_only_rule(&tool_only));
    }

    #[test]
    fn test_tool_only_with_regex_not_tool_only() {
        let with_regex = Rule {
            tool: "Bash".to_string(),
            tool_regex: None,
            file_path_regex: None,
            file_path_exclude_regex: None,
            command_regex: Some(Regex::new(r"^cargo").unwrap()),
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: None,
        };
        assert!(!is_tool_only_rule(&with_regex));
    }

    #[test]
    fn test_tool_only_rule_matches() {
        let rule = Rule {
            tool: "WebFetch".to_string(),
            tool_regex: None,
            file_path_regex: None,
            file_path_exclude_regex: None,
            command_regex: None,
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: None,
        };
        let input = HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/test".to_string(),
            cwd: "/home/user".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: "WebFetch".to_string(),
            tool_input: serde_json::json!({"url": "https://example.com"}),
        };
        let result = check_rule(&rule, &input);
        assert!(result.is_some());
        assert!(result.unwrap().contains("tool-only"));
    }

    #[test]
    fn test_glob_uses_path_field() {
        let rule = Rule {
            tool: "Glob".to_string(),
            tool_regex: None,
            file_path_regex: Some(Regex::new(r"^/home/user/").unwrap()),
            file_path_exclude_regex: None,
            command_regex: None,
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: None,
        };
        let input = HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/test".to_string(),
            cwd: "/home/user".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: "Glob".to_string(),
            tool_input: serde_json::json!({"path": "/home/user/project", "pattern": "*.rs"}),
        };
        let result = check_rule(&rule, &input);
        assert!(result.is_some());
        assert!(result.unwrap().contains("path:"));
    }

    #[test]
    fn test_grep_uses_path_field() {
        let rule = Rule {
            tool: "Grep".to_string(),
            tool_regex: None,
            file_path_regex: Some(Regex::new(r"^/home/user/").unwrap()),
            file_path_exclude_regex: None,
            command_regex: None,
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: None,
        };
        let input = HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/test".to_string(),
            cwd: "/home/user".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: "Grep".to_string(),
            tool_input: serde_json::json!({"path": "/home/user/project", "pattern": "fn main"}),
        };
        let result = check_rule(&rule, &input);
        assert!(result.is_some());
        assert!(result.unwrap().contains("path:"));
    }

    #[test]
    fn test_check_subagent_type() {
        let rule = Rule {
            tool: "Task".to_string(),
            tool_regex: None,
            file_path_regex: None,
            file_path_exclude_regex: None,
            command_regex: None,
            command_exclude_regex: None,
            subagent_type: Some("codebase-analyzer".to_string()),
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: None,
        };

        assert!(check_subagent_type(&rule, "codebase-analyzer"));
        assert!(!check_subagent_type(&rule, "other-agent"));
    }

    #[test]
    fn test_custom_reason_overrides_auto() {
        let rule = Rule {
            tool: "Bash".to_string(),
            tool_regex: None,
            file_path_regex: None,
            file_path_exclude_regex: None,
            command_regex: Some(Regex::new(r"\$PYTHON\b").unwrap()),
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: Some("Use python3 directly instead of $PYTHON".to_string()),
        };
        let input = HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/test".to_string(),
            cwd: "/home/user".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({"command": "$PYTHON foo.py"}),
        };
        let result = check_rules(&[rule], &input);
        assert!(result.is_some());
        let reason = result.unwrap();
        // Custom reason is prepended, auto-generated reason appended
        assert!(reason.starts_with("Use python3 directly instead of $PYTHON"));
        assert!(reason.contains("$PYTHON foo.py"));
    }

    #[test]
    fn test_no_custom_reason_uses_auto() {
        let rule = Rule {
            tool: "Bash".to_string(),
            tool_regex: None,
            file_path_regex: None,
            file_path_exclude_regex: None,
            command_regex: Some(Regex::new(r"^echo\b").unwrap()),
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
            reason: None,
        };
        let input = HookInput {
            session_id: "test".to_string(),
            transcript_path: "/tmp/test".to_string(),
            cwd: "/home/user".to_string(),
            hook_event_name: "PreToolUse".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({"command": "echo hello"}),
        };
        let result = check_rules(&[rule], &input);
        assert!(result.is_some());
        // Auto-generated reason should contain the command
        assert!(result.unwrap().contains("echo hello"));
    }
}
