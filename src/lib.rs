#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![warn(rust_2018_idioms)]
#![warn(rust_2024_compatibility)]
#![warn(deprecated_safe)]

//! Claude Code command permissions hook library.
//!
//! This library provides the core logic for evaluating tool use permissions
//! based on configurable allow/deny rules with regex pattern matching.

pub mod auditing;
pub mod config;
pub mod decomposer;
pub mod hook_io;
pub mod matcher;

use anyhow::{Context, Result};
use std::path::Path;

pub use auditing::Decision;
pub use config::{Config, Rule};
pub use hook_io::{HookInput, HookOutput};
pub use matcher::check_rules;

/// Result of processing a hook input against the configured rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookResult {
    pub decision: Decision,
    pub reason: Option<String>,
}

impl HookResult {
    /// Create an allow result with a reason.
    pub fn allow(reason: String) -> Self {
        Self {
            decision: Decision::Allow,
            reason: Some(reason),
        }
    }

    /// Create a deny result with a reason.
    pub fn deny(reason: String) -> Self {
        Self {
            decision: Decision::Deny,
            reason: Some(reason),
        }
    }

    /// Create a passthrough result (no matching rule).
    pub fn passthrough() -> Self {
        Self {
            decision: Decision::Passthrough,
            reason: None,
        }
    }
}

/// Process a hook input against the rules from a config file.
///
/// Returns the decision (allow/deny/passthrough) and optional reason.
/// This is the core logic that can be tested without stdin/stdout.
pub fn process_hook_input(config_path: &Path, input: &HookInput) -> Result<HookResult> {
    let config = Config::load_from_file(config_path).context("Failed to load configuration")?;
    process_hook_input_with_config(&config, input)
}

/// Process a hook input against pre-loaded config.
///
/// Useful when you want to load the config once and process multiple inputs,
/// or for testing with custom configs.
pub fn process_hook_input_with_config(config: &Config, input: &HookInput) -> Result<HookResult> {
    let (deny_rules, allow_rules) = config.compile_rules().context("Failed to compile rules")?;
    Ok(process_hook_input_with_rules(
        &deny_rules,
        &allow_rules,
        config.limits.max_chain_length,
        input,
    ))
}

/// Process a hook input against pre-compiled deny and allow rules.
///
/// Use this when rules are already compiled (e.g. from `load_config()`)
/// to avoid recompiling regex patterns on every call.
///
/// For Bash commands, the command string is decomposed into leaf
/// sub-commands (splitting on `&&`, `||`, `;`, pipes, loops, etc.)
/// and each sub-command is checked independently:
///   - Chain limit: if sub-command count exceeds max_chain_length, deny.
///   - Deny wins: if ANY sub-command matches a deny rule, deny the whole command.
///   - Allow requires all: ALL sub-commands must match an allow rule.
///   - Otherwise passthrough.
pub fn process_hook_input_with_rules(
    deny_rules: &[Rule],
    allow_rules: &[Rule],
    max_chain_length: usize,
    input: &HookInput,
) -> HookResult {
    // Decompose Bash commands and check each sub-command
    if input.tool_name == "Bash" {
        if let Some(command) = input.extract_field("command") {
            let sub_commands = decomposer::decompose_command(&command);

            // Chain length limit: deny overly complex compound commands
            if max_chain_length > 0 && sub_commands.len() > max_chain_length {
                return HookResult::deny(format!(
                    "Command has {} chained sub-commands (limit: {}). Break into smaller commands.",
                    sub_commands.len(),
                    max_chain_length,
                ));
            }

            // Deny check: if ANY sub-command matches ANY deny rule, deny everything
            for sub_cmd in &sub_commands {
                let synthetic = input.with_command(sub_cmd);
                if let Some(reason) = check_rules(deny_rules, &synthetic) {
                    return HookResult::deny(reason);
                }
            }

            // Allow check: ALL sub-commands must match some allow rule
            let mut all_reasons = Vec::new();
            let mut all_allowed = true;
            for sub_cmd in &sub_commands {
                let synthetic = input.with_command(sub_cmd);
                if let Some(reason) = check_rules(allow_rules, &synthetic) {
                    all_reasons.push(reason);
                } else {
                    all_allowed = false;
                    break;
                }
            }

            if all_allowed && !sub_commands.is_empty() {
                let combined = all_reasons.join("; ");
                return HookResult::allow(combined);
            }

            return HookResult::passthrough();
        }
    }

    // Non-Bash tools: original logic
    if let Some(reason) = check_rules(deny_rules, input) {
        return HookResult::deny(reason);
    }
    if let Some(reason) = check_rules(allow_rules, input) {
        return HookResult::allow(reason);
    }
    HookResult::passthrough()
}

/// Validate a configuration file.
///
/// Returns Ok with (deny_rule_count, allow_rule_count) if valid.
pub fn validate_config(config_path: &Path) -> Result<(usize, usize)> {
    let config = Config::load_from_file(config_path).context("Failed to load configuration")?;
    let (deny_rules, allow_rules) = config.compile_rules().context("Failed to compile rules")?;
    Ok((deny_rules.len(), allow_rules.len()))
}

/// Load and compile a configuration file.
///
/// Returns the Config and compiled rules (deny_rules, allow_rules).
pub fn load_config(config_path: &Path) -> Result<(Config, Vec<Rule>, Vec<Rule>)> {
    let config = Config::load_from_file(config_path).context("Failed to load configuration")?;
    let (deny_rules, allow_rules) = config.compile_rules().context("Failed to compile rules")?;
    Ok((config, deny_rules, allow_rules))
}
