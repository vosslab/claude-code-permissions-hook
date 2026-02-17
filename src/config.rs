#![forbid(unsafe_code)]
#![warn(clippy::all)]

use anyhow::{Context, Result, bail};
use log::debug;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub audit: AuditConfig,
    /// Reusable string fragments for regex patterns.
    /// Reference in regex fields as `${VAR_NAME}`.
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    pub allow: Vec<RuleConfig>,
    #[serde(default)]
    pub deny: Vec<RuleConfig>,
}

/// Controls what gets written to the audit log file.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    /// No audit logging
    Off,
    /// Log only tool use that matches a rule (default)
    #[default]
    Matched,
    /// Log all tool use including passthrough
    All,
}

#[derive(Debug, Deserialize)]
pub struct AuditConfig {
    pub audit_file: PathBuf,
    #[serde(default)]
    pub audit_level: AuditLevel,
    pub passthrough_log_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Exact tool name match. Required unless tool_regex is set.
    #[serde(default)]
    pub tool: String,
    /// Regex pattern for matching tool names (alternative to exact tool match).
    pub tool_regex: Option<String>,
    pub file_path_regex: Option<String>,
    pub file_path_exclude_regex: Option<String>,
    pub command_regex: Option<String>,
    pub command_exclude_regex: Option<String>,
    pub subagent_type: Option<String>,
    pub subagent_type_regex: Option<String>,
    pub subagent_type_exclude_regex: Option<String>,
    pub prompt_regex: Option<String>,
    pub prompt_exclude_regex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub tool: String,
    pub tool_regex: Option<Regex>,
    pub file_path_regex: Option<Regex>,
    pub file_path_exclude_regex: Option<Regex>,
    pub command_regex: Option<Regex>,
    pub command_exclude_regex: Option<Regex>,
    pub subagent_type: Option<String>,
    pub subagent_type_regex: Option<Regex>,
    pub subagent_type_exclude_regex: Option<Regex>,
    pub prompt_regex: Option<Regex>,
    pub prompt_exclude_regex: Option<Regex>,
}

impl Config {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let mut config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse TOML config: {}", path.display()))?;

        // Expand environment variables ($HOME, $USER, etc.) in variable values
        config.variables = config
            .variables
            .into_iter()
            .map(|(k, v)| {
                let expanded = expand_env_vars(&v);
                debug!("Variable {} = {}", k, expanded);
                (k, expanded)
            })
            .collect();

        Ok(config)
    }

    pub fn compile_rules(&self) -> Result<(Vec<Rule>, Vec<Rule>)> {
        let vars = &self.variables;
        if !vars.is_empty() {
            debug!("Config has {} variables defined", vars.len());
        }

        let deny_rules = self
            .deny
            .iter()
            .map(|r| compile_rule_with_vars(r, vars))
            .collect::<Result<Vec<_>>>()
            .context("Failed to compile deny rules")?;

        let allow_rules = self
            .allow
            .iter()
            .map(|r| compile_rule_with_vars(r, vars))
            .collect::<Result<Vec<_>>>()
            .context("Failed to compile allow rules")?;

        Ok((deny_rules, allow_rules))
    }
}

/// Expand `$ENV_VAR` references in a string using environment variables.
/// Only expands standard OS/ecosystem env vars (HOME, USER, TMPDIR, etc.).
/// Uses `$VARNAME` syntax (no braces) to distinguish from `${TOML_VAR}`.
fn expand_env_vars(input: &str) -> String {
    let env_pattern = Regex::new(r"\$([A-Z_][A-Z0-9_]*)").unwrap();
    let mut result = input.to_string();

    let matches: Vec<(String, String)> = env_pattern
        .captures_iter(input)
        .map(|cap| (cap[0].to_string(), cap[1].to_string()))
        .collect();

    for (full_match, var_name) in matches {
        // Skip ${...} patterns (those are TOML variables, handled separately)
        if input.contains(&format!("${{{}}}", var_name)) {
            continue;
        }
        if let Ok(value) = std::env::var(&var_name) {
            debug!("Expanding env var ${}", var_name);
            result = result.replace(&full_match, &value);
        }
    }

    result
}

/// Expand `${VAR_NAME}` references in a string using the variables map.
/// Returns an error if a referenced variable is not defined.
fn expand_variables(input: &str, vars: &HashMap<String, String>) -> Result<String> {
    // Fast path: no variables to expand
    if !input.contains("${") {
        return Ok(input.to_string());
    }

    let mut result = input.to_string();
    // Find all ${...} references and expand them
    let var_pattern = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
        .context("Failed to compile variable pattern")?;

    // Collect matches first to avoid borrow issues
    let matches: Vec<(String, String)> = var_pattern
        .captures_iter(input)
        .map(|cap| {
            let full_match = cap[0].to_string();
            let var_name = cap[1].to_string();
            (full_match, var_name)
        })
        .collect();

    for (full_match, var_name) in matches {
        match vars.get(&var_name) {
            Some(value) => {
                debug!("Expanding ${{{}}}", var_name);
                result = result.replace(&full_match, value);
            }
            None => {
                bail!("Undefined variable '{}' referenced in pattern: {}", var_name, input);
            }
        }
    }

    Ok(result)
}

/// Expand variables in an optional string field.
fn expand_opt(field: &Option<String>, vars: &HashMap<String, String>) -> Result<Option<String>> {
    match field {
        Some(s) => Ok(Some(expand_variables(s, vars)?)),
        None => Ok(None),
    }
}

/// Compile a rule config into a Rule, expanding any ${VAR} references first.
fn compile_rule_with_vars(
    rule_config: &RuleConfig,
    vars: &HashMap<String, String>,
) -> Result<Rule> {
    // Validate that at least one of tool or tool_regex is set
    if rule_config.tool.is_empty() && rule_config.tool_regex.is_none() {
        bail!("Rule must have either 'tool' or 'tool_regex' set");
    }

    // Compile tool_regex if present
    let tool_regex = rule_config.tool_regex.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid tool_regex")?;

    // Expand variables in all regex string fields
    let fp = expand_opt(&rule_config.file_path_regex, vars)
        .context("In file_path_regex")?;
    let fp_ex = expand_opt(&rule_config.file_path_exclude_regex, vars)
        .context("In file_path_exclude_regex")?;
    let cmd = expand_opt(&rule_config.command_regex, vars)
        .context("In command_regex")?;
    let cmd_ex = expand_opt(&rule_config.command_exclude_regex, vars)
        .context("In command_exclude_regex")?;
    let sa = expand_opt(&rule_config.subagent_type_regex, vars)
        .context("In subagent_type_regex")?;
    let sa_ex = expand_opt(&rule_config.subagent_type_exclude_regex, vars)
        .context("In subagent_type_exclude_regex")?;
    let pr = expand_opt(&rule_config.prompt_regex, vars)
        .context("In prompt_regex")?;
    let pr_ex = expand_opt(&rule_config.prompt_exclude_regex, vars)
        .context("In prompt_exclude_regex")?;

    // Compile expanded regex strings
    let file_path_regex = fp.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid file_path_regex")?;

    let file_path_exclude_regex = fp_ex.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid file_path_exclude_regex")?;

    let command_regex = cmd.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid command_regex")?;

    let command_exclude_regex = cmd_ex.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid command_exclude_regex")?;

    let subagent_type_regex = sa.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid subagent_type_regex")?;

    let subagent_type_exclude_regex = sa_ex.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid subagent_type_exclude_regex")?;

    let prompt_regex = pr.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid prompt_regex")?;

    let prompt_exclude_regex = pr_ex.as_ref()
        .map(|s| Regex::new(s))
        .transpose()
        .context("Invalid prompt_exclude_regex")?;

    Ok(Rule {
        tool: rule_config.tool.clone(),
        tool_regex,
        file_path_regex,
        file_path_exclude_regex,
        command_regex,
        command_exclude_regex,
        subagent_type: rule_config.subagent_type.clone(),
        subagent_type_regex,
        subagent_type_exclude_regex,
        prompt_regex,
        prompt_exclude_regex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_compile_rule() -> Result<()> {
        let rule_config = RuleConfig {
            tool: "Read".to_string(),
            tool_regex: None,
            file_path_regex: Some(r"^/home/.*".to_string()),
            file_path_exclude_regex: Some(r"\.\.".to_string()),
            command_regex: None,
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
        };

        let vars = HashMap::new();
        let rule = compile_rule_with_vars(&rule_config, &vars)?;
        assert_eq!(rule.tool, "Read");
        assert!(rule.file_path_regex.is_some());
        assert!(rule.file_path_exclude_regex.is_some());

        Ok(())
    }

    #[test]
    fn test_expand_variables() -> Result<()> {
        let mut vars = HashMap::new();
        vars.insert("UTILS".to_string(), "echo|ls|cat".to_string());
        vars.insert("EXCLUDE".to_string(), "`|\\$\\(".to_string());

        // Simple expansion
        let result = expand_variables("^(${UTILS})\\b", &vars)?;
        assert_eq!(result, "^(echo|ls|cat)\\b");

        // Multiple variables in one string
        let result = expand_variables("${UTILS}.*${EXCLUDE}", &vars)?;
        assert_eq!(result, "echo|ls|cat.*`|\\$\\(");

        // No variables - passthrough
        let result = expand_variables("^cargo\\b", &vars)?;
        assert_eq!(result, "^cargo\\b");

        Ok(())
    }

    #[test]
    fn test_expand_undefined_variable_errors() {
        let vars = HashMap::new();
        let result = expand_variables("^(${UNDEFINED})\\b", &vars);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("UNDEFINED"), "Error should mention variable name: {}", err_msg);
    }

    #[test]
    fn test_compile_rule_with_variables() -> Result<()> {
        let mut vars = HashMap::new();
        vars.insert("SAFE_CMDS".to_string(), "echo|ls|cat".to_string());

        let rule_config = RuleConfig {
            tool: "Bash".to_string(),
            tool_regex: None,
            file_path_regex: None,
            file_path_exclude_regex: None,
            command_regex: Some("^(${SAFE_CMDS})\\b".to_string()),
            command_exclude_regex: None,
            subagent_type: None,
            subagent_type_regex: None,
            subagent_type_exclude_regex: None,
            prompt_regex: None,
            prompt_exclude_regex: None,
        };

        let rule = compile_rule_with_vars(&rule_config, &vars)?;
        // Verify the expanded regex matches expected commands
        let re = rule.command_regex.unwrap();
        assert!(re.is_match("echo hello"));
        assert!(re.is_match("ls -la"));
        assert!(re.is_match("cat file.txt"));
        assert!(!re.is_match("rm -rf /"));

        Ok(())
    }
}
