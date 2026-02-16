#![forbid(unsafe_code)]
#![warn(clippy::all)]

//! Shell command decomposer that parses Bash commands into leaf sub-commands.
//!
//! Uses brush-parser to build an AST from compound shell commands, then walks
//! the tree to extract each simple command independently.  This lets deny/allow
//! rules inspect every sub-command inside `&&`, `||`, `;`, pipes, loops, etc.

use brush_parser::ast;
use log::{debug, trace};

/// Decompose a compound Bash command into its leaf simple-command strings.
///
/// Returns a flat list of sub-command strings.  If parsing fails the original
/// command is returned as-is (fail open to preserve current behaviour).
pub fn decompose_command(command: &str) -> Vec<String> {
    if command.trim().is_empty() {
        return vec![command.to_string()];
    }

    let tokens = match brush_parser::tokenize_str(command) {
        Ok(t) => t,
        Err(e) => {
            debug!("Tokenizer failed, returning original command: {}", e);
            return vec![command.to_string()];
        }
    };

    let options = brush_parser::ParserOptions::default();
    let source_info = brush_parser::SourceInfo {
        source: command.to_string(),
    };

    let program = match brush_parser::parse_tokens(&tokens, &options, &source_info) {
        Ok(p) => p,
        Err(e) => {
            debug!("Parser failed, returning original command: {}", e);
            return vec![command.to_string()];
        }
    };

    let commands = extract_from_program(&program);
    if commands.is_empty() {
        return vec![command.to_string()];
    }
    trace!("Decomposed into {} sub-commands", commands.len());
    commands
}

// ------------------------------------------------------------------
// AST walkers
// ------------------------------------------------------------------

fn extract_from_program(program: &ast::Program) -> Vec<String> {
    let mut result = Vec::new();
    for complete_cmd in &program.complete_commands {
        result.extend(extract_from_compound_list(complete_cmd));
    }
    result
}

fn extract_from_compound_list(list: &ast::CompoundList) -> Vec<String> {
    let mut result = Vec::new();
    for item in &list.0 {
        result.extend(extract_from_and_or_list(&item.0));
    }
    result
}

fn extract_from_and_or_list(list: &ast::AndOrList) -> Vec<String> {
    let mut result = Vec::new();
    result.extend(extract_from_pipeline(&list.first));
    for and_or in &list.additional {
        match and_or {
            ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => {
                result.extend(extract_from_pipeline(pipeline));
            }
        }
    }
    result
}

fn extract_from_pipeline(pipeline: &ast::Pipeline) -> Vec<String> {
    let mut result = Vec::new();
    for cmd in &pipeline.seq {
        result.extend(extract_from_command(cmd));
    }
    result
}

fn extract_from_command(cmd: &ast::Command) -> Vec<String> {
    match cmd {
        ast::Command::Simple(simple) => {
            // Unwrap bash -c "inner command" patterns and recursively
            // decompose the inner command string.  This lets normal
            // allow/deny rules match the inner commands directly
            // without needing special bash-wrapper regex rules.
            if let Some(inner) = try_unwrap_bash_c(simple) {
                return decompose_command(&inner);
            }
            let s = simple_command_to_string(simple);
            if s.is_empty() {
                vec![]
            } else {
                vec![s]
            }
        }
        ast::Command::Compound(compound, _redirect_list) => {
            extract_from_compound_command(compound)
        }
        ast::Command::Function(_) => vec![],
        ast::Command::ExtendedTest(_) => vec![],
    }
}

/// Detect `bash -c "inner command"` patterns and extract the inner
/// command string.  Handles combined flags like `-lc`, `-cl`, `-c`,
/// as well as separate flags like `-l -c`.
fn try_unwrap_bash_c(cmd: &ast::SimpleCommand) -> Option<String> {
    let name = cmd.word_or_name.as_ref()?;
    let name_val = name.value.as_str();
    if !matches!(name_val, "bash" | "/bin/bash" | "/usr/bin/bash" | "/usr/local/bin/bash") {
        return None;
    }

    let suffix = cmd.suffix.as_ref()?;
    let mut found_c = false;

    for item in &suffix.0 {
        if let ast::CommandPrefixOrSuffixItem::Word(w) = item {
            if !found_c {
                // Look for a flag containing 'c' (e.g. -c, -lc, -cl)
                if w.value.starts_with('-') && w.value[1..].contains('c') {
                    found_c = true;
                }
            } else {
                // First word after the -c flag is the inner command
                let inner = strip_outer_quotes(&w.value);
                trace!("Unwrapped bash -c inner command: {:?}", inner);
                return Some(inner);
            }
        }
    }
    None
}

/// Strip a single layer of matching outer quotes if present.
fn strip_outer_quotes(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0];
        let last = trimmed.as_bytes()[trimmed.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

fn extract_from_compound_command(cmd: &ast::CompoundCommand) -> Vec<String> {
    match cmd {
        ast::CompoundCommand::BraceGroup(bg) => extract_from_compound_list(&bg.list),
        ast::CompoundCommand::Subshell(sub) => extract_from_compound_list(&sub.list),
        ast::CompoundCommand::ForClause(fc) => extract_from_compound_list(&fc.body.list),
        ast::CompoundCommand::WhileClause(wc) => {
            // condition is wc.0, body is wc.1
            let mut result = extract_from_compound_list(&wc.0);
            result.extend(extract_from_compound_list(&wc.1.list));
            result
        }
        ast::CompoundCommand::UntilClause(uc) => {
            let mut result = extract_from_compound_list(&uc.0);
            result.extend(extract_from_compound_list(&uc.1.list));
            result
        }
        ast::CompoundCommand::IfClause(ic) => {
            let mut result = extract_from_compound_list(&ic.condition);
            result.extend(extract_from_compound_list(&ic.then));
            if let Some(ref elses) = ic.elses {
                for else_clause in elses {
                    if let Some(ref cond) = else_clause.condition {
                        result.extend(extract_from_compound_list(cond));
                    }
                    result.extend(extract_from_compound_list(&else_clause.body));
                }
            }
            result
        }
        ast::CompoundCommand::CaseClause(cc) => {
            let mut result = Vec::new();
            for case_item in &cc.cases {
                if let Some(ref cmd_list) = case_item.cmd {
                    result.extend(extract_from_compound_list(cmd_list));
                }
            }
            result
        }
        ast::CompoundCommand::Arithmetic(_) => vec![],
        ast::CompoundCommand::ArithmeticForClause(_) => vec![],
    }
}

// ------------------------------------------------------------------
// SimpleCommand -> String
// ------------------------------------------------------------------

/// Reconstruct a command string from a SimpleCommand AST node.
///
/// Collects prefix words, the command name, and suffix words.
/// I/O redirections are intentionally skipped since they do not
/// affect which program runs.
fn simple_command_to_string(cmd: &ast::SimpleCommand) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Prefix items (assignments and words)
    if let Some(ref prefix) = cmd.prefix {
        for item in &prefix.0 {
            match item {
                ast::CommandPrefixOrSuffixItem::Word(w) => {
                    parts.push(w.value.clone());
                }
                ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
                    parts.push(w.value.clone());
                }
                _ => {} // skip IoRedirect, ProcessSubstitution
            }
        }
    }

    // Command name
    if let Some(ref word) = cmd.word_or_name {
        parts.push(word.value.clone());
    }

    // Suffix items (word arguments only)
    if let Some(ref suffix) = cmd.suffix {
        for item in &suffix.0 {
            match item {
                ast::CommandPrefixOrSuffixItem::Word(w) => {
                    parts.push(w.value.clone());
                }
                _ => {} // skip IoRedirect, ProcessSubstitution
            }
        }
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_simple_command() {
        let result = decompose_command("ls -la");
        assert_eq!(result, vec!["ls -la"]);
    }

    #[test]
    fn test_and_chain() {
        let result = decompose_command("echo hi && echo bye");
        assert_eq!(result, vec!["echo hi", "echo bye"]);
    }

    #[test]
    fn test_or_chain() {
        let result = decompose_command("echo hi || echo bye");
        assert_eq!(result, vec!["echo hi", "echo bye"]);
    }

    #[test]
    fn test_semicolons() {
        let result = decompose_command("echo a; echo b");
        assert_eq!(result, vec!["echo a", "echo b"]);
    }

    #[test]
    fn test_pipe() {
        let result = decompose_command("ls | grep foo");
        assert_eq!(result, vec!["ls", "grep foo"]);
    }

    #[test]
    fn test_for_loop() {
        let result = decompose_command("for i in 1 2; do echo $i; done");
        assert_eq!(result, vec!["echo $i"]);
    }

    #[test]
    fn test_while_loop() {
        let result = decompose_command("while true; do sleep 1; done");
        assert_eq!(result, vec!["true", "sleep 1"]);
    }

    #[test]
    fn test_mixed_operators() {
        let result = decompose_command("echo a && echo b || echo c; echo d");
        assert_eq!(result, vec!["echo a", "echo b", "echo c", "echo d"]);
    }

    #[test]
    fn test_malformed_returns_original() {
        // Unclosed quote should fail to parse, returning original string
        let input = "echo 'unterminated";
        let result = decompose_command(input);
        assert_eq!(result, vec![input.to_string()]);
    }

    #[test]
    fn test_empty_string() {
        let result = decompose_command("");
        assert_eq!(result, vec!["".to_string()]);
    }

    #[test]
    fn test_pipeline_chain() {
        let result = decompose_command("cat file.txt | sort | uniq -c");
        assert_eq!(result, vec!["cat file.txt", "sort", "uniq -c"]);
    }

    #[test]
    fn test_complex_compound() {
        let result = decompose_command("echo start && ls -la | grep test || echo fallback");
        assert_eq!(result.len(), 4);
        assert!(result.contains(&"echo start".to_string()));
        assert!(result.contains(&"ls -la".to_string()));
        assert!(result.contains(&"grep test".to_string()));
        assert!(result.contains(&"echo fallback".to_string()));
    }

    #[test]
    fn test_redirect_stripped() {
        let result = decompose_command("echo hello > /tmp/out.txt");
        assert_eq!(result, vec!["echo hello"]);
    }

    #[test]
    fn test_if_clause() {
        let result = decompose_command("if test -f file; then echo yes; fi");
        assert!(result.contains(&"test -f file".to_string()));
        assert!(result.contains(&"echo yes".to_string()));
    }

    // ---------------------------------------------------------------
    // bash -c unwrapping tests
    // ---------------------------------------------------------------

    #[test]
    fn test_bash_c_double_quotes() {
        let result = decompose_command("bash -c \"echo hello\"");
        assert_eq!(result, vec!["echo hello"]);
    }

    #[test]
    fn test_bash_c_single_quotes() {
        let result = decompose_command("bash -c 'echo hello'");
        assert_eq!(result, vec!["echo hello"]);
    }

    #[test]
    fn test_bash_lc_with_compound() {
        let result = decompose_command("bash -lc 'source env.sh && python3 -m pytest tests/'");
        assert_eq!(result, vec!["source env.sh", "python3 -m pytest tests/"]);
    }

    #[test]
    fn test_bash_lc_double_quotes_compound() {
        let result = decompose_command("bash -lc \"echo hi && echo bye\"");
        assert_eq!(result, vec!["echo hi", "echo bye"]);
    }

    #[test]
    fn test_bash_cl_flag_order() {
        let result = decompose_command("bash -cl 'ls -la'");
        assert_eq!(result, vec!["ls -la"]);
    }

    #[test]
    fn test_bash_c_dangerous_inner() {
        // Decomposer unwraps, deny rule would catch rm separately
        let result = decompose_command("bash -c 'echo ok && rm -rf /'");
        assert_eq!(result, vec!["echo ok", "rm -rf /"]);
    }

    #[test]
    fn test_bash_n_no_unwrap() {
        // bash -n (syntax check) has no -c flag, should not unwrap
        let result = decompose_command("bash -n script.sh");
        assert_eq!(result, vec!["bash -n script.sh"]);
    }

    #[test]
    fn test_not_bash_no_unwrap() {
        // zsh -c should not be unwrapped (only bash)
        let result = decompose_command("zsh -c 'echo hello'");
        assert_eq!(result, vec!["zsh -c 'echo hello'"]);
    }
}
