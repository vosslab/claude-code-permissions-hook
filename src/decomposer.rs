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
}
