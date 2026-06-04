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

    // Extract commands from $(...) substitutions in each leaf and
    // add them as additional leaves for rule checking.
    let mut all_commands = Vec::new();
    for cmd in &commands {
        all_commands.push(cmd.clone());
        for inner in extract_command_substitutions(cmd) {
            // Recursively decompose the inner command (it may itself
            // contain &&, pipes, etc.)
            let inner_leaves = decompose_command(&inner);
            all_commands.extend(inner_leaves);
        }
    }

    trace!("Decomposed into {} sub-commands (with $() extraction)", all_commands.len());
    all_commands
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
            let normalized = simple_command_to_normalized(simple);
            let mut result = Vec::new();
            if !normalized.command.is_empty() {
                result.push(normalized.command);
            }
            // Add $() substitutions found in stripped env-var assignments
            // so they still get rule-checked (e.g. name=$(basename "$file"))
            for inner in normalized.assignment_substitutions {
                result.extend(decompose_command(&inner));
            }
            result
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

/// Extract inner command strings from `$(...)` command substitutions.
///
/// Uses parenthesis-depth tracking to handle nested `$(...)`. Skips
/// `$(...)` occurrences inside single-quoted regions (literal) and
/// occurrences preceded by an unescaped backslash. Double quotes do
/// not protect `$(...)` (shell expands substitutions inside `"..."`).
///
/// Without this guard, grep PATTERN strings like `'... \$( ...'` or
/// `"... \$( ..."` were extracted as phantom leaves and forced the
/// surrounding chain into passthrough (passthrough audit 2026-05-15).
fn extract_command_substitutions(s: &str) -> Vec<String> {
    let mut results = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    while i < bytes.len().saturating_sub(1) {
        let c = bytes[i];
        // Single-quoted regions are literal: only a closing `'` ends them.
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        // Backslash escapes the next byte (whether inside or outside "...").
        if c == b'\\' {
            i += 2;
            continue;
        }
        // Open a single-quoted region. We do NOT track double quotes
        // because `$(...)` IS active inside double quotes.
        if c == b'\'' {
            in_single = true;
            i += 1;
            continue;
        }
        // Look for $( pattern
        if c == b'$' && bytes[i + 1] == b'(' {
            // Track paren depth starting after $(
            let start = i + 2;
            let mut depth = 1;
            let mut j = start;
            while j < bytes.len() && depth > 0 {
                if bytes[j] == b'(' {
                    depth += 1;
                } else if bytes[j] == b')' {
                    depth -= 1;
                }
                if depth > 0 {
                    j += 1;
                }
            }
            // Extract inner command if we found matching close paren
            if depth == 0 && j > start {
                let inner = &s[start..j];
                trace!("Extracted $() substitution: {:?}", inner);
                results.push(inner.to_string());
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    results
}

/// Returns true if `leaf` contains an ACTIVE (shell-evaluated) command
/// substitution: an unescaped, non-single-quoted backtick or `$(`.
///
/// A backtick or `$(` INSIDE single quotes is a literal regex/path char (for
/// example a grep PATTERN written 'BACKTICK foo' or a path named '$(x)') and
/// returns false. `${VAR}` (brace expansion, no `(`) is never a substitution
/// and also returns false. Double quotes do NOT protect -- the shell expands
/// substitutions inside "...". Mirrors the single-quote / backslash scanning in
/// `extract_command_substitutions`.
///
/// Used by the search-command (grep/rg/find) cmd-sub guard so that quoted
/// substitution characters in a search pattern no longer force passthrough,
/// while real (unquoted) command substitution is still denied.
pub(crate) fn has_active_cmd_sub(leaf: &str) -> bool {
    let bytes = leaf.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    while i < bytes.len() {
        let c = bytes[i];
        // Single-quoted regions are literal: only a closing `'` ends them.
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        // Backslash escapes the next byte.
        if c == b'\\' {
            i += 2;
            continue;
        }
        // Open a single-quoted region.
        if c == b'\'' {
            in_single = true;
            i += 1;
            continue;
        }
        // Unquoted backtick is a (legacy) command substitution.
        if c == b'`' {
            return true;
        }
        // Unquoted `$(` opens a command substitution.
        if c == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            return true;
        }
        i += 1;
    }
    false
}

fn extract_from_compound_command(cmd: &ast::CompoundCommand) -> Vec<String> {
    match cmd {
        ast::CompoundCommand::BraceGroup(bg) => extract_from_compound_list(&bg.list),
        ast::CompoundCommand::Subshell(sub) => extract_from_compound_list(&sub.list),
        ast::CompoundCommand::ForClause(fc) => {
            let mut result = Vec::new();
            // Extract $() from the for clause's values (e.g. "for i in $(cmd)")
            if let Some(ref values) = fc.values {
                for w in values {
                    for inner in extract_command_substitutions(&w.value) {
                        result.extend(decompose_command(&inner));
                    }
                }
            }
            result.extend(extract_from_compound_list(&fc.body.list));
            result
        }
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
/// Result of converting a simple command to a normalized string.
/// Contains the main command (with env-var assignments stripped)
/// and any $() substitutions found inside stripped assignment values.
struct NormalizedCommand {
    command: String,
    assignment_substitutions: Vec<String>,
}

fn simple_command_to_normalized(cmd: &ast::SimpleCommand) -> NormalizedCommand {
    let mut parts: Vec<String> = Vec::new();
    let mut assignment_subs: Vec<String> = Vec::new();

    // Prefix items (assignments and words)
    if let Some(ref prefix) = cmd.prefix {
        for item in &prefix.0 {
            match item {
                ast::CommandPrefixOrSuffixItem::Word(w) => {
                    parts.push(w.value.clone());
                }
                ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
                    // Strip env-var assignments from the leaf command string.
                    // The AST parser identifies assignments structurally,
                    // so no regex needed. This is syntax-level normalization:
                    // "NODE_PATH=/foo node script.js" -> "node script.js"
                    // TOML rules then match the normalized command only.
                    //
                    // Still extract $() from assignment values so commands
                    // inside them get rule-checked (e.g. name=$(basename "$file")).
                    for inner in extract_command_substitutions(&w.value) {
                        assignment_subs.push(inner);
                    }
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

    NormalizedCommand {
        command: parts.join(" "),
        assignment_substitutions: assignment_subs,
    }
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

    // ---------------------------------------------------------------
    // $() command substitution extraction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_cmd_sub_in_for_loop() {
        // for i in $(ls *.txt); do echo $i; done
        // The loop body "echo $i" is a leaf; "ls *.txt" is inside $() in the
        // for clause word list which is not a SimpleCommand leaf.
        // But the $() extractor scans leaf strings, and the for clause
        // word list with $() gets captured via the for-loop word extraction.
        let result = decompose_command("for i in $(ls *.txt); do echo $i; done");
        assert!(result.contains(&"echo $i".to_string()));
        // The $() in the for word list should be extracted
        assert!(result.contains(&"ls *.txt".to_string()));
    }

    #[test]
    fn test_cmd_sub_in_assignment() {
        // VAR=$(git rev-parse --show-toplevel)
        let result = decompose_command("REPO_ROOT=$(git rev-parse --show-toplevel)");

        assert!(result.contains(&"git rev-parse --show-toplevel".to_string()));
    }

    #[test]
    fn test_cmd_sub_nested() {
        // Nested $() should extract outer content
        let result = decompose_command("echo $(cat $(find . -name foo))");
        assert!(result.contains(&"cat $(find . -name foo)".to_string()));
        assert!(result.contains(&"find . -name foo".to_string()));
    }

    #[test]
    fn test_cmd_sub_no_false_positive() {
        // ${VAR} is NOT a command substitution, only $() is
        let result = extract_command_substitutions("echo ${HOME}/file");
        assert!(result.is_empty());
    }

    #[test]
    fn test_has_active_cmd_sub() {
        // Unquoted substitutions are active.
        assert!(has_active_cmd_sub("grep `whoami` src/x"));
        assert!(has_active_cmd_sub("grep $(cat /etc/passwd) src/x"));
        assert!(has_active_cmd_sub("find . -name x\"$(evil)\""));
        // Single-quoted substitution chars are inert (literal pattern/path).
        assert!(!has_active_cmd_sub("grep '`references/' src/x.md"));
        assert!(!has_active_cmd_sub("grep '$(cat x)' src/x"));
        assert!(!has_active_cmd_sub("find src/'(0)concepts' -name '*.mdx'"));
        // Inert here because the token is single-quoted; `${` is also not `$(`.
        assert!(!has_active_cmd_sub("grep '${.*}__${' src/main.ts"));
        // ${VAR} is brace expansion (no `(`), not a substitution, even unquoted.
        assert!(!has_active_cmd_sub("echo ${HOME}/x"));
        // Backslash-escaped backtick is literal.
        assert!(!has_active_cmd_sub("grep \\`x src/x"));
    }

    #[test]
    fn test_cmd_sub_multiple() {
        // Two $() in one command
        let result = extract_command_substitutions("echo $(date) and $(whoami)");
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"date".to_string()));
        assert!(result.contains(&"whoami".to_string()));
    }

    #[test]
    fn test_for_loop_with_basename_cmd_sub() {
        // Real-world: for file in *.py; do name=$(basename "$file"); ... done
        // The body has name=$(basename "$file") which contains $()
        let result = decompose_command(
            r#"for file in *.py; do name=$(basename "$file"); echo "$name"; done"#,
        );

        assert!(result.contains(&"echo \"$name\"".to_string()));
        // basename extracted from $() inside the loop body
        assert!(result.contains(&"basename \"$file\"".to_string()));
    }

    #[test]
    fn test_for_loop_plain_values_no_cmd_sub() {
        // for loop with plain values (no $()) should not produce extra leaves
        let result = decompose_command(
            "for locale in cs de fr; do echo $locale; done",
        );
        assert_eq!(result, vec!["echo $locale"]);
    }

    // ---------------------------------------------------------------
    // env-var assignment stripping tests
    // ---------------------------------------------------------------

    #[test]
    fn test_env_prefix_stripped_uppercase() {
        // Uppercase env prefix should be stripped from the leaf
        let result = decompose_command("NODE_PATH=/foo node script.js");
        assert_eq!(result, vec!["node script.js"]);
    }

    #[test]
    fn test_env_prefix_stripped_lc_all() {
        let result = decompose_command("LC_ALL=C sort file.txt");
        assert_eq!(result, vec!["sort file.txt"]);
    }

    #[test]
    fn test_env_prefix_stripped_lowercase() {
        // Lowercase env prefix is also stripped (AST-structural, not policy)
        let result = decompose_command("foo=bar node script.js");
        assert_eq!(result, vec!["node script.js"]);
    }

    #[test]
    fn test_env_prefix_multiple_assignments() {
        // Multiple env prefixes should all be stripped
        let result = decompose_command("FOO=1 BAR=2 python3 test.py");
        assert_eq!(result, vec!["python3 test.py"]);
    }

    #[test]
    fn test_bare_assignment_no_command() {
        // Bare assignment with no command: the parser treats it as the command name
        // (word_or_name), not as a prefix AssignmentWord. The deny rule for bare
        // assignments catches this on the raw string before decomposition.
        let result = decompose_command("FOO=bar");
        assert_eq!(result, vec!["FOO=bar"]);
    }
}
