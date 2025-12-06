# Configuration Guide

This guide explains how to configure rules for each supported tool in the permissions hook.

## Overview

Rules are defined in TOML format with two types:
- `[[allow]]` - Permits tool use when matched (checked after deny rules)
- `[[deny]]` - Blocks tool use when matched (checked first, takes precedence)

Each rule specifies:
- `tool` - The tool name to match
- A regex field for the value to match (tool-specific)
- An optional exclude regex to reject matches containing certain patterns

## Supported Tools

### File Path Tools: Read, Write, Edit, Glob

These tools operate on file paths. The hook extracts the `file_path` field from the tool input.

**Available fields:**
| Field | Description |
|-------|-------------|
| `file_path_regex` | Pattern the file path must match |
| `file_path_exclude_regex` | Pattern that rejects the match if found |

**Example: Allow reading files in a project directory**
```toml
[[allow]]
tool = "Read"
file_path_regex = "^/Users/myname/projects/.*"
```

**Example: Allow writes but block sensitive files**
```toml
[[allow]]
tool = "Write"
file_path_regex = "^/Users/myname/projects/.*"
file_path_exclude_regex = "\\.(env|secret|key|pem)$"
```

**Example: Block reading outside home directory**
```toml
[[deny]]
tool = "Read"
file_path_regex = "^/(?!Users/myname/).*"
```

**Example: Prevent path traversal attacks**
```toml
[[allow]]
tool = "Edit"
file_path_regex = "^/safe/directory/.*"
file_path_exclude_regex = "\\.\\."  # Block ../ sequences
```

**Tool input reference:**
```json
{
  "file_path": "/absolute/path/to/file.txt",
  "content": "...",      // Write only
  "old_string": "...",   // Edit only
  "new_string": "...",   // Edit only
  "pattern": "..."       // Glob only (not matched by this hook)
}
```

### Command Tool: Bash

The Bash tool executes shell commands. The hook extracts the `command` field.

**Available fields:**
| Field | Description |
|-------|-------------|
| `command_regex` | Pattern the command must match |
| `command_exclude_regex` | Pattern that rejects the match if found |

**Example: Allow specific build commands**
```toml
[[allow]]
tool = "Bash"
command_regex = "^cargo (build|test|check|clippy|fmt|run)"
```

**Example: Allow git commands but prevent force push**
```toml
[[allow]]
tool = "Bash"
command_regex = "^git "
command_exclude_regex = "push.*--force|push.*-f"
```

**Example: Block dangerous commands**
```toml
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"

[[deny]]
tool = "Bash"
command_regex = "^sudo "
```

**Example: Prevent shell injection in allowed commands**
```toml
[[allow]]
tool = "Bash"
command_regex = "^npm (install|test|run)"
command_exclude_regex = "&|;|\\||`|\\$\\(|>"  # Block shell metacharacters
```

**Common shell injection patterns to exclude:**
- `&` - Background/chain commands
- `;` - Command separator
- `|` - Pipe to another command
- `` ` `` - Command substitution (backticks)
- `$(` - Command substitution
- `>` - Output redirection

**Tool input reference:**
```json
{
  "command": "cargo build --release",
  "description": "Build release binary",
  "timeout": 120000
}
```

### Agent Tool: Task

The Task tool spawns subagents. The hook can match on `subagent_type` or `prompt`.

**Available fields:**
| Field | Description |
|-------|-------------|
| `subagent_type` | Exact match on the subagent type (not regex) |
| `prompt_regex` | Pattern the prompt must match |
| `prompt_exclude_regex` | Pattern that rejects the match if found |

**Example: Allow specific agent types**
```toml
[[allow]]
tool = "Task"
subagent_type = "Explore"

[[allow]]
tool = "Task"
subagent_type = "codebase-analyzer"
```

**Example: Block general-purpose agents**
```toml
[[deny]]
tool = "Task"
subagent_type = "general-purpose"
```

**Example: Allow agents but filter prompts**
```toml
[[allow]]
tool = "Task"
subagent_type = "Explore"
prompt_regex = ".*"
prompt_exclude_regex = "password|secret|credential"
```

**Known subagent types** (may change between versions):
- `general-purpose` - Full tool access
- `Explore` - Codebase exploration
- `Plan` - Architecture planning
- `codebase-analyzer` - Code analysis
- `codebase-locator` - File/component location
- `statusline-setup` - Status line configuration

**Tool input reference:**
```json
{
  "description": "Search for auth code",
  "prompt": "Find all authentication-related code",
  "subagent_type": "Explore"
}
```

## Rule Matching Logic

1. **Deny rules are checked first** - If any deny rule matches, the tool is blocked
2. **Allow rules are checked second** - If any allow rule matches, the tool is permitted
3. **No match means passthrough** - Normal Claude Code permission flow applies

For each rule:
1. Tool name must match exactly
2. Main regex must match the extracted field
3. Exclude regex (if specified) must NOT match

## Auditing Configuration

Configure auditing in the `[audit]` section:

```toml
[audit]
audit_file = "/tmp/claude-tool-use.json"
audit_level = "matched"  # off | matched | all
```

| Level | Description |
|-------|-------------|
| `off` | No auditing |
| `matched` | Record only allow/deny decisions (default) |
| `all` | Record everything including passthrough |

## Complete Example

```toml
[audit]
audit_file = "/tmp/claude-tool-use.json"
audit_level = "matched"

# === DENY RULES (checked first) ===

# Block dangerous commands
[[deny]]
tool = "Bash"
command_regex = "^rm .*-rf"

[[deny]]
tool = "Bash"
command_regex = "^sudo "

# Protect sensitive files
[[deny]]
tool = "Read"
file_path_regex = "\\.(env|pem|key)$"

[[deny]]
tool = "Write"
file_path_regex = "\\.(env|pem|key)$"

# === ALLOW RULES (checked after deny) ===

# Allow reading project files (with path traversal protection)
[[allow]]
tool = "Read"
file_path_regex = "^/Users/myname/projects/.*"
file_path_exclude_regex = "\\.\\."

# Allow writing to project files
[[allow]]
tool = "Write"
file_path_regex = "^/Users/myname/projects/.*"
file_path_exclude_regex = "\\.\\."

# Allow editing project files
[[allow]]
tool = "Edit"
file_path_regex = "^/Users/myname/projects/.*"
file_path_exclude_regex = "\\.\\."

# Allow glob in project directory
[[allow]]
tool = "Glob"
file_path_regex = "^/Users/myname/projects/.*"

# Allow safe build commands
[[allow]]
tool = "Bash"
command_regex = "^cargo (build|test|check|clippy|fmt|run)"
command_exclude_regex = "&|;|\\||`|\\$\\("

# Allow git commands (no force push)
[[allow]]
tool = "Bash"
command_regex = "^git "
command_exclude_regex = "push.*--force|push.*-f"

# Allow codebase exploration agents
[[allow]]
tool = "Task"
subagent_type = "Explore"

[[allow]]
tool = "Task"
subagent_type = "codebase-analyzer"
```

## Tips

1. **Start restrictive** - Begin with specific allow rules rather than broad permissions
2. **Use exclude patterns** - They simplify rules by handling edge cases
3. **Test with audit_level = "all"** - See what's passing through to identify gaps
4. **Check the audit log** - Review `/tmp/claude-tool-use.json` to understand patterns
5. **Validate config** - Run `claude-code-permissions-hook validate --config your.toml`

## See Also

- [Tool Input Schemas](./tool-input-schemas.md) - Complete reference for all Claude Code tool inputs
- [example.toml](../example.toml) - Working example configuration
