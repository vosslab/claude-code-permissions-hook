# Claude Code Tool Input Schemas

This document describes the `tool_input` JSON schemas for Claude Code's built-in tools. These schemas are relevant when writing PreToolUse hooks that need to inspect or match against tool inputs.

## Source Attribution

> **Important**: As of December 2025, Anthropic does not publish official documentation for tool_input schemas. The information below is compiled from:
>
> | Source | Reliability | Notes |
> |--------|-------------|-------|
> | [Claude Code system prompt](https://gist.github.com/wong2/e0f34aac66caf890a332f7b6f9e2ba8f) | High | Extracted from actual Claude Code sessions; schemas are embedded in the system prompt |
> | [vtrivedy tools reference](https://www.vtrivedy.com/posts/claudecode-tools-reference) | Medium-High | Community-maintained, cross-referenced with system prompt |
> | [bgauryy implementation gist](https://gist.github.com/bgauryy/0cdb9aa337d01ae5bd0c803943aa36bd) | Medium | Reverse-engineered from behavior |
> | Direct observation | High | Verified by inspecting actual hook inputs in this project |
>
> Schemas may change between Claude Code versions. Always test against actual hook inputs.

## File Operation Tools

### Read

Reads file contents. Can read text files, images, PDFs, and Jupyter notebooks.

```json
{
  "file_path": "/absolute/path/to/file.txt",
  "offset": 100,
  "limit": 50
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | Yes | Absolute path to the file |
| `offset` | number | No | Line number to start reading from (1-indexed) |
| `limit` | number | No | Number of lines to read (default: 2000) |

### Write

Creates or overwrites a file.

```json
{
  "file_path": "/absolute/path/to/file.txt",
  "content": "file contents here"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | Yes | Absolute path to the file |
| `content` | string | Yes | Complete file content to write |

### Edit

Performs exact string replacement in a file.

```json
{
  "file_path": "/absolute/path/to/file.txt",
  "old_string": "text to find",
  "new_string": "replacement text",
  "replace_all": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | Yes | Absolute path to the file |
| `old_string` | string | Yes | Exact text to replace |
| `new_string` | string | Yes | Replacement text |
| `replace_all` | boolean | No | Replace all occurrences (default: false) |

### MultiEdit

Performs multiple edits in a single file atomically.

```json
{
  "file_path": "/absolute/path/to/file.txt",
  "edits": [
    {
      "old_string": "first match",
      "new_string": "first replacement",
      "replace_all": false
    },
    {
      "old_string": "second match",
      "new_string": "second replacement"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file_path` | string | Yes | Absolute path to the file |
| `edits` | array | Yes | Array of edit operations |
| `edits[].old_string` | string | Yes | Text to replace |
| `edits[].new_string` | string | Yes | Replacement text |
| `edits[].replace_all` | boolean | No | Replace all occurrences |

### NotebookEdit

Edits Jupyter notebook cells.

```json
{
  "notebook_path": "/absolute/path/to/notebook.ipynb",
  "new_source": "print('hello')",
  "cell_id": "abc123",
  "cell_type": "code",
  "edit_mode": "replace"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `notebook_path` | string | Yes | Absolute path to .ipynb file |
| `new_source` | string | Yes | New cell content |
| `cell_id` | string | No | ID of cell to edit |
| `cell_type` | string | No | `"code"` or `"markdown"` |
| `edit_mode` | string | No | `"replace"`, `"insert"`, or `"delete"` |

## Search Tools

### Glob

Fast file pattern matching.

```json
{
  "pattern": "**/*.rs",
  "path": "/optional/search/directory"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | Yes | Glob pattern (e.g., `"**/*.js"`, `"src/**/*.ts"`) |
| `path` | string | No | Directory to search in (default: cwd) |

### Grep

Content search using ripgrep.

```json
{
  "pattern": "fn\\s+main",
  "path": "/search/directory",
  "glob": "*.rs",
  "type": "rust",
  "output_mode": "content",
  "-A": 3,
  "-B": 3,
  "-C": 5,
  "-i": true,
  "-n": true,
  "multiline": false,
  "head_limit": 100
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pattern` | string | Yes | Regular expression to search for |
| `path` | string | No | File or directory to search |
| `glob` | string | No | Filter files by glob pattern |
| `type` | string | No | Filter by file type (`"js"`, `"py"`, `"rust"`, etc.) |
| `output_mode` | string | No | `"content"`, `"files_with_matches"`, or `"count"` |
| `-A` | number | No | Lines to show after match |
| `-B` | number | No | Lines to show before match |
| `-C` | number | No | Lines to show before and after match |
| `-i` | boolean | No | Case insensitive search |
| `-n` | boolean | No | Show line numbers (default: true) |
| `multiline` | boolean | No | Enable multiline matching |
| `head_limit` | number | No | Limit output to first N results |

### LS

Lists directory contents.

```json
{
  "path": "/absolute/path/to/directory",
  "ignore": ["node_modules", "*.log"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | Absolute path to directory |
| `ignore` | array | No | Glob patterns to exclude |

## Command Execution

### Bash

Executes shell commands.

```json
{
  "command": "cargo build --release",
  "description": "Build release binary",
  "timeout": 120000,
  "run_in_background": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | Yes | Shell command to execute |
| `description` | string | No | 5-10 word description |
| `timeout` | number | No | Timeout in milliseconds (default: 120000, max: 600000) |
| `run_in_background` | boolean | No | Run asynchronously |

### BashOutput

Retrieves output from background shell.

```json
{
  "bash_id": "shell-abc123",
  "filter": "error|warning"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bash_id` | string | Yes | ID of the background shell |
| `filter` | string | No | Regex to filter output lines |

### KillShell

Terminates a background shell.

```json
{
  "shell_id": "shell-abc123"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `shell_id` | string | Yes | ID of shell to terminate |

## Agent Tools

### Task

Launches a subagent for complex tasks.

```json
{
  "description": "Search for auth code",
  "prompt": "Find all authentication-related code in the codebase",
  "subagent_type": "Explore",
  "model": "haiku",
  "resume": "agent-id-123"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | Yes | Short 3-5 word task description |
| `prompt` | string | Yes | Detailed task instructions |
| `subagent_type` | string | Yes | Agent type (see below) |
| `model` | string | No | `"sonnet"`, `"opus"`, or `"haiku"` |
| `resume` | string | No | Agent ID to resume from |

**Subagent types** (may vary by Claude Code version):
- `general-purpose` - Full tool access for complex tasks
- `Explore` - Fast codebase exploration (Glob, Grep, Read, Bash)
- `Plan` - Software architecture planning
- `statusline-setup` - Configure status line (Read, Edit)

## Web Tools

### WebFetch

Fetches and processes web content.

```json
{
  "url": "https://example.com/docs",
  "prompt": "Extract the API endpoints from this page"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | Fully-formed URL (HTTP upgraded to HTTPS) |
| `prompt` | string | Yes | What information to extract |

### WebSearch

Searches the web.

```json
{
  "query": "rust async tutorial 2025",
  "allowed_domains": ["docs.rs", "rust-lang.org"],
  "blocked_domains": ["pinterest.com"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | Yes | Search query (min 2 characters) |
| `allowed_domains` | array | No | Only include these domains |
| `blocked_domains` | array | No | Exclude these domains |

## Task Management

### TodoWrite

Manages task list.

```json
{
  "todos": [
    {
      "content": "Implement feature X",
      "activeForm": "Implementing feature X",
      "status": "in_progress"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `todos` | array | Yes | Array of todo items |
| `todos[].content` | string | Yes | Task description (imperative form) |
| `todos[].activeForm` | string | Yes | Task description (present continuous) |
| `todos[].status` | string | Yes | `"pending"`, `"in_progress"`, or `"completed"` |

## MCP Tools

MCP (Model Context Protocol) tools have dynamic schemas defined by their servers. They follow the naming pattern `mcp__<server>__<tool>`. To match MCP tools in hooks, use regex patterns like:

```
mcp__.*           # All MCP tools
mcp__github__.*   # All GitHub MCP tools
```

## Fields Used by This Hook

The `claude-code-permissions-hook` currently extracts these fields for rule matching:

| Tool(s) | Field | Used For |
|---------|-------|----------|
| Read, Write, Edit, Glob | `file_path` | Path-based allow/deny rules |
| Bash | `command` | Command pattern matching |
| Task | `subagent_type` | Agent type restrictions |
| Task | `prompt` | Prompt content filtering |

See `src/matcher.rs` for implementation details.
