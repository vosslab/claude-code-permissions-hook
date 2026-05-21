## 2026-05-15

### Behavior or Interface Changes

- Rewrote all 54 deny `reason` strings in `example.toml` and `claude-code-permissions-hook.toml` (the live config; symlink to `~/nsh/junk-drawer/CODEX/claude/claude-code-permissions-hook.toml`) to lead with the next recoverable action instead of the prohibition. Reason text is injected into the agent's next turn after a deny; the first sentence is the highest-attention slot, so opening with the imperative ("Use `git mv` ...", "Invoke the Grep tool: pattern=...") gets the agent unstuck faster than opening with "blocked"/"denied"/"Do not". Standard shape: solution sentence first, rationale clause second, blocked enumeration trailing. Two reasons use `Ask the user to ...` (sudo, force push, podman destructive, registry mutations); one uses `N/A: ...` (gh CLI). The protected-branch workflow block (commit + reset --hard share text) was preserved verbatim with only the leading sentence reordered. Path personalization (~/projects/ in example.toml vs. ~/nsh/ in the live config) is the only intentional diff between the two configs on reason text; a new `tests/test_toml_parse.py` plus a tomllib-based parity tool confirmed both. Rule regexes, allow rules, and `tests/command_decisions.tsv` are untouched -- 1707 fixtures still pass.
- Rewrote the `## Denied commands` section of `docs/CLAUDE_HOOK_USAGE_GUIDE.md` to match the new TOML convention. Each `### <command>` subsection now orders its labelled blocks `**Instead:**` -> `**Why:**` -> `**Blocked:**` instead of the old `Blocked` -> `Why` -> `Instead`. Exception sections (`sed -n` with its `**Allowed (pipe usage):**` block, `git reset --hard` with branch-specific behavior, `git restore .` / `git checkout -- .` with their wholesale-discard enumeration) keep their extra blocks but place them after `**Instead:**`. No anchor labels moved (anchors are heading-derived); no rule regexes changed.

### Additions and New Features

- Added a `## Deny message style` section to `docs/CONFIGURATION_GUIDE.md` (maintainer-facing source of truth). Documents the recovery-path-first convention with preferred / avoided examples. Kept out of `docs/CLAUDE_HOOK_USAGE_GUIDE.md` because that guide is vendored to other repos and must stay agent-facing only.
- Added `tests/test_toml_parse.py`: a fast tomllib-only parse check for both configs (no subprocess). Catches TOML syntax errors introduced by manual edits before the heavier `tools/run_command_decisions.py` fixture suite runs, so a parse regression is no longer blurred with a decision-logic regression. Also asserts every deny rule carries a non-empty `reason` field.

### Decisions and Failures

- Considered adding a `### Denied-command sections` block to `docs/MARKDOWN_STYLE.md` as a reusable documentation-ordering rule. Deferred: `docs/REPO_STYLE.md` marks `docs/MARKDOWN_STYLE.md` as centrally maintained ("do not edit locally"). Will recommend the addition upstream rather than editing the local copy.
- Considered adding a one-sentence note to `## Bash-side reference for redirected commands` in `docs/CLAUDE_HOOK_USAGE_GUIDE.md` ("Deny messages should start with the tool call or command to try next"). Rejected: that guide is vendored to other repos and must stay agent-facing; maintainer convention belongs in `docs/CONFIGURATION_GUIDE.md`.

### Developer Tests and Notes

- `python3 tools/run_command_decisions.py`: 1707 fixtures pass against both `example.toml` and the live config (no expected-outcome changes; only `reason` text changed).
- `pytest tests/test_toml_parse.py`: 2 passed.
- `pytest tests/test_markdown_links.py tests/test_ascii_compliance.py`: 2 passed (guide rewrite preserved every link and stayed ASCII-clean).
- Verified `readlink claude-code-permissions-hook.toml` still resolves to `~/nsh/junk-drawer/CODEX/claude/claude-code-permissions-hook.toml` after the edits; the Edit tool followed the symlink correctly.

## 2026-05-14

### Fixes and Maintenance

- Fixed 83 markdown link errors flagged by `tests/test_markdown_links.py` across `docs/CHANGELOG.md`, `docs/CHANGELOG-2026-05a.md`, `docs/CODE_ARCHITECTURE.md`, `docs/CONFIGURATION_GUIDE.md`, `docs/FILE_STRUCTURE.md`, `docs/INSTALL.md`, `docs/USAGE.md`, and `tests/README.md`. Three failure modes: (1) path-like link text mismatched URL or basename (e.g. `[docs/REPO_STYLE.md](REPO_STYLE.md)` from inside `docs/` -- text rewritten to bare basename per [MARKDOWN_STYLE.md](MARKDOWN_STYLE.md) same-folder rule); (2) broken targets (`docs/WORKTREE_POLICY.md` from inside `docs/` resolved to `docs/docs/...`; lowercase `configuration-guide.md`/`tool-input-schemas.md` -- repointed at the SCREAMING_SNAKE_CASE files that exist); (3) historical changelog references to nonexistent files (`tests/test_hook.py`) and directory-only links (`[src/](../src/)`) converted to inline backticks since the test rejects directory targets and missing-file targets.

### Behavior or Interface Changes

- Denied `awk` (and `gawk`/`mawk`) entirely in both configs and removed `awk` from `TEXT_CMDS`. Unlike the grep/sed denies there is no file-path guard -- awk is denied even as a stdin filter, and pipeline leaves (`... | awk ...`) are caught because the decomposer splits on `|`. Rationale: passthrough-log review showed agent awk usage was almost always line-matching ("find lines matching X, print them"), which is exactly the Grep tool's job, and the awk attempts were consistently overcomplicated; awk's `/regex/` syntax also makes a reliable file-vs-stdin guard impractical, so an unconditional deny is cleaner than a half-working guard. The deny reason steers to the Grep tool, with `cut` or a `_temp.py` script for genuine field extraction. Added eight fixtures to `tests/command_decisions.tsv` (lead-command, pipeline-leaf, absolute-path, and `command`-prefix forms) and removed the two now-stale `allow awk` rows.
- Fixed a regression in the grep/rg file-search deny rule in both configs. The pattern `^${TOOL_PREFIX}(grep|egrep|fgrep|rg)\b[^|]*/` used `[^|]` to scan up to the file-path slash, but grep patterns routinely contain `|` alternation (e.g. `grep -nE "a|b|c" file.md`). The `[^|]*` stopped scanning at the first `|` inside the quoted pattern and never reached the `/`, so any grep with an alternation pattern plus a file path leaked to passthrough instead of being denied. Changed the char class to `[^>]` (the decomposer already splits real pipelines into separate leaves, so a `|` in a leaf is always inside a quoted pattern, never a pipe boundary; the `>` exclusion stays so a stdin filter with a redirect is not denied) and added `${TOOL_PATH}` so absolute-path invocations (`/usr/bin/grep ... file`) are covered by this rule too. Motivation: passthrough-log review showed three `grep <flags> "...|..." <file>` forms slipping through.
- Broadened the python `-c` inline-code deny in both configs. The old rule `/opt/homebrew/bin/python3[^\s]*\s+-c\b` caught only the absolute-path Homebrew binary, so bare `python3 -c "..."` had no deny and was inconsistently handled (the broad python allow rule would pass it unless its script body tripped `NO_CMD_SUB`). New rule `^${TOOL_PREFIX}${TOOL_PATH}python3?[^\s]*\s+(-\S+\s+)*-c\b` denies every invocation form -- bare `python3 -c`, `python -c`, version-suffixed `python3.12 -c`, absolute-path binaries, `command`/`env` prefixes, and interpreter flags before `-c` (`python3 -B -c`). `python3 script.py` is unaffected (no `-c` token). Steers to a `_temp.py` file, matching the existing guidance. Added seven fixtures (every form plus a `python3 -m pytest` negative).
- Applied the same `[^|]` -> `[^>]` fix to the `sed -n` file-extraction deny in both configs. A sed address regex can contain `|` (e.g. `sed -n '/a|b/,/c/p' file`), which the old `[^|]*/` scan would stop on before reaching the file path. Added three fixtures, including a documented known over-match: a `sed -n` with a `/regex/` address is denied even as a stdin filter because the `/` in the address looks like a path to the `[^>]*/` scan -- not a regression (the old `[^|]*/` over-matched identically), same root cause as awk's `/regex/` syntax; plain-numeric stdin ranges stay allowed.
- Corrected `tests/command_decisions.tsv` row `grep -n "sed\|Grep\|Read" /tmp/x.toml`, which was marked `allow` with a comment claiming the tool-name-enumeration pattern must not be denied. That conflated two rules: the tool-name deny anchors on a capital `Grep`/`Read` at start-of-leaf and correctly ignores lowercase grep, but a lowercase grep WITH a file path must still hit the file-grep deny. The row now expects `deny`; a new row keeps the real negative case (same pattern as a stdin filter with no file arg stays `allow`). Added five fixtures for the `|`-in-pattern regression (relative and absolute paths, plus stdin-filter negatives).

### Fixes and Maintenance

- Bumped the version from `26.02` to `26.05` (CalVer `0Y.0M`): `VERSION` to `26.05` and `Cargo.toml` `[package] version` to `26.5.0` (Cargo normalizes the zero-padded month). `Cargo.lock` regenerates on the next `cargo build`.
- Doc-set audit refresh of the main docs. Updated `docs/FILE_STRUCTURE.md`: the `tools/` subtree was missing `test_plan_mode_enforcement.py`, and the `command_decisions.tsv` row-count note was stale (`~490` -> `~1150`). Updated `docs/INSTALL.md`: the `validate` sample output hard-coded `Deny rules: 3` / `Allow rules: 7`, far below the current `example.toml` rule count -- genericized to `<N>` with a note that counts reflect the passed config. Flagged but not changed: the root license file is `LICENSE.LGPL_v3` while `README.md` advertises GPLv3 (legal call for the maintainer); `docs/CHANGELOG.md` is 1232 lines and past the ~1000-line rotation threshold in `docs/REPO_STYLE.md`.
- Applied audit-review fixes to this same 2026-05-14 changeset. Updated `docs/CLAUDE_HOOK_USAGE_GUIDE.md` to match the new rule behavior: removed `awk` from the allowed "safe utilities" list, added a dedicated `### awk` denied section, and rewrote the `### Homebrew python -c` section as `### python -c (inline code)` to reflect that every `python -c` form is now denied. Corrected the cat/head/tail file-deny char class from `[^>|]` to `[^>]` in both configs for consistency with the grep/sed fix (a `|` in a quoted argument before the path no longer breaks the rule). Reworded the `awk` deny `reason` to lead with the awk-specific steer instead of a grep copy-paste. Synced the tool-name-deny comment in the live config to match `example.toml` (the live comment incorrectly claimed the rule matched mid-pipeline; the regex is start-of-leaf anchored). Removed 26 duplicate fixture rows from `tests/command_decisions.tsv`, split the conflated `cat ... | awk` row into single-rule cases, and added `mawk`, absolute-path `egrep`/`fgrep`, and `source source_me.sh && python3 -c` fixtures.
- Polished `docs/CLAUDE_HOOK_USAGE_GUIDE.md` for coders who just want to get unstuck (it was accurate but policy-heavy). Added a short "what to do" lead to the Node.js subsection (`node <script>` / `node --test <test-file>`; write `_temp.js` instead of `node -e`); clarified that `rmdir -p` is allowed and that `rmdir` fails on non-empty targets; made the `for`/`while` "Instead" line a concrete run-the-temp-file recipe. No rule changes -- documentation only.
- Fixed stale `bash -n` claims in `docs/CLAUDE_HOOK_USAGE_GUIDE.md`. The Shell scripts allowed block listed `bash -n script.sh` as allowed and the `bash -c` deny section claimed `bash -n script.sh` was "still allowed", but the live config denies `bash`/`sh`/`zsh -n` (steered to the Read tool) -- the doc predated that deny rule. Removed `bash -n` from the allowed block, corrected the `bash -c` section, and added a dedicated `bash`/`sh`/`zsh -n` entry to the denied commands section. Documentation only; the deny rule itself was already in place.
- Applied audit-review fixes to the 2026-05-13 changeset (no rule-behavior changes). Corrected the `for`/`while` deny comments in both configs: the old comment claimed the shell decomposer "keeps the post-pipe segment as one leaf", an unverified mechanism claim; the comment now describes only what the anchor matches (loop keyword at start-of-leaf, after `|`/`;`/`&`, or after `do `). Fixed the same imprecision in the `for`/`while` doc section and in `tests/command_decisions.tsv`. Rewrote the misleading `node -e "$(curl ...)"` fixture comment to state the real reason (matches no allow rule and no deny rule, so it falls through to passthrough). Removed two duplicate node fixtures (`node -c script.js`, `node --version`) that were already covered by pre-existing rows. Added fixtures for the compound `git mv ... && rmdir` chain, the `find | while` form, and a `do`-nested loop. Rewrapped one over-long line in the Node.js doc subsection. Updated the stale `~440 rows` count in `docs/FILE_STRUCTURE.md` to `~490`.

### Developer Tests and Notes

- Added a "SAFE_CMDS coverage matrix" block to `tests/command_decisions.tsv`: every command in the `TEXT_CMDS`, `SEARCH_CMDS`, `FORMAT_CMDS`, `INSPECT_CMDS`, `CHECKSUM_CMDS`, `FS_CMDS`, `PROC_CMDS`, `SYS_CMDS`, and `DEV_CMDS` groups is tested twice -- bare (no path) and with a `/tmp/x` path argument. This locks in the file-path deny carve-outs: `cat`, `head`, `tail`, `grep`, `rg` deny with a path argument, while every other safe command stays `allow` with a path. A regression in any file-deny rule, or an accidental add/remove of a command from `SAFE_CMDS`, now flips a row.
- Added a second matrix for the absolute-path binary form (`/usr/bin/<cmd>`) of every SAFE_CMDS command, bare and with a path argument. The `SAFE_CMDS` allow rule is `^(${SAFE_CMDS})\b` with no `${TOOL_PATH}`, so an absolute-path invocation does not match the allow: `cat`/`head`/`tail` pass through bare and deny with a path arg, `grep`/`rg` deny unconditionally (dedicated absolute-path grep deny), `sed` passes through except the `-n <range> <file>` shape, and every other safe command passes through both ways. These passthrough rows document a deliberate monitored gap -- absolute-path benign tools are not auto-allowed -- and will flip if `${TOOL_PATH}` is ever added to the `SAFE_CMDS` allow.

## 2026-05-13

### Additions and New Features

- Replaced the four narrow `node` allow rules (`.js/.mjs/.cjs` only, `-c`/`--check`, `-e`/`--eval`, `--version`) in `claude-code-permissions-hook.toml` and `example.toml` with two rules that allow local-script execution plus common dev/test flags. Rule 1: `node <flags> <path>.{js,mjs,cjs,ts,tsx} [script args...]` where flags are `--test`, `--watch`, `--check`, `-c`, `--loader(=|<space>)<arg>`, `--import(=|<space>)<arg>`, or any short `-<letters>` flag. The rule is anchored full-command with a `(\s.*)?$` tail so arguments after the script path are intentionally allowed (the script's own argv is the script's concern), not allowed by accidental prefix matching. Rule 2: bare `node --test`, `node --version`, `node --help`. This unblocks the Node built-in test runner and tsx/ts-node loader workflows that dominated the passthrough log. Inline JS (`-e`/`--eval`) and unrecognized `--long-flags` (`--inspect`, `--experimental-*`) are intentionally left to passthrough: `node` is a general-purpose interpreter (shell spawn, fs, network), and inline code is the dangerous shape -- a tightening over the initially-proposed `^node(\s|$)` blanket allow, which was rejected in review for auto-allowing arbitrary inline JS. Motivation: passthrough-log review (`/tmp/claude-passthrough.json`, 45 entries) showed Claude stalling on ~12 safe `node`/`npx` test-runner invocations per session.
- Added `tsx` to the `npx` whitelist alongside `tsc`, `eslint`, `prettier`, `playwright`, `esbuild`. `npx tsx` is the standard TypeScript file runner (analog to `npx tsc`) used by Node test suites.
- Added `^rmdir(\s|$)` allow rule in both configs. POSIX `rmdir` only removes empty directories (no `-r`/`-R` behavior); a non-empty target errors out. Unblocks `git mv A/* B/ && rmdir A/` cleanup chains that previously hit passthrough on the trailing `rmdir`. ~10 such chains were logged.
- Added new fixtures to `tests/command_decisions.tsv` covering the tightened node allow (script-trailing allow rows, inline-JS and unknown-long-flag passthrough rows), the `tsx` whitelist addition, the `rmdir` allow, and the tightened `for`/`while` deny anchoring. Both `example.toml` and the live symlinked config were updated in the same session, so all fixtures pass against both.

### Behavior or Interface Changes

- Tightened the `for` and `while` deny anchors from `^for\b` / `^while\b` to `(^|[|;&]\s*|\bdo\s+)for\b` and the same for `while`. Catches pipeline forms like `ls *.md | while read f; do grep pat "$f"; done`, sequenced forms `cmd; while ...`, conjunction forms `cmd && for ...`, and nested loops `do for ...`. Motivation: passthrough log showed three file-grep-in-loop forms slipping through despite policy stating loops are denied. Root cause: the shell decomposer keeps `lead | while ...; do ...; done` as one leaf starting with `lead`, so an unanchored `^while` could not match.
- Updated `docs/CLAUDE_HOOK_USAGE_GUIDE.md`: rewrote the Node.js subsection in "Local runtimes" to document the script-trailing allow shape, the whitelisted flag set, and the inline-JS / unknown-long-flag passthrough behavior; added `tsx` to the npx whitelist code block; added an `rmdir` row to the "File deletion (safe patterns)" table; tightened the `for` and `while` loop description to call out the new pipeline-form coverage.

### Decisions and Failures

- Reviewed `/tmp/claude-passthrough.json` (45 entries) at the user's request. By-design passthroughs (ExitPlanMode 8, AskUserQuestion 2, `npm install` 1) accounted for 24%; the rest were almost entirely safe operations that should have been auto-allowed. No security-relevant passthroughs.
- Rejected an initial `^node(\s|$)` blanket-allow proposal in review. It would have auto-allowed arbitrary inline JS via `-e`/`--eval` -- `node` can spawn shells, touch the filesystem, and make network requests, so inline code is the real danger (unlike `npx`, the risk is not just remote-package fetch). Final rule allows only script-trailing forms with a whitelisted flag set and leaves `-e`/`--eval` plus unknown `--long-flags` to passthrough.
- Deferred two findings: (1) widening the Read allow zone for `/Users/vosslab/cell-culture-game-claude/` -- one Read attempt out of 45, user confirms these are coder-CWD-confusion symptoms and leaving them as passthrough is the right shape; (2) decomposer behavior on `wc -l $(git ls-files src/ | grep '\.ts$')` -- single occurrence, command-substitution-as-argument; not worth a rule change yet.
- Dropped the plan's "wrong-path steering deny" item (a deny rule for `~/claude-code-permissions-hook`, the nonexistent path coders sometimes use instead of `~/nsh/claude-code-permissions-hook`). The user confirmed that path was only an illustrative example and asked not to add the specific case, so no rule or fixture was added for it.

### Developer Tests and Notes

- `cargo build` clean; `cargo test` 17 passed (protected-branch integration); `pytest tests/` 142 passed.
- `python3 tools/run_command_decisions.py`: 941 fixtures pass against both `example.toml` and the live `~/.config/claude-code-permissions-hook.toml` (both configs updated in the same session).

## 2026-05-08

### Additions and New Features

- Added two Bash deny rules in `claude-code-permissions-hook.toml` and `example.toml` that block wholesale-discard forms of `git restore` and `git checkout`: any invocation whose pathspec is `.` or `:/`. Covers `git restore .`, `git restore :/`, `git restore --staged --worktree .`, `git restore --source=HEAD .`, `git checkout .`, `git checkout -- .`, `git checkout HEAD -- .`, `git checkout main -- .`, `git checkout :/`, and `git checkout -- :/`. These have the same blast radius as `git reset --hard` -- they wipe every uncommitted change and unstage all renames in one shot. Motivated by an observed incident where an agent ran `git restore .` (or equivalent) in a separate repo and destroyed staged renames, cross-reference rewrites, and changelog updates that lived only in the index + worktree. Single-file forms (`git restore path/to/file.py`, `git checkout -- one_file.py`) and branch switches (`git checkout main`, `git checkout -b feature/x`) remain allowed unchanged.
- Added decision-table coverage in `tests/command_decisions.tsv` for the new denies (10 deny rows for the wholesale-discard shapes, 4 allow rows for single-file and branch-switch forms).
- Added `fsck`, `reflog`, and `cat-file` to the git subcommand allowlist regex in both configs. All three are read-only and directly support the recovery flow agents need after an accidental wipe (`git fsck --lost-found` to surface dangling objects, `git reflog` to find prior index states, `git cat-file -p <blob>` to read recovered content). Without these on the allowlist, the very recovery commands an agent would reach for after a wipe were stuck behind passthrough prompts. Added 6 allow fixtures covering bare and `-C` invocations. Total fixtures now: 883 cases passing across both configs.

### Behavior or Interface Changes

- Added a `### git restore .` and `git checkout -- .` section to `docs/CLAUDE_HOOK_USAGE_GUIDE.md` placed alongside the `git push --force` rule, listing every blocked shape, the rationale (wipes uncommitted work, unstages renames), and the allowed alternatives.

### Decisions and Failures

- Investigated `/tmp/claude-passthrough.json` (1418 entries) at the user's request. Roughly 80% of traffic was synthetic (torture-corpus rotations at 54x/108x batches and hook self-test runs); the rest was real. Identified the wholesale-discard gap above as the highest-priority real-traffic finding -- `git checkout` and `git restore` were both on the git allowlist with no shape filtering, so any of `git restore .`, `git restore --staged --worktree .`, `git checkout -- .`, etc. auto-allowed despite having `git reset --hard`-equivalent blast radius. Other findings flagged for follow-up but not addressed in this commit: tighten abs-path `find`/`grep` denies (already partially done), verify `for`/`while`/`VAR=$(...)` denies are firing as documented, and decide policy for Read of `~/Documents/**` and `/Volumes/**` user data.

## 2026-05-06

### Additions and New Features

- Added a Bash deny rule that catches Claude Code tool names typed as shell commands (`Grep`, `Read`, `Glob`, `Edit`, `Write`, `Task`, `WebFetch`, `WebSearch`). Pattern: agents read steering messages like "Use the Grep tool" and literally paste `Grep -n '^## ' docs/CHANGELOG.md` into Bash, which runs nothing useful. The deny anchors at start-of-leaf and the decomposer handles pipeline splitting, so mid-pipeline cases are still caught without false-positiving on grep patterns that enumerate tool names (e.g. `grep "Grep\|Read" file`). Added TSV fixtures including the regression negative-case.
- Added an explicit `git grep` deny in `claude-code-permissions-hook.toml` and `example.toml`, and dropped `grep` from the allowed git subcommand regex (now: `add|branch|check-ignore|checkout|diff|ls-files|ls-tree|log|mv|pull|remote|restore|rev-parse|show|status|worktree`). Pattern: an agent that hit the file-`grep` deny reached for `git grep` as a Bash escape hatch and stayed shell-side instead of using the Grep tool. The Grep tool is the canonical search path; `git grep` is now denied with the same three-slot reason as the file-grep rule, naming the tool's invocation parameters.
- Tightened the `find` deny to `^${TOOL_PREFIX}${TOOL_PATH}find\b`, so absolute-path invocations (`/usr/bin/find`, `/opt/homebrew/.../find`) and command/env prefixes are caught. Previously the rule only anchored on bare `find`, leaving an obvious bypass.
- Added decision-table coverage in `tests/command_decisions.tsv` for the new escape-hatch and deny rows: `ls /tmp`, `ls docs/`, `git ls-files`, `git ls-files '*.py'`, `git ls-files docs/` (allow); `/usr/bin/find . -name *.py` (deny, regression for the absolute-path gap); `git grep -n pattern`, `git grep -n pattern -- '*.py'`, `git -C /tmp/repo grep -n pattern` (deny).
- Created `docs/CODE_ARCHITECTURE.md`: module map covering `src/main.rs`, `src/lib.rs`, `src/config.rs`, `src/decomposer.rs`, `src/matcher.rs`, `src/auditing.rs`, `src/hook_io.rs`, the end-to-end data flow for a Bash tool call, and extension points.
- Created `docs/FILE_STRUCTURE.md`: top-level layout, key subtrees (src, tests, tools, docs), generated artifacts, documentation map, and where to add new work. Linked both new docs from `README.md`.
- `docs/CLAUDE_HOOK_USAGE_GUIDE.md`: added a top-level **Bash-side reference for redirected commands** section near the Overview that tabulates each denied form, the tool call that replaces it, and the Bash forms that remain allowed (pipeline-only carve-outs, `ls`, `git ls-files`). Added a section for the tool-name-as-Bash deny, a sed -n pipe carve-out section, and a **Pipe-only commands** table summarizing the cat/head/tail, grep/rg, sed -n family that are denied as the lead command but allowed when filtering piped stdin. Added a corresponding row in the **Common patterns** table.
- Added a compound-command note to the guide's decomposition section: a chain like `find ... ; ls ...` fails as a whole even though `ls ...` alone would have been allowed -- agents should drop the denied leaf and re-run rather than rewrite both.

### Behavior or Interface Changes

- Reworded the redirect-style deny `reason` strings in `claude-code-permissions-hook.toml` and `example.toml` for the four rules that steer at a Claude Code tool call: `find` -> Glob, `cat`/`head`/`tail` -> Read, `grep`/`egrep`/`fgrep`/`rg` (relative and absolute path) -> Grep, and `sed -n` on a file -> Read. New text uses the three-slot template "<Tool> is a Claude Code tool call (like Read/Edit/Write). Invoke it directly with <key params>. <Allowed Bash forms>." Motivated by an observed agent loop where the previous "Use the Grep tool instead of grep/egrep/fgrep/rg" message was misread as "find a different grep binary," sending the agent through `/usr/bin/grep`, `/opt/homebrew/.../grep`, then `rg`. The new strings name the tool's invocation parameters, state that the deny covers alternate binaries and absolute paths, and for `find` and the pipeline carve-outs name the legal Bash forms (`ls <dir>`, `git ls-files <pathspec>`, `... | grep pat`, `... | head -5`, `... | sed -n '10,20p'`).
- Tightened the per-rule entries in `docs/CLAUDE_HOOK_USAGE_GUIDE.md` for `cat`/`head`/`tail`, `grep`, and `find` with the same positive-framed three-slot template (tool call + key params + allowed Bash forms). Updated the **Common patterns** intro and replaced the prior "Bash search escape hatch" row with a "Bash file listing" row that names `git ls-files` and `ls <dir>` as the real allowed forms.
- Reworded the `git stash` deny `reason` in `claude-code-permissions-hook.toml` and `example.toml`. The previous message ("Work directly on the current branch") didn't address the common motivation -- agents reach for `git stash` to silence dirty changes in `git diff`, not to switch branches. New message steers to `git diff` / `git diff --staged` for inspection and to committing on an `agent/<task>` branch for setting work aside. Pattern unchanged.
- Narrowed the `sed -n` deny so it only fires when sed is reading a file (path-shaped argument). Previously the rule blocked any `sed -n`, including legitimate piped use like `git diff ... | sed -n '250,400p'` for paginating subprocess stdout, where Read cannot substitute. The reason string now clarifies "sed -n on piped stdin is fine." Added TSV coverage for both the deny (file arg) and allow (pipe) cases.
- Renamed `docs/configuration-guide.md` -> `docs/CONFIGURATION_GUIDE.md` and `docs/tool-input-schemas.md` -> `docs/TOOL_INPUT_SCHEMAS.md` via `git mv` to comply with `docs/REPO_STYLE.md` (SCREAMING_SNAKE_CASE for all docs filenames). Updated all in-repo references.
- Tightened `README.md`: removed the prose "Protected-branch workflow" section (now linked once in the documentation list) so the README stays a short overview + doc map per the readme-fix skill.
- Refreshed `docs/INSTALL.md` and `docs/USAGE.md`: corrected stale output JSON shape (now `{"hookSpecificOutput": {...}}`) and updated the dev-requirements blurb to reflect that pytest is for repo lint gates only, with the decision-table runner driving the hook binary.

### Fixes and Maintenance

- Reworked the `git grep` deny regex from inline `^${TOOL_PREFIX}git\s+(-C\s+\S+\s+)?grep\b` to `.*${GIT_INVOCATION}grep\b`, matching the pattern every other git deny rule (`stash`, `clean`, force-push, etc.) already uses. The previous regex only handled bare `git -C <path> grep` and would not catch `command git grep`, `env X=y git grep`, `/usr/bin/git grep`, `git -c core.pager=cat grep`, or `git --git-dir=.git grep`. Independent reviewers (Style + Test) flagged the gap; the bypass is now closed and the rule is consistent with neighbors.
- Added decision-table coverage for the bypass forms the new regex now catches: `command git grep -n pat`, `env X=y git grep -n pat`, `/usr/bin/git grep -n pat`, `git -c core.pager=cat grep -n pat`.
- Synced the `sed -n` and `git grep` deny-rule comment blocks in the live config (`~/nsh/junk-drawer/CODEX/claude/claude-code-permissions-hook.toml`) to match the longer, more accurate comments in `example.toml`. The live config previously had a stale two-line `sed -n` comment that omitted the stdin-pagination carve-out and a `git grep` comment with vestigial "mid-pipeline" wording copied from the old tool-name deny block.
- Reframed the `git grep` deny `reason` to drop the misleading "pipeline filtering of stdout stays allowed" sentence. The pipeline carve-out is a property of the decomposer's pipe-splitting, not of this rule's regex; mentioning it in this rule's reason could mislead someone debugging why a pipeline case fired.
- Merged the two redundant `find . -name "*.py"` rows in `docs/CLAUDE_HOOK_USAGE_GUIDE.md` **Common patterns** table into a single row that names both the Glob tool (canonical fix) and the allowed Bash forms (`ls <dir>`, `git ls-files <pathspec>`).
- Added a `### \`git grep\`` subsection to the guide's **Denied commands** list, mirroring the per-rule format used by the other redirect-style denies. Agents reading the guide cold now see that `git grep` is explicitly denied and what the alternative is.
- Relaxed the `rm` deny in `claude-code-permissions-hook.toml` and `example.toml` to allow paths under `~/nsh/` (the same zone the Write/Edit tools already operate in) and bare relative paths. Same blast radius as Write -- an agent that can Write a source file can already overwrite it; rm is no more dangerous. Motivated by an observed loop where the agent had explicit user approval to delete two specific files (`Final_Exam/Final_Exam_2A_2B_combined.{yaml,docx}`) but `rm` was hard-denied, so the agent reached for `python3 -c "import os; os.remove(...)"` -- the same kind of bypass loop the grep/find rework was meant to break. Two new hard-deny rules still block dangerous shapes regardless of the relaxation: (1) `rm` against system directories (`/etc /usr /opt /System /Library /var /bin /sbin /Volumes /private /boot /dev /proc /sys /root /lib`), bare `/`, `~`, `$HOME`, or unanchored `*`; (2) `rm` with `..` traversal anywhere in the path. Decided against switching `rm` to passthrough (which would prompt the user) because that would stall overnight autonomous runs.
- Added decision-table coverage for the `rm` relaxation: positive cases (paths under `~/nsh/`, bare relative paths like `Final_Exam/foo.yaml` and `subdir/nested/file.txt`, `rm -rf build_output`), the existing safe patterns (`/tmp/`, `_prefix`, caches, `git rm`), the system-path hard-denies, the bare root/$HOME/wildcard hard-denies, and the `..` traversal hard-deny including the case where traversal escapes from a path that starts under `~/nsh/`. Flipped the pre-existing `deny rm -rf src/` row to `allow` since the new bare-relative-path allow rule now covers it (consistent with the new intent).
- Fixed a stale runner reference in the `tests/command_decisions.tsv` header comment (`tests/run_command_decisions.sh` -> `tools/run_command_decisions.py`); the shell runner was deleted earlier on this date.

### Removals and Deprecations

- Moved `tests/run_command_decisions.py` -> `tools/run_command_decisions.py`
  via `git mv`. The script drives the hook binary against a fixture
  corpus -- it is operational tooling, not a pytest file, so it
  belongs under `tools/`. Updated `README.md`, `docs/USAGE.md`,
  `tests/README.md`, and `config_test.sh` to point at the new path.
  The runner adds `tests/` to `sys.path` so the existing
  `git_file_utils` helper still imports cleanly.
- Deleted `tests/test_hook.py` (2317 lines, 123 parametrized test
  functions). Its decision-table coverage is now expressed as rows in
  `tests/command_decisions.tsv`. The pytest harness was a poor fit for
  what was effectively a fixture corpus driving a binary -- per-case
  subprocess startup dominated wall time, and there was already a
  separate shell runner (`tests/run_command_decisions.sh`) with the
  same shape.
- Deleted `tests/run_command_decisions.sh`. Replaced by
  `tools/run_command_decisions.py` (lives under `tools/` since it is
  operational tooling that drives the binary, not a pytest file). The
  Python rewrite understands a richer TSV format covering non-Bash
  tools (Read/Write/Edit/Glob/Grep/WebFetch/WebSearch/etc.) and
  supports per-row config overrides for the small subset of cases that
  depend on `tests/test_config.toml`'s synthetic path-zone setup.
  Why Python over bash: the new format embeds JSON `tool_input` blobs
  inside the outer hook-input JSON envelope, which is painful to
  escape correctly in shell. Python's `json` module makes it trivial.
- `tests/test_config.toml` is retained because `tests/integration_test.rs`
  (the Rust integration test suite) still references it.
- Updated `README.md`, `docs/USAGE.md`, and `tests/README.md` to point
  at the new runner. pytest is now reserved for repo-wide Python
  source-quality gates (pyflakes, ascii, shebangs, imports, etc.) and
  not for hook decision testing.

### Decisions and Failures

- Initial tool-name deny used a mid-pipeline alternation
  `(^|\||&&|;|\$\()\s*(Grep|Read|...)` and false-positived on
  `grep "sed\|Grep\|Read" file` because the regex saw `\|Grep` inside
  the quoted argument. Fixed by relying on the leaf decomposer (which
  already splits on `|`/`&&`/`;`) and anchoring only at start-of-leaf.
  Lesson: when the decomposer already covers a separator, do not also
  encode it in the regex -- the regex sees raw command text including
  quoted arguments.

## 2026-05-05

### Additions and New Features

- Added `[variables] TOOL_PREFIX` and `TOOL_PATH` regex helpers in
  `example.toml` and the live config. `TOOL_PREFIX` matches optional
  `command ` or `env ` invocation prefixes; `TOOL_PATH` matches an
  optional absolute-path prefix on the tool name (e.g. `/usr/bin/`,
  `/opt/homebrew/bin/`). `PATH=...` and other env-var assignments are
  already stripped structurally by the decomposer, so they do not need
  separate regex variants. Caveat: `env FOO=bar <cmd>` (env tool
  followed by an inline assignment) is NOT covered by `TOOL_PREFIX`
  alone; this residual gap is documented and left for follow-up if it
  appears in real traffic.

### Tier A: confirmed real-traffic bypass fixes

A 2026-05-05 audit of `/tmp/claude-passthrough.json` (516 entries, 19
sessions) revealed two real evasion patterns reaching passthrough:

- `/usr/bin/grep -n "ui\." src/...` -- absolute-path grep with a
  relative path argument. The previous absolute-path grep deny
  (`example.toml:347` before this commit) only matched when the
  argument started with `/`. The bypass used `src/...` (no leading
  slash) and slipped through.
- `bash -n ~/.claude/skills/.../check_codebase.sh` -- shell-as-analysis
  via `bash -n`. The previous rule (`example.toml:608` before this
  commit) explicitly ALLOWED this form, which is the wrong default.

Fixes:

- Rewrote the cat/head/tail, grep/rg, and sed -n denies to use
  `${TOOL_PREFIX}` (catches `command grep`, `env grep`).
- Replaced the two pre-existing grep denies with one path-shaped-arg
  deny plus an unconditional absolute-path-grep deny (any
  `/usr/bin/grep`, `/opt/homebrew/bin/rg`, etc. is steered regardless
  of arguments).
- Replaced the `[[allow]]` for `bash -n script.sh` with a `[[deny]]`
  covering `bash`/`sh`/`zsh -n` on any script. Steer message points
  agents to the Read tool for inspection.
- Added 13 TSV fixtures in `tests/command_decisions.tsv` covering the
  two confirmed bypasses, the `command`/`env` prefix variants, and the
  absolute-path no-path-arg case.

### Tier B: preventive hardening

These rules close known evasion shapes that did not appear in the
real-traffic sample but did appear in synthetic torture-fixture
sessions:

- Pipe-to-interpreter deny extended from `(curl|wget) | (bash|sh|python|node)`
  to `(curl|wget|fetch) | (python3?|bash|sh|zsh|node|ruby|perl)`.
- Sensitive-path read deny added: matches `/etc/passwd`, `/etc/shadow`,
  `/etc/sudoers`, `/etc/hosts`, `~/.ssh/`, `~/.aws/credentials`, and
  the macOS-resolved equivalents under `/Users/<u>/`. Placed before the
  broad allow blocks so it fires first regardless of the underlying
  tool (cat, sox, grep, etc.).
- Registry-mutating package commands explicitly denied:
  `cargo (publish|yank|login|logout|owner)` and
  `npm (publish|unpublish|deprecate|owner|adduser|login|logout|token)`.
  Previously these fell through to silent passthrough; now they
  produce an explicit steer message.
- System package install denied: `brew (install|uninstall|reinstall|upgrade|tap|untap|cask)`.
- Added 23 TSV fixtures covering the pipe-to-interpreter expansions,
  sensitive-path reads, registry-mutating cargo/npm, and brew system
  installs.

### Behavior or Interface Changes

- `bash -n script.sh` is no longer allowed. Steered to the Read tool.
  Existing `bash script.sh` (execution, no `-n`) remains allowed.
- The two pre-existing grep denies (one for bare grep with absolute-path
  arg, one for absolute-path grep with absolute-path arg) collapsed into
  two new denies (path-shaped-arg + absolute-path-unconditional).
- `cargo publish/yank/login/logout/owner` and the equivalent npm
  registry commands are now denied with a steer message instead of
  passthrough. The cargo allow rule already excluded these subcommands;
  the new deny replaces the silent passthrough.
- `brew install foo` is now denied (was passthrough). The pre-existing
  TSV row was updated from `passthrough` to `deny`.
- `wget https://x | python3` is now denied (was passthrough; the
  pre-existing curl|interpreter rule covered fewer interpreters).

### Verification

- `cargo build --release` clean.
- `bash tests/run_command_decisions.sh` -- 330/330 pass on both example
  and live configs (was 297/297 before this change).
- `cargo test --release` -- 103 tests pass, 0 failures.
- Spot-check by hand on the two original bypasses confirms each
  receives `permissionDecision":"deny"` with the new steer message.

### Known limitations

- `env FOO=bar grep ...` (env tool followed by an inline assignment) is
  not covered by `TOOL_PREFIX`. Document-only; not observed in real
  traffic. If it appears, add a dedicated pattern.
- `npx` auto-install allowlist (B4 in the audit plan) was deliberately
  deferred. The audit showed `npx tsx` and `npx tsc` as the most common
  legitimate commands (107 invocations); a heuristic deny would have
  high false-positive risk against real workflow traffic.

## 2026-05-04

### Additions and New Features

- Ported the full protected-branch rule set into the live user config at
  `~/nsh/junk-drawer/CODEX/claude/claude-code-permissions-hook.toml` so the
  new behavior is active in real Claude sessions. Live and example configs
  now have parity on every TSV case (297/297 pass on each).
- Updated `tests/run_command_decisions.sh` with ANSI-colored output: green
  pass message on full success, loud red FAIL lines and a banner-style
  failure block when live and example diverge. The script still exits
  non-zero on any mismatch -- drift between configs is a hard failure.
- Added `[git_protection]` config section with `protected_branches` (list of
  branch names; default `["main", "master"]`) and `protected_refs` (list of full
  ref paths; default `["refs/heads/main", "refs/heads/master"]`). Allows
  customization of which branches are protected from agent mutation.
- Added `protected_branch_check` rule field that gates a rule on live git state
  via `git rev-parse --abbrev-ref HEAD`. When `true`, the rule fires only if the
  current branch is in `protected_branches`.
- Added one allowed merge form on protected branches:
  `git merge --no-commit --no-ff <non-protected-source>`. The allow rule is
  narrow: rejects missing source, protected source branches, and `-m` /
  `--message`. The human writes the commit message at finalization.
- Added two paired denies that catch the disallowed merge-prepare variants:
  `-m`/`--message` on the merge-prepare line, and a protected source branch.
  These produce specific steering messages instead of falling through to
  passthrough.
- Added [WORKTREE_POLICY.md](WORKTREE_POLICY.md) as the canonical
  maintainer-facing reference for the protected-branch workflow,
  configuration, allowed/denied table, and security model.
- Trimmed the protected-branch section in `docs/CLAUDE_HOOK_USAGE_GUIDE.md` to
  a short summary and pointer to `docs/WORKTREE_POLICY.md`.

### Behavior or Interface Changes

- Switched `git commit` from blanket deny to branch-aware deny: denied only on
  protected branches; allowed on agent/feature branches.
- Switched `git reset --hard` from blanket deny to branch-aware deny: denied on
  protected branches; allowed on agent/feature branches.
- Switched `git rebase`, `git cherry-pick`, `git revert` from blanket denies to
  branch-aware denies (same pattern).
- Added blanket deny for all push forms targeting protected refs, covering:
  `git push <remote> <protected>`, `git push <remote> <any>:<protected>`,
  `git push <remote> refs/heads/<protected>`, `git push <remote> :<protected>`,
  `git push --delete origin <protected>`. All forms are denied; agents do not
  push protected refs (humans push after final commit).
- Updated `docs/CLAUDE_HOOK_USAGE_GUIDE.md` section "git commit, git stash,
  git clean" to explain branch awareness and link to the new workflow section.
- Updated `docs/CLAUDE_HOOK_USAGE_GUIDE.md` section "git reset --hard" to note
  it is now branch-aware.
- Updated `docs/configuration-guide.md` with `[git_protection]` schema entry,
  documenting `protected_branches`, `protected_refs`, and `protected_branch_check`.
- Updated `README.md` with a new subsection "Protected-branch workflow: agents
  prepare, humans commit" linking to `docs/WORKTREE_POLICY.md`.
- Made `--continue` denies unconditional (every branch) for `git merge`,
  `git cherry-pick`, `git revert`, and `git rebase`. These finalize commits
  after conflict resolution and violate the "human makes the commit" rule.
- Wired auto-injected `${PROTECTED_REFS}` (full ref paths plus bare branch
  names) and `${PROTECTED_BRANCHES}` into the push, ref-plumbing, and
  branch -f rules so `protected_branches = ["trunk"]` actually protects
  `trunk`, `refs/heads/trunk`, and refspec targets ending in either form.
- Wired the shared `${GIT_INVOCATION}` regex variable into every git rule.
  Centralizes recognition of `git`, `command git`, `/usr/bin/git`,
  `/opt/homebrew/bin/git`, `GIT_DIR=... git`, and `git -C <path>` in one
  place.
- Added 11 integration tests in `tests/test_protected_branch.rs` covering
  config override (`trunk` instead of `main`), fail-closed on non-repo cwd,
  `git -C <other-repo>` branch resolution, raw `git merge` deny on protected,
  `--no-commit --no-ff` with protected source, `-m` flag rejection, missing
  `--no-commit` or `--no-ff` boundary cases, prepare-merge allow on feature
  branches, `merge --continue` deny, and `merge --abort` allow.

### Scope

This change is a guardrail for normal Git workflows, not a security boundary.
Real enforcement belongs on the forge (branch protection, required PRs, no
force push) and at the OS layer. Maintainer-facing detail in
[WORKTREE_POLICY.md](WORKTREE_POLICY.md).

## 2026-04-27

### Additions and New Features

- Added `make`, `bandit`, `column`, `shasum`, `sha256sum` to the safe-command
  allowlist. Driven by a passthrough-log review showing these as common,
  legitimate Claude requests that were stalling on user prompts.
- Added `./bin/<name>` and `./bin/<name>.exe` to the local-executable allow
  rules so project-shipped compiled tools (e.g. `./bin/Volume.exe`) run without
  user approval.
- Added `ffprobe` deny rule with steering message pointing Claude to
  `mediainfo --Output=JSON`, with an exclude/allow pair that keeps
  `ffprobe -show_chapters`, `-show_packets`, `-show_frames`, and
  `-f lavfi` available (the cases mediainfo cannot handle). Driven by a
  passthrough-log review.
- Added `TMP_SCOPED_CMDS` variable (`ffmpeg|sox` to start) and a single
  generic allow rule that grants any tool in the group when the leaf only
  touches `/tmp` or `/private/tmp`. Backed by a `NON_TMP_ROOTS` denylist
  variable (`Users|home|usr|etc|opt|var|bin|...`) reused in the exclude.
  Adding a new tmp-scoped tool is a one-token edit to `TMP_SCOPED_CMDS`.
- Added `tests/command_decisions.tsv` (fixture) and
  `tests/run_command_decisions.sh` (runner) for iteratively building up
  expected-decision coverage against the live config. Wired into
  `config_test.sh`. Seeded with 93 regression cases drawn from
  `docs/CLAUDE_HOOK_USAGE_GUIDE.md` (Python/git/cargo/npm/pip/podman/
  rm/cat/grep/sed-n/find/sudo/gh/curl-pipe-bash/heredoc/bare-assignments)
  plus the new ffprobe and tmp-scoped rules.
- Mirrored `TMP_SCOPED_CMDS`, `NON_TMP_ROOTS`, the ffprobe deny+allow
  pair, and the tmp-scoped allow rule into `example.toml` so the
  reference config matches the live config.
- Updated `docs/CLAUDE_HOOK_USAGE_GUIDE.md` with new sections for
  "Tools scoped to /tmp scratch dirs" (allow) and "ffprobe (steered to
  mediainfo)" (deny), plus two new rows in the common-patterns table.

### Behavior or Interface Changes

- Reorganized the long `FILE_CMDS` and `SYS_CMDS` variables into smaller
  semantic groups: `TEXT_CMDS`, `SEARCH_CMDS`, `FORMAT_CMDS`, `INSPECT_CMDS`,
  `CHECKSUM_CMDS`, `FS_CMDS`, `PROC_CMDS`, `SYS_CMDS`, and `DEV_CMDS`.
  `SAFE_CMDS` now merges all of them. Naming makes the intent of each safe
  utility group obvious.
- Extended the grep file-path deny rule to also block `egrep` and `fgrep`
  (both bare and absolute-path forms), steering Claude to the Grep tool.
  `egrep`/`fgrep` are deprecated GNU aliases but still common in habit.

### Fixes and Maintenance

- Synced `example.toml` to be a full mirror of the production config
  (90 rules, 31 deny, 59 allow), with personal paths genericized:
  `~/nsh/` -> `~/projects/`, `NSH_PATH` -> `PROJECT_PATH`,
  `audit_level = "all"` -> `"matched"`. Previously the example was a
  trimmed-down 365-line subset that drifted out of sync with reality.
- `config_test.sh`: 23 tests pass, both production and example configs
  validate.
- Expanded `tests/command_decisions.tsv` from 93 to 268 regression cases,
  adding coverage for safe utilities (awk/jq/sort/wc/date/pwd/uname/etc.),
  the new `make`/`bandit`/`column`/`shasum`/`sha256sum`/`md5sum` allow rules,
  pipeline forms of cat/head/tail/grep, file-path forms of the dedicated-tool
  deny rules (incl. `egrep`/`fgrep`), `./bin/<name>(.exe)?` local-exec
  patterns, more git/cargo/node/deno/eslint/prettier/podman/pip/npm/brew
  cases, the `TMP_SCOPED_CMDS` group (optipng, jpegoptim, lame, flac,
  pngcrush, cwebp, pdftk, gm, mogrify) plus mixed-root passthroughs,
  rm-exception patterns, more heredoc/loop/`bash -c`/env-var denies,
  ffprobe edge cases, and `perl` on PG/PGML. `tests/run_command_decisions.sh`
  now evaluates every fixture against both the live config and
  `example.toml`; Bash command rules are byte-identical between them, so
  every row must produce the same decision on both.

## 2026-04-22

### Additions and New Features

- Added `grep` to the git allowlist (line 418 of the production `.toml`).
  `git grep` is inherently read-only -- no write mode exists -- and the
  2026-04-22 passthrough log showed 8 of 16 Bash passthroughs were
  `git grep` invocations (both in-tree and `--no-index` absolute-path
  forms) during a rename refactor. Covers `git grep ...`,
  `git grep --no-index ...`, and `git -C <dir> grep ...`. The existing
  `${NO_CMD_SUB}` exclude still blocks command substitution.
- Extended the pip info allow rule to cover `python -m pip` invocation.
  Old regex `^pip3?\s+(show|list|freeze|check)` only matched bare
  `pip`/`pip3`; new regex
  `^(pip3?|python3?\s+-m\s+pip)\s+(show|list|freeze|check)` also matches
  `python -m pip show`, `python3 -m pip list`, etc. The `python -m pip`
  form is the pip team's officially recommended invocation and is
  functionally different from bare `pip` (it pins to a specific
  interpreter), so an allow (not a steering deny) is the right fit.
  `pip install` and `pip uninstall` still passthrough.

### Tests

- Mirrored both rules into
  [test_config.toml](../tests/test_config.toml) so integration
  tests exercise them.
- Added 23 parametrized cases in
  `tests/test_hook.py`:
  `test_git_grep_allowed` (8), `test_git_grep_command_substitution_blocked`
  (2), `test_python_m_pip_info_allowed` (8),
  `test_pip_install_passthrough` (5 regression cases covering
  install/uninstall across `pip`, `pip3`, `python -m pip`, `python3 -m pip`).
  Full suite: 655 passed (up from 621 after the 2026-04-13 additions +
  prior growth). Pyflakes lint: 18 passed.

## 2026-04-13

### Build/Tooling

- `config_test.sh`: after a successful build/test/validate, remove
  `target/debug` and the release `deps`/`build`/`incremental`/rlib scratch,
  keeping only the 3.6M release binary. Shrinks `target/` from ~666M to ~4M.
  Uses `set -e` and `git rev-parse --show-toplevel` for REPO_ROOT.

### Additions and New Features

- Added `pdftotext` to `FILE_CMDS` safe-utility group. Read-only PDF-to-text
  extractor appeared 6 times in the passthrough log for lecture material
  extraction; no side effects, belongs with `awk`/`cat`/`jq`.
- Added `esbuild` to the `npx` whitelist alongside `tsc`/`eslint`/`prettier`/
  `playwright`. Same class of local-dev build tool; eliminates one
  passthrough class.
- Added `podman` allow rule for read-only inspection, build, compose,
  lifecycle, and exec subcommands (`ps`, `pod`, `images`, `image ls`, `logs`,
  `inspect`, `info`, `version`, `port`, `top`, `stats`, `history`, `diff`,
  `build`, `compose`, `start`, `stop`, `restart`, `pull`, `tag`, `cp`,
  `exec`). Covers a coherent 3vee-server debugging session that accounted
  for 14 passthroughs.
- Added matching `podman` deny rule for destructive operations: `rm -f`,
  `rmi -f`, `kill`, `stop -t 0`, `system prune`, `volume rm|prune`,
  `network rm|prune`, `image rm|prune`. Ask the user manually for these.
- Added narrow allow for the exact `npm install` commands that the tsc
  steering deny recommends: `npm install --save-dev typescript` and
  `npm install -g typescript`. All other `npm install` variations (version
  pins, extra packages, different flags) still passthrough for user
  approval. Lets Claude self-remediate a missing TypeScript install without
  opening the door to arbitrary package installation.
- Added steering deny for `tsc` via `node_modules` paths (matches
  `./node_modules/.bin/tsc`, `./node_modules/typescript/bin/tsc`, absolute
  path forms, and `node node_modules/typescript/bin/tsc`). Redirects to
  `npx tsc`; the passthrough log showed Claude retrying 6 invocation forms
  (9 calls total) in one TypeScript session, which is a workaround pattern
  we want to surface as a real "install TypeScript" problem instead.

### Documentation

- Updated [CLAUDE_HOOK_USAGE_GUIDE.md](CLAUDE_HOOK_USAGE_GUIDE.md):
  added `pdftotext` to safe utilities, added `esbuild` to the npx whitelist
  section, added a new "Podman (containers)" section under Allowed commands,
  added a new "`tsc` via `node_modules` paths" entry under Denied commands.

### Tests

- Mirrored the four new rules into
  [test_config.toml](../tests/test_config.toml) so they are covered by
  integration tests.
- Added 47 parametrized cases in
  `tests/test_hook.py`:
  `test_pdftotext_allowed` (3),
  `test_npx_whitelist_allowed` (7),
  `test_npx_non_whitelist_passthrough` (2),
  `test_podman_allowed` (17),
  `test_podman_destructive_denied` (12),
  `test_tsc_node_modules_steering_denied` (6, including a
  `source source_me.sh &&` compound variant and a reason-message assertion).
  Full suite: 621 passed (up from 574). Pyflakes lint: 18 passed.

## 2026-04-05

### Fixes and Maintenance

- Fixed rm underscore-prefix regex to match full paths (e.g.,
  `rm -f /path/to/dir/_test_file.ts`). Previously only matched when the filename
  argument started with `_`, not when `_` appeared after a path separator.
  Updated both the deny exclude regex and the allow rule.
- Added `playwright` to the npx whitelist for local browser testing
  (screenshots, automation).

## 2026-04-04

### Additions and New Features

- Added `npx` allow rule with whitelisted packages (`tsc`, `eslint`, `prettier`).
  Unknown npx packages still passthrough to user prompt. This eliminates ~86% of
  Bash passthroughs from the passthrough log (132 of 154 were `npx tsc`)
- Added allow rules for `eslint` and `prettier` as direct commands for linting
  and formatting TypeScript/JavaScript projects
- Added `npm run` allow rule for executing local `package.json` scripts
  (`npm run build`, `npm run test`, etc.)
- Added `node -e` / `node --eval` allow rule for quick inline JS evaluation
  (e.g., JSON validation)

### Fixes and Maintenance

- Added `${NO_CMD_SUB}` (command substitution blocking) to all allow rules that
  accept user-controlled arguments: `pytest`/`pyflakes`, `git` subcommands,
  `launchctl`, `pip`/`brew`/`npm` read-only queries, and all four `rm` exception
  rules (`git rm`, `rm /tmp/`, `rm *Cache*`, `rm _prefix`). Only `--version` and
  `--check` rules (no meaningful arguments) were intentionally left without it
- Updated `example.toml` to match: added `NO_CMD_SUB` to all rules that accept
  arguments, added node/npx/eslint/prettier/deno/npm run/package manager rules

### Decisions and Failures

- Passthrough log assessment (296 entries): all commands were legitimate. The
  sports-life-game TypeScript project generated 205/296 entries, mostly `npx tsc`
  compilations. The whitelist approach for npx preserves security while allowing
  routine dev tool usage

## 2026-04-02

### Additions and New Features

- Added deny rule for `perl` on `.pg` and `.pgml` files. PGML is not standard Perl;
  agents are steered to the `/webwork-writer` skill lint guide instead
- Added allow rule for `launchctl` read-only queries (`list`, `print`, `blame`,
  `dumpstate`, `dumpjpcategory`). Mutating subcommands (`load`, `unload`, `bootout`,
  `kickstart`, `enable`, `disable`) still fall through to passthrough
- Added allow rules for Read/Glob/Grep on `~/Library/LaunchAgents/` and
  `~/Library/Logs/` for debugging launchd jobs. Write/Edit remain denied
- Added allow rule for `mkdocs` local subcommands (`--version`, `build`, `serve`)

### Fixes and Maintenance

- Fixed Glob and Grep `/tmp` allow rules to match bare `/tmp` directory path (without
  trailing slash). Previously `path: "/tmp"` fell through to passthrough because the
  regex `^(/private)?/tmp/` required a trailing slash. Changed to `^(/private)?/tmp(/|$)`
  for Glob and Grep only. Read/Write/Edit left unchanged since they operate on files,
  not directories

## 2026-03-31

### Additions and New Features

- Added `update_rust.sh` script to update Rust toolchains via `rustup update`
  and rustup itself via `brew upgrade rustup` (Homebrew-managed install)

## 2026-03-26

### Additions and New Features

- Added Write/Edit allow rules for macOS per-user temp directory
  (`^/var/folders/[^/]+/[^/]+/T/`). Previously only Read was allowed for
  `/var/folders/`. The regex targets only the `T/` temp subdirectory, not
  caches (`C/`) or other dirs. Fixes issue where `tempfile.gettempdir()` paths
  were blocked for writes

- Added `tools/test_plan_mode_enforcement.py`: two-phase A/B test for Claude Code
  plan mode enforcement. Runs 4 prompt variants, each with a control phase (no
  plan mode, must succeed) then plan mode phase (should be blocked). Verdict is
  based on filesystem state (MD5), not Claude's text. A prompt is valid only if
  its control edit succeeds. Uses `--effort low` for faster runs. Includes colored
  terminal output and JSON response parsing for diagnostics. Confirms upstream bug
  (anthropics/claude-code#14570, #19874). Exit codes: 0=PASS, 1=FAIL, 2=SKIP

- **TOML trust model restructure**: separated "can execute code" from "can change the
  machine". `JS_CMDS` removed; runtimes moved out of `SAFE_CMDS` into new
  `LOCAL_RUNTIMES = "node|deno"` with constrained allow patterns (.js/.mjs/.cjs files,
  syntax checks, local deno subcommands). npx deliberately excluded -- passthroughs to
  user prompt since it may fetch remote packages
- **Rust decomposer: strip env-var prefixes from leaf commands** (`src/decomposer.rs`).
  `NODE_PATH=/foo node script.js` now decomposes to `node script.js`. Eliminates
  duplicate env-prefixed TOML allow rules and prevents env-prefix back doors. Uses
  AST-structural `AssignmentWord` detection, not regex. Also extracts `$()` from
  stripped assignment values so inner commands still get rule-checked
- **Rust matcher: missing subagent\_type fails closed** (`src/matcher.rs`). Agent tool
  calls without `subagent_type` now pass through to user prompt instead of silently
  defaulting to "general-purpose"
- **Agent allow rule**: replaced hardcoded list of 20+ agent names with broad pattern
  `^[a-zA-Z][a-zA-Z0-9_:-]*$`. New agents in `~/.claude/agents/` are auto-allowed
  without TOML changes. Documented two-layer permission model (hook gates launch,
  agent .md specs constrain tools)
- 7 new deny-and-steer rules: sudo, git reset --hard, git push --force (including
  --force-with-lease), deno run with URLs, curl/wget piped to runtime, Write to
  system dirs, Edit to system dirs
- Added `reason` steering to 4 existing deny rules that lacked guidance: rm, .env
  reads, git commit, git stash. Every deny rule now has a reason field
- `HOME_PATH` tightened from `^$HOME/(nsh|\.)?` (matched all of home) to
  `^$HOME/(nsh(/|$)|\.[^/]+(/|$))` (nsh + top-level dotdirs only)
- `NSH_PATH` tightened from `^$HOME/nsh` to `^$HOME/nsh(/|$)` to match both the
  directory itself and its contents
- Added passthrough gap fixes: bare relative-path .py/.sh scripts without `./` prefix
  (e.g. `tools/runner.py`) now match allow rules
- `open`, `which`, `type` added to `FS_CMDS`; `find` removed (has deny-and-steer rule)
- Improved section comments across all TOML rule groups documenting trust rationale
- Updated [CLAUDE_HOOK_USAGE_GUIDE.md](CLAUDE_HOOK_USAGE_GUIDE.md) and
  [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) with new trust model

### Behavior or Interface Changes

- deno eval no longer auto-allowed; falls through to passthrough (user prompted)
- npm install, pip install, git rebase intentionally left as passthrough (not denied)
  so user can approve legitimate uses
- Bare assignment deny message updated from TOML-internal language to user-friendly
  "no command after assignment" steering

### Decisions and Failures

- Trust model philosophy: "allow routine local work, deny/steer on machine-changing
  actions, prompt on high-impact operations"
- npx kept as passthrough (not hard deny) because some npx usage is reasonable and
  not every npx use has an MCP substitute
- Env-var prefix stripping done unconditionally (AST-structural) rather than
  uppercase-only, per user guidance: decomposer should be syntax-level, not
  policy-opinionated
- LOCAL_RUNTIMES kept narrow (node|deno only); will grow from passthrough log
  evidence, not in advance

### Developer Tests and Notes

- Added 5 decomposer tests for env-var stripping: uppercase, lowercase, LC_ALL,
  multiple assignments, bare assignment
- Updated matcher test `test_agent_missing_subagent_type_fails_closed` (was
  `test_agent_missing_subagent_type_defaults_to_general_purpose`)
- All 63 tests pass (34 decomposer + 16 matcher + 13 integration)

### Previous entries for 2026-03-26

- Updated [CLAUDE_HOOK_USAGE_GUIDE.md](CLAUDE_HOOK_USAGE_GUIDE.md) to reflect
  restructured permissions model: added trust model philosophy, env-var assignment
  decomposer behavior, new "Local runtimes" section with node/deno/npx details,
  npm read-only commands, expanded denied commands (sudo, git reset --hard,
  git push --force, deno run URLs, curl/wget piped to runtime, Write/Edit to
  system directories). Replaced hardcoded agent list with regex pattern. Split
  passthrough section into "user approval" (npm install, pip install, git rebase,
  deno eval) and "interactive tools" (worktree, cron, dialogs). Added bare
  relative-path scripts to shell scripts section (tools/runner.py, scripts/build.sh).
  Updated file access zones table to clarify Read paths (~/nsh/ vs full home).
  Removed env-prefixed commands subsection (handled by decomposer)

### Additions and New Features (continued)

- Added `JS_CMDS` variable group (`node|deno|npx`) to production TOML and merged
  into `SAFE_CMDS`. Eliminates 6 node + 2 deno Bash passthroughs from laptop log
  and 9 node + 3 npx passthroughs from studio log
- Added npm read-only allow rule for `npm list|root|ls|show|view|info|search|
  outdated|doctor|prefix|version|--version`. npm install/uninstall remains as
  passthrough for user permission
- **Rust: normalize missing Agent subagent\_type to "general-purpose"**: When the
  `subagent_type` field is absent from Agent tool input JSON, the matcher now
  treats it as `"general-purpose"` (Claude Code's documented default) before
  matching against `subagent_type_regex`. Eliminates 6 Agent passthroughs. Added
  unit test `test_agent_missing_subagent_type_defaults_to_general_purpose`
- Updated `improve_prompt.txt` with JSONL format note and guiding principle about
  allowing reasonable requests

### Fixes and Maintenance

- Fixed `NSH_PATH` variable from `^$HOME/nsh/` to `^$HOME/nsh` to match paths
  without trailing slash (e.g., Glob/Grep with `path=/Users/vosslab/nsh`).
  Eliminates ~15 Glob/Grep passthroughs

### Decisions and Failures

- Passthrough log assessment (2026-03-26): 323 entries (laptop) + 25 entries
  (studio). 228/323 laptop entries (70%) are intentional passthroughs
  (ExitPlanMode, AskUserQuestion, EnterPlanMode, worktree tools). Remaining 95
  addressed by 5 changes in this changeset
- npx added to SAFE\_CMDS after discussion: downloads to ~/.cache (user-space),
  risk comparable to node. npm install kept as passthrough for user approval
- Decomposer investigation: chained command passthroughs (git check-ignore,
  which, source && python | head) were caused by missing allow rules at the time,
  not decomposer bugs. Decomposer correctly strips redirects and splits chains

## 2026-03-13

### Additions and New Features

- Created [CLAUDE_HOOK_USAGE_GUIDE.md](CLAUDE_HOOK_USAGE_GUIDE.md): comprehensive
  best-practices guide for AI agents working in repos that use the permissions hook.
  Covers allowed/denied/passthrough commands, file access zones, safe utility lists,
  common patterns cheat sheet, and preferred alternatives for every deny rule. Sourced
  from the production TOML config (21 deny rules, 37 allow rules)
- Added 11 Gas Town agent types to Agent subagent allowlist: `coder`, `reviewer`,
  `tester`, `maintainer`, `planner`, `orchestrator`, `integrator`, `architect`,
  `scheduler`, `monitor`, `parallelizer`. Eliminates 22 Agent passthroughs from
  the 2026-03-09 to 2026-03-13 assessment (20 coder + 2 reviewer)
- Added `git check-ignore` to git subcommand allowlist (read-only, safe). Eliminates
  2 passthroughs
- Added Glob and Grep allow rules for `/tmp/` and `/private/tmp/` paths, consistent
  with existing Read/Write/Edit `/tmp/` rules. Eliminates 3 Grep passthroughs
- Added deny rule for absolute-path `grep`/`rg` invocations (e.g.
  `/opt/homebrew/bin/rg`). The existing `^(grep|rg)` deny was bypassable via full
  path. Pattern: `^/\S*(grep|rg)\b.*\s/\S`
- Added allow rule for executing Python scripts via relative path
  (`./script.py`, `./dir/script.py`). Eliminates 10 Bash passthroughs from piped
  python script execution
- Broadened variable assignment deny rules from uppercase-only (`^[A-Z_]+=`) to
  include lowercase (`^[A-Za-z_]+=`). Closes gap where `project=$(basename...)`
  bypassed the uppercase-only pattern

### Fixes and Maintenance

- **Rust: absolutize relative paths for Glob/Grep**: When the `path` field is a
  relative path (e.g. `emwy_tools/track_runner`), the hook now prepends `cwd + "/"`
  to make it absolute before matching against allow rules. Previously relative paths
  never matched `^$HOME/nsh/` patterns. Eliminates 10 Grep passthroughs. Added 2
  unit tests (`test_grep_relative_path_absolutized`, `test_glob_relative_path_absolutized`)

### Decisions and Failures

- Passthrough log assessment (2026-03-09 to 2026-03-13): 185 entries across 39
  sessions. 130/185 (70%) are expected passthroughs (ExitPlanMode, AskUserQuestion,
  EnterPlanMode). Remaining 55 addressed by 7 changes in this changeset. 1 pip3
  install passthrough correctly requires user approval

### Removals and Deprecations

- **Removed ExitPlanMode and EnterPlanMode from auto-allow rule**: Auto-approving
  these tools bypasses Claude Code's interactive UI dialogs (user never sees the
  plan review screen). Same class of bug as AskUserQuestion (see 2026-03-03).
  Both tools now passthrough to Claude Code's default handling. Updated production
  TOML and `example.toml`

### Additions and New Features

- Added MUST PASSTHROUGH documentation block to both production TOML and
  `example.toml` listing the eight tools that must never be auto-allowed:
  `AskUserQuestion`, `EnterPlanMode`, `ExitPlanMode`, `EnterWorktree`,
  `ExitWorktree`, `CronCreate`, `CronDelete`, `CronList`. The first five
  have interactive UI dialogs that break if bypassed; the Cron tools are
  kept as passthrough so the user approves scheduled jobs

### Decisions and Failures

- Full audit of all Claude Code tools (30+) against allow/deny/passthrough
  classification. All tools with interactive user-facing dialogs must passthrough;
  all stateless orchestration tools can be safely auto-allowed. The audit
  confirmed the existing rules are correct except for the ExitPlanMode/
  EnterPlanMode bug fixed in this changeset

## 2026-03-06

### Fixes and Maintenance

- **Fixed Agent vs Task tool name mismatch**: Claude Code sends tool name
  `Agent` but matcher.rs only handled `Task`. Added `"Agent"` as an alias
  alongside `"Task"` in the match arm of `check_rule()`. This eliminates
  364 passthroughs (26% of total) from the passthrough log
- Changed `tool = "Task"` to `tool = "Agent"` in the production TOML
  subagent allow rule to match what Claude Code actually sends

### Additions and New Features

- Did NOT add `AskUserQuestion` to the TOML internal tools regex. Per the
  2026-03-03 bug fix, auto-approving this tool (whether via `settings.json`
  or the TOML hook) bypasses Claude Code's interactive question dialog,
  causing blank answers. The 61 AskUserQuestion passthroughs are intentional
- Added `./script.sh` allow rule for relative-path shell script execution
  (pattern: `^\./[A-Za-z0-9_.-]+\.sh\b`)
- Added `mv` deny rule to enforce `git mv` convention for tracked files

### Behavior or Interface Changes

- **Removed conflicting `settings.json` allow entries**: Stripped all Bash,
  Glob, Task, Read, Write, WebFetch, WebSearch, and orchestration tool
  entries from `~/.claude/settings.json` permissions allow list. These were
  bypassing the TOML hook entirely (settings.json is evaluated before the
  PreToolUse hook). Only Skill entries remain. The TOML hook is now the
  single source of truth for permissions

### Decisions and Failures

- Passthrough log assessment (2026-02-27 to 2026-03-07): 1,405 entries
  reviewed. Glob (49%) and Grep (16%) passthroughs attributed to cwd
  fallback fix from 2026-03-05. Agent (26%) addressed by this changeset.
  AskUserQuestion (4%) intentionally left as passthrough per 2026-03-03
  bug fix. Read passthroughs (1%) flagged for investigation -- existing
  rules should cover them

## 2026-03-05

### Additions and New Features

- Added `while` loop deny rule to production TOML and `example.toml`, matching
  existing `for` loop deny. Reason messages direct Claude to use underscore-prefixed
  scratch files
- Added `rm` allow rule for underscore-prefixed files (`_temp.py`, `_scratch.sh`,
  etc.) in both production TOML and `example.toml`. Also added exclude pattern to
  the rm deny rule so `rm _foo.py` bypasses the deny
- Added `for` and `while` loop deny rules to `example.toml` (previously only in
  production config)

### Behavior or Interface Changes

- Updated deny reason messages to recommend underscore-prefixed files as the
  preferred pattern for throwaway scripts:
  - Heredoc deny: "Write code to a `_temp.py` or `_temp.sh` file instead"
  - For-loop deny: "Write the logic in a `_temp.py` or `_temp.sh` file instead"
  - While-loop deny: same message as for-loop
  - Homebrew python `-c` deny: "Write a `_temp.py` file" instead of "a `.py` file"
- All updated reason messages include "(underscore-prefixed files can be removed
  freely)" suffix

### Fixes and Maintenance

- **Rust cwd fallback for Glob/Grep**: When the `path` field is omitted (70%
  of Glob/Grep passthroughs), the hook now falls back to `input.cwd` instead
  of passing through. This eliminates the majority of unnecessary passthroughs.
  Added 4 unit tests (glob/grep cwd fallback match, no-match, explicit path
  override). Updated 2 Python tests from passthrough to allow expectation

### Additions and New Features

- Synced `example.toml` with production TOML changes: removed `for` from
  `SYS_CMDS`, added `git clean` deny rule, expanded git subcommand allowlist
  with `branch`, `remote`, `rev-parse`, `worktree`, `ls-tree`
- Added 3 new deny rules to production TOML config:
  - `git clean` denied: destructive command that removes untracked files
  - `for` loops denied: forces looping logic into `.py` or `.sh` files
  - `gh` CLI denied: not installed on this system
- Removed `for` and `done` from `SYS_CMDS` (now denied instead of allowed)
- Expanded git subcommand allowlist: added `branch`, `remote`, `rev-parse`,
  `worktree` (read-only or standard workflow commands)
- Added `pip3 show|list|freeze|check` allow rule (read-only pip commands)
- Added `Read` allow rule for Homebrew site-packages paths
  (`/opt/homebrew/` and `/usr/local/` Python site-packages)
- Added `Glob` and `Grep` allow rules for `~/.claude/` paths
- Expanded `SYS_CMDS`: added `curl`, `ln`, `pkill`, `screencapture`,
  `unlink`, `xxd`

## 2026-03-03

- **Bug fix**: Removed `AskUserQuestion` from `permissions.allow` in
  `~/.claude/settings.json`. Claude Code's built-in permission system checks
  `settings.json` **before** the PreToolUse hook runs, so having
  `AskUserQuestion` in the allow list short-circuited the entire flow and
  auto-approved the tool without rendering the interactive question dialog.
  Users saw "User answered Claude's questions:" with blank answers but never
  saw the actual question. The previous TOML hook change (removing
  AskUserQuestion from the hook's internal allow rule) was harmless but
  insufficient since the settings.json allow was the real root cause.

## 2026-02-27

- Added deny rule for redundant `bash -c` / `bash -lc` wrappers. The Bash
  tool already runs bash, so `bash -lc "source source_me.sh && python ..."` is
  unnecessary bash-in-bash. Pattern `^bash\s+-[a-zA-Z]*c[a-zA-Z]*\s+` catches
  `-c`, `-lc`, `-cl` flags. Still allows `bash script.sh` and `bash -n script.sh`
- Added 4 deny rules to enforce dedicated tool usage over Bash equivalents:
  - `find` denied - agents must use the Glob tool instead
  - `cat`/`head`/`tail` with absolute file path denied - agents must use the
    Read tool (with offset/limit for line ranges). Pattern `[^>|]*/` avoids
    matching redirect targets like `cat file >> /tmp/out.txt`
  - `grep`/`rg` with absolute file path denied - agents must use the Grep tool.
    Pattern `\s/\S` catches paths but not regex patterns containing `/`
  - `sed -n` denied - agents must use Read tool with offset and limit params
- Each deny rule includes an educational reason message explaining which tool
  to use and what features it offers
- Added 26 new tests (574 total): 4 find denied, 6 cat/head/tail denied,
  3 cat/head/tail stdin not denied, 5 grep denied, 3 grep stdin not denied,
  3 sed -n denied, 2 sed substitute not denied
- Updated 5 existing tests that conflicted with new deny rules: removed
  `find` and `cat /dev/null` from allow lists, relaxed command substitution
  tests to accept deny or passthrough

## 2026-02-24

- **Bug fix**: `$HOME` in rule fields was not expanded. Environment variables
  are only expanded in `[variables]` values via `expand_env_vars()`, not in
  rule regex fields. Rules like `file_path_regex = "^$HOME/nsh/"` matched
  literal `$HOME`, never matching real paths. Fixed by adding `NSH_PATH` and
  `CLAUDE_PATH` TOML variables and replacing all bare `$HOME` in rule fields
  with `${NSH_PATH}`, `${CLAUDE_PATH}`, or existing `${HOME_PATH}`
- Added `NSH_PATH = "^$HOME/nsh/"` and `CLAUDE_PATH = "^$HOME/\\.claude/"`
  to `[variables]` in production TOML config
- Added `file_path_exclude_regex = "${NO_TRAVERSAL}"` to `~/.claude/`
  Write/Edit rules (was missing path traversal protection)
- Added deny rule for `/opt/homebrew/bin/python3 -c` with inline code.
  Custom reason directs Claude to write `.py` files and use
  `source source_me.sh && python3 script.py` instead
- Added allow rule for `/opt/homebrew/bin/python3` running `.py` files
  directly (excludes `-c` flag and command substitution)
- Added deny rule for heredoc patterns (`<<EOF`, `<<'EOF'`, `<<"EOF"`,
  `<<-EOF`). Custom reason directs Claude to write `.py` or `.sh` files
  instead of using inline heredocs
- Changed `src/lib.rs` to check deny rules against the original full command
  before decomposition. The decomposer strips redirections (including heredocs)
  when extracting leaf commands, so heredoc deny rules were invisible to the
  decomposed leaves. Now deny rules see both the full command and each leaf
- Added 17 new tests to `tests/test_hook.py` (546 total, up from 529):
  - 5 tests: heredoc patterns denied with educational reason
  - 3 tests: homebrew python `-c` inline code denied with reason
  - 3 tests: homebrew python running `.py` scripts allowed
  - 4 tests: Write/Edit to `~/.claude/` paths allowed via `CLAUDE_PATH`
  - 2 tests: Write/Edit traversal via `~/.claude/` not allowed
- Updated `tests/test_config.toml` with `NSH_PATH`, `CLAUDE_PATH` variables,
  homebrew python deny/allow rules, and `~/.claude/` Write/Edit rules

## 2026-02-18

- Created [rotate_logs.sh](../rotate_logs.sh) to rotate `/tmp/claude-tool-use.json`
  and `/tmp/claude-passthrough.json` with numbered suffixes (`.1.json`,
  `.2.json`, etc.), bumping existing numbered files up before moving
- Added `rm` cache allow rule to production TOML config: matches
  `rm` commands targeting `[Cc]ache` paths (e.g. `~/Library/Caches/`),
  which were already excluded from the deny rule but had no allow rule
- Added `ls-tree` to git subcommand allowlist in production TOML config
  (read-only command, was falling through to passthrough)
- Added optional `reason` field to TOML deny/allow rules
  - When a rule matches and has a `reason` set, that custom message is shown
    to Claude instead of the auto-generated match description
  - Added `reason: Option<String>` to `RuleConfig` and `Rule` in `src/config.rs`
  - Updated `check_rules()` in `src/matcher.rs` to prefer custom reason
  - Added unit tests: `test_custom_reason_overrides_auto`,
    `test_no_custom_reason_uses_auto`
  - Example TOML usage:
    ```toml
    [[deny]]
    tool = "Bash"
    command_regex = "\\$PYTHON\\b"
    reason = "Use 'python3' directly instead of $PYTHON variable"
    ```
- Added `$(...)` command substitution extraction to the decomposer
  - Commands inside `$(...)` are now extracted and checked against rules
  - Works in SimpleCommand leaves (e.g. `VAR=$(cmd)`) and ForClause
    values (e.g. `for i in $(cmd); do ...`)
  - Recursive: inner `$(...)` in nested contexts are also extracted
  - Added `extract_command_substitutions()` with paren-depth tracking
  - Added ForClause value scanning in `extract_from_compound_command()`
  - 7 new unit tests: for-loop `$()`, assignment `$()`, nested, no
    false positive on `${}`, multiple, basename in loop body, plain values
- Custom reason now includes the matched command: format is
  `"<custom reason> (Matched rule for Bash with command: <actual cmd>)"`
  instead of completely replacing the auto-generated reason
- Added four new deny rules with custom reasons to production config
  - `PYTHONDONTWRITEBYTECODE`/`PYTHONUNBUFFERED` usage: tells Claude to use
    `source source_me.sh && python3` instead of setting env vars manually
  - `VAR=$(...)` assignments: tells Claude to use `source source_me.sh` or
    inline the command directly
  - `$PYTHON` variable usage: denies `$PYTHON` and `${PYTHON}`, tells Claude
    to use `python3` directly
  - Bare env-var assignment: denies `^[A-Z_]+=[^\s]+$` (decomposed leaves
    like `REPO_ROOT=x` with no command), tells Claude to use space-separated
    env prefixes on one line
- Added `[limits]` config section with `max_chain_length` setting
  - Denies Bash commands with more chained sub-commands than the limit
  - Set to 0 to disable (default). Production config set to 5
  - Checked in `process_hook_input_with_rules()` after decomposition,
    before deny/allow rule matching
  - Added `LimitsConfig` struct to `src/config.rs` with `Default` impl
  - Deny message: "Command has N chained sub-commands (limit: M).
    Break into smaller commands."
- Updated env-var-prefix Bash rule to support multiple prefixes and
  `python3`/`pytest`/`pyflakes` commands (was only single prefix + SAFE_CMDS).
  Fixes passthrough for `REPO_ROOT=x PYTHONPATH=y python3 -m pytest ...`
- Added `[Cc]ache` to rm deny exclude pattern (cache files are safe to delete)
- Added Write and Edit allow rules for `$HOME/nsh/` (project files)
- Added Write and Edit allow rules for `$HOME/.claude/` (plan files, settings)
- Added `ls-files` to git subcommand allowlist in [example.toml](../example.toml)
- Added commented `reason` example to [example.toml](../example.toml)
- Added inter-variable expansion: `${VAR}` references in variable values are
  now resolved, allowing variables to reference other variables. Iterates until
  stable; detects circular references. Added unit test
  `test_inter_variable_expansion`
- Split `SAFE_CMDS` into grouped sub-variables (`FILE_CMDS`, `FS_CMDS`,
  `SYS_CMDS`) merged via `SAFE_CMDS = "${FILE_CMDS}|${FS_CMDS}|${SYS_CMDS}"`.
  Applied to production config, example config, and test config
- Fixed `test_while_loop_passthrough` -> `test_while_loop_allowed` in Python
  tests (true and sleep are now in SAFE_CMDS)

## 2026-02-16

- Bumped version to 26.02 (26.2.0 in Cargo.toml due to SemVer constraints),
  added `VERSION` file
- **Bug fix**: `subagent_type_regex` field in TOML was silently ignored by serde
  because the field did not exist in `RuleConfig`. The Task allow rule in
  `example.toml` was acting as a tool-only rule (allowing ALL subagent types)
  instead of restricting to Explore/general-purpose.
  - Added `subagent_type_regex: Option<String>` to `RuleConfig` and
    `subagent_type_regex: Option<Regex>` to `Rule`
  - Updated `check_subagent_type()` in `src/matcher.rs` to check regex match
    as an alternative to exact `subagent_type` match
  - Updated `is_tool_only_rule()` to include `subagent_type_regex`
- **Bug fix**: Added `#[serde(deny_unknown_fields)]` to `RuleConfig` so that
  typos or non-existent fields in TOML rules cause a parse error at startup
  instead of being silently ignored
  - Also fixed `path_regex`/`path_exclude_regex` in Glob/Grep rules (these
    were unknown fields silently ignored) to `file_path_regex`/
    `file_path_exclude_regex`
- Added `tool_regex` field to `RuleConfig` and `Rule` for regex-based tool
  name matching. Allows collapsing many tool-only rules into a single rule
  with a pattern (e.g. `tool_regex = "^mcp__plugin_playwright_"`)
- Added `tree` and `lsof` to SAFE_CMDS in `example.toml`
- Added env-var-prefix Bash rule (`LC_ALL=C grep ...` pattern)
- Fixed macOS `/private/tmp/` path matching: `/tmp/` rules now use
  `^(/private)?/tmp/` to handle macOS symlink resolution
- Added Claude internal tool rules via `tool_regex` (TaskOutput, TaskCreate,
  TaskList, TaskGet, TaskUpdate, TaskStop, Skill, AskUserQuestion,
  ExitPlanMode, EnterPlanMode, SendMessage, TeamCreate, TeamDelete,
  NotebookEdit)
- Added Playwright MCP browser tool rules via `tool_regex`
  (`^mcp__plugin_playwright_playwright__browser_`)
- Expanded Task `subagent_type_regex` to include all standard subagent types
  (Explore, general-purpose, Plan, Bash, haiku, sonnet, opus,
  statusline-setup, claude-code-guide, superpowers:code-reviewer)
- Added `bash -c` unwrapping to `src/decomposer.rs`
  - `try_unwrap_bash_c()` detects `bash -c "inner command"` patterns (including
    `-lc`, `-cl`, and other combined flags) and recursively decomposes the inner
    command string
  - `strip_outer_quotes()` helper removes a single layer of matching quotes
  - Handles both single and double quotes: `bash -lc "..."` and `bash -lc '...'`
  - Only unwraps `bash` (not `zsh`, `sh`, etc.) and only when `-c` flag is present
  - Inner commands are checked against normal allow/deny rules, eliminating the
    need for special `bash -lc` wrapper regex rules in the config
  - Added 8 unit tests: double/single quotes, compound inner commands, `-cl` flag
    order, dangerous inner commands, `-n` without `-c`, non-bash commands
- Added `touch`, `cd`, `file` to SAFE_CMDS in production config
- Fixed production config `bash -lc` rules to accept single quotes (`[\"']`
  instead of `\"` only)
- Removed 5 redundant allow rules from production config (24 -> 19 rules)
  - `bash -lc "source && python/pytest"` wrapper rule (decomposer unwraps bash -c)
  - `source && python/pytest` compound rule (decomposer splits &&)
  - Comment blocks rule (parser ignores comments, leaf commands match SAFE_CMDS)
  - `sleep && safe` compound rule (decomposer splits &&)
  - `bash -[lcn]+ "safe_cmd"` wrapper rule (decomposer unwraps bash -c)
- Simplified python rule exclude regex (removed `&&`/`;`/`|` exclusions since
  the decomposer splits compound operators before rules see them)
- Fixed git allowlist regex: `\s` -> `(\s|$)` so bare `git status`, `git diff`,
  `git log` (without args) now match
- Updated [example.toml](../example.toml) to match production config patterns
  - 5 deny rules (rm, .env/.secret, git commit/stash/rm)
  - 17 allow rules (python, cargo, git, bash scripts, SAFE_CMDS, Glob/Grep,
    Read/Write/Edit, /tmp, web tools, Task)
  - Variables (SAFE_CMDS, NO_CMD_SUB, PROJECT_PATH, NO_TRAVERSAL)
  - Decomposer explanation comment, fixed git regex
- Rewrote [README.md](../README.md) to be concise with links to docs/
- Created [INSTALL.md](INSTALL.md) with requirements, build steps, Claude Code
  hook setup, and verify command
- Created [USAGE.md](USAGE.md) with CLI reference, input/output format,
  examples, audit file descriptions, and test commands
- Removed shebang from `tests/test_hook.py` (pytest-only file, not executable)
- Added `# nosec B108` security annotations to 10 test data lines in
  `tests/test_hook.py` with hardcoded `/tmp` paths (false positives, not actual temp usage)
- Created [pip_requirements-dev.txt](../pip_requirements-dev.txt) with dev dependencies
  (bandit, packaging, pyflakes, pytest, rich)
- Updated `tests/test_shebangs.py` to allowlist `tests/test_hook.py` as a
  non-executable pytest module
- Added passthrough logging to `src/auditing.rs`
  - New `audit_passthrough()` function writes JSON-lines entries to a dedicated file
  - Entry format: `{ timestamp, session_id, tool_name, tool_input, cwd }` (no decision/reason)
  - Reuses existing `truncate_json_strings()` and file-locking patterns
  - Independent of `audit_level`; logs when `passthrough_log_file` is configured
  - Added unit test `test_audit_passthrough_writes_entry`
- Implemented `passthrough_log_file` config field in `src/main.rs`
  - Already defined in config struct but was completely unimplemented
  - After audit, checks if decision is Passthrough and config has `passthrough_log_file`
  - Calls `audit_passthrough()` to write the entry
- Updated `example.toml` and `tests/test_config.toml` with `passthrough_log_file` setting
- Added shell command decomposer in new `src/decomposer.rs`
  - Uses `brush-parser` (v0.3) to parse Bash commands into AST
  - `decompose_command()` walks the AST to extract leaf SimpleCommand strings
  - Handles: `&&`, `||`, `;`, pipes, for/while/until loops, if/case clauses,
    brace groups, subshells
  - Graceful fallback: if parsing fails, returns original command as-is
  - 14 unit tests covering simple commands, compound operators, loops,
    if clauses, redirections, malformed input, and empty strings
- Updated `src/lib.rs` with decomposition-aware rule checking
  - `process_hook_input_with_rules()` now decomposes Bash commands into sub-commands
  - Deny check: if ANY sub-command matches ANY deny rule, deny the whole command
  - Allow check: ALL sub-commands must match some allow rule to allow the whole command
  - Otherwise passthrough
  - Added `with_command()` method to `HookInput` for creating synthetic inputs
- Added `brush-parser = "0.3"` to `Cargo.toml` dependencies
- Added `tempfile = "3"` to dev-dependencies for passthrough audit test
- Added 5 decomposer integration tests to `tests/integration_test.rs`
  - Safe compound allowed, dangerous sub-command denied, mixed passthrough,
    for loop safe body, for loop dangerous body
- Updated `tests/test_hook.py` with 15 new tests (529 total, up from 515)
  - 3 passthrough logging tests: log written, not written for allow, not written for deny
  - 5 tests for dangerous commands inside control flow (for/while/if/brace group)
  - 4 tests for safe control flow decomposition
  - 1 test for mixed safe/unknown passthrough
  - 1 test for deny overriding safe in pipeline
  - Behavioral test updates: `if/case/[[` with safe bodies now expect allow
    (decomposer extracts safe leaf commands); for loop with `$()` in values
    now expects allow (body command `echo $i` is safe, `$()` is in values not body)
- Fixed `src/matcher.rs`: tool-only rule matching and Glob/Grep field extraction
  - Added `is_tool_only_rule()` helper so rules like `[[allow]] tool = "WebFetch"` (no regex) now match
  - Split Glob/Grep into separate match arm using `path` field instead of `file_path`
  - Added unit tests for tool-only rules and Glob/Grep path extraction
- Fixed `src/lib.rs`: added `process_hook_input_with_rules()` to accept pre-compiled rules
  - Eliminates double rule compilation when using `load_config()` + `process_hook_input_with_config()`
- Fixed `src/main.rs`: `run_hook()` now uses pre-compiled rules from `load_config()`
  - Removed `let _ = (deny_rules, allow_rules)` suppression
- Cleaned up `Cargo.toml`: removed unused dependencies (itertools, derive_builder, lazy_static)
- Fixed `claude-code-permissions-hook.toml` user config
  - Fixed empty regex alternative (`||`) in source+python/pytest allow rule
  - Added `command_exclude_regex` to broad shell utilities rule to block command substitution
  - Added Edit tool allow rules mirroring existing Read/Write rules
  - Added `bash <script>.sh` allow rule for running shell scripts directly
  - Added Read allow rule for macOS temp paths (`/var/folders/`)
  - Synced utilities list with settings.json: added chmod, colordiff, comm, diff, done, for, rg, test
  - Added `git -C <path>` variant to git allowlist
  - Added `bash -lc "<utility>"` rule for non-source bash wrapper commands
- Rewrote `tests/test_config.toml` with targeted deny rules
  - Replaced broad `.*(&|;|\\||...).*` deny pattern with targeted `\brm\b` deny rule
  - Added Write, Edit, Glob, and Grep allow rules for the Dropbox project path
  - Added common shell utilities allow rule with narrow exclude (backtick/`$(` only)
  - Added tool-only allow rules for WebFetch and WebSearch
- Added 10 new JSON test fixtures for compound commands, tool-only, Glob/Grep, Edit
- Added 10 new Rust integration tests in `tests/integration_test.rs`
- Created `tests/test_hook.py` pytest harness with 47 parameterized tests
  - Simple allowed commands, safe compound commands, dangerous compound denial
  - Loop passthrough, tool-only rules, path-based rules, deny rules, edge cases
- Added `[variables]` support to TOML config for reusable regex fragments
  - Define variables in `[variables]` section, reference as `${VAR_NAME}` in regex fields
  - Errors on undefined variable references
  - Added `expand_variables()`, `expand_opt()`, and `compile_rule_with_vars()` to `src/config.rs`
  - Added unit tests for variable expansion
- Added `$HOME`/`$USER`/`$TMPDIR` environment variable expansion in `[variables]` values
  - `$VARNAME` (no braces) expands standard OS env vars during config load
  - `${TOML_VAR}` (with braces) expands TOML-defined variables in regex fields
  - Added `expand_env_vars()` to `src/config.rs`
- Updated `example.toml` to demonstrate `[variables]` feature
- Updated user's production TOML config to use variables (`SAFE_CMDS`, `NO_CMD_SUB`, `HOME_PATH`, `NO_TRAVERSAL`)
- Expanded `tests/test_hook.py` from 47 to 346 parameterized torture tests
  - Cargo: allowed subcommands (15) and disallowed subcommands passthrough (11)
  - Utilities: comprehensive coverage of all SAFE_CMDS with flag variations (60+)
  - Compound commands: pipes, &&, ||, semicolons, redirections, complex pipelines (30+)
  - rm denial: standalone (8), hidden in compounds (13), substring false-positive avoidance (8)
  - Command substitution: $() and backtick blocking, ${VAR} vs $() distinction (20+)
  - Control flow: for/while loops, if/case/until passthrough (7)
  - Path traversal: various ../  patterns across Read/Write/Edit (15+)
  - Sensitive files: .env/.secret denial and near-miss patterns not denied (18+)
  - Tool-only rules: WebFetch/WebSearch with varied inputs (12)
  - Glob/Grep: allowed paths, outside paths, no-path, deep nesting (12+)
  - Task/subagent: matching and non-matching types, missing fields (8)
  - Deny-over-allow priority: rm vs echo, sensitive vs allowed path (3)
  - Unknown tools: 11 tool names including NotebookEdit, Skill, etc.
  - Edge cases: empty/whitespace/null/numeric/bool/array inputs, long strings (15+)
  - Special characters and newline injection (15+)
  - Regex boundary testing: misspelled utilities, almost-cargo commands (12)
  - Dangerous non-rm commands passthrough (7)
  - Non-utility programs passthrough (11)
  - JSON edge cases: extra fields, wrong types (5)
  - Stress test: 60 rapid sequential calls (1)
  - Config validation: test and example configs (2)
  - Regression tests: command sub in loops/cargo, pipe/semicolon chains (5)
- Added adversarial evasion tests (126 tests) to `tests/test_hook.py`
  - git commit: 21 evasion attempts including flag insertion (`git -C /tmp commit`),
    chaining, env prefixes, full paths, pipes - all denied
  - git stash: 18 evasion attempts with same bypass techniques - all denied
  - git rm: 12 evasion attempts - all denied
  - rm: 30 evasion attempts including flag variations, full paths, chaining,
    backslash-escaped rm, newline injection, comment prefixes - all denied
  - Path traversal: 14 evasion patterns including deep traversal, targeting
    .ssh/id_rsa, .aws/credentials, .gnupg, proc/self/environ - all denied
  - Sensitive files: 12 patterns including deny-beats-allow priority tests
  - False positive checks: commands with "rm" as substring (alarm, formatting),
    safe git commands (status, diff, log), .env.local/.envrc not denied
  - Deny-beats-allow priority: 10 tests proving deny rules win over allow
  - Newline injection: 7 tests hiding dangerous commands after \\n
  - Write/Edit traversal: 4 tests verifying traversal not allowed
- Added git deny rules to `tests/test_config.toml`
  - `\\bgit\\b.*\\bcommit\\b` - catches git with any flags before commit
  - `\\bgit\\b.*\\bstash\\b` - catches git stash with any flags
  - `\\bgit\\b.*\\brm\\b` - catches git rm with any flags
- **SECURITY FIX**: Fixed production config deny rules
  - Old `.*git\\s+commit.*` was bypassable with `git --no-pager commit`,
    `git -C /tmp commit`, `git -c user.name=evil commit`, etc.
  - Old `.*git\\s+stash.*` had same bypass vulnerability
  - Old rm rules (`^rm .*-rf` and complex -rf flag pattern) missed `rm file.txt`,
    `rm -r dir/`, `rm -f file` (only caught combined -rf flags)
  - New patterns use `\\b` word boundaries: `\\bgit\\b.*\\bcommit\\b`,
    `\\bgit\\b.*\\bstash\\b`, `\\brm\\b`
- Copied shared repo docs and test infrastructure from central repo
  - Added [AGENTS.md](../AGENTS.md), [CLAUDE.md](../CLAUDE.md), [source_me.sh](../source_me.sh)
  - Added [REPO_STYLE.md](REPO_STYLE.md), [PYTHON_STYLE.md](PYTHON_STYLE.md),
    [MARKDOWN_STYLE.md](MARKDOWN_STYLE.md), [AUTHORS.md](AUTHORS.md)
  - Added shared test harnesses: `tests/test_shebangs.py`, `tests/test_bandit_security.py`,
    `tests/test_pyflakes_code_lint.py`, `tests/test_ascii_compliance.py`,
    `tests/test_whitespace.py`, `tests/test_indentation.py`,
    `tests/test_import_requirements.py`, `tests/test_import_star.py`
  - Added `tests/git_file_utils.py` and `.gitignore`

## 2025-12-06

- Created [CONFIGURATION_GUIDE.md](CONFIGURATION_GUIDE.md) with rule syntax
  for each supported tool (Read, Write, Edit, Bash, Task, Glob, Grep, WebFetch, WebSearch)
- Created [TOOL_INPUT_SCHEMAS.md](TOOL_INPUT_SCHEMAS.md) with Claude Code
  tool input JSON reference
- Cleaned up [README.md](../README.md), moved detailed docs to `docs/`
- Truncated audit log string fields at 256 characters to keep JSON-lines manageable

## 2025-12-05

- Renamed logging module from `src/logging.rs` to `src/auditing.rs` to avoid
  conflict with `log` crate naming
- Added audit level support: `off`, `matched` (default), `all`
- Added integration test suite in `tests/integration_test.rs` with sample JSON fixtures
- Created `tests/test_config.toml` for integration testing
- Truncated long tool input strings in audit entries
- Cleaned up spurious `Decision` type duplication

## 2025-10-10

- Initial project release
- Core permission hook: reads JSON from stdin, evaluates deny/allow rules, outputs
  decision to stdout
- TOML config with `[[deny]]` and `[[allow]]` rule sections
- Regex pattern matching for Bash `command`, file path tools (`file_path`), and
  Task `subagent_type`
- Exclude regex support (`command_exclude_regex`, `file_path_exclude_regex`)
- JSON-lines audit logging with file locking
- CLI with `run` and `validate` subcommands via `clap`
- [example.toml](../example.toml) with starter rules
- [README.md](../README.md) with setup instructions and flowchart
