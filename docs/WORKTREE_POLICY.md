# Worktree and protected-branch policy

This document is the canonical reference for how `claude-code-permissions-hook`
enforces protected-branch policy and how agents and humans split the
work of integrating changes.

## Why this exists

Agents work fast and tend to commit directly on whatever branch they
happened to start on. Without a guardrail, a single careless turn can
land an agent commit on `main`. This hook switches that default: routine
commits, resets, rebases, cherry-picks, reverts, and pushes against
protected branches are denied. The agent is steered toward a
non-protected branch, and the human owns the final step.

## Protected branches

By default the protected list is `["main", "master"]`. Override in TOML:

```toml
[git_protection]
protected_branches = ["main", "trunk"]
protected_refs     = ["refs/heads/main", "refs/heads/trunk"]
```

`protected_refs` matches the full ref path used by push refspecs (e.g.
`HEAD:refs/heads/main`). Both lists should be kept in sync.

## Workflow: agents prepare, humans commit

Agents do the work on a feature branch and prepare a merge. The human
reviews the merge result and creates the final commit on the protected
branch.

### Agent steps

```bash
git switch -c agent/<task>
# ...edit, commit, push the agent branch...

git switch main
git merge --no-commit --no-ff agent/<task>
# resolve conflicts, run tests, leave the staged result in place
```

The merge command above is the only allowed way to mutate a protected
branch's working tree. It updates the index and worktree but stops
before creating the merge commit. Both `--no-commit` and `--no-ff` are
required.

### Human steps (outside the hook surface)

```bash
git diff HEAD          # full merge result, staged and unstaged
git diff               # unstaged
git diff --staged      # staged
git status

git commit             # finalize the merge
git push origin main
```

### Allowed escape hatch

If the merge preparation goes wrong (conflicts, broken tests, wrong
source branch), `git merge --abort` is allowed unconditionally on any
branch. The same applies to `git cherry-pick --abort`, `git revert
--abort`, and `git rebase --abort`.

### --continue is denied everywhere

`git merge --continue`, `git cherry-pick --continue`, `git revert
--continue`, and `git rebase --continue` create commits after conflict
resolution. They violate the "human makes the commit" rule and are
denied on every branch. If you hit a `--continue` state, abort and
re-prepare on a feature branch instead.

## Allowed and denied operations

For day-to-day work on an agent or feature branch, every git command
is allowed (subject to other hook rules elsewhere). The protected-branch
guardrail only fires when the current branch is in
`protected_branches`.

| Command                                | Protected | Non-protected |
| -------------------------------------- | --------- | ------------- |
| `git commit` (any flag)                | deny      | allow         |
| `git rebase`                           | deny      | allow         |
| `git reset --hard`                     | deny      | allow         |
| `git cherry-pick`, `git revert`        | deny      | allow         |
| `git cherry-pick --continue`, `git revert --continue` | deny | deny |
| `git rebase --continue`                | deny      | deny          |
| `git merge <branch>`                   | deny      | allow         |
| `git merge --no-commit --no-ff <branch>`| allow    | allow         |
| `git merge --continue`                 | deny      | deny          |
| `git merge --ff-only`, `--squash`      | deny      | allow         |
| `git merge --abort`                    | allow     | allow         |
| `git push origin <protected>` (any form) | deny    | deny          |
| `git push origin <non-protected>`      | allow     | allow         |
| `git push --force` (anywhere)          | deny      | deny          |
| `git update-ref refs/heads/<protected>` | deny     | deny          |
| `git branch -f <protected>`, `-D <protected>` | deny | deny       |

## Worktrees

Worktrees are encouraged. Each worktree is an independent checkout on
its own branch, which keeps agent work isolated from the user's main
checkout:

```bash
git worktree add ../wt-add-foo agent/add-foo
cd ../wt-add-foo
```

Worktree-ness is not what the hook checks. The hook checks the
*branch name* of the current checkout. A worktree on `main` is still
protected; a non-worktree checkout on `agent/foo` is not.

## Security model

This hook is a workflow guardrail, not a security boundary. It is
designed to prevent accidental protected-branch mutations through
normal Git commands.

For strong enforcement, use repository-host branch protection,
required reviews, required status checks, restricted push permissions,
and limited filesystem permissions for agent processes. Do not rely on
this hook as the only protection against a process with arbitrary
shell or filesystem access.

## Maintenance notes

- The protected-branch list lives in `[git_protection]` in the active
  TOML config.
- The `${PROTECTED_BRANCHES}` regex variable is auto-injected from the
  list at config load time and is available to rules.
- The merge-prepare allow rule must remain narrow: only
  `git merge --no-commit --no-ff <non-protected-source>`. Do not
  whitelist `-m`/`--message` or other commit-shaping flags. The
  handoff to the human is the entire point of the rule.
- Changes to verb-level rules in `example.toml` should be paired with
  rows in `tests/command_decisions.tsv` for shape coverage and cases
  in `tests/test_protected_branch.rs` for branch-aware coverage.
