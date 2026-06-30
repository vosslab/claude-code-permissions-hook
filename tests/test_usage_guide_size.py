"""
Size guard for docs/CLAUDE_HOOK_USAGE_GUIDE.md.

The usage guide is injected into agent context, so it must stay compact.
This test enforces a hard character ceiling; trim or compress the guide if
it trips. The ceiling is intentionally a round number above the current
size, not a tight fit, so normal edits do not churn the limit.
"""

import os

import file_utils

# Hard ceiling on the guide size, in characters (bytes for ASCII content).
MAX_CHARS = 30000


#============================================
def test_usage_guide_under_char_limit() -> None:
	repo_root = file_utils.get_repo_root()
	guide_path = os.path.join(repo_root, "docs", "CLAUDE_HOOK_USAGE_GUIDE.md")
	with open(guide_path, encoding="utf-8") as handle:
		text = handle.read()
	char_count = len(text)
	assert char_count < MAX_CHARS, (
		f"docs/CLAUDE_HOOK_USAGE_GUIDE.md is {char_count} chars, "
		f"limit is {MAX_CHARS}. Trim or compress the guide."
	)
