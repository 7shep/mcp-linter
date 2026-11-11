"""Draft v2 of the trifecta tagger: v1 evidence plus rules for inbound and shared data.

v1 (``tagging.py``) is frozen and is not edited here. v2 is a pure superset: every
v1 Evidence item is returned unchanged, and the new rules only add evidence. The
new rules cover two cases the AgentDojo cross-check found v1 missing:

* data the user owns but third parties can write into (payments, calendar
  invites, chat channels, shared cloud files) is UNTRUSTED_READ;
* the user's own transaction, message, profile and cloud-file reads are
  PRIVATE_READ.

Like v1, this reads tool names, input schema structure and annotations only,
never descriptions. The rules are tuned on the AgentDojo export, so numbers
measured on it are dev-set numbers, not a holdout.

THREAT MODEL
  DEFENDS AGAINST: a tool whose inbound-content or private-data capability is
    hidden from the tagger by a name that uses the words above, or a malformed
    schema or name crashing the tagger.
  ATTACKER CONTROLS: tool name, inputSchema, annotations.
  MUST FAIL CLOSED WHEN: a read tool has a name word that suggests inbound or
    private data and no local path parameter rules it out.
  OUT OF SCOPE: descriptions, homoglyph names, and whether a rule is right on
    every real server (checked on the survey and AgentDojo lists only).
"""

from __future__ import annotations

import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from mcp_lint.models import ToolDef  # noqa: E402
import tagging  # noqa: E402
from tagging import (  # noqa: E402,F401  (re-exported)
    ALL_TAGS,
    HIGH,
    MEDIUM,
    Evidence,
    Tag,
    minimal_trifecta_sets,
    tags_for,
)

VERSION = "v2-draft"

LOCAL_PATH_PARAMS = frozenset({"path", "paths", "file_path", "filepath", "repo_path"})
INBOUND_HIGH = frozenset(
    "transaction payment calendar event invite invitation channel chat conversation".split()
)
INBOUND_FILE = frozenset("file document attachment drive".split())
PRIVATE_V2_HIGH = frozenset("transaction payment balance iban passport bank".split())
PRIVATE_V2_MEDIUM = frozenset("message chat conversation channel".split())
PROFILE_WORDS = frozenset("info information profile".split())


def tag_tool(tool: ToolDef) -> list[Evidence]:
    """v1 evidence plus the v2 rules. Never raises on malformed names or schemas."""
    out = list(tagging.tag_tool(tool))

    name = tool.name if isinstance(tool.name, str) else ""
    words = tagging.name_tokens(name)
    word_set = set(words)
    verb = tagging._verb(words)
    props = tagging._properties(tool.input_schema)
    top = {k.lower() for k in props}
    is_read = verb in tagging.READ_VERBS
    is_forge = {"owner", "repo"} <= top
    browser = bool(word_set & tagging.BROWSER_NOUNS) or "navigate" in word_set

    def add(tag: Tag, conf: str, rule: str, detail: str) -> None:
        out.append(Evidence(tag, conf, rule, detail))

    if is_read:
        inbound = word_set & INBOUND_HIGH
        if inbound and not is_forge:
            add(Tag.UNTRUSTED_READ, HIGH, "U-INBOUND",
                f"{verb} on inbound content written by others {sorted(inbound)}")

        shared_file = word_set & INBOUND_FILE
        if shared_file and not top & LOCAL_PATH_PARAMS and not is_forge:
            add(Tag.UNTRUSTED_READ, MEDIUM, "U-SHARED-FILE",
                f"{verb} on shared files {sorted(shared_file)} with no local path")

        private_high = word_set & PRIVATE_V2_HIGH
        if private_high:
            add(Tag.PRIVATE_READ, HIGH, "P-NOUN-V2", f"{verb} on {sorted(private_high)}")

        private_medium = word_set & PRIVATE_V2_MEDIUM
        if private_medium and not browser:
            add(Tag.PRIVATE_READ, MEDIUM, "P-MESSAGE", f"{verb} on {sorted(private_medium)}")

        profile = word_set & PROFILE_WORDS
        if "user" in word_set and profile:
            add(Tag.PRIVATE_READ, HIGH, "P-USER-PROFILE", f"{verb} on user {sorted(profile)}")

        if shared_file and not top & LOCAL_PATH_PARAMS and not is_forge:
            add(Tag.PRIVATE_READ, MEDIUM, "P-CLOUD-FILE",
                f"{verb} on cloud files {sorted(shared_file)} with no local path")

    return out
