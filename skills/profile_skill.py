"""
ARGUS - User profile / long-term memory.

The vault stores individual notes; this stores who *you* are. It's a single
markdown file loaded into every conversational prompt, so ARGUS answers with
your context instead of generic advice.

Plain markdown on purpose — you can open it, read exactly what ARGUS believes
about you, and edit or delete any line by hand. No hidden embedding store.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import re
from datetime import datetime

from config import VAULT_PATH

PROFILE_PATH = os.path.join(VAULT_PATH, "profile.md")

DEFAULT_PROFILE = """# User Profile

_ARGUS's long-term memory. Edit freely — this is read at the start of every conversation._

## About
- (nothing recorded yet)

## Work
- (nothing recorded yet)

## Preferences
- (nothing recorded yet)
"""


def ensure_profile():
    os.makedirs(VAULT_PATH, exist_ok=True)
    if not os.path.exists(PROFILE_PATH):
        with open(PROFILE_PATH, "w", encoding="utf-8") as f:
            f.write(DEFAULT_PROFILE)


def read_profile() -> str:
    ensure_profile()
    with open(PROFILE_PATH, "r", encoding="utf-8") as f:
        return f.read()


def profile_context() -> str:
    """Compact form injected into prompts. Strips headers and empty placeholders
    so we're not burning context window on markdown scaffolding."""
    text = read_profile()
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("-"):
            continue
        if "nothing recorded yet" in line:
            continue
        lines.append(line)
    if not lines:
        return ""
    return "What you know about the user:\n" + "\n".join(lines)


# The only section names remember() will ever create. Found in the real
# vault, not hypothesised: the LLM router's "reply" field is free text --
# meant to carry a section name for this one skill, but the model
# sometimes filled it with an entire conversational sentence instead
# ("You mentioned you're feeling red today, is everything okay?"), and
# remember() used to write that VERBATIM as "## <whatever the model said>",
# a new permanent markdown header, no matter its shape or length. Five
# section headers in the real profile.md were corrupted this way. Whatever
# arrives now is matched case-insensitively against this fixed set; anything
# that doesn't match -- a whole sentence, a stray word, empty -- falls back
# to "About" rather than becoming a new header.
VALID_SECTIONS = {"about": "About", "work": "Work", "preferences": "Preferences"}


def _clean_section(section: str) -> str:
    return VALID_SECTIONS.get((section or "").strip().lower(), "About")


def remember(fact: str, section: str = "About") -> str:
    """Appends a fact under the given section, creating the section if needed."""
    ensure_profile()
    fact = fact.strip().rstrip(".")
    if not fact:
        return "There was nothing to remember there."

    # Defence in depth at the WRITE side. brain.py fences the profile as
    # untrusted data when it builds a prompt, but a stored fact is read back
    # on every future turn and shown in the HUD, so instruction-shaped text
    # should never get in here in the first place. passive_memory's patterns
    # make that unlikely; profile/remember reached through the LLM router with
    # a model-chosen target does not have that protection.
    import security

    cleaned = security.strip_injection(fact)
    if cleaned != fact:
        # Redact before echoing: a "fact" can fail the injection gate by
        # virtue of BEING a secret ("my PIN is 1234" carries an instruction
        # frame). fact is unredacted here; printing it raw would put a secret
        # into the console.
        print(f"[profile] refused to store instruction-shaped text: "
              f"{security.redact(fact)[:60]!r}")
        return "That didn't look like a fact about you, so I haven't saved it."
    fact = security.redact(fact)

    with open(PROFILE_PATH, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    # Already known? Say so instead of storing it again.
    #
    # Nothing deduplicated before this, so saying the same thing twice stored
    # it twice: a real profile ended up with "I like strong coffee" on three
    # separate lines. That is not just untidy -- the profile is read back into
    # the prompt on every turn, so each duplicate spends context and makes a
    # repeated fact look like an emphasised one.
    #
    # Compared on the fact text with case and punctuation normalised, since
    # "I like strong coffee" and "i like strong coffee." are the same claim.
    def _norm(s: str) -> str:
        return re.sub(r"[^a-z0-9 ]", "", s.lower()).strip()

    target = _norm(fact)
    for line in lines:
        if not line.strip().startswith("- "):
            continue
        existing = line.strip()[2:].split("  _(learned")[0]
        if _norm(existing) == target:
            return f"I already knew that."

    stamp = datetime.now().strftime("%Y-%m-%d")
    entry = f"- {fact}  _(learned {stamp})_"

    # Drop the placeholder in the target section, then insert after the header.
    header = f"## {_clean_section(section)}"
    if header not in lines:
        lines.extend(["", header, entry])
    else:
        idx = lines.index(header)
        # find insertion point: after header, skipping any placeholder line
        insert_at = idx + 1
        while insert_at < len(lines) and lines[insert_at].strip() == "":
            insert_at += 1
        if insert_at < len(lines) and "nothing recorded yet" in lines[insert_at]:
            lines[insert_at] = entry
        else:
            lines.insert(insert_at, entry)

    with open(PROFILE_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return "Got it, I'll remember that."


# forget() is the only destructive operation on the user's long-term memory,
# and it is reached from a speech recognizer. These bound the damage a single
# misheard word can do.
MIN_FORGET_KEYWORD = 3   # "i", "a", "my" match nearly every line
MAX_FORGET_ITEMS = 3     # more than this needs a more specific word


def forget(keyword: str) -> str:
    """Removes profile lines matching the keyword.

    BUGFIX: this used to be a plain substring test, `keyword.lower() in
    l.lower()`, with no minimum length and no cap. Measured directly:
    forget("i") removed 13 of 13 facts -- the entire profile, in one utterance,
    because the letter "i" appears in almost every English sentence. "Forget
    it" mis-transcribed, or a router that pulled the wrong target out of a
    sentence, would silently erase everything ARGUS knows about the user, with
    a cheerful "Forgotten." as the only sign.

    Three changes: match on WORD BOUNDARIES so "i" no longer matches "hospital"
    and "coffee"; refuse a keyword too short to identify anything; and refuse a
    bulk delete outright rather than performing it, since a request that
    matches most of the profile is far more likely to be a mishearing than an
    intention.
    """
    ensure_profile()
    keyword = (keyword or "").strip()
    if len(keyword) < MIN_FORGET_KEYWORD:
        return (f"{keyword!r} is too short for me to know what to forget. "
                "Give me a specific word from the fact you want removed.")

    with open(PROFILE_PATH, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    pattern = re.compile(r"\b" + re.escape(keyword.lower()) + r"\b", re.I)
    matched = [l for l in lines
               if l.strip().startswith("-")
               and "nothing recorded yet" not in l
               and pattern.search(l)]

    if not matched:
        return f"I don't have anything recorded about {keyword}."

    if len(matched) > MAX_FORGET_ITEMS:
        preview = "; ".join(
            l.split("_(learned")[0].lstrip("- ").strip() for l in matched[:3])
        return (f"That would remove {len(matched)} facts, including: {preview}. "
                "That's more than I'll delete at once — name something more "
                "specific.")

    kept = [l for l in lines if l not in matched]
    with open(PROFILE_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(kept) + "\n")
    removed = len(matched)
    return f"Forgotten. Removed {removed} item{'s' if removed > 1 else ''}."


def summary() -> str:
    """Spoken-friendly readback of what ARGUS knows."""
    ctx = profile_context()
    if not ctx:
        return "I don't know anything about you yet. Tell me something with 'remember that'."
    facts = [l.split("_(learned")[0].lstrip("- ").strip() for l in ctx.splitlines() if l.startswith("-")]
    return "Here's what I know: " + "; ".join(facts) + "."
