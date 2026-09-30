"""
ARGUS - Conversation persistence.

conversation_history lived in a module-level list and nowhere else, so every
restart was total amnesia: ask a question, restart ARGUS, and the follow-up
"what did you say about that?" met a blank slate. For an assistant that is
meant to be running all day on your own machine, forgetting the entire
conversation because the process was restarted is one of the more obviously
bot-like behaviours left.

This mirrors the in-memory list to disk so a restart resumes mid-conversation.

Two deliberate limits. The transcript is trimmed to the same MAX_HISTORY the
in-memory list uses -- this is short-term conversational context, not an
archive, and the vault already exists for anything worth keeping. And it
expires: resuming a conversation from three days ago is worse than starting
fresh, because the model would confidently answer follow-ups about a context
the user has long since forgotten.

Stored as plain JSON next to the profile, for the same reason everything else
here is plain text -- it can be read, checked, and deleted by hand.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import time

from config import VAULT_PATH

HISTORY_PATH = os.path.join(VAULT_PATH, "conversation.json")

# Older than this and a resumed conversation is more confusing than helpful.
STALE_AFTER = 6 * 3600


def load(max_items: int) -> list:
    """Returns the saved exchange list, or empty if missing, stale or unreadable."""
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            blob = json.load(f)
    except (OSError, ValueError):
        return []

    if not isinstance(blob, dict):
        return []
    if time.time() - blob.get("saved", 0) > STALE_AFTER:
        return []

    msgs = blob.get("messages")
    if not isinstance(msgs, list):
        return []

    # Validate shape rather than trusting the file: a hand-edited or truncated
    # transcript must not reach the model as malformed messages.
    clean = [
        m for m in msgs
        if isinstance(m, dict)
        and m.get("role") in ("user", "assistant")
        and isinstance(m.get("content"), str)
        and m["content"].strip()
    ]
    return clean[-max_items:]


def save(messages: list, max_items: int):
    """Persists the tail of the conversation. Never raises -- losing the
    transcript must not break the exchange that produced it."""
    try:
        os.makedirs(VAULT_PATH, exist_ok=True)
        blob = {"saved": time.time(), "messages": messages[-max_items:]}
        tmp = HISTORY_PATH + ".tmp"
        # Write-then-replace so a crash mid-write can't leave a truncated file
        # that then fails to parse and silently drops the whole conversation.
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(blob, f, ensure_ascii=False, indent=1)
        os.replace(tmp, HISTORY_PATH)
    except OSError as e:
        print(f"[history] could not save: {e}")


def clear():
    try:
        os.remove(HISTORY_PATH)
    except OSError:
        pass
