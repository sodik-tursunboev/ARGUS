"""
ARGUS - Context skill (current app, window, file, selection).

Three of the most common questions a voice assistant gets are
"What am I looking at?", "What file did you just find?" and
"What's selected right now?" — all the same shape: "tell me the current
state of whatever is in front of me." Pieces of the answer already exist
scattered across pc_skill, vision_skill, browser_skill, and
followup_skill, but no one module composes them into a single scene.

That is what this module does. It is strictly read-only, strictly local,
and produces a spoken paragraph — not a data structure. It never asserts
what the user SHOULD be doing; it only describes what is visible right now.

READ-ONLY BY DESIGN. This module never moves, opens, clicks, or writes
anything. Its purpose is to ANSWER, not to ACT. Any action after the answer
must come from a separate, independently-authorised decision by the router.

NOT THE CLIPBOARD, BY TIER. The scene (window, file, tab) is L1-safe: it is
the machine's own state, no more private than the taskbar. The clipboard is
NOT in the scene -- control/clipboard_read is gated at L2_REAUTH because the
clipboard may hold a password, and this skill is L1, so a cheaper route to
the same content does not exist here.

SCREEN IS HEAVY. Calling vision_skill.read_text() to OCR the whole screen
is slow (it must take a screenshot and process it). This module does NOT
do that unless the user explicitly asks for it via the screen=True argument
to current(). The default scene is window, app, and file only.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re


# ── helpers ────────────────────────────────────────────────────────────────

# Editor process names (without .exe) — used to infer that a file is open.
_EDITOR_NAMES = {
    "notepad", "notepad++", "vscode", "code", "sublime", "notepad2",
    "atom", "vim", "gvim", "emacs", "gedit", "code - insider", "vscode-insiders",
    "pycharm", "intellij", "studio64", "studio6464", "studio",
    "txt", "wordpad", "word", "excel", "powerpnt", "calc",
}


def _clean_window(w: dict) -> dict:
    """Strip anything non-essential from a window dict for display."""
    return {
        "title": (w or {}).get("title", ""),
        "process": (w or {}).get("process", ""),
    }


def _process_name(raw: str) -> str:
    """Normalise: strip .exe, lowercase."""
    name = (raw or "").strip()
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name


def _is_editor(process: str) -> bool:
    p = _process_name(process).lower()
    return p in _EDITOR_NAMES or any(p.startswith(e) for e in _EDITOR_NAMES)


def _active_browser_tab() -> str:
    """Try to read the active tab title/URL from browser_skill. Returns ""
    if the browser is not running or we can't get it."""
    try:
        from skills import browser_skill
        result = browser_skill.list_tabs()
        # browser_skill.list_tabs() returns lines like:
        # "https://example.com | Example"
        # and "[active]" prefix on the current tab
        for line in str(result or "").splitlines():
            line = line.strip()
            if line.startswith("[active] "):
                tab = line[len("[active] "):].strip()
                # The title part is after the last " | " separator
                return tab
    except Exception:
        pass
    return ""


# ── public API ─────────────────────────────────────────────────────────────

def current(screen: bool = False) -> str:
    """The current scene: what app, what window, and (in an editor) what file.

    If screen=True, also OCR the screen (slow). Follow-up hint: this module
    does NOT re-point "close it" / "move that" — followup_skill already does
    that via focused_app() and last_file(). What this module DOES is record
    the current file into followup_skill.remember_file() when it can, so
    "move that to Documents" works after asking "what am I looking at".

    NOT THE CLIPBOARD. control/clipboard_read is gated at L2_REAUTH because
    the clipboard may hold a password; this skill is L1, so its scene stops
    at the window and the file and never echoes buffer contents. "what's on
    my clipboard" routes to control/clipboard_read, which is the L2 route
    that gate belongs to.
    """
    from skills import pc_skill
    from skills import followup_skill

    w = pc_skill.focused_window()
    w = _clean_window(w)
    process = _process_name(w.get("process", ""))
    title = w.get("title", "")
    is_ed = _is_editor(process)

    parts = []

    # App and window
    if title:
        parts.append(f"You're looking at {title}")
        if process:
            parts.append(f"({process})")
    elif process:
        parts.append(f"You're looking at {process}")
    else:
        parts.append("I can't see what app has focus right now")

    # If it's an editor, we might be able to infer a file path
    if is_ed and title:
        # Many editors put the file name in the window title.
        # Heuristic: if it contains a path separator or an extension, treat
        # the last part as a file name.
        m = re.search(r"([A-Z]:\\[^:]+\\([^:]+)\.(?:[a-zA-Z0-9]+))", title)
        if m:
            filepath = m.group(1)
            parts.append(f"File: {filepath}")
            followup_skill.remember_file(filepath)

    # Active browser tab, if the managed browser is running
    tab = _active_browser_tab()
    if tab:
        parts.append(f"Browser tab: {tab}")

    # Optional: full screen OCR (expensive, only when asked)
    if screen:
        try:
            from skills import vision_skill
            result = vision_skill.read_text()
            preview = str(result or "")[:120]
            if len(str(result or "")) > 120:
                preview += "…"
            parts.append(f"Screen OCR: {preview}")
        except Exception:
            parts.append("(Could not OCR the screen)")

    return " ".join(parts) + "."


def selection() -> str:
    """What ARGUS was just working with: the last file it found or named.
    Does NOT read the clipboard -- see current()'s note on why that stays at
    the L2 control/clipboard_read route."""
    from skills import followup_skill

    last = followup_skill.last_file()
    if last:
        return f"The last file you mentioned was: {last}"

    return "I don't have anything selected right now."


def file() -> str:
    """The file ARGUS most recently found, or a fallback."""
    from skills import followup_skill

    last = followup_skill.last_file()
    if last:
        return f"The file: {last}"
    return "I haven't found a file in the last few minutes."