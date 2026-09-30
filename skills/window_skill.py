"""
ARGUS - Window management.

Focus, minimize, and maximize windows by spoken name. "Switch to Chrome" is one
of those commands that feels trivial but you end up using constantly.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import difflib


def _windows():
    import pygetwindow as gw
    out = []
    for w in gw.getAllWindows():
        try:
            if w.title and w.title.strip() and w.width > 0:
                out.append(w)
        except Exception:
            continue
    return out


def _find(query: str):
    q = query.lower().strip()
    wins = _windows()
    if not wins:
        return None

    for w in wins:
        if q in w.title.lower():
            return w

    titles = [w.title.lower() for w in wins]
    close = difflib.get_close_matches(q, titles, n=1, cutoff=0.5)
    if close:
        for w in wins:
            if w.title.lower() == close[0]:
                return w
    return None


def focus(query: str) -> str:
    if not query.strip():
        return "Which window?"
    w = _find(query)
    if not w:
        return f"I don't see a window for {query}."
    try:
        if w.isMinimized:
            w.restore()
        w.activate()
        return f"Switched to {w.title[:45]}."
    except Exception as e:
        return f"Couldn't switch to it: {e}"


# "all", "everything", "all windows" -- said constantly, and none of them is
# the name of a window. Without this, "minimise all windows" searched for a
# window literally called "all windows", failed, and answered "I don't see a
# window for all windows" -- a confusing refusal to a request ARGUS could
# already serve, since minimize_all() has existed all along.
_ALL_WINDOWS = frozenset({
    "all", "all windows", "everything", "every window", "all of them",
    "them all", "the windows", "windows", "all my windows", "everything else",
})


def _means_all(query: str) -> bool:
    q = " ".join((query or "").lower().split())
    return q in _ALL_WINDOWS


def minimize(query: str) -> str:
    if _means_all(query):
        return minimize_all()
    w = _find(query) if query.strip() else None
    if not w:
        return (f"I don't see a window called {query}. "
                f"Say \"minimise all\" to show the desktop, or "
                f"\"what windows are open\" to hear the list.")
    w.minimize()
    return "Minimized."


def maximize(query: str) -> str:
    w = _find(query) if query.strip() else None
    if not w:
        return (f"I don't see a window called {query}. Say "
                f"\"what windows are open\" to hear the list.")
    w.maximize()
    return "Maximized."


# ── tiling ───────────────────────────────────────────────────────────────────
#
# "Put the browser on the left" is the other command you use constantly and
# could not say. Windows has snap, but only under the mouse or a chord; naming
# the window out loud is the thing that was missing.
#
# GEOMETRY COMES FROM THE WORK AREA, NEVER THE SCREEN. The taskbar is part of
# the screen and not part of the usable space, so tiling to screen height puts
# the bottom of every window underneath it -- including its own status bar,
# which is where the useful part of a terminal or an editor lives.
_HALVES = {
    "left":  (0.0, 0.0, 0.5, 1.0),
    "right": (0.5, 0.0, 0.5, 1.0),
    "top":   (0.0, 0.0, 1.0, 0.5),
    "bottom": (0.0, 0.5, 1.0, 0.5),
    "top left": (0.0, 0.0, 0.5, 0.5),
    "top right": (0.5, 0.0, 0.5, 0.5),
    "bottom left": (0.0, 0.5, 0.5, 0.5),
    "bottom right": (0.5, 0.5, 0.5, 0.5),
    "full": (0.0, 0.0, 1.0, 1.0),
    "centre": (0.15, 0.1, 0.7, 0.8),
}
_SIDE_ALIASES = {
    "middle": "centre", "center": "centre", "middle of the screen": "centre",
    "maximised": "full", "maximized": "full", "fullscreen": "full",
    "the left": "left", "the right": "right", "left side": "left",
    "right side": "right", "left half": "left", "right half": "right",
    "top half": "top", "bottom half": "bottom",
}


def normalise_side(side: str) -> str:
    """A spoken side -> a key in _HALVES, or "" if it is not a side at all."""
    s = " ".join((side or "").lower().split()).strip(" .")
    s = _SIDE_ALIASES.get(s, s)
    return s if s in _HALVES else ""


def _work_area():
    """(x, y, w, h) of the usable desktop, taskbar excluded.

    Delegated to pc_skill rather than implemented here, and the reason is a
    capability one: the scanner counts ctypes.windll as a filesystem
    signature, so asking Windows for the work area from THIS module would
    mean declaring `filesystem` on a module that manages window geometry and
    opens no file. pc_skill already declares it and owns system queries.

    Kept as a function here so callers -- and the tests that patch it -- have
    one name for "the usable desktop".
    """
    from skills import pc_skill
    return pc_skill.work_area()


def _place(w, side: str) -> bool:
    """Move and size one window into SIDE of the work area. Never raises."""
    frac = _HALVES.get(side)
    if not frac:
        return False
    ax, ay, aw, ah = _work_area()
    fx, fy, fw, fh = frac
    try:
        # A maximized window ignores moveTo/resizeTo -- it stays maximized and
        # the call silently does nothing, which looks exactly like a bug in
        # the matching. Restore first, always.
        if w.isMaximized:
            w.restore()
        if w.isMinimized:
            w.restore()
        w.moveTo(int(ax + aw * fx), int(ay + ah * fy))
        w.resizeTo(int(aw * fw), int(ah * fh))
        return True
    except Exception:
        return False


def snap(query: str, side: str) -> str:
    """Put one named window on one side of the screen."""
    key = normalise_side(side)
    if not key:
        return (f"I don't know where {side!r} is. Try left, right, top, "
                f"bottom, a corner, centre, or full screen.")
    if not (query or "").strip():
        return "Which window?"
    w = _find(query)
    if not w:
        return (f"I don't see a window called {query}. Say \"what windows are "
                f"open\" to hear the list.")
    if not _place(w, key):
        return f"I couldn't move {w.title[:40]}."
    try:
        w.activate()
    except Exception:
        pass                      # placed is the job; focus is a nicety
    return f"{w.title[:40]} is on the {key}." if key not in ("full", "centre") \
        else f"{w.title[:40]} is {key} screen." if key == "full" \
        else f"{w.title[:40]} is centred."


def arrange(pairs) -> str:
    """Lay several windows out in one command.

    `pairs` is [(query, side), ...] -- "put my code on the left and the
    browser on the right" is one sentence and should be one action, not two
    that half-succeed.
    """
    placed, missed = [], []
    for query, side in pairs or []:
        key = normalise_side(side)
        w = _find(query) if (query or "").strip() else None
        if not key or not w or not _place(w, key):
            missed.append(query)
            continue
        placed.append(f"{w.title[:26]} {key}")
    if not placed:
        return ("I couldn't find those windows. Say \"what windows are open\" "
                "to hear the list.")
    out = "Arranged: " + ", ".join(placed) + "."
    if missed:
        out += f" I couldn't find {', '.join(missed)}."
    return out


def minimize_all() -> str:
    import keyboard
    keyboard.send("windows+d")
    return "Showing the desktop."


def list_windows() -> str:
    wins = _windows()
    if not wins:
        return "No open windows."
    names = []
    for w in wins[:8]:
        t = w.title.split(" - ")[-1] if " - " in w.title else w.title
        names.append(t[:30])
    return "Open windows: " + ", ".join(names) + "."
