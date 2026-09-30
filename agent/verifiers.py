"""
ARGUS - Agent Kernel: verifier registry.

The single place observer.py looks up a real, machine-state verifier for a
(skill, action) pair. This module owns NO verification logic itself -- it
only aggregates the domain modules below, each scoped to capabilities that
share a kind of state worth checking:

  verifiers_desktop.py   apps/window/control -- process, foreground window
                         and audio state, via psutil/win32/pycaw.
  verifiers_storage.py   vault/timer/files -- the note store, the reminder
                         store, and confined filesystem writes.
  verifiers_browser.py   browser navigate/search/bookmark_add/bookmark_remove
                         -- browser_skill's own plain, un-marshalled history
                         and bookmarks state (never a live Playwright call).

Split by domain rather than kept as one file for the same reason
skills/registry.py stays one flat table instead of a class hierarchy: each
domain's checks are independent, reviewed independently, and adding a new
domain should never require touching an unrelated one.

COVERAGE IS PARTIAL BY DESIGN. Most of ARGUS's ~90 plannable capabilities
are reads with no "changed" state to verify -- see capability_catalog.py's
own `reversible=True` note. A (skill, action) with no entry here is not a
gap to apologise for; observer.observe() already handles it honestly
(verified=False, changed=None) rather than pretending. See coverage() below
for what IS covered right now.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from agent import verifiers_browser, verifiers_desktop, verifiers_storage

_MODULES = (verifiers_desktop, verifiers_storage, verifiers_browser)

# Merged from every domain module. A key collision between two domain
# modules would mean two different checks silently shadowing each other --
# asserted against at import time so that mistake fails loudly at boot
# rather than quietly picking whichever module happened to load last.
VERIFIERS: dict[tuple[str, str], callable] = {}
for _mod in _MODULES:
    _dupes = set(_mod.VERIFIERS) & set(VERIFIERS)
    if _dupes:
        raise RuntimeError(
            f"verifier domain collision in {_mod.__name__}: {_dupes} already "
            f"registered by another domain module")
    VERIFIERS.update(_mod.VERIFIERS)


def capture_state(skill: str, action: str, target: str) -> dict | None:
    """Try each domain module in turn; the first non-None snapshot wins.
    Domains are disjoint by construction (see the collision check above), so
    at most one module will ever actually have something to say for a given
    pair -- this loop is just how that "ask the module that owns this
    capability" dispatch happens without VERIFIERS needing to also carry a
    second table mapping pairs back to their capture function.
    """
    for mod in _MODULES:
        try:
            state = mod.capture_state(skill, action, target)
        except Exception:
            # A domain module's capture must already fail closed (return
            # None) per its own contract; this is a last-resort guard so one
            # broken domain can never take capture_state() down for every
            # OTHER capability's steps in the same plan.
            state = None
        if state is not None:
            return state
    return None


def coverage() -> list[tuple[str, str]]:
    """Every (skill, action) pair a real verifier exists for right now."""
    return sorted(VERIFIERS)
