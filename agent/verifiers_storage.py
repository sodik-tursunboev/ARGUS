"""
ARGUS - Agent Kernel: storage-domain verifiers.
(see that module's own docstring for the sibling domain, verifiers_desktop.py,
and for why the split is by domain rather than one flat file).

WHAT THIS COVERS, AND WHY THESE THREE ARE SAFE TO VERIFY. Every pair here is
an ORDINARY data-store or filesystem write -- nothing security-sensitive,
nothing that needed a gate beyond what auth.py and files_skill.py's own path
confinement already apply before a step ever reaches this module:

  ("vault", "write")  a markdown note appended to vault_skill's note store
                      (RAW_DIR/WIKI_DIR/OUTPUTS_DIR).
  ("timer", "set")    a reminder appended to timer_skill's reminders.json.
  ("files", "move")   a file relocated inside files_skill.py's own confined
                      SEARCH_ROOTS -- see that file's FILE OPERATIONS
                      header. WEB_TASK_ACTIONS-only (see router.py): not
                      part of the ordinary PLANNABLE allowlist, because "a
                      write outside the browser window" is exactly the
                      class of step rule 2 above PLANNABLE keeps off it.
                      It only ever runs as a step inside a web task, gated
                      at browser/task's L3 plus the per-write PIN pause --
                      this module verifies what happened, same as it would
                      for any other write, and changes nothing about when
                      that step is allowed to run.

Deletion, power and dictation are NOT here, on purpose -- PLANNABLE and
WEB_TASK_ACTIONS both exclude them for the same reason (see router.py's
rule 2 comment above PLANNABLE), so there is nothing for a plan-step
verifier to ever check against them in the first place.

EACH CHECK REUSES THE SKILL'S OWN STORE-READING CODE. vault_skill._all_notes(),
timer_skill._load(), and files_skill._resolve_folder() are the EXACT
functions the real skills already trust to answer "what's in the store" and
"where does this path actually resolve" -- never a second, parallel reading
that could quietly drift from what the skill itself considers current. For
files/move specifically, _resolve_folder() is the ONE place a destination's
path confinement is enforced; this module never constructs or trusts a path
built directly from the raw target string -- see _capture_files_move()'s own
docstring.

WHY COUNT, NOT CONTENT, FOR VAULT AND TIMER. Both stores only ever grow from
their own write action -- vault_skill.write_note() always mints a fresh,
timestamped filename, and timer_skill.set_timer() always appends. So the one
fact that distinguishes "the write actually landed" from "the skill said it
worked but didn't" is whether the store has one more entry afterward than it
did before -- independent of the reply text, and robust to a `target` that
doesn't exactly match whatever the store ends up calling the new entry (see
each verifier's own docstring for specifics).

FAIL CLOSED, ALWAYS. capture_state() below runs on the hot path of EVERY
step a plan takes, not only the fraction that end up needing verification --
verifiers.py's own capture_state() calls every domain module's copy of this
function for every step -- so a locked file, a missing folder, or a store
that doesn't parse must come back as None, never as an exception that takes
the step itself down with it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os

from skills import files_skill, timer_skill, vault_skill


# ── vault/write ---------------------------------------------------------------
def _capture_vault_write(target: str) -> dict:
    """Snapshot of the note store: how many .md files exist across
    vault_skill's RAW/WIKI/OUTPUTS folders right now, plus their filenames.

    Calls vault_skill._all_notes() -- the exact listing search() and
    read_recent() already trust as "what's in the vault" -- rather than
    walking the three folders again here with a second copy of the same
    .md-only logic that could quietly drift from it.

    `target` (the note's intended title) is accepted but unused: the
    verifier below only compares COUNTS, so there is nothing to do with it
    at capture time -- see _verify_vault_write()'s docstring for why a count
    is the honest check here rather than a title match.
    """
    notes = vault_skill._all_notes()
    return {"count": len(notes), "names": [os.path.basename(p) for p in notes]}


def _verify_vault_write(target: str, before: dict, after: dict) -> bool:
    """True if the note store actually grew.

    COUNT, not a title match, is the signal -- see the module docstring's
    "WHY COUNT, NOT CONTENT" section. `target` may be the note's title, may
    be empty, or may be whatever plan_and_stage happened to put in the
    step's target field, and write_note() itself sanitises the title before
    it ever reaches a filename (strips punctuation, prefixes a timestamp --
    see vault_skill.py's write_note()). A verifier that demanded an exact
    title match would report a REAL, successful write as a failure just
    because the title got mangled on the way to a filename. One more file
    in the store than before this step ran is the entire claim vault/write
    makes, and the entire thing worth checking.
    """
    before_count = before.get("count")
    after_count = after.get("count")
    if before_count is None or after_count is None:
        # Ordinary "couldn't determine" case: one of the two snapshots is
        # missing the field this check needs -- not a bug in this function.
        return False
    return after_count > before_count


# ── timer/set -------------------------------------------------------------
def _capture_timer_set(target: str) -> dict:
    """Snapshot of the reminder store: how many pending timers/reminders
    timer_skill._load() currently returns, plus their labels.

    _load() is the EXACT list set_timer() reads, appends to, and _save()s
    back (see timer_skill.py's own module docstring on why this store is
    plain JSON on disk), so reading it here reads the same file the real
    action just wrote rather than a proxy for it. It already fails closed
    on a missing or corrupt file (returns []), so there is nothing extra to
    guard against here.

    `target` (a duration in seconds -- see router.py's ROUTING_PROMPT entry
    for "timer": target=seconds as number) is accepted but unused, same
    reasoning as _capture_vault_write(): the verifier compares COUNTS, and a
    bare duration number identifies nothing in the store to match against
    even if a stronger check were wanted.
    """
    items = timer_skill._load()
    return {"count": len(items), "labels": [str(i.get("label", "")) for i in items]}


def _verify_timer_set(target: str, before: dict, after: dict) -> bool:
    """True if the reminder store actually grew.

    Same reasoning as _verify_vault_write(): COUNT is the one signal that
    can't be fooled by set_timer()'s reply text alone, and it is also
    exactly right for the one way this action legitimately does nothing --
    set_timer() returns early, before ever touching the store, when the
    duration "didn't make sense" (seconds <= 0). That case correctly shows
    no growth here, independent of whichever wording the reply used.
    """
    before_count = before.get("count")
    after_count = after.get("count")
    if before_count is None or after_count is None:
        return False  # ordinary "couldn't determine" case, not a bug here
    return after_count > before_count


# ── files/move (WEB_TASK_ACTIONS-only -- see router.py) -----------------------
def _capture_files_move(target: str) -> dict | None:
    """Snapshot of the move's DESTINATION folder: its confined, resolved
    path and the set of names currently in it. None if `target` doesn't
    carry a destination, or the destination doesn't resolve to a folder
    ARGUS is confined to -- in both cases the real move() call is about to
    fail for the identical reason, so there is nothing to verify either way.

    PARSING MATCHES router.py's _dispatch_inner EXACTLY, not the comment
    written above it there. That comment claims the shape is
    "<what> -> <where>", but the code right below the comment actually does
    `src, _, dest = (target or "").partition("|")` -- a split on the FIRST
    "|", not "->". The code is what runs, so this splits the same way,
    rather than trusting the comment or inventing a third shape of its own.

    Deliberately does NOT try to resolve or snapshot the SOURCE side.
    files_skill.move() may rename the incoming file if something of the
    same name is already sitting in the destination (see its _unique()
    helper), so the one fact that actually answers "did this move land" is
    whether the destination folder's CONTENTS changed at all -- not whether
    one specific, predicted filename showed up.

    Resolves the destination through files_skill._resolve_folder() -- the
    SAME confinement/shortcut-lookup helper move() itself calls, and the
    one timer_skill.py's add_watcher() already reaches into this exact way
    for a folder watcher's target -- rather than re-deriving what "confined"
    means here. Path safety has exactly one enforcement point in this
    codebase; this module reads through it, never around it.
    """
    _src, _, dest_part = str(target or "").partition("|")
    dest = dest_part.strip()
    if not dest:
        return None
    try:
        dest_dir = files_skill._resolve_folder(dest)
    except files_skill.FileOpError:
        # Doesn't resolve to a folder ARGUS is confined to -- move() is
        # about to refuse this step for the identical reason, so there is
        # no destination state to snapshot.
        return None
    entries = sorted(os.listdir(dest_dir))
    return {"dest_dir": dest_dir, "entries": entries}


def _verify_files_move(target: str, before: dict, after: dict) -> bool:
    """True if the destination folder actually gained a new entry.

    Compares directory LISTINGS rather than checking a single predicted
    filename, because _unique() (files_skill.py) may have suffixed the
    incoming file's name to avoid overwriting something already there -- a
    verifier that only checked one exact, guessed basename would report a
    real, successful move as a failure whenever a name collision renamed
    it. Once a candidate new name is found, it is additionally confirmed
    with os.path.exists() against the resolved dest_dir -- the SAME
    confined path _capture_files_move() produced, never a path rebuilt from
    the raw target string -- so this doesn't trust the listdir() snapshot
    alone.
    """
    dest_dir = after.get("dest_dir")
    if not dest_dir or dest_dir != before.get("dest_dir"):
        # Ordinary "couldn't determine" case: the two snapshots disagree on
        # (or are missing) the destination they resolved. Should not happen
        # given both parse the identical target string, but this is a real
        # check and must not assume its own inputs.
        return False
    new_entries = set(after.get("entries") or ()) - set(before.get("entries") or ())
    if not new_entries:
        return False
    return any(os.path.exists(os.path.join(dest_dir, name)) for name in new_entries)


# ── entry points agent/verifiers.py aggregates ────────────────────────────
_CAPTURERS: dict[tuple[str, str], callable] = {
    ("vault", "write"): _capture_vault_write,
    ("timer", "set"): _capture_timer_set,
    ("files", "move"): _capture_files_move,
}


def capture_state(skill: str, action: str, target: str) -> dict | None:
    """A snapshot of whatever state is relevant to verifying (skill, action),
    or None if this module has nothing to capture for that pair -- the
    aggregator in agent/verifiers.py then asks the other domain module --
    or the read itself failed for any reason.

    NEVER RAISES. Called once before a step's real dispatch and once after,
    for EVERY step a plan takes, not only the fraction that end up needing a
    verifier (see verifiers.py's own capture_state(), which calls every
    domain module's copy of this function on every step) -- so a locked
    reminders.json, a vault folder deleted out from under ARGUS, or a
    destination that no longer confines must come back as "nothing to
    verify", never as an exception that takes the step itself down with it.
    That is the one job of the try/except below; the per-capability
    functions above are free to raise ordinary exceptions (FileOpError,
    OSError) because this is where they're meant to be caught -- exactly
    like files_skill.py's own FileOpError is raised deep inside
    _confined()/_resolve_folder() and only caught at each public action's
    boundary, not at every call site in between.
    """
    fn = _CAPTURERS.get((str(skill or "").strip(), str(action or "").strip()))
    if fn is None:
        return None
    try:
        return fn(target)
    except Exception:
        return None


# Every value here has the identical signature: (target: str, before: dict,
# after: dict) -> bool. See each function's own docstring above for what
# `target` actually carries for that pair, and why the comparison is
# COUNT-based (vault, timer) or LISTING-based (files) rather than anything
# stronger.
VERIFIERS: dict[tuple[str, str], callable] = {
    ("vault", "write"): _verify_vault_write,
    ("timer", "set"): _verify_timer_set,
    ("files", "move"): _verify_files_move,
}
