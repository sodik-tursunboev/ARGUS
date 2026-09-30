"""
ARGUS - Agent Kernel: browser-domain verifiers.
module's own docstring for the sibling domain modules, verifiers_desktop.py
and verifiers_storage.py, and for why the split is by domain rather than one
flat file -- that same docstring already names "a future verifiers_browser.py"
as this domain's natural home).

WHAT THIS COVERS, AND WHY THESE FOUR ARE SAFE TO VERIFY. All four reuse
skills/browser_skill.py's own, already-written bookkeeping -- never a second,
parallel read of browser state that could quietly drift from what the skill
itself considers current (see each capture function's own docstring):

  ("browser", "navigate")        page.goto() landed -- browser_skill._history
                                 grew a fresh entry whose URL matches `target`.
  ("browser", "search")          same store, same freshness signal; see "WHY
                                 SEARCH ONLY CHECKS FRESHNESS" below for why
                                 the URL itself is not also matched here.
  ("browser", "bookmark_add")    ARGUS's own saved-link list (NOT your real
                                 browser's bookmarks -- see browser_skill.py's
                                 module docstring) gained an entry.
  ("browser", "bookmark_remove") the same list lost one.

navigate and search are ordinary router.PLANNABLE actions. bookmark_add/
bookmark_remove are WEB_TASK_ACTIONS-only, same tier as files/move in
verifiers_storage.py -- this module verifies what happened, same as it would
for any other write, and changes nothing about when either step is allowed
to run.

THREAD SAFETY -- NO NEW CROSS-THREAD CALL. browser_skill.py's own module
docstring explains why Playwright's sync API is pinned to one dedicated
daemon thread (_BrowserThread): every public accessor that touches a Page or
BrowserContext marshals the work onto it through _get_thread().call(fn), and
calling a Playwright object from any other thread raises. Nothing in this
module goes near that. The two stores read below are both plain,
un-marshalled Python/filesystem state, written directly by the ORDINARY
calling thread, never by a job submitted to the browser thread:
  - _history is appended to by _remember(), called directly from navigate()
    (and, through it, search() -- see search()'s own body) AFTER
    _get_thread().call(...) has already returned, on whichever thread called
    navigate() in the first place -- never from inside the job function that
    actually runs ON the browser thread.
  - the bookmarks file is read/written directly by bookmark_add()/
    bookmark_remove() through _load_bookmarks()/_save_bookmarks() -- plain
    open()/json calls, nothing Playwright-shaped at all.
Reading either needs no _get_thread().call() of any kind, so this module adds
zero new work to the browser thread and cannot block behind a slow or wedged
page load the way a fresh cross-thread read would. It is also not even a
genuinely CONCURRENT read in the one pattern this module is actually used in:
router.py's plan loop calls capture_state() immediately before and
immediately after the SAME synchronous _dispatch() call, on the SAME calling
thread, with plan steps run strictly one at a time (see router.py's
_run_steps loop) -- so by the time this module's capture runs, it is reading
state on the very thread that just mutated it, sequentially, never in
parallel with the mutation itself. CPython's GIL makes a bare list append/
index and a dict assignment individually atomic regardless, so even a truly
concurrent reader (a live voice command landing mid-plan-step, say) could
only ever see the state from just-before or just-after an append, never a
half-written entry.

Given all of that, this module does NOT add a live current-URL accessor to
browser_skill.py, even though it would have been permitted to: _history
already answers "did a real navigation land" honestly and for free, and a
new accessor would only trade that zero-cost safety for a new blocking,
cross-thread call on the hot path of every plannable step. See "WHAT'S
DELIBERATELY NOT HERE" below for the other browser pairs this same reasoning
kept out of scope.

WHY FRESHNESS, NOT RAW COUNT, FOR _history. _history is capped at
_HISTORY_MAX (200) entries -- _remember() trims the OLDEST entries off the
front on every append once the cap is hit (`del _history[:-_HISTORY_MAX]`),
so a plain `len(after) > len(before)` comparison would silently go blind
after the assistant's 200th navigation in a process's lifetime: a genuine
fresh append can leave the length UNCHANGED once the list is already at the
cap, because the trim removes exactly as many old entries as the append
just added. What IS immune to that trim is the identity of the newest entry,
so these verifiers instead check that its own "at" timestamp moved forward
-- the same time.time() field _remember() already stamps every entry with,
not a new one invented here -- which cannot be affected by anything falling
off the front. A before-snapshot with no last entry at all (nothing ever
recorded yet) is treated as a valid baseline to grow from, the same as a
count-based zero would be.

WHY SEARCH ONLY CHECKS FRESHNESS, NOT THE RESULTING URL. navigate()'s target
IS the URL, run through browser_skill._normalize_url() -- a pure function --
before being stamped into _history, so calling that exact function here on
the exact same target reproduces the recorded URL exactly, not
approximately, with no risk of drifting from what navigate() actually does.
search()'s target is a QUERY, not a URL; the URL that actually lands in
_history is built by search()'s own quote_plus() + hard-coded
Google-search-URL logic, one layer further removed from `target` than
navigate's is. Reproducing that construction here just to compare it would
be a second copy of search()'s own URL-building that could quietly drift
from it -- exactly what verifiers_storage.py's own "WHY COUNT, NOT CONTENT"
section warns against for vault/write. A fresh entry landing at all, right
after search() ran, is already the honest, whole claim this verifier can
make -- the same "count, not content" reasoning storage applies to
vault/write and timer/set, applied here as "freshness, not content" for the
reason above.

BOOKMARKS ARE THE SIMPLER, STORAGE-SHAPED CASE. _load_bookmarks()/
_save_bookmarks() are plain JSON-file I/O, the same shape as
timer_skill._load() -- reused directly rather than re-read a second way, and
already fails closed to [] on any error (see _load_bookmarks() itself). No
cap or trim exists on this store (unlike _history), so the plain count
comparison verifiers_storage.py uses for vault/write and timer/set applies
here unmodified: bookmark_add() unconditionally appends on every real add,
and bookmark_remove() only ever calls _save_bookmarks() when at least one
entry actually matched the query (see its own `len(keep) == len(items)`
early return) -- so a genuine shrink is exactly as honest a signal as
vault/timer's genuine growth.

WHAT'S DELIBERATELY NOT HERE:
  - extract_text, find_elements, screenshot, list_tabs, tab_search,
    history_search -- reads. Nothing to verify, same as most of ARGUS's ~90
    plannable capabilities (see verifiers.py's own module docstring).
  - click -- a real write, but declined on purpose: unlike navigate, a
    successful click's effect is not reliably observable through any one
    generic signal. It may navigate, may toggle something visible only
    inside the page's own DOM, or may legitimately change nothing external
    at all (focusing a field). click() does not call _remember(), so there
    is no store to read here either way, and a URL-before/after diff would
    misreport the large fraction of legitimate no-navigation clicks as
    unchanged -- a confident-looking signal that is actually close to a
    guess. The same reasoning keeps pc/ui_click and vision/click_text out of
    their own domains' coverage.
  - back, forward, refresh, tab_open, tab_close, tab_switch, zoom, fill,
    follow_link -- none of these touch _history, the bookmarks file, or any
    other plain, un-marshalled state this module can already read; every one
    of them lives only inside Playwright's own page/context objects, behind
    _get_thread().call(...). Verifying any of them would mean adding a NEW
    cross-thread accessor purely to feed this module's before/after
    snapshots, on the hot path of every plannable step -- and even then the
    signal would be uneven (refresh() reloads the SAME url and would look
    unchanged on every success; tab_open() with no url argument touches
    nothing URL-shaped either). Declined for the same reason as click: an
    honest gap beats a verifier that mostly guesses.
  - submit, download, upload -- the most heavily-gated actions in this file
    already (STAGED, PIN-confirmed, individually audited -- see
    browser_skill.confirm()/_audit()). download does write to a plain,
    un-marshalled store this module could otherwise read (_downloads_log,
    appended to the same way _history is) -- but reaching it correctly means
    reasoning through the staged/PIN-confirm "resume bridge" router.py's
    plan loop uses for these three actions specifically (a paused plan step
    re-dispatches through browser_skill.confirm() rather than through the
    ordinary skill call), and this module was not confident that a plan
    step's before/after bracket reliably surrounds only the confirmed action
    across every pause/resume path without a much deeper read of that loop
    than a domain module like this one should need. Declined rather than
    risk a subtly wrong verifier on the most sensitive action class in this
    file -- an honest "not covered" over a shaky guess.

FAIL CLOSED, ALWAYS. capture_state() below runs on the hot path of EVERY
plannable step, not only the browser fraction -- verifiers.py's own
capture_state() calls every domain module's copy of this function for every
step a plan takes -- so a bookmarks file that will not parse, or any other
failure reading browser_skill's plain state, must come back as None, never
as an exception that takes the step itself down with it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from skills import browser_skill


# ── browser interaction success journal ------------------------------------
# browser_skill records one target-hashed event only after Playwright reports
# success. Reading it is plain Python state, so verification never performs a
# second browser call or retains form values/upload paths in observations.
_EVENT_ACTIONS = {
    "tab_open", "tab_close", "tab_switch", "back", "forward", "refresh",
    "zoom", "click", "follow_link", "fill", "submit", "download", "upload",
}


def _normalized_event_target(action: str, target: str) -> str:
    raw = str(target or "")
    if action in {"fill", "upload"}:
        left, sep, right = raw.partition("|")
        return f"{left.strip()}|{right.strip()}" if sep else raw.strip()
    if action == "zoom":
        try:
            return str(max(25, min(500, int(float(raw)))))
        except (TypeError, ValueError):
            return raw.strip()
    return raw.strip()


def _capture_browser_event(target: str) -> dict:
    return browser_skill.verification_snapshot()


def _verify_browser_event(action: str, target: str,
                          before: dict, after: dict) -> bool:
    try:
        advanced = int(after.get("seq", 0)) > int(before.get("seq", 0))
    except (TypeError, ValueError):
        return False
    expected = browser_skill._target_digest(_normalized_event_target(action, target))
    return (advanced and after.get("action") == action
            and after.get("target_digest") == expected)


def _event_verifier(action: str):
    return lambda target, before, after: _verify_browser_event(
        action, target, before, after)


# ── browser/navigate & browser/search (shared _history store) ─────────────
def _capture_browser_history(target: str) -> dict:
    """Snapshot of browser_skill._history: how many entries it holds, and
    the newest one's url/title/timestamp -- or None for each if nothing has
    been recorded yet this process.

    Reads the list directly rather than through any accessor -- there isn't
    one, and none is needed (see the module docstring's THREAD SAFETY
    section for why a bare read here is safe with no new cross-thread call).

    `target` is accepted but unused here, for the same reason
    _capture_vault_write() ignores it in verifiers_storage.py: this snapshot
    is deliberately target-agnostic. navigate's verifier re-derives the
    expected URL from `target` itself at VERIFY time (see
    _verify_browser_navigate()); search's verifier does not attempt a
    content match at all (see the module docstring's "WHY SEARCH ONLY CHECKS
    FRESHNESS").
    """
    hist = browser_skill._history
    last = hist[-1] if hist else None
    return {
        "count": len(hist),
        "last_url": last.get("url") if last else None,
        "last_title": last.get("title") if last else None,
        "last_at": last.get("at") if last else None,
    }


def _fresh_entry(before: dict, after: dict) -> bool:
    """True if the newest _history entry in `after` was not there yet in
    `before` -- i.e. a real append happened between the two snapshots.

    Compares the newest entry's OWN "at" timestamp rather than the two
    snapshots' "count" fields -- see the module docstring's "WHY FRESHNESS,
    NOT RAW COUNT" for why raw length can understate a genuine append once
    _history is trimmed at its 200-entry cap. A missing `after` timestamp
    means nothing has ever been recorded (capture itself found an empty
    list) -- nothing to confirm, not a bug in this function.
    """
    after_at = after.get("last_at")
    if after_at is None:
        return False
    before_at = before.get("last_at")
    if before_at is not None and after_at <= before_at:
        return False
    return True


def _verify_browser_navigate(target: str, before: dict, after: dict) -> bool:
    """True if _history grew a fresh entry AND that entry's URL is exactly
    the one navigate() would have recorded for `target`.

    browser_skill._normalize_url() is a pure function of `target` alone --
    the SAME call navigate() itself makes, on the SAME string, before ever
    touching Playwright (see navigate()'s own body) -- so re-calling it here
    reproduces the recorded URL exactly, not approximately, with no risk of
    drifting from what navigate() actually does. Requiring both the
    fresh-append signal AND this match costs nothing in false negatives (a
    real navigate(target) success can only ever produce an entry equal to
    _normalize_url(target) -- the two are the same computation) while ruling
    out crediting this step with an append that actually came from something
    else entirely.
    """
    if not _fresh_entry(before, after):
        return False
    return after.get("last_url") == browser_skill._normalize_url(target)


def _verify_browser_search(target: str, before: dict, after: dict) -> bool:
    """True if _history grew a fresh entry as a result of this search.

    No URL match here -- see the module docstring's "WHY SEARCH ONLY CHECKS
    FRESHNESS" for why content-matching would mean duplicating search()'s
    own query-to-URL construction rather than reusing it.
    """
    return _fresh_entry(before, after)


# ── browser/bookmark_add & browser/bookmark_remove ─────────────────────────
def _capture_browser_bookmarks(target: str) -> dict:
    """Snapshot of ARGUS's own saved-link list: how many entries it holds
    right now.

    Calls browser_skill._load_bookmarks() -- the exact function
    bookmark_add()/bookmarks_list()/bookmark_remove() already trust as "what
    is saved", and which already fails closed to [] on any read error --
    rather than a second copy of the same open()/json.load() here.

    `target` is accepted but unused: both verifiers below compare COUNTS
    only, same reasoning as verifiers_storage.py's vault/timer functions --
    see _verify_browser_bookmark_add()/_verify_browser_bookmark_remove().
    """
    return {"count": len(browser_skill._load_bookmarks())}


def _verify_browser_bookmark_add(target: str, before: dict, after: dict) -> bool:
    """True if the bookmark list actually grew.

    bookmark_add() unconditionally appends on every real add (see its own
    body) -- there is no dedup or merge to make a count-only check
    ambiguous, the same "grows only from its own write" reasoning
    _verify_vault_write() documents for the vault's note store.
    """
    before_count = before.get("count")
    after_count = after.get("count")
    if before_count is None or after_count is None:
        return False  # ordinary "couldn't determine" case, not a bug here
    return after_count > before_count


def _verify_browser_bookmark_remove(target: str, before: dict, after: dict) -> bool:
    """True if the bookmark list actually shrank.

    Mirrors _verify_browser_bookmark_add(): bookmark_remove() only calls
    _save_bookmarks() when at least one entry matched `target` (see its own
    `len(keep) == len(items)` early return before ever writing) -- so this
    correctly reports False, not a guessed True, for "nothing matched", the
    same way _verify_timer_set() does for a duration that never reached the
    store.
    """
    before_count = before.get("count")
    after_count = after.get("count")
    if before_count is None or after_count is None:
        return False
    return after_count < before_count


# ── entry points agent/verifiers.py aggregates ─────────────────────────────
_CAPTURERS: dict[tuple[str, str], callable] = {
    ("browser", "navigate"): _capture_browser_history,
    ("browser", "search"): _capture_browser_history,
    ("browser", "bookmark_add"): _capture_browser_bookmarks,
    ("browser", "bookmark_remove"): _capture_browser_bookmarks,
    **{("browser", action): _capture_browser_event for action in _EVENT_ACTIONS},
}


def capture_state(skill: str, action: str, target: str) -> dict | None:
    """A snapshot of whatever state is relevant to verifying (skill, action),
    or None if this module has nothing to capture for that pair -- the
    aggregator in agent/verifiers.py then asks the other domain modules, or
    the read itself failed for any reason.

    NEVER RAISES. Called once before a step's real dispatch and once after,
    for EVERY step a plan takes, not only the browser fraction (see
    verifiers.py's own capture_state(), which calls every domain module's
    copy of this function on every step) -- so a bookmarks file that will
    not parse, or any other failure reading browser_skill's plain state,
    must come back as "nothing to verify", never as an exception that takes
    the step itself down with it. That is the one job of the try/except
    below, matching verifiers_storage.py's own capture_state() exactly; the
    per-capability functions above are free to raise ordinary exceptions
    because this is where they're meant to be caught.
    """
    fn = _CAPTURERS.get((str(skill or "").strip(), str(action or "").strip()))
    if fn is None:
        return None
    try:
        return fn(target)
    except Exception:
        return None


# Every value here has the identical signature: (target: str, before: dict,
# after: dict) -> bool. See each function's own docstring above for exactly
# what it checks and why; the module docstring's "WHY FRESHNESS, NOT RAW
# COUNT" and "WHY SEARCH ONLY CHECKS FRESHNESS" sections cover the two
# non-obvious design choices that apply across more than one of them.
VERIFIERS: dict[tuple[str, str], callable] = {
    ("browser", "navigate"): _verify_browser_navigate,
    ("browser", "search"): _verify_browser_search,
    ("browser", "bookmark_add"): _verify_browser_bookmark_add,
    ("browser", "bookmark_remove"): _verify_browser_bookmark_remove,
    **{("browser", action): _event_verifier(action) for action in _EVENT_ACTIONS},
}
