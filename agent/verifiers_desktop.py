"""
ARGUS - Agent Kernel: desktop verifiers.

One of the domain modules agent/verifiers.py aggregates -- see that module's
own docstring for why the split is by domain rather than one flat file. This
domain owns the capabilities whose state Windows already exposes cheaply
through three existing channels: the process table (psutil), the foreground
window (user32, the same well pc_skill.focused_window() already taps), and
the default audio endpoint (pycaw, the same one control_skill.py fought to
keep working across an API break). Covers exactly:

    ("apps", "open"), ("apps", "close")
    ("window", "focus"), ("window", "minimize"), ("window", "maximize")
    ("control", "volume_set"), ("control", "mute"), ("control", "unmute")

All eight are ordinary, reversible desktop actions already on router.PLANNABLE
-- nothing here decides authorisation (auth.py alone still does that) or
touches anything rule 2 above PLANNABLE's own definition keeps off the
allowlist in the first place.

WHAT "changed" MEANS HERE. Every function in VERIFIERS answers one question,
literally: did the relevant bit of machine state TRANSITION from not matching
the target to matching it, between the before and after snapshot -- not
"does after satisfy the target" alone. An app already running when "open" was
said, a window already focused when "focus" was said, a volume already at the
requested level: all of these report changed=False, because nothing actually
changed as a result of the step. That is not this module calling those cases
FAILURES -- observer.py keeps classify_reply()'s status and a verifier's
changed deliberately free to disagree (see its "TWO KINDS OF EVIDENCE, KEPT
HONESTLY SEPARATE"), so a step whose reply says "Opening Chrome." can still
be status=success, changed=False, and both are correct at once. Reporting
changed=True for a state that was already correct before the step ran would
be a guess wearing a verification's clothes -- the same failure shape
apps_skill.py's own BUGFIX comments (silently collapsing ambiguous
candidates into one answer) exist to stop -- so this module declines to make
that guess.

THE FOREGROUND WINDOW IS A PROXY, NOT THE NAMED TARGET. minimize and maximize
verify against whatever window is in the foreground, read with the same raw
user32 calls pc_skill.focused_window() already uses for title/process/pid
(that function stops short of IsIconic/IsZoomed, so those two are read here
directly off the same handle -- see _foreground_snapshot()). That is exact
for the dominant voice pattern -- "minimize this", "maximize it", or naming
whatever is already on screen -- because window_skill's minimize()/maximize()
act on that same window in that case. It is a KNOWN, ACCEPTED GAP for the
less common case of naming a window that is not focused: a minimize never
brings a background window through the foreground slot this module can
observe, so that transition is invisible here, and the verifier honestly
answers False rather than guessing True. See _verify_window_minimize and
_verify_window_maximize for the exact signal each one uses, and this
module's own delivery notes for the full list of known gaps.

FAIL CLOSED, NEVER RAISE FROM capture_state(). It runs on the hot path of
EVERY plannable step, not only the ones that end up needing verification
(see agent/verifiers.py's own capture_state(), which calls straight through
to this module's) -- so every OS call here is wrapped, and any failure
degrades to None rather than taking the step down. A VERIFIERS function may
still raise on a genuine bug in this module's own code; a normal "couldn't
determine" case returns False instead, with the reasoning left in a comment
at that call site -- never a guessed True.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ctypes

import psutil


# ── name/title matching ──────────────────────────────────────────────────────
def _loose_match(target: str, candidate: str) -> bool:
    """Case-insensitive substring match, either direction, against the ".exe"
    stem.

    A launched app's process name, or a focused window's title, essentially
    never equals what the user said letter for letter -- "chrome" launches
    as "chrome.exe", "code" ends up in a window titled "Visual Studio Code -
    verifiers_desktop.py". An exact-equality check here would fail on almost
    every real command, so this is deliberately the same SHAPE of match
    apps_skill.close_app() and window_skill._find() already resolve spoken
    names against -- reused as a rule (substring, symmetric, case-insensitive,
    ".exe" stripped) rather than re-derived, so this module's idea of "looks
    like the target" cannot quietly diverge from the one actually deciding
    what gets closed or focused.
    """
    t = (target or "").strip().lower().removesuffix(".exe")
    c = (candidate or "").strip().lower().removesuffix(".exe")
    if not t or not c:
        return False
    return t in c or c in t


def _window_matches(target: str, state: dict | None) -> bool:
    """True if a captured window snapshot looks like `target`, by title or by
    process name -- either is a legitimate way a person names a window
    ("minimize chrome" names the process, "switch to the invoice" names the
    title), so both are checked."""
    state = state or {}
    return (_loose_match(target, state.get("title", "")) or
            _loose_match(target, state.get("process", "")))


# ── apps: open / close ───────────────────────────────────────────────────────
def _proc_state(target: str) -> dict:
    """Snapshot: does any process ARGUS can currently enumerate look like
    `target`?

    Walks psutil.process_iter() the same way apps_skill._running_processes()
    already does -- same call, same per-process try/except around
    NoSuchProcess/AccessDenied -- rather than inventing a second way to ask
    Windows the same question. A process that disappears mid-iteration, or
    one ARGUS cannot see into, is skipped, not fatal: process_iter() is
    inherently a snapshot of a moving target, and losing one entry to a race
    is normal, not an error worth surfacing. A total enumeration failure
    (the try/except around the loop itself) degrades to "nothing found"
    rather than raising -- see the module docstring's FAIL CLOSED section --
    which is a safe default either way: both VERIFIERS functions below
    require a genuine before/after DISAGREEMENT, so two identical "couldn't
    tell" snapshots just report changed=False, never a false positive.
    """
    matched = None
    try:
        for p in psutil.process_iter(["name"]):
            try:
                name = p.info["name"] or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if name and _loose_match(target, name):
                matched = name
                break
    except Exception:
        return {"running": False, "matched_name": None}
    return {"running": matched is not None, "matched_name": matched}


def _verify_apps_open(target: str, before: dict, after: dict) -> bool:
    """True only if no matching process was running before and one is now
    (target itself is not re-checked here -- it is already baked into what
    _proc_state() recorded as "running"). See the module docstring's "WHAT
    changed MEANS HERE" for why "already running, still running" reports
    False rather than True.
    """
    b, a = before or {}, after or {}
    return (not b.get("running")) and bool(a.get("running"))


def _verify_apps_close(target: str, before: dict, after: dict) -> bool:
    """Mirror of _verify_apps_open: was running, now genuinely is not.
    close_app() terminates every process sharing the matched name in one
    pass (see apps_skill._terminate()), so "not running" here correctly
    means none of them survived, not just the first one checked."""
    b, a = before or {}, after or {}
    return bool(b.get("running")) and (not a.get("running"))


# ── window: focus / minimize / maximize ──────────────────────────────────────
def _foreground_snapshot() -> dict:
    """Everything this module needs to know about whatever window is in
    front right now.

    Identity (title/process/pid) comes from pc_skill.focused_window(),
    reused rather than re-read so this module's notion of "what's focused"
    can never quietly diverge from the one followup_skill's "close it"
    already depends on. minimized/maximized are the two bits that function
    does NOT carry (confirmed by reading it before writing this -- it
    returns only title/process/exe/pid), so IsIconic/IsZoomed are read here
    directly, on the SAME handle, using the same bare ctypes.windll.user32
    style focused_window() itself uses -- no argtypes/restype overrides,
    matching the existing, working pattern rather than adding a stricter one
    this file would be the only caller of.

    Never raises: this is the capture side of the hot path every plannable
    step runs through (see capture_state()), so a Win32 call failing here
    degrades individual fields to None, never the whole function to an
    exception.
    """
    from skills import pc_skill  # local: see capture_state()'s own note

    info = {}
    try:
        info = pc_skill.focused_window() or {}
    except Exception:
        info = {}

    hwnd = None
    minimized = None
    maximized = None
    try:
        user32 = ctypes.windll.user32
        h = user32.GetForegroundWindow()
        if h:
            hwnd = int(h)
            minimized = bool(user32.IsIconic(h))
            maximized = bool(user32.IsZoomed(h))
    except Exception:
        pass

    return {
        "hwnd": hwnd,
        "title": info.get("title", ""),
        "process": info.get("process", ""),
        "pid": info.get("pid"),
        "minimized": minimized,
        "maximized": maximized,
    }


def _verify_window_focus(target: str, before: dict, after: dict) -> bool:
    """True only if the foreground window did not already look like `target`
    and now does -- see the module docstring for why "was already focused
    on it" reports False rather than True."""
    if not _window_matches(target, after):
        return False           # not looking at the target now -- didn't work
    return not _window_matches(target, before)


def _verify_window_minimize(target: str, before: dict, after: dict) -> bool:
    """True if the window that was in front (and was not already minimized)
    is simply not in front any more.

    A minimized window CANNOT be the foreground window, so re-checking
    IsIconic on "whatever is foreground after" would always read False and
    make every successful minimize look like a failure -- by construction it
    would be inspecting a DIFFERENT window than the one that was just
    hidden. This function makes no fresh Win32 call to work around that (it
    only compares what capture_state already took -- see the module
    docstring's FAIL CLOSED section); identity moving away from a
    not-yet-minimized window is the honest signal actually available here.
    It happens to also cover window_skill.minimize_all()'s "show desktop"
    path for free, since that too replaces the foreground window with the
    desktop.

    Deliberately does not require `target` to match `before`: minimize()
    can act on a named window that was never focused to begin with (see
    window_skill._find(), which searches every open window, not only the
    foreground one) -- in that case the foreground slot never moves, and
    this verifier honestly returns False rather than guessing. See the
    module docstring's gap note.
    """
    b, a = before or {}, after or {}
    if not b.get("hwnd"):
        return False            # nothing was in front -- nothing to confirm
    if b.get("minimized"):
        return False            # already minimized -- no transition to see
    return a.get("hwnd") != b.get("hwnd")


def _verify_window_maximize(target: str, before: dict, after: dict) -> bool:
    """True if a maximized window is in front afterward, and that was not
    already true of this exact window beforehand.

    Unlike minimize, maximizing does not remove a window from the
    foreground: Win32's SW_MAXIMIZE activates the window it maximizes, so
    the common case (maximize the window already in front) keeps the same
    hwnd, and the less common case (maximize a named background window)
    typically PULLS that window into the foreground instead. Both show up
    here as "the foreground window is now maximized"; only the true no-op --
    identical hwnd, already maximized beforehand -- is excluded, the same
    "was already true" rule the rest of this module applies. `target` is not
    re-checked by name for the same reason it is not in _verify_window_
    minimize: identity (hwnd) is the more reliable signal already captured.
    """
    b, a = before or {}, after or {}
    if not a.get("hwnd") or not a.get("maximized"):
        return False
    if a.get("hwnd") == b.get("hwnd") and b.get("maximized"):
        return False             # same window, already maximized -- no-op
    return True


# ── control: volume / mute ───────────────────────────────────────────────────
def _audio_state() -> dict | None:
    """Current system output level and mute flag, off the SAME COM endpoint
    control_skill.py already fought pycaw's shifting API to reach.

    Calls control_skill._get_volume_interface() rather than re-deriving the
    three-path AudioDevice/IMMDevice fallback that function's own docstring
    explains at length (pycaw silently broke this once already, across
    every volume command) -- reusing it means a future pycaw break only
    needs fixing in that one place, and this module's reading of the volume
    can never disagree with the interface volume_set()/mute() themselves
    just used to CHANGE it.

    Returns None (not a half-filled dict) on any failure -- the COM call
    itself can raise (see that function's own RuntimeError path) -- which is
    exactly capture_state()'s "nothing usable to report" case, not a value
    for a VERIFIERS function to compare against.
    """
    try:
        from skills import control_skill  # local: see capture_state()'s note

        vol = control_skill._get_volume_interface()
        level = vol.GetMasterVolumeLevelScalar()
        muted = bool(vol.GetMute())
        return {"level_percent": int(round(level * 100)), "muted": muted}
    except Exception:
        return None


def _parse_percent(target: str) -> int | None:
    """The same parse router.py performs before ever calling
    control_skill.volume_set() -- int(float(target)), clamped 0-100 --
    copied rather than imported because router.py does not import from
    agent/, and this package does not import router (see observer.py's own
    docstring on why that direction stays one-way). If `target` will not
    parse as a number here, it would not have parsed there either, so there
    is no numeric target for this verifier to compare against.
    """
    try:
        return max(0, min(100, int(float(target))))
    except (TypeError, ValueError):
        return None


# Scalar volume read back from pycaw can land a point or two off what was
# asked for (a float round-trip through SetMasterVolumeLevelScalar, plus
# whatever step size the audio driver actually honours) -- "roughly
# matches", not bit-exact, the same spirit as window/focus matching a title
# loosely rather than exactly.
_VOLUME_TOLERANCE = 2


def _verify_control_volume_set(target: str, before: dict, after: dict) -> bool:
    """True if the level was not already at (roughly) the requested percent
    and now is."""
    desired = _parse_percent(target)
    if desired is None:
        return False            # no numeric target to compare against
    b, a = before or {}, after or {}
    after_level = a.get("level_percent")
    if after_level is None:
        return False
    after_ok = abs(after_level - desired) <= _VOLUME_TOLERANCE
    before_level = b.get("level_percent")
    before_ok = (before_level is not None and
                 abs(before_level - desired) <= _VOLUME_TOLERANCE)
    return after_ok and not before_ok


def _verify_control_mute(target: str, before: dict, after: dict) -> bool:
    """True only if it was not muted before and is muted now. `target` is
    unused -- router.py's own dispatch does not pass one through to
    control_skill.mute() either (see router.py's "control" branch), there
    being nothing to name when the action is a single global toggle."""
    b, a = before or {}, after or {}
    return (b.get("muted") is not True) and (a.get("muted") is True)


def _verify_control_unmute(target: str, before: dict, after: dict) -> bool:
    """Mirror of _verify_control_mute."""
    b, a = before or {}, after or {}
    return (b.get("muted") is True) and (a.get("muted") is not True)


# ── the public contract ──────────────────────────────────────────────────────
# agent/verifiers.py aggregates this table with its sibling domain modules'
# own, asserting the key sets never collide (see that module's own
# docstring) -- so this dict is the ONLY place these eight pairs' checks are
# defined, never duplicated into a second lookup anywhere else.
VERIFIERS: dict[tuple[str, str], callable] = {
    ("apps", "open"): _verify_apps_open,
    ("apps", "close"): _verify_apps_close,
    ("window", "focus"): _verify_window_focus,
    ("window", "minimize"): _verify_window_minimize,
    ("window", "maximize"): _verify_window_maximize,
    ("control", "volume_set"): _verify_control_volume_set,
    ("control", "mute"): _verify_control_mute,
    ("control", "unmute"): _verify_control_unmute,
}


def capture_state(skill: str, action: str, target: str) -> dict | None:
    """A snapshot of whatever state is relevant to verifying (skill, action).

    Returns None if this module has nothing to capture for that pair -- the
    caller (agent/verifiers.py's own capture_state()) then tries the other
    domain module -- and never raises: every branch below is wrapped, and
    any failure degrades to None, since this runs on the hot path of EVERY
    plannable step, not only the ones that end up needing verification.

    Driven off VERIFIERS' own keys rather than a second, separately
    maintained list of pairs: the two could otherwise drift silently (a pair
    added to VERIFIERS with no matching branch here would always verify
    against None and simply never fire, with nothing to say so).

    pc_skill and control_skill are imported LOCALLY, inside the capture
    helpers below, not at module scope -- the same choice window_skill.py's
    own _work_area() makes for pc_skill, and the same reason observer.py
    gives for its own local `from agent import verifiers`: this module
    should not force every caller of the lightweight parts of the agent
    package to also eagerly load pycaw/comtypes/screen_brightness_control
    the moment it is imported.
    """
    key = (skill, action)
    if key not in VERIFIERS:
        return None
    try:
        if skill == "apps":
            return _proc_state(target)
        if skill == "window":
            return _foreground_snapshot()
        if skill == "control":
            return _audio_state()
    except Exception:
        return None
    return None   # unreachable while VERIFIERS only names apps/window/control
