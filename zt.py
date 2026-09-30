"""
ARGUS - Zero-trust session trust.

THE IDEA, STATED PRECISELY. The six-level authorization table in auth.py
answers "how sensitive is this command". It has never answered a second
question that matters just as much: "how much do we actually know about who
is driving this session RIGHT NOW". A session unlocked five minutes ago from
which three authentication failures, a critical detection and a dozen denied
commands have since arrived is not the same session, and the static table
cannot see any of that -- it is deliberately static, because the model must
never decide what it is allowed to do.

This module is the dynamic half, and it is equally deliberate about its
boundaries:

  * The score is computed from SECURITY EVENTS ONLY -- authentication
    outcomes, denials, detector findings, session age. Nothing the user
    said, nothing a model produced, and nothing that arrived over the
    network can move it. A prompt injection cannot lower the score and
    cannot phrase its way past a refusal, because the inputs are all
    events this codebase itself emitted.

  * The score can only REFUSE or require a fresher unlock. It can never
    GRANT anything. A high score changes no decision; auth.authorize()'s
    static level is still the only thing that allows a command. Removing
    trust is the safe direction, so the dynamic layer only ever subtracts.

  * Fail-open is impossible by construction: when this module cannot
    compute a score it returns "trusted", because auth's static gate has
    already handled everything the static gate handles. Zero trust here
    means "no implicit trust in session age", not "deny everything when
    the scorer hiccups" -- the latter is how a hardening layer gets
    deleted by its own user.

WHAT IT IS NOT. It is not a network zero-trust architecture (no micro
segmentation, no device posture attestation against an MDM). It is the
session-level piece of the idea, applied to the one principal this process
actually has.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

# ── policy ─────────────────────────────────────────────────────────────
DEFAULT_ENABLED = True          # used when config.ZT_ENABLED is absent


def enabled() -> bool:
    try:
        import config
        return bool(getattr(config, "ZT_ENABLED", DEFAULT_ENABLED))
    except Exception:
        return DEFAULT_ENABLED


# Bands. ABOVE the step-up threshold the static decision stands. Below it,
# L2 commands need a fresh unlock; below the fail threshold, L3+ is refused
# outright. L0/L1 are never touched -- machine control staying usable while
# the session is merely *less* trusted is what keeps this layer from being
# turned off the first week.
FAIL_BELOW = 0.35
STEPUP_BELOW = 0.60

# Weights. Each component is bounded; the sum is clamped to [0, 1].
# A clean, non-cold session must begin in the trusted band. Keeping this
# below STEPUP_BELOW made the zero-trust layer impose step-up friction before
# any adverse security signal had occurred.
BASE_SCORE = 0.60
_W_AUTH_FAILURE = -0.15         # per recent failure (capped)
_W_AUTH_SUCCESS = 0.10          # a verified-very-recently session
_W_DENIED = -0.10               # per burst of denied commands (capped)
_W_COLD_SESSION = -0.10         # first two minutes of process life
_W_THREAT_CRITICAL = -0.35      # an active critical finding
_W_THREAT_HIGH = -0.15

# Windows over which signals mean anything.
FAILURE_WINDOW_S = 15 * 60
SUCCESS_WINDOW_S = 5 * 60       # "fresh" — mirrors auth.REAUTH_FRESHNESS
DENIED_WINDOW_S = 10 * 60
THREAT_WINDOW_S = 10 * 60
COLD_SESSION_S = 120.0

# "Fresh" matches auth.REAUTH_FRESHNESS in spirit; kept as its own constant
# so zt never imports auth (which imports zt) and the import graph stays
# acyclic at module-load time.
REAUTH_FRESH_S = 900.0

_MAX_COUNTED_FAILURES = 3
_MAX_COUNTED_DENIED = 2

_lock = threading.RLock()
_sig = {
    "auth_failures": [],        # epoch times
    "auth_success": 0.0,        # last successful unlock
    "denied": [],               # refused commands
    "threat": [],               # (epoch, severity)
    "started": time.time(),
}


def _now():
    return time.time()


# ── signal intake ──────────────────────────────────────────────────────
# Called by auth.py (verify/lock/authorize) and threatmon (record). Each is
# never-raises: a scoring bug must not be able to break authentication.
def note_auth_success():
    try:
        with _lock:
            _sig["auth_success"] = _now()
    except Exception:
        pass


def note_auth_failure():
    try:
        with _lock:
            _sig["auth_failures"].append(_now())
            del _sig["auth_failures"][:-32]
    except Exception:
        pass


def note_denied():
    try:
        with _lock:
            _sig["denied"].append(_now())
            del _sig["denied"][:-64]
    except Exception:
        pass


def note_lock():
    try:
        with _lock:
            # A lock ends the trusted window; a fresh unlock is required
            # before any L2+ command anyway, so this only resets recency.
            _sig["auth_success"] = 0.0
    except Exception:
        pass


def note_threat(severity: str):
    try:
        with _lock:
            _sig["threat"].append((_now(), str(severity or "")))
            del _sig["threat"][:-64]
    except Exception:
        pass


def _reset():
    """Test seam. Not a production path."""
    with _lock:
        _sig.update(auth_failures=[], auth_success=0.0, denied=[],
                    threat=[], started=_now())


# ── scoring ────────────────────────────────────────────────────────────
def _score() -> float:
    """The current session-trust score in [0, 1].

    Pure over the signal store plus the clock. Deliberately simple arithmetic
    rather than a model: every move must be explainable in one sentence to the
    person it refuses.
    """
    now = _now()
    with _lock:
        fails = [t for t in _sig["auth_failures"]
                 if now - t < FAILURE_WINDOW_S]
        last_ok = _sig["auth_success"]
        denied = [t for t in _sig["denied"]
                  if now - t < DENIED_WINDOW_S]
        threats = [s for t, s in _sig["threat"] if now - t < THREAT_WINDOW_S]
        age = now - _sig["started"]

    score = BASE_SCORE
    if fails:
        score += max(_W_AUTH_FAILURE * min(len(fails), _MAX_COUNTED_FAILURES),
                     -0.30)
    if last_ok and now - last_ok < SUCCESS_WINDOW_S:
        score += _W_AUTH_SUCCESS
    if denied:
        score += max(_W_DENIED * min(len(denied), _MAX_COUNTED_DENIED), -0.20)
    if age < COLD_SESSION_S:
        score += _W_COLD_SESSION
    if "critical" in threats:
        score += _W_THREAT_CRITICAL
    elif "high" in threats:
        score += _W_THREAT_HIGH

    return max(0.0, min(1.0, score))


def score() -> float:
    try:
        return _score()
    except Exception:
        return 1.0          # fail towards "static rules decide alone"


def band() -> str:
    s = score()
    if s >= STEPUP_BELOW:
        return "trusted"
    if s >= FAIL_BELOW:
        return "low"
    return "untrusted"


# ── the decision ───────────────────────────────────────────────────────
def evaluate(skill: str, action: str, level: int,
             auth_age_s: float | None = None) -> tuple[bool, str]:
    """The zero-trust step-up decision for one command.

    Returns (allowed, spoken_reason). ONLY ever refuses; a True answer means
    "the static authorization result stands", never "allow despite it".

    auth_age_s is the seconds since the last successful unlock, passed in by
    auth.authorize() so this module never has to import auth (which imports
    this one) -- the laziness keeps the import graph acyclic at load time.
    """
    if not enabled():
        return True, ""
    # L0/L1: time, weather, volume, window control. Refusing those on a
    # low score adds friction to exactly the commands that cannot hurt
    # anything, which is how zero trust earns itself a switch named OFF.
    if level <= 1:
        return True, ""

    s = score()
    if s >= STEPUP_BELOW:
        return True, ""

    if s < FAIL_BELOW:
        # Untrusted: nothing that reads private data or acts with the
        # user's authority may ride on this session state.
        if level >= 3:
            return False, (
                "Several things have gone wrong in this session recently, so "
                "I'm not treating it as yours. Lock and authenticate again, "
                "then ask me once more.")
        # L2 still allowed ONLY on a provably fresh unlock.
        if auth_age_s is None or auth_age_s > REAUTH_FRESH_S:
            return False, (
                "This session doesn't look trustworthy right now. "
                "Authenticate again and I'll continue.")

    else:
        # Low (not untrusted): L2 rides only on a fresh unlock, same rule
        # as above. L3+ is already gated by an explicit confirmation in
        # auth, which is itself a proof of presence, so it passes.
        if level == 2 and (auth_age_s is None or auth_age_s > REAUTH_FRESH_S):
            return False, (
                "That needs a fresh authentication — this session has had "
                "some failures recently.")

    return True, ""


# ── reporting (for zt_skill / the security summary) ────────────────────
def _explain() -> list:
    """One sentence per signal that is currently moving the score."""
    now = _now()
    with _lock:
        fails = [t for t in _sig["auth_failures"]
                 if now - t < FAILURE_WINDOW_S]
        last_ok = _sig["auth_success"]
        denied = [t for t in _sig["denied"] if now - t < DENIED_WINDOW_S]
        threats = [s for t, s in _sig["threat"] if now - t < THREAT_WINDOW_S]
        age = now - _sig["started"]

    out = []
    if fails:
        out.append(f"{len(fails)} authentication "
                   f"{'failure' if len(fails) == 1 else 'failures'} in the "
                   f"last 15 minutes")
    if last_ok and now - last_ok < SUCCESS_WINDOW_S:
        out.append("you authenticated within the last few minutes")
    if denied:
        out.append(f"{len(denied)} refused "
                   f"{'command' if len(denied) == 1 else 'commands'} recently")
    if "critical" in threats:
        out.append("a critical detection is active")
    elif "high" in threats:
        out.append("a high-severity detection is active")
    if age < COLD_SESSION_S:
        out.append("this session just started")
    if not out:
        out.append("nothing adverse has happened in this session")
    return out


def posture() -> dict:
    """The full zero-trust posture, for zt_skill and the HUD."""
    try:
        import hwkey
        hw = hwkey.status()
    except Exception:
        hw = {"available": False, "backend": "", "enrolled": False,
              "note": "hwkey module unavailable"}
    return {
        "enabled": enabled(),
        "score": round(score(), 3),
        "band": band(),
        "signals": _explain(),
        "hardware": hw,
    }


def describe() -> str:
    """A spoken one-liner. String logic only -- no model, no network."""
    if not enabled():
        return "Zero-trust scoring is switched off, so my usual rules apply."
    b = band()
    s = score()
    if b == "trusted":
        return (f"This session is in good standing — trust score "
                f"{s:.0%}. {(_explain() or [''])[0]}.")
    if b == "low":
        return (f"I'm treating this session as low trust — score {s:.0%}. "
                f"{(_explain() or [''])[0]}. Sensitive commands will need a "
                f"fresh authentication.")
    return (f"I don't currently trust this session — score {s:.0%}. "
            f"{(_explain() or [''])[0]}. Lock me and authenticate again "
            f"before doing anything sensitive.")
