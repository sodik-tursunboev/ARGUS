"""
ARGUS - Security state machine.

THE STATES, AND WHAT THEY ACTUALLY DO HERE.

  NORMAL     everything runs as it always has.
  DEGRADED   a security-relevant signal is standing (an integrity drift on
             a non-critical file, a high-severity detection). Execution
             continues, but every grant redemption re-checks the state,
             and the state is visible in status().
  SAFE_MODE  only narrowly-safe functions run: reads, diagnostics,
             integrity and audit inspection. Everything that could change
             machine state is refused regardless of its level. Entered by
             the owner (or diagnostics), never by the model.
  LOCKDOWN   sensitive execution stops: outstanding grants are revoked,
             staged plans are cancelled, and new L2+ actions are refused
             until the owner explicitly recovers. Entered automatically on
             a CRITICAL-tier integrity failure or by the owner's kill
             switch -- never by anything the model says or proposes.
  RECOVERY   the authenticated owner is performing the verified repair;
             sensitive actions remain refused, read-only diagnostics stay
             open. Returning to NORMAL requires the recovery procedure to
             complete successfully (verify_return()), which re-verifies
             the manifest rather than trusting the word "fixed".

THE RULE THE WHOLE FILE ENFORCES: the model cannot set these states. Every
transition function takes its authority from one of two places -- a
deterministic signal (integrity.verify(), a critical detection) or the
owner's own authenticated action (the kill switch, the recovery command).
Nothing here accepts a string from model output as a state or a reason to
change one.

KILL SWITCH (section 23), mapped point by point:
  revoke capability grants        -> grants.revoke_all("kill switch")
  terminate active execution      -> staged plan cancelled; watched/goals
                                     threads already pull-only and stage-
                                     only, but their fire paths call
                                     executable() and refuse
  cancel agent tasks              -> plan slot + paused slot cleared
  suspend watchers                -> watchers_suspended() returns True and
                                     monitor/watched/goals due-checks honor it
  deny external writes            -> L2+ authorize() refuses while not NORMAL
  block network actions           -> same gate; netpolicy fetch is L2-gated
  preserve audit records          -> nothing here touches the log; the
                                     transition itself is audited
  preserve forensic state         -> detections/history untouched
  read-only diagnostics stay up   -> L0/L1 reads unaffected

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
Part of ARGUS. See LICENSE for the full terms.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

NORMAL = "NORMAL"
DEGRADED = "DEGRADED"
SAFE_MODE = "SAFE_MODE"
LOCKDOWN = "LOCKDOWN"
RECOVERY = "RECOVERY"

# Ordered: an index is a rough "how much is withheld" measure. Transitions
# never walk this lattice blindly -- each one is explicit below -- but the
# lattice makes refuse-levels legible: L2+ is withheld above NORMAL, and
# everything but reads is withheld above SAFE_MODE.
_ORDER = [NORMAL, DEGRADED, SAFE_MODE, LOCKDOWN, RECOVERY]

_lock = threading.Lock()
_state = {"state": NORMAL, "since": time.time(), "reason": "",
          "by": "boot", "auto": False}
# How long an AUTOMATIC lockdown stays armed before it is treated as
# requiring the owner no matter what -- recovery from an automatic
# transition is still an owner act (section 63: break-glass is outside
# ordinary agent control). A RECOVERY entered by the owner has no timer.
AUTO_LOCKDOWN_S = 3600.0


def current() -> str:
    with _lock:
        return _state["state"]


def status() -> dict:
    """Read-only view for diagnostics and the HUD. Never mutable from
    outside; callers that want a change go through the transition fns."""
    with _lock:
        s = dict(_state)
        s["age_s"] = round(time.time() - _state["since"], 1)
        return s


def executable() -> bool:
    """The continuous-authorization check (section 21) grants.redeem() makes
    before every execution. Lockdown/RECOVERY refuse; SAFE_MODE refuses
    (its allowance is handled by the authorize() gate, which still runs for
    reads); DEGRADED and NORMAL allow."""
    return current() in (NORMAL, DEGRADED)


def watchers_suspended() -> bool:
    """Section 23: kill switch suspends watchers. True in every state above
    DEGRADED -- a machine that is in lockdown should not have its watcher
    threads staging or firing anything."""
    return current() not in (NORMAL, DEGRADED)


def l2_allowed() -> bool:
    """The authorize()-side gate: state-changing actions run only from
    NORMAL or DEGRADED. SAFE_MODE allows its narrow list (handled inside
    auth.authorize via safe_mode_allowed), everything above refuses."""
    return current() in (NORMAL, DEGRADED)


def safe_mode_allowed(skill: str, action: str) -> bool:
    """Section 24's narrow list, as (skill, action) pairs ARGUS actually
    has. Anything not listed is refused in SAFE_MODE regardless of level."""
    allowed = {
        ("audit", ""), ("audit", "read"),
        ("diag", ""), ("pc", "stats"), ("pc", "time"),
        ("security", "status"), ("security", "integrity"),
        ("integrity", ""), ("vault", "search"), ("apps", "list"),
        ("system", "health"),
    }
    return (skill, action) in allowed or (skill, "") in allowed


def _audit_transition(new: str, reason: str, by: str) -> None:
    try:
        import security
        security.audit("security_state", f"-> {new}; {reason[:80]} by {by}",
                       "ok")
        # security_event's fields are an ALLOWLIST (SAFE_FIELDS) and state=
        # / by= are not on it -- an event that tried to carry free text would
        # raise, not log. outcome carries the fixed state name, reason the
        # bounded trigger, component who acted. Nothing here can smuggle
        # transcript-shaped content into the event log.
        security.security_event(security.SECURITY_STATE_CHANGED,
                                component="security_state", outcome=new,
                                reason=reason[:80], status="ok")
    except Exception:
        # The transition itself must stand even if the audit call fails --
        # refusing to enter lockdown because the log hiccuped would be the
        # exact fail-open shape this module exists to prevent.
        pass


def degrade(reason: str) -> bool:
    """NORMAL -> DEGRADED on a standing non-fatal signal. Idempotent; a
    degrade request in a stricter state changes nothing."""
    with _lock:
        if _state["state"] != NORMAL:
            return False
        _state.update(state=DEGRADED, since=time.time(), reason=reason[:120],
                      by="signal", auto=True)
    _audit_transition(DEGRADED, reason, "signal")
    return True


def _to(new: str, reason: str, by: str, auto: bool) -> None:
    with _lock:
        if _state["state"] == new:
            _state["reason"] = reason[:120] or _state["reason"]
            return
        _state.update(state=new, since=time.time(), reason=reason[:120],
                      by=by, auto=auto)
    _audit_transition(new, reason, by)


def enter_safe_mode(reason: str = "owner request") -> bool:
    """Owner/diagnostics action. Also revokes outstanding grants -- SAFE_MODE
    should not leave a pre-approved mutation armed while it narrows the
    world."""
    if current() in (LOCKDOWN, RECOVERY):
        return False
    from grants import revoke_all
    revoke_all("safe mode")
    _to(SAFE_MODE, reason, "owner", False)
    return True


def enter_lockdown(reason: str, auto: bool = False) -> bool:
    """The kill switch (section 23) and the critical-integrity response
    (section 22). RECOVERY/LOCKDOWN are already contained; everything else
    gets the full treatment: grants die, staged plans die."""
    was = current()
    if was in (LOCKDOWN, RECOVERY):
        return False
    from grants import revoke_all
    revoked = revoke_all("lockdown")
    try:
        import router
        router.cancel_plan()
        router.cancel_paused_plan()
    except Exception:
        pass
    _to(LOCKDOWN, f"{reason} (+{revoked} grants revoked)" if revoked
        else reason, "owner" if not auto else "signal", auto)
    return True


def enter_recovery(reason: str) -> bool:
    """Owner-authenticated recovery (section 63): strong authentication is
    enforced by the caller (the router gate requires L4 + Hello), not by
    this function -- this function only marks the state and refuses to run
    from anything below LOCKDOWN/SAFE_MODE."""
    if current() not in (LOCKDOWN, SAFE_MODE):
        return False
    _to(RECOVERY, reason, "owner", False)
    return True


def verify_return() -> tuple[bool, str]:
    """RECOVERY -> NORMAL only when the tree actually verifies. The repair
    is proven by the manifest, not asserted by anyone."""
    if current() != RECOVERY:
        return False, "not in recovery"
    try:
        import integrity
        r = integrity.verify()
        if not getattr(r, "ok", False):
            return False, "integrity still fails; staying in recovery"
    except Exception as e:
        return False, f"integrity check failed to run ({type(e).__name__})"
    _to(NORMAL, "recovery verified by manifest", "owner", False)
    return True, "normal"


def auto_lockdown_expired() -> bool:
    """An AUTOMATIC lockdown older than AUTO_LOCKDOWN_S is surfaced as
    requiring owner action regardless of anything else. Pure query."""
    with _lock:
        return (_state["auto"] and _state["state"] == LOCKDOWN
                and time.time() - _state["since"] > AUTO_LOCKDOWN_S)


def note_integrity_result(critical_problems: list, problems) -> None:
    """The deterministic signal intake (section 22's transition table):
    called by boot/diagnostics with integrity.verify()'s result. A critical
    failure is LOCKDOWN; a non-critical drift is DEGRADED; a clean verify
    lifts a DEGRADED that this signal caused (never one an owner set)."""
    if critical_problems:
        enter_lockdown("critical integrity failure", auto=True)
        return
    if problems:
        degrade("non-critical integrity drift")
        return
    with _lock:
        if _state["state"] == DEGRADED and _state["by"] == "signal":
            _state.update(state=NORMAL, since=time.time(), reason="",
                          by="signal", auto=False)
