'ARGUS - Agent Kernel: structured observations.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
from dataclasses import dataclass, field

# ── status classification ---------------------------------------------------
# Deliberately the SAME patterns router.py's _STEP_FAILED/_NEEDS_AUTH already
# Keep these reply patterns aligned with router.py without importing router
# and creating an import cycle.
_FAILED = re.compile(
    r"\b(?:i (?:can'?t|cannot|couldn'?t|could not|don'?t have)|"
    r"that needs|needs stronger|is locked|authenticate again|"
    r"type your pin to confirm|"
    r"i won'?t|not found|nothing called|no such|didn'?t work|"
    r"hit a problem|went wrong|unavailable|refused)\b", re.I)

_NEEDS_AUTH = re.compile(
    r"needs you to authenticate again|"
    r"is locked\. authenticate|"
    r"needs confirming\. say|"
    r"type your pin to confirm|"
    r"needs stronger authentication|"
    r"hold the push-to-talk", re.I)

STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_PAUSED = "paused"
STATUS_UNKNOWN = "unknown"


def classify_reply(reply: str) -> tuple[str, tuple[str, ...]]:
    """(status, warnings) from a raw reply string alone. Pure -- no OS calls,
    no imports beyond stdlib -- so it is unit-testable anywhere and callable
    on any reply ARGUS has ever produced, not only ones that went through
    router's plan loop.

    An EMPTY reply is UNKNOWN, not failed: several real skills return "" for
    a state that genuinely has nothing to report (see router.py's own
    handling), and calling that a failure would make this module noisier
    than the thing it is classifying.
    """
    text = str(reply or "").strip()
    if not text:
        return STATUS_UNKNOWN, ()
    if _NEEDS_AUTH.search(text):
        return STATUS_PAUSED, ()
    if _FAILED.search(text):
        return STATUS_FAILED, (text[:200],)
    return STATUS_SUCCESS, ()


# ── the Observation type -----------------------------------------------------
@dataclass(frozen=True)
class Observation:
    """What happened, normalized. Immutable -- once produced, an Observation
    cannot be quietly edited into claiming a different outcome than what was
    actually seen.

    status        one of STATUS_SUCCESS / STATUS_FAILED / STATUS_PAUSED /
                  STATUS_UNKNOWN -- from classify_reply(), always present.
    reply         the raw reply text, kept verbatim. The owner-facing report
                  should still read THIS, not a summary of it -- see
                  router.py's own "it reports the real replies, not a
                  summary" test for why that discipline matters.
    changed       True/False if a real verifier ran and could tell; None if
                  no verifier exists for this (skill, action) or it could not
                  be checked. NEVER a guess from the reply text alone --
                  that is what `verified` distinguishes.
    verified      True only when a REAL machine-state check ran (see
                  verifiers.py). False means `changed`/`before`/`after` are
                  unknown, not that nothing changed.
    before/after  whatever the relevant verifier captured, as plain dicts.
                  None when unverified.
    warnings      non-fatal notes (e.g. classify_reply's matched failure
                  text, or a verifier that could not run).
    errors        populated only when observe() itself failed to run (a
                  verifier raising, say) -- kept separate from `warnings` so
                  a caller can tell "the STEP had a problem" from "checking
                  the step had a problem."
    """
    status: str
    reply: str
    changed: bool | None = None
    verified: bool = False
    before: dict | None = None
    after: dict | None = None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    expected: str = ""
    expected_met: bool | None = None

    @property
    def ok(self) -> bool:
        return self.status == STATUS_SUCCESS

    def summary(self) -> str:
        bits = [self.status]
        if self.verified:
            bits.append("changed" if self.changed else "unchanged")
        else:
            bits.append("unverified")
        return f"{'/'.join(bits)}: {self.reply[:80]}"


def observe(skill: str, action: str, target: str, reply: str,
           before: dict | None = None, after: dict | None = None,
           artifacts: tuple[str, ...] = (), expected: str = "") -> Observation:
    """The one entry point. classify_reply() always runs; a verifier runs
    IN ADDITION when verifiers.VERIFIERS has one for (skill, action) and
    BEFORE/AFTER snapshots are supplied by the caller (capture_state() in
    verifiers.py is how those get taken -- observe() itself never touches
    the machine, so it stays safe to call from anywhere, including a unit
    test, without side effects).

    Local import of verifiers: keeps this module importable stand-alone
    (verifiers.py imports psutil/pycaw-touching helpers this module has no
    business depending on just to classify a string), and avoids a cycle if
    verifiers.py ever needs something from here beyond the Observation type.
    """
    status, warnings = classify_reply(reply)
    errors: tuple[str, ...] = ()
    changed = None
    verified = False
    expected_met = None

    if before is not None and after is not None:
        try:
            from agent import verifiers
            check = verifiers.VERIFIERS.get((skill, action))
        except Exception as e:
            check = None
            errors = (f"verifier lookup failed: {type(e).__name__}",)
        if check is not None:
            try:
                changed = bool(check(target, before, after))
                verified = True
                expected_met = changed
                if status == STATUS_SUCCESS and not expected_met:
                    status = STATUS_FAILED
                    warnings = warnings + (
                        "the before/after verifier did not observe the expected state change",
                    )
            except Exception as e:
                errors = errors + (f"verifier raised: {type(e).__name__}: {e}"[:150],)

    return Observation(status=status, reply=str(reply or ""), changed=changed,
                       verified=verified, before=before, after=after,
                       warnings=warnings, errors=errors,
                       artifacts=tuple(str(x)[:500] for x in artifacts[:20]),
                       expected=" ".join(str(expected or "").split())[:300],
                       expected_met=expected_met)
