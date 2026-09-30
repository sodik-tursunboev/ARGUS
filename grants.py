"""
ARGUS - Capability grants.

WHY THIS EXISTS. auth.authorize() answers "may this (skill, action) run at
all" from the static table. It has always been an EXACT-ACTION gate, but it
has never been an EXACT-REQUEST gate: nothing bound the decision to the
normalized arguments and re-checked that binding at execution time, so the
attack in section 49 -- "LLM changes arguments after approval" -- was
answered by discipline (the confirmation matching in take_confirmation(),
whole-plan validation) rather than by construction. The grant below makes
argument binding CONSTRUCTION: authorization is minted for one ActionHash,
the hash is re-verified at the moment of execution, and anything material
that changed in between invalidates it.

WHAT A GRANT IS (section 4.2's properties, each mapped):

  short lifetime      GRANT_TTL_S = 120 -- matches router.PLAN_TTL_S, the
                      longest window an approved step is legitimately
                      pending execution (pause + resume across the same
                      plan). A grant never outlives the approval it came
                      from.
  single use          uses_left: a one-time grant is consumed by the first
                      redeem(); a multi-use grant counts down (a plan step
                      within MAX_STEP_RETRIES legitimately runs up to 3
                      times -- the bounded correction loop -- so plans mint
                      with uses=3; a use is still consumed per redemption,
                      which is what bounds a retry loop even when the model
                      would keep going).
  bound to task       goal: the goal string whose approval produced it --
                      a grant from one task cannot execute in another.
  bound to action hash ActionHash = SHA256 over the canonical step tuple
                      (section 4.3): capability + normalized arguments +
                      target. Any material change re-hashes to a different
                      digest and the redeem refuses.
  revocable           revoke() / revoke_all(); every redemption re-checks
                      the global security state first (section 21's
                      continuous authorization).
  replay prevention   a consumed one-time grant is gone; redeeming it
                      again is a REPLAY -- recorded as a security event and
                      refused (section 49's "replayed grant -> deny").

WHAT A GRANT IS NOT. It is not a second permission source. authorize()
remains the only tier decision; a grant never LOWERS a level. The gate is
interpositional: redeem() is called immediately before dispatch, and it can
only refuse. If grants are unavailable (import failure, state loss) the
redeem refuses -- section 25: a failed security dependency causes denial,
not fallback.

THE MODEL CANNOT TOUCH ANY OF IT. No skill, no plan step, and no piece of
model output selects, mints, or extends a grant. Minting happens only at
the three seams that represent real owner intent (interactive confirmation
acceptance, staged-plan approval, staged-plan run), and every mint is
audited.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
Part of ARGUS. See LICENSE for the full terms.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import hashlib
import threading
import time

GRANT_TTL_S = 120.0          # one plan slot's lifetime; see PLAN_TTL_S
MAX_USES = 4                 # retry ceiling + 1, never a long-lived token
MAX_GRANTS = 32              # bounded table; oldest-expiring evicted

_lock = threading.Lock()
_grants: dict = {}           # token -> grant dict
_tombstones: list = []       # hashes of recently consumed one-time grants
_MAX_TOMBSTONES = 64
_seq = 0

# Stable reason strings appear in audit lines.
R_OK = "ok"
R_ABSENT = "no grant for this action"
R_EXPIRED = "the authorization for this step expired"
R_HASH = "this step no longer matches what was approved"
R_USES = "the authorization for this step was already used"
R_GOAL = "this step does not belong to the approved task"
R_STATE = "security state does not allow execution"
R_CONSUMED = "that approval was already used"


def action_hash(skill: str, action: str, target: str) -> str:
    """Section 4.3's digest, narrowed to the fields a step actually carries.

    SHA256(capability + normalized arguments + canonical target identity).
    Normalization is deliberate and matches what the dispatcher will act
    on: the pair lower-cased and whitespace-collapsed, the target
    lower-cased and stripped. Hashing UNnormalized text would mint hashes
    that fail their own redemption on a trailing space; hashing only the
    (skill, action) pair would make the target -- the thing substitution
    attacks change -- invisible to the binding.
    """
    norm = lambda s: " ".join(str(s or "").split()).strip().lower()  # noqa: E731
    payload = "\x1f".join((norm(skill), norm(action), norm(target)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def mint(skill: str, action: str, target: str, *, goal: str = "",
         uses: int = 1, ttl: float = GRANT_TTL_S,
         source: str = "") -> str:
    """Create a grant for ONE exact action. Returns the opaque token.

    `source` records which owner-intent seam minted it ("confirmation",
    "plan_stage", "plan_run") -- provenance for the audit line, and a
    canary in tests that nothing else has started minting.
    """
    global _seq
    if uses < 1:
        uses = 1
    uses = min(uses, MAX_USES)
    now = time.time()
    token = action_hash(skill, action, target)[:12] + "-" + \
        hashlib.sha256(f"{now:.6f}{_seq}".encode()).hexdigest()[:16]
    with _lock:
        _seq += 1
        _grants[token] = {
            "h": action_hash(skill, action, target),
            "skill": str(skill or ""), "action": str(action or ""),
            "target": str(target or ""),
            "goal": str(goal or "")[:200],
            "uses": uses,
            "expires": now + max(1.0, min(ttl, GRANT_TTL_S)),
            "source": str(source or "")[:24],
        }
        # Bounded table: evict the soonest-expiring grant first. Evidence
        # hygiene, not security -- expired grants are refused by time.
        while len(_grants) > MAX_GRANTS:
            oldest = min(_grants, key=lambda k: _grants[k]["expires"])
            del _grants[oldest]
    import security
    try:
        security.audit("grant_mint", f"{source or 'seam'} "
                       f"{skill}/{action} uses={uses}", "ok")
    except Exception:
        pass
    return token


def redeem(token: str, skill: str, action: str, target: str,
           goal: str = "") -> tuple[bool, str]:
    """Validate the grant IMMEDIATELY BEFORE execution (section 21).

    (allowed, reason). Refuses -- never degrades -- on: absent token,
    expiry, action-hash mismatch (the argument-substitution defense),
    exhausted uses, goal mismatch, or a security state that withdraws
    execution. The only success path consumes one use; a one-time grant
    consumed is DELETED, so redeeming it again is a replay and lands in
    R_CONSUMED.

    Thread-safe: plan steps and watcher fires redeem concurrently.
    """
    import security
    import security_state
    if not security_state.executable():
        return False, R_STATE
    with _lock:
        g = _grants.get(token)
        if g is None:
            th = hashlib.sha256(token.encode()).hexdigest()[:24]
            if th in _tombstones:
                try:
                    security.security_event(security.TOOL_DENIED,
                                            skill=skill, action=action or "-",
                                            reason="grant_replay",
                                            status="failed")
                except Exception:
                    pass
                return False, R_CONSUMED
            return False, R_ABSENT
        now = time.time()
        if now > g["expires"]:
            del _grants[token]
            return False, R_EXPIRED
        if g["h"] != action_hash(skill, action, target):
            # The binding did its job: what is about to run is NOT what was
            # approved. Record it -- this is section 49's model attack
            # arriving late -- and refuse.
            try:
                security.security_event(security.TOOL_DENIED, skill=skill,
                                        action=action or "-", status="failed",
                                        reason="grant_hash_mismatch")
            except Exception:
                pass
            return False, R_HASH
        if goal and g["goal"] and goal != g["goal"]:
            return False, R_GOAL
        if g["uses"] <= 0:
            return False, R_CONSUMED
        g["uses"] -= 1
        if g["uses"] <= 0:
            del _grants[token]
            # Tombstone the consumed one-time grant: redeeming it AGAIN is
            # section 49's "reused one-time capability -> deny", and the
            # distinction from a merely-unknown token is the signal -- an
            # absent grant is a bug, a tombstoned one is a replay attempt.
            _tombstones.append(hashlib.sha256(token.encode()).hexdigest()[:24])
            del _tombstones[:-_MAX_TOMBSTONES]
        return True, R_OK


def revoke(token: str) -> bool:
    with _lock:
        return _grants.pop(token, None) is not None


def revoke_all(reason: str = "") -> int:
    """Section 21/23: continuous authorization and the kill switch both end
    here. Every outstanding grant dies at once. Returns the count."""
    with _lock:
        n = len(_grants)
        _grants.clear()
    if n:
        import security
        try:
            security.audit("grant_revoke_all", f"{n} grants; {reason[:60]}",
                           "ok")
        except Exception:
            pass
    return n


def outstanding() -> int:
    """Prune-then-count. Read-only diagnostics (status surfaces, tests)."""
    now = time.time()
    with _lock:
        for k in [k for k, v in _grants.items() if now > v["expires"]]:
            del _grants[k]
        return len(_grants)


def describe() -> str:
    """One honest line for `security status`-style surfaces."""
    return f"{outstanding()} outstanding execution grant(s)"
