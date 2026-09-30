"""
ARGUS - Agent Kernel: task budgets.

WHY THIS EXISTS. Section 20's rule is that autonomy must be bounded, and the
bound must be CODE, not the model's good judgement: "If the budget is
exhausted: STOP, REPORT, ASK OWNER. Never continue indefinitely." A plan
already has two such ceilings inside router.py (MAX_STEP_RETRIES per step and
MAX_PLAN_RETRIES per plan) -- but those bound ONE execution. Replanning gives
a failed task a second plan, which would otherwise mean a second set of
ceilings with nothing connecting them: a goal that fails, replans, fails,
replans ... would run forever, each plan individually well-behaved. The
ledger below is the thing that connects them, per GOAL rather than per plan.

WHAT IT COUNTS. Four counters, deliberately the section 20 limits that apply
to the current planner/replanner surface:

  replans       how many ALTERNATIVE plans this goal has already been given
                (max_replans -- hard cap; record_replan() returns False past it)
  planned_steps the sum of step counts across the original plan and every
                replacement (max_steps -- so a goal cannot launder a 40-step
                campaign through six 6-step plans)
  runtime       wall-clock from the ledger's creation (max_runtime_s -- a task
                that has been failing for ten minutes has been failing long
                enough)
  model_calls   planning, correction, diagnosis and alternative-proposal calls
                combined (max_model_calls -- a failing goal cannot keep the
                local model busy after action retries are already bounded)

Nothing here decides what MAY run -- that stays auth.authorize() and
validate_plan(), before every step, exactly as before. This module only ever
says "enough attempts"; it can refuse, never permit. That is the same
one-way direction the rest of the agent package keeps: advisory about
quantity, silent about permission.

KEYING. Ledgers are keyed on the normalized goal text, so "clean up
downloads" failing twice across two differently-worded retries of the SAME
request is one budget, not two -- replanning the same goal repeatedly is
exactly the runaway section 20 exists to stop. Normalization is deliberately
mechanical (lowercase, collapse whitespace, truncate) -- no model call, no
similarity heuristic, so the key can never drift between two calls.

LIFETIME. In-memory only, matching agent/working_memory.py's rule for the
same reason: an artifact a restart would have to protect is an artifact
needing its own security story, and "how many times did this goal replan"
does not need to survive a reboot -- a reboot also resets every plan, so the
budget cannot be evaded by restarting. A TTL and a hard cap on live ledgers
keep this from becoming an unbounded log of everything the owner has asked
for (the same shape working_memory._MAX and threatmon.__init__'s _buffer
already apply to their own history).

FAIL CLOSED. record_replan() on a goal with no ledger creates one -- a first
replan of something that never staged a plan is still a bounded event, and
refusing to count it would be a free pass shaped like a missing record.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time
from dataclasses import dataclass, field

# ── the caps ─────────────────────────────────────────────────────────────────
# Two REPLANS, not five: each replacement plan is itself capped at
# MAX_PLAN_STEPS (6) and each of its steps is individually authorised, so two
# alternatives already give a failing goal three full, owner-approved
# attempts. Section 20's own example ("5 replans") describes the general
# shape, not a floor; the tighter number matches router.py's existing
# MAX_PLAN_RETRIES=3 total-retry discipline -- a goal gets bounded patience,
# not indefinite patience.
DEFAULT_MAX_REPLANS = 2
# Initial plan (<= router.MAX_PLAN_STEPS) plus both replacements. A goal whose
# replacements keep growing would otherwise turn one request into a
# step-count the owner never approved; this is the ceiling on the SUM.
DEFAULT_MAX_STEPS = 18
# A task that has been failing for ten minutes has failed enough. Longer than
# PLAN_TTL_S (120s) and PLAN_PAUSE_TTL (300s) combined, so an ordinary
# pause-and-resume cycle never trips it by accident.
DEFAULT_MAX_RUNTIME_S = 600.0
DEFAULT_MAX_MODEL_CALLS = 10


@dataclass(frozen=True)
class Budget:
    """The caps for one goal. Frozen -- a cap a caller could mutate after the
    fact would be a cap that never actually bounded anything."""
    max_replans: int = DEFAULT_MAX_REPLANS
    max_steps: int = DEFAULT_MAX_STEPS
    max_runtime_s: float = DEFAULT_MAX_RUNTIME_S
    max_model_calls: int = DEFAULT_MAX_MODEL_CALLS


DEFAULT_BUDGET = Budget()


def normalize_goal(text: str) -> str:
    """The ledger key for a goal. Mechanical only: lowercased, whitespace
    collapsed, truncated. Truncation matches working_memory.remember_
    completed()'s 200-char rule so the two places that key on goal text can
    never disagree about what 'the same goal' means."""
    return " ".join(str(text or "").split()).lower()[:200]


@dataclass
class _Ledger:
    budget: Budget
    started_at: float
    planned_steps: int = 0
    replans_used: int = 0
    model_calls: int = 0
    last_activity: float = field(default_factory=time.time)


_ledgers: dict[str, _Ledger] = {}
_LOCK = threading.Lock()

# How long an idle ledger is kept, and how many may exist at once. Both are
# hygiene, not security: the counters are in-memory evidence of recent
# attempts, not credentials.
_LEDGER_TTL_S = 3600.0
_MAX_LEDGERS = 50


def _prune_locked() -> None:
    """Drop expired ledgers and, if still over the cap, the oldest. Caller
    holds _LOCK."""
    now = time.time()
    expired = [k for k, v in _ledgers.items()
               if now - v.last_activity > _LEDGER_TTL_S]
    for k in expired:
        del _ledgers[k]
    while len(_ledgers) > _MAX_LEDGERS:
        oldest = min(_ledgers, key=lambda k: _ledgers[k].last_activity)
        del _ledgers[oldest]


def ledger_for(goal: str, budget: Budget | None = None) -> _Ledger:
    """The (creating if needed) ledger for this goal text. A lookup after the
    TTL returns a fresh ledger -- the task it belonged to expired with every
    other plan state, and a restart freshens all of them equally."""
    key = normalize_goal(goal)
    with _LOCK:
        _prune_locked()
        led = _ledgers.get(key)
        now = time.time()
        if led is not None and now - led.last_activity > _LEDGER_TTL_S:
            led = None
        if led is None:
            led = _Ledger(budget=budget or DEFAULT_BUDGET, started_at=now)
            _ledgers[key] = led
        led.last_activity = now
        return led




# ── the questions a caller asks ──────────────────────────────────────────────

def replans_left(goal: str) -> int:
    """How many replacement plans this goal may still be given."""
    led = ledger_for(goal)
    with _LOCK:
        return max(0, led.budget.max_replans - led.replans_used)


def record_replan(goal: str) -> bool:
    """Consume one replan. TRUE means the goal may be given a replacement
    plan (and the caller must then stage it through plan_and_stage() --
    approval still belongs to the owner, and every step still goes through
    the ordinary gate). FALSE means the budget is spent: the caller stops and
    reports, per section 20."""
    led = ledger_for(goal)
    with _LOCK:
        led.last_activity = time.time()
        if led.replans_used >= led.budget.max_replans:
            return False
        led.replans_used += 1
        return True


def note_plan(goal: str, step_count: int) -> None:
    """Record how many steps a plan (original or replacement) carried, for
    the max_steps ceiling. Call at staging time, not at approval time --
    the owner rejecting a proposed plan still bounded the task by seeing it."""
    led = ledger_for(goal)
    with _LOCK:
        led.last_activity = time.time()
        led.planned_steps += max(0, int(step_count or 0))


def reserve_plan(goal: str, step_count: int) -> tuple[bool, str]:
    """Atomically reserve a plan's steps before it is staged.

    Unlike ``note_plan`` (kept as a small compatibility/reporting primitive),
    this refuses the plan that would cross the ceiling instead of recording an
    already-visible over-budget proposal and discovering it on the next turn.
    """
    led = ledger_for(goal)
    count = max(0, int(step_count or 0))
    with _LOCK:
        led.last_activity = time.time()
        proposed = led.planned_steps + count
        if proposed > led.budget.max_steps:
            return False, (f"that goal would exceed its {led.budget.max_steps}-step budget")
        if time.time() - led.started_at > led.budget.max_runtime_s:
            return False, "that goal has been running too long"
        led.planned_steps = proposed
        return True, ""


def consume_model_call(goal: str, count: int = 1) -> bool:
    """Reserve local-model work for this goal; false means stop before calling."""
    led = ledger_for(goal)
    amount = max(0, int(count or 0))
    with _LOCK:
        led.last_activity = time.time()
        if led.model_calls + amount > led.budget.max_model_calls:
            return False
        if time.time() - led.started_at > led.budget.max_runtime_s:
            return False
        led.model_calls += amount
        return True


def exceeded(goal: str) -> tuple[bool, str]:
    """(over, reason). Checked BEFORE offering or staging a replacement plan.
    Runtime and step-count ceilings both land here; the replan count has its
    own answer in record_replan()'s return value."""
    led = ledger_for(goal)
    with _LOCK:
        led.last_activity = time.time()
        if led.planned_steps > led.budget.max_steps:
            return True, (f"that goal has already run through "
                          f"{led.planned_steps} planned steps")
        if led.model_calls >= led.budget.max_model_calls:
            return True, (f"that goal has used its {led.budget.max_model_calls} "
                          "local-model calls")
        if time.time() - led.started_at > led.budget.max_runtime_s:
            return True, "that goal has been running too long"
        return False, ""


def summary(goal: str) -> str:
    """One line, for a status panel or an honest 'why I stopped'."""
    led = ledger_for(goal)
    with _LOCK:
        return (f"replans {led.replans_used}/{led.budget.max_replans}, "
                f"{led.planned_steps} planned steps, "
                f"model calls {led.model_calls}/{led.budget.max_model_calls}, "
                f"{int(time.time() - led.started_at)}s")
