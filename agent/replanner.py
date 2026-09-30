"""Controlled replanning stages validated alternatives for owner approval.

This module does not execute steps or bypass router authorization.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time

from ollama_client import chat_json

# Deliberately narrow: what FAILED, what was tried, what happened. No
# process lists, no filesystem contents, no conversation history -- a
# replan decision needs the step's own outcome and nothing else. (The same
# discipline _observe_decision's prompt_input already applies one loop
# tighter.)
DIAGNOSE_PROMPT = """A step in an approved plan failed and the plan stopped.
Output ONLY a JSON object: {"diagnosis": "<one short sentence>"}.
Say what kind of failure this looks like (missing, refused, transient,
unsupported) -- not what to do about it."""

# The alternative may ONLY be a fresh step list. The model is told the
# constraint in the prompt AND the constraint is re-enforced in code by
# validate_plan() -- the prompt is for quality, the validator is the law.
REPLAN_PROMPT = """A step in a plan failed. Propose a DIFFERENT smallest
sequence of steps that still achieves the original goal. Output ONLY a JSON
object, no markdown.

Shape: {{"steps":[{{"skill":"...","action":"...","target":"...","expect":"..."}}, ...]}}

Use ONLY these (skill, action) pairs:
{capabilities}

RULES:
- Two to four steps. If one step does it, output one step.
- Do NOT repeat the pair that just failed unless you also change the target
  for a concrete reason.
- Never invent a skill or action that is not listed above.
- For website goals, put a concrete observable expected state in "expect" for
  every step. For other goals the field may be empty.
- If no different approach exists, output {{"steps":[]}}."""

# Diagnoses reused verbatim when the local model is unavailable -- honest,
# specific classes, not invented detail. Keyed on the failure regex that
# matched, so the fallback says something true about THIS failure rather
# than one generic line for all of them.
_FALLBACK_DIAGNOSES = (
    ("not found", "the thing it named isn't there"),
    ("nothing called", "the thing it named isn't there"),
    ("no such", "the thing it named isn't there"),
    ("refused", "the machine refused it"),
    ("locked", "something was locked"),
    ("authenticate", "it needed fresh authentication"),
    ("unavailable", "it was temporarily unavailable"),
    ("hit a problem", "it hit an error"),
    ("went wrong", "it hit an error"),
)


def _fallback_diagnosis(reply: str) -> str:
    low = (reply or "").lower()
    for marker, diagnosis in _FALLBACK_DIAGNOSES:
        if marker in low:
            return diagnosis
    return "the step didn't do what the plan expected"


def diagnose(step: dict, reply: str, goal: str = "") -> str:
    """One short sentence about WHY a step failed. Local model first, honest
    class-level fallback second. Never raises; an empty diagnosis string is
    the failure value, and the caller must treat it as such."""
    step_desc = f"{step.get('skill', '')} {step.get('action', '')}"
    prompt_input = (f"Step: {step_desc}\nResult: {str(reply or '')[:400]}")
    try:
        if goal:
            import agent.budgets as budgets
            if not budgets.consume_model_call(goal):
                return _fallback_diagnosis(reply)
        raw = chat_json(DIAGNOSE_PROMPT, prompt_input)
        diagnosis = str((raw or {}).get("diagnosis", "")).strip()
        if diagnosis:
            return diagnosis[:200]
    except Exception:
        pass
    return _fallback_diagnosis(reply)


def propose_alternative(goal: str, failed_step: dict, reply: str,
                        web: bool = False) -> tuple[bool, str]:
    """The one entry point: a failed plan may get a STAGED replacement.

    Returns (staged, message). staged=True means a VALIDATED alternative
    plan is now sitting in router's _plan awaiting the owner's "say go
    ahead" -- never executed by this function. staged=False means no
    alternative is offered and `message` is the honest reason why.

    Every rejection reason is the owner-facing truth: budget spent, model
    silent, proposal not allowed, or the model itself concluding no
    different approach exists.
    """
    import agent.budgets as budgets
    import router

    goal = (goal or "").strip()
    if not goal:
        return False, "There's no goal left to work towards."

    # ONE plan at a time, the same discipline plan_and_stage itself applies:
    # something already staged or paused must not be silently replaced by a
    # recovery plan nobody asked for.
    if router.plan_is_pending() or router.plan_paused_pending():
        return False, "There's already a task in front of this one."

    # BUDGET FIRST. A capped goal never costs another model call: the whole
    # point of the ledger is that runaway recovery is cut off before it
    # starts, not after the proposal is already built.
    over, why = budgets.exceeded(goal)
    if over:
        return False, f"I've stopped working on this: {why}."
    if not budgets.record_replan(goal):
        return False, ("I've already tried reworking this a few times, so "
                       "I'm stopping here rather than going in circles.")

    diagnosis = diagnose(failed_step, reply, goal=goal)

    # The model's alternative is proposed to the validator, not to the
    # machine. Whatever comes back malformed or empty lands in refusal --
    # there is no code path from this function to a running step.
    capabilities = router._render_capability_block(router.PLANNABLE)
    if not budgets.consume_model_call(goal):
        return False, (f"{diagnosis[0].upper()}{diagnosis[1:]} — and this "
                       "goal has used its local-model call budget, so I stopped.")
    try:
        raw = chat_json(REPLAN_PROMPT.format(capabilities=capabilities),
                        f"Original goal: {goal}\n"
                        f"Failed step: {failed_step.get('skill', '')} "
                        f"{failed_step.get('action', '')} "
                        f"({diagnosis})\n"
                        f"Result: {str(reply or '')[:300]}")
    except Exception:
        return False, (f"{diagnosis[0].upper()}{diagnosis[1:]} — and I "
                       f"can't work out an alternative right now, since "
                       f"the local model isn't answering.")

    # The model's own "no different approach exists" answer, BEFORE the
    # validator: validate_plan treats an empty list as a malformed plan and
    # would bury this honest outcome under a refusal that means something
    # else. Recognising it here is what makes "I couldn't find another way"
    # a first-class answer instead of dead code.
    if not (raw or {}).get("steps"):
        return False, (f"{diagnosis[0].upper()}{diagnosis[1:]}, and there's "
                       f"no different way I can see to get there. Say it "
                       f"another way and I'll work it out fresh.")

    steps, refusal = router.validate_plan((raw or {}).get("steps"), web=web)
    if refusal:
        return False, (f"{diagnosis[0].upper()}{diagnosis[1:]}. The "
                       f"alternative I came up with isn't something I'll "
                       f"do as a bigger task, so I've dropped it.")

    # Budget accounting for the REPLACEMENT plan's size, then stage the
    # VALIDATED steps directly -- deliberately NOT a fresh plan_and_stage()
    # call on the goal text, which would make a second model call that
    # ignores the diagnosis entirely and could stage something different
    # from the alternative the owner is about to be shown. What gets staged
    # is exactly what validate_plan() just approved and exactly what the
    # offer text describes. The staging tail mirrors plan_and_stage()'s own
    # (fill _plan, clear the evidence trail); from here the ordinary "say
    # go ahead" flow takes over, identical to any first plan -- nothing
    # about this path pre-approves anything, and nothing has run.
    reserved, reason = budgets.reserve_plan(goal, len(steps))
    if not reserved:
        return False, f"I've stopped working on this: {reason}."
    router._plan.update(steps=steps, goal=goal, at=time.time())
    router._set_plan_metadata(goal, steps, {
        "strategy": f"Alternative after {diagnosis}",
        "assumptions": [diagnosis],
    })

    try:
        import security
        security.audit("plan_replan",
                       f"{len(steps)} steps after failing at "
                       f"{failed_step.get('skill', '')} "
                       f"{failed_step.get('action', '')}"[:160], "staged")
    except Exception:
        pass

    return True, (f"{diagnosis[0].upper()}{diagnosis[1:]}. Here's a different "
                  f"way: {router.describe_plan(steps)}. Say go ahead and "
                  f"I'll run that instead.")
