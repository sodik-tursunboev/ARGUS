'ARGUS - Agent Kernel: the entry point.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from dataclasses import dataclass
from enum import Enum

import router
from agent.context import WorldState, capture
from agent.goals import Goal
from agent.task_state import current_task
from agent.working_memory import remember_completed


class DecisionType(str, Enum):
    """The bounded vocabulary of agent decisions."""
    ACTION = "ACTION"        # a plan is staged; approving it is the existing, separate "say go ahead" step
    ASK_USER = "ASK_USER"    # the goal was ambiguous or refused in a way a rephrase could fix
    FINISH = "FINISH"
    WAIT = "WAIT"
    REPLAN = "REPLAN"
    STOP = "STOP"            # cannot proceed right now for a reason unrelated to phrasing: planner offline, another task already active, a malformed plan


@dataclass(frozen=True)
class AgentDecision:
    type: DecisionType
    message: str
    goal: Goal | None = None
    steps: tuple = ()    # populated only for ACTION: what was staged, for display
    world_state: WorldState | None = None  # local read-only snapshot at decision time


# Substrings of router.plan_and_stage()'s own known reply text (see
# router.py's plan_and_stage() and validate_plan()) that mean "the OWNER
# could fix this by asking differently" rather than "something is broken."
# Matched the same way router.py's own _STEP_FAILED/_NEEDS_AUTH match
# auth.py's refusal text -- against known wording, not guessed -- so this
# stays accurate as long as the two files are kept in sync; a test asserting
# that sync is worth adding once this is wired into something that speaks.
_ASK_USER_MARKERS = (
    "what would you like me to do",
    "try asking for one thing at a time",
    "break it up for me",
    "ask me for that one directly",
    "sort that first",
)


def _classify(reply: str) -> DecisionType:
    # Authoritative first: if a plan is actually sitting staged, nothing
    # about the reply's wording needs guessing at.
    if router.plan_is_pending():
        return DecisionType.ACTION
    if any(marker in reply.lower() for marker in _ASK_USER_MARKERS):
        return DecisionType.ASK_USER
    return DecisionType.STOP


def run_goal(text: str, web: bool = False) -> AgentDecision:
    """Understand a goal and stage a plan for it. Runs nothing.

    web=True is the same flag router.plan_and_stage(web=True) already takes
    for a single-utterance website task (see WEB_TASK_ACTIONS in router.py)
    -- passed straight through, not reinterpreted here.
    """
    goal = Goal(text=text, web=web)
    # Context is evidence for a caller or future planner, never an input to
    # authorization. Capture failures must not prevent an owner from asking
    # for help, so unavailable local sources simply produce no snapshot.
    try:
        world_state = capture()
    except Exception:
        world_state = None
    if not goal.text.strip():
        return AgentDecision(DecisionType.ASK_USER, "What would you like me to do?",
                             goal=goal, world_state=world_state)

    try:
        reply = router.plan_and_stage(goal.text, web=web)
    except Exception as e:
        return AgentDecision(DecisionType.STOP,
                             f"Couldn't plan that: {type(e).__name__}", goal=goal,
                             world_state=world_state)

    decision = _classify(reply)
    steps = tuple(current_task().pending_actions) if decision == DecisionType.ACTION else ()
    return AgentDecision(decision, reply, goal=goal, steps=steps,
                         world_state=world_state)


def report_outcome(goal: Goal, outcome: str, ok: bool = True) -> None:
    """Record a finished task into working memory (agent/working_memory.py).

    Kept as the typed public API for callers that already own a Goal. The
    ordinary plan loop records its final outcome automatically through the
    same bounded storage primitive.
    """
    remember_completed(goal.text if goal else "", outcome, ok=ok)


def task_observations() -> list:
    """Structured evidence from the current or most recently run plan.

    router._run_steps() captures read-only state immediately before and after
    each dispatch attempt, then normalizes its reply through
    observer.observe().  The returned list includes failed and paused attempts
    as well as completed actions, which is essential for an honest task report.
    It is a copy; callers cannot mutate router's record or affect execution.
    """
    try:
        return router.plan_observations()
    except Exception:
        return []


def current_decision() -> AgentDecision:
    """Describe the task lifecycle using the same typed decision vocabulary.

    This is observational only: it never approves, resumes or executes a task.
    It gives callers real FINISH/WAIT/REPLAN states instead of forcing them to
    parse plan-status prose.
    """
    task = current_task()
    if task.state == "paused":
        return AgentDecision(DecisionType.WAIT, task.summary(),
                             goal=Goal(task.goal), steps=tuple(task.pending_actions))
    if task.state == "staged":
        kind = (DecisionType.REPLAN
                if any(s.lower().startswith("alternative after")
                       for s in task.candidate_strategies)
                else DecisionType.ACTION)
        return AgentDecision(kind, task.summary(), goal=Goal(task.goal),
                             steps=tuple(task.pending_actions))
    try:
        from agent.working_memory import recent_tasks
        latest = recent_tasks(1)
    except Exception:
        latest = []
    if latest:
        item = latest[0]
        return AgentDecision(DecisionType.FINISH if item.ok else DecisionType.STOP,
                             item.outcome, goal=Goal(item.goal))
    return AgentDecision(DecisionType.STOP, "No task in progress.")
